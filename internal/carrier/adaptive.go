package carrier

import (
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/bug0000/pingtun/internal/wire"
)

// AdaptiveConfig explicitly opts both peers into protocol v2. Defaults favor
// bounded queues and low idle traffic, not a promise of a particular bandwidth.
type AdaptiveConfig struct {
	MaxPPS    int    `json:"max_pps,omitempty"`
	MaxWindow int    `json:"max_window,omitempty"`
	IdleMS    int    `json:"idle_ms,omitempty"`
	IDMode    string `json:"id_mode,omitempty"`
}

func (a AdaptiveConfig) settings() AdaptiveConfig {
	if a.MaxPPS == 0 {
		a.MaxPPS = 1000
	}
	if a.MaxWindow == 0 {
		a.MaxWindow = 128
	}
	if a.IdleMS == 0 {
		a.IdleMS = 500
	}
	if a.IDMode == "" {
		a.IDMode = "rotate"
	}
	return a
}
func (a AdaptiveConfig) validate() error {
	if a.MaxPPS < 10 || a.MaxPPS > 5000 || a.MaxWindow < 4 || a.MaxWindow > 128 || a.IdleMS < 100 || a.IdleMS > 5000 || (a.IDMode != "stable" && a.IDMode != "rotate") {
		return errors.New("invalid adaptive limits")
	}
	return nil
}

func (b *Bind) Restarts() <-chan struct{} { return b.restarts }
func (b *Bind) Snapshot() map[string]any {
	protocol := "v1"
	if b.cfg.Adaptive != nil {
		protocol = "v2"
	}
	return map[string]any{"protocol": protocol, "echo_sent": b.Stats.Sent.Load(), "datagrams_received": b.Stats.Received.Load(), "invalid": b.Stats.Invalid.Load(), "dropped": b.Stats.Dropped.Load(), "expired": b.Stats.Expired.Load(), "wire_sent_bytes": b.Stats.WireSent.Load(), "wire_received_bytes": b.Stats.WireReceived.Load(), "data_frames_sent": b.Stats.DataSent.Load(), "control_frames_sent": b.Stats.ControlSent.Load(), "window": b.Stats.Window.Load(), "peak_outstanding": b.Stats.PeakOutstanding.Load(), "rtt_us": b.Stats.RTTUS.Load(), "peer_restarts": b.Stats.PeerRestarts.Load(), "limited": b.Stats.Limited.Load(), "last_reply_unix": b.Stats.LastReplyUnix.Load()}
}
func (b *Bind) readAdaptive(g *generation, p Echo) {
	if p.Reply == b.cfg.Server || (!b.cfg.Server && p.Addr != b.cfg.Remote) {
		return
	}
	f, e := wire.DecodeAdaptive(p.Data, b.cfg.Key[:], time.Now())
	if e != nil || int(f.Lane) >= b.cfg.Lanes || (b.cfg.Server && f.Kind != wire.Request) || (!b.cfg.Server && f.Kind != wire.Response) {
		b.Stats.Invalid.Add(1)
		return
	}
	size := b.cfg.WireMTU - 28
	if f.Flags&wire.Control != 0 {
		size = wire.AdaptiveHeaderSize
	}
	if len(p.Data) != size {
		b.Stats.Invalid.Add(1)
		return
	}
	b.Stats.WireReceived.Add(uint64(len(p.Data) + 28))
	select {
	case g.input <- incoming{packet: p, adaptive: f}:
	case <-g.ctx.Done():
	default:
		b.Stats.Dropped.Add(1)
	}
}
func (b *Bind) writeAdaptive(g *generation, p Echo, f wire.AdaptiveFrame) bool {
	size := b.cfg.WireMTU - 28
	if f.Flags&wire.Control != 0 {
		size = wire.AdaptiveHeaderSize
	}
	data, e := wire.EncodeAdaptive(f, b.cfg.Key[:], size)
	if e != nil {
		b.Stats.Dropped.Add(1)
		return false
	}
	p.Data = data
	if g.socket.WriteEcho(p) != nil {
		b.Stats.Dropped.Add(1)
		return false
	}
	b.Stats.Sent.Add(1)
	b.Stats.WireSent.Add(uint64(size + 28))
	if len(f.Payload) > 0 {
		b.Stats.DataSent.Add(1)
	}
	if f.Flags&wire.Control != 0 {
		b.Stats.ControlSent.Add(1)
	}
	return true
}

// A single limiter covers every logical lane. RTT excludes authenticated server
// hold time; loss reduces the window once per RTT rather than once per timeout.
type controller struct {
	window            float64
	rtt               time.Duration
	tokens            float64
	last, lastCut     time.Time
	maxWindow, maxPPS int
	rto, maxRTO       time.Duration
	sampled           bool
}

func (c *controller) allow(now time.Time) bool {
	if c.last.IsZero() {
		c.last = now
		c.tokens = 1
	}
	rate := math.Min(float64(c.maxPPS), c.window/math.Max(c.rtt.Seconds(), .005)*1.1)
	c.tokens = math.Min(4, c.tokens+now.Sub(c.last).Seconds()*rate)
	c.last = now
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}
func (c *controller) ack(sample time.Duration, useful bool) {
	if sample < time.Millisecond {
		sample = time.Millisecond
	}
	if sample > 5*time.Second {
		return
	}
	if c.sampled {
		c.rtt = (7*c.rtt + sample) / 8
	} else {
		c.rtt = sample
		c.sampled = true
	}
	c.rto = min(c.maxRTO, max(500*time.Millisecond, 4*c.rtt+50*time.Millisecond))
	if useful {
		c.window = math.Min(float64(c.maxWindow), c.window+1/c.window)
	}
}
func (c *controller) loss(now time.Time) {
	if now.Sub(c.lastCut) < max(c.rtt, 100*time.Millisecond) {
		return
	}
	c.window = math.Max(2, c.window/2)
	c.rto = min(c.maxRTO, max(500*time.Millisecond, 2*c.rto))
	c.tokens = math.Min(c.tokens, 1)
	c.lastCut = now
}

type adaptiveTicket struct {
	packet         Echo
	frame          wire.AdaptiveFrame
	sent, deadline time.Time
}

func (b *Bind) adaptiveClient(g *generation, id [16]byte) {
	a := *b.cfg.Adaptive
	c := controller{window: float64(min(a.MaxWindow, max(4, b.cfg.Lanes*b.cfg.Window))), rtt: 50 * time.Millisecond, maxWindow: a.MaxWindow, maxPPS: a.MaxPPS, rto: b.cfg.Timeout, maxRTO: b.cfg.Timeout}
	pending := make(map[uint64]adaptiveTicket)
	queue := make([]message, 0, queueLimit)
	number := uint64(binary.BigEndian.Uint32(id[:4]))
	baseID := binary.BigEndian.Uint16(id[4:6])
	var full int
	var controlPending bool
	var active, lastIdle time.Time
	var backlog uint16
	var feedback uint64
	var epoch uint64
	retired := make(map[uint64]bool)
	var retiredOrder []uint64
	clock := time.NewTicker(time.Millisecond)
	defer clock.Stop()
	pump := func(now time.Time) {
		for len(queue) > 0 && now.Sub(queue[0].created) > 5*time.Second {
			queue = queue[1:]
			b.Stats.Dropped.Add(1)
		}
		target := int(c.window)
		isActive := len(queue) > 0 || backlog > 0 || (!active.IsZero() && now.Sub(active) < max(150*time.Millisecond, 2*c.rtt))
		for burst := 0; burst < 4; burst++ {
			control := !isActive
			if control {
				if controlPending || now.Sub(lastIdle) < time.Duration(a.IdleMS)*time.Millisecond {
					return
				}
			} else {
				limit := target
				if len(queue) == 0 {
					limit -= max(1, target/4)
				}
				if full >= limit {
					return
				}
			}
			if !c.allow(now) {
				return
			}
			number++
			lane := uint16(number % uint64(b.cfg.Lanes))
			f := wire.AdaptiveFrame{Kind: wire.Request, Lane: lane, Session: id, Number: number, Time: now.Unix()}
			if control {
				f.Flags = wire.Control
			} else if len(queue) > 0 {
				f.Payload = queue[0].data
				queue = queue[1:]
			}
			p := Echo{ID: baseID + lane, Seq: uint16(number), Addr: b.cfg.Remote}
			if a.IDMode == "rotate" {
				p.ID = uint16(number)
				p.Seq = uint16(number >> 16)
			}
			if !b.writeAdaptive(g, p, f) {
				c.loss(now)
				return
			}
			rto := c.rto
			pending[number] = adaptiveTicket{p, f, now, now.Add(rto)}
			if control {
				controlPending = true
				lastIdle = now
			} else {
				full++
			}
			if uint64(len(pending)) > b.Stats.PeakOutstanding.Load() {
				b.Stats.PeakOutstanding.Store(uint64(len(pending)))
			}
		}
	}
	pump(time.Now())
	for {
		select {
		case <-g.ctx.Done():
			return
		case m := <-g.outgoing:
			if m.ip != b.cfg.Remote || len(queue) >= queueLimit {
				b.Stats.Dropped.Add(1)
			} else {
				queue = append(queue, m)
				active = time.Now()
			}
		case event := <-g.input:
			f := event.adaptive
			t, ok := pending[f.Number]
			if !ok || f.Session != id || f.Lane != t.frame.Lane || f.Flags != t.frame.Flags || t.packet.ID != event.packet.ID || t.packet.Seq != event.packet.Seq || retired[f.Epoch] {
				b.Stats.Invalid.Add(1)
				continue
			}
			now := time.Now()
			delete(pending, f.Number)
			if t.frame.Flags&wire.Control != 0 {
				controlPending = false
			} else {
				full--
			}
			if now.After(t.deadline) {
				b.Stats.Expired.Add(1)
				c.loss(now)
				continue
			}
			if epoch != 0 && f.Epoch != epoch {
				if len(retiredOrder) == 8 {
					delete(retired, retiredOrder[0])
					retiredOrder = retiredOrder[1:]
				}
				retiredOrder = append(retiredOrder, epoch)
				retired[epoch] = true
				epoch = f.Epoch
				b.Stats.Dropped.Add(uint64(len(queue)))
				queue = nil
				clear(pending)
				full = 0
				controlPending = false
				backlog = 0
				feedback = 0
			drain:
				for {
					select {
					case <-g.outgoing:
						b.Stats.Dropped.Add(1)
					default:
						break drain
					}
				}
				b.Stats.PeerRestarts.Add(1)
				select {
				case b.restarts <- struct{}{}:
				default:
				}
				active = now
				continue
			}
			epoch = f.Epoch
			b.Stats.LastReplyUnix.Store(uint64(now.Unix()))
			delay := time.Duration(f.DelayUS) * time.Microsecond
			sample := now.Sub(t.sent)
			if delay < sample {
				sample -= delay
			}
			c.ack(sample, len(f.Payload) > 0 || len(t.frame.Payload) > 0)
			if f.Number >= feedback {
				feedback = f.Number
				backlog = f.Backlog
			}
			if len(f.Payload) > 0 || f.Backlog > 0 {
				active = now
			}
			b.deliver(g, f.Payload, b.cfg.Remote)
		case now := <-clock.C:
			for n, t := range pending {
				if now.After(t.deadline) {
					delete(pending, n)
					if t.frame.Flags&wire.Control != 0 {
						controlPending = false
					} else {
						full--
					}
					b.Stats.Expired.Add(1)
					c.loss(now)
				}
			}
		}
		b.Stats.Window.Store(uint64(c.window))
		b.Stats.RTTUS.Store(uint64(c.rtt.Microseconds()))
		pump(time.Now())
	}
}

func (b *Bind) adaptiveServer(g *generation, epoch uint64) {
	clock := time.NewTicker(5 * time.Millisecond)
	defer clock.Stop()
	sessions := make(map[[16]byte]*session)
	requests := make([]adaptiveTicket, 0, queueLimit)
	queue := make([]message, 0, queueLimit)
	tokens, last := 32.0, time.Now()
	respond := func(t adaptiveTicket, data []byte) {
		now := time.Now()
		f := t.frame
		f.Kind = wire.Response
		f.Epoch = epoch
		f.Time = now.Unix()
		f.Payload = data
		f.DelayUS = uint32(min(now.Sub(t.sent).Microseconds(), int64(math.MaxUint32)))
		for _, m := range queue {
			if m.ip == t.packet.Addr {
				f.Backlog++
			}
		}
		p := t.packet
		p.Reply = true
		b.writeAdaptive(g, p, f)
	}
	dispatch := func(now time.Time) {
		for len(queue) > 0 && now.Sub(queue[0].created) > 5*time.Second {
			queue = queue[1:]
			b.Stats.Dropped.Add(1)
		}
		for i := 0; i < len(requests); {
			t := requests[i]
			found := -1
			for j, m := range queue {
				if m.ip == t.packet.Addr {
					found = j
					break
				}
			}
			if found < 0 && now.Before(t.deadline) {
				i++
				continue
			}
			var data []byte
			if found >= 0 {
				data = queue[found].data
				queue = append(queue[:found], queue[found+1:]...)
			}
			respond(t, data)
			requests = append(requests[:i], requests[i+1:]...)
		}
	}
	for {
		select {
		case <-g.ctx.Done():
			return
		case m := <-g.outgoing:
			if len(queue) < queueLimit {
				queue = append(queue, m)
			} else {
				b.Stats.Dropped.Add(1)
			}
		case event := <-g.input:
			now := time.Now()
			f := event.adaptive
			tokens = math.Min(32, tokens+now.Sub(last).Seconds()*float64(b.cfg.Adaptive.MaxPPS))
			last = now
			if tokens < 1 {
				b.Stats.Limited.Add(1)
				continue
			}
			tokens--
			s := sessions[f.Session]
			if s == nil {
				for id, old := range sessions {
					if now.Sub(old.last) > 2*time.Minute {
						delete(sessions, id)
					}
				}
				if len(sessions) >= 8 {
					b.Stats.Limited.Add(1)
					continue
				}
				s = &session{}
				sessions[f.Session] = s
			}
			if !s.window.Accept(f.Number) {
				b.Stats.Invalid.Add(1)
				continue
			}
			s.last = now
			b.deliver(g, f.Payload, event.packet.Addr)
			hold := 25 * time.Millisecond
			if len(f.Payload) > 0 {
				hold = 5 * time.Millisecond
			}
			t := adaptiveTicket{packet: event.packet, frame: f, sent: now, deadline: now.Add(hold)}
			if f.Flags&wire.Control != 0 {
				respond(t, nil)
			} else if len(requests) < queueLimit {
				requests = append(requests, t)
			} else {
				b.Stats.Limited.Add(1)
				respond(t, nil)
			}
		case <-clock.C:
		}
		dispatch(time.Now())
	}
}
