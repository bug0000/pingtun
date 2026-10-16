// Package carrier transports WireGuard datagrams in authenticated ICMP echoes.
// It is a transport implementation, not an independent encryption protocol.
package carrier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bug0000/pingtun/internal/wire"
	"golang.zx2c4.com/wireguard/conn"
)

const queueLimit = 256

var ErrQueueFull = errors.New("carrier queue full")

type Config struct {
	Server        bool
	Remote        netip.Addr
	Key           [32]byte
	Lanes, Window int
	WireMTU       int
	Hold          time.Duration
	Timeout       time.Duration
	Socket        func() (EchoSocket, error)
}

func (c Config) Validate() error {
	if c.Lanes < 1 || c.Lanes > 8 || c.Window < 1 || c.Window > 16 || c.WireMTU < 512 || c.WireMTU > 1500 || c.Hold < 50*time.Millisecond || c.Hold > time.Second || c.Timeout < c.Hold+100*time.Millisecond || c.Timeout > 10*time.Second {
		return errors.New("invalid carrier limits")
	}
	if c.Key == ([32]byte{}) {
		return errors.New("transport key must not be zero")
	}
	if !c.Server && (!c.Remote.Is4() || c.Remote.IsUnspecified() || c.Remote.IsMulticast()) {
		return errors.New("client requires a unicast server IPv4 address")
	}
	if c.Socket == nil {
		return errors.New("socket factory required")
	}
	return nil
}

type Stats struct{ Sent, Received, Invalid, Dropped, Expired atomic.Uint64 }
type Endpoint struct{ IP netip.Addr }

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) DstToString() string { return netip.AddrPortFrom(e.IP, 1).String() }
func (e *Endpoint) DstToBytes() []byte  { return e.IP.AsSlice() }
func (e *Endpoint) DstIP() netip.Addr   { return e.IP }
func (e *Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type message struct {
	data    []byte
	ip      netip.Addr
	created time.Time
}
type incoming struct {
	packet Echo
	frame  wire.Frame
}
type ticket struct {
	packet   Echo
	frame    wire.Frame
	deadline time.Time
}
type session struct {
	window wire.Window
	last   time.Time
}
type generation struct {
	ctx      context.Context
	cancel   context.CancelFunc
	socket   EchoSocket
	outgoing chan message
	received chan message
	input    chan incoming
	workers  sync.WaitGroup
}
type Bind struct {
	cfg   Config
	mu    sync.Mutex
	gen   *generation
	Stats Stats
}

var _ conn.Bind = (*Bind)(nil)

func New(c Config) (*Bind, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	return &Bind{cfg: c}, nil
}
func (b *Bind) BatchSize() int { return 1 }
func (b *Bind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("ICMP SO_MARK is not implemented; use explicit endpoint routing")
	}
	return nil
}
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, e := netip.ParseAddrPort(s)
	if e != nil || !a.Addr().Is4() {
		return nil, errors.New("endpoint must be IPv4:port")
	}
	return &Endpoint{a.Addr()}, nil
}
func (b *Bind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.gen != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	socket, e := b.cfg.Socket()
	if e != nil {
		return nil, 0, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &generation{ctx: ctx, cancel: cancel, socket: socket, outgoing: make(chan message, queueLimit), received: make(chan message, queueLimit), input: make(chan incoming, queueLimit)}
	var id [16]byte
	if _, e = rand.Read(id[:]); e != nil {
		cancel()
		socket.Close()
		return nil, 0, e
	}
	b.gen = g
	g.workers.Add(2)
	go func() { defer g.workers.Done(); b.read(g) }()
	go func() {
		defer g.workers.Done()
		if b.cfg.Server {
			b.server(g)
		} else {
			b.client(g, id)
		}
	}()
	receive := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if g.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, errors.New("receive buffers missing")
		}
		select {
		case <-g.ctx.Done():
			return 0, net.ErrClosed
		case m := <-g.received:
			if g.ctx.Err() != nil {
				return 0, net.ErrClosed
			}
			if len(m.data) > len(packets[0]) {
				return 0, errors.New("receive buffer too small")
			}
			sizes[0] = copy(packets[0], m.data)
			eps[0] = &Endpoint{m.ip}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{receive}, 1, nil
}
func (b *Bind) Close() error {
	b.mu.Lock()
	g := b.gen
	b.gen = nil
	b.mu.Unlock()
	if g == nil {
		return nil
	}
	g.cancel()
	e := g.socket.Close()
	g.workers.Wait()
	return e
}
func (b *Bind) Done() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.gen != nil {
		return b.gen.ctx.Done()
	}
	done := make(chan struct{})
	close(done)
	return done
}
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	endpoint, ok := ep.(*Endpoint)
	if !ok || endpoint == nil || !endpoint.IP.Is4() {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	g := b.gen
	b.mu.Unlock()
	if g == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if len(buf) > b.cfg.WireMTU-28-wire.HeaderSize {
			return fmt.Errorf("datagram %d exceeds carrier budget", len(buf))
		}
		m := message{append([]byte(nil), buf...), endpoint.IP, time.Now()}
		select {
		case <-g.ctx.Done():
			return net.ErrClosed
		case g.outgoing <- m:
		default:
			b.Stats.Dropped.Add(1)
			return ErrQueueFull
		}
	}
	return nil
}
func (b *Bind) read(g *generation) {
	for {
		p, e := g.socket.ReadEcho()
		if e != nil {
			g.cancel()
			return
		}
		if len(p.Data) != b.cfg.WireMTU-28 || p.Reply == b.cfg.Server || (!b.cfg.Server && p.Addr != b.cfg.Remote) {
			b.Stats.Invalid.Add(1)
			continue
		}
		f, e := wire.Decode(p.Data, b.cfg.Key[:], time.Now())
		if e != nil || int(f.Lane) >= b.cfg.Lanes || (b.cfg.Server && f.Kind != wire.Request) || (!b.cfg.Server && f.Kind != wire.Response) {
			b.Stats.Invalid.Add(1)
			continue
		}
		select {
		case g.input <- incoming{p, f}:
		case <-g.ctx.Done():
			return
		default:
			b.Stats.Dropped.Add(1)
		}
	}
}
func (b *Bind) deliver(g *generation, data []byte, ip netip.Addr) {
	if len(data) == 0 {
		return
	}
	m := message{append([]byte(nil), data...), ip, time.Now()}
	select {
	case g.received <- m:
		b.Stats.Received.Add(1)
	default:
		b.Stats.Dropped.Add(1)
	}
}
func (b *Bind) write(g *generation, p Echo, f wire.Frame) bool {
	data, e := wire.Encode(f, b.cfg.Key[:], b.cfg.WireMTU-28)
	if e != nil {
		b.Stats.Dropped.Add(1)
		return false
	}
	p.Data = data
	if e = g.socket.WriteEcho(p); e != nil {
		b.Stats.Dropped.Add(1)
		return false
	}
	b.Stats.Sent.Add(1)
	return true
}

func (b *Bind) client(g *generation, id [16]byte) {
	timer := time.NewTicker(25 * time.Millisecond)
	defer timer.Stop()
	pending := make(map[uint64]ticket)
	queue := make([]message, 0, queueLimit)
	counts := make([]int, b.cfg.Lanes)
	var seed [8]byte
	if _, e := rand.Read(seed[:]); e != nil {
		g.cancel()
		return
	}
	number := binary.BigEndian.Uint64(seed[:]) >> 1
	replenish := func() {
		for lane := 0; lane < b.cfg.Lanes; lane++ {
			for counts[lane] < b.cfg.Window {
				number++
				var data []byte
				if len(queue) > 0 {
					data = queue[0].data
					queue = queue[1:]
				}
				f := wire.Frame{Kind: wire.Request, Lane: uint16(lane), Session: id, Number: number, Time: time.Now().Unix(), Payload: data}
				p := Echo{ID: uint16(number), Seq: uint16(number >> 16), Addr: b.cfg.Remote}
				if !b.write(g, p, f) {
					break
				}
				pending[number] = ticket{packet: p, frame: f, deadline: time.Now().Add(b.cfg.Timeout)}
				counts[lane]++
			}
		}
	}
	replenish()
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
			f := event.frame
			t, ok := pending[f.Number]
			if !ok || f.Session != id || f.Lane != t.frame.Lane || t.packet.ID != event.packet.ID || t.packet.Seq != event.packet.Seq || time.Now().After(t.deadline) {
				b.Stats.Invalid.Add(1)
				continue
			}
			delete(pending, f.Number)
			counts[f.Lane]--
			b.deliver(g, f.Payload, b.cfg.Remote)
		case now := <-timer.C:
			for n, t := range pending {
				if now.After(t.deadline) {
					delete(pending, n)
					counts[t.frame.Lane]--
					b.Stats.Expired.Add(1)
				}
			}
			for len(queue) > 0 && now.Sub(queue[0].created) > 5*time.Second {
				queue = queue[1:]
				b.Stats.Dropped.Add(1)
			}
		}
		replenish()
	}
}

func (b *Bind) server(g *generation) {
	timer := time.NewTicker(10 * time.Millisecond)
	defer timer.Stop()
	sessions := make(map[[16]byte]*session)
	requests := make([]ticket, 0, queueLimit)
	queue := make([]message, 0, queueLimit)
	respond := func(t ticket, data []byte) {
		f := t.frame
		f.Kind = wire.Response
		f.Time = time.Now().Unix()
		f.Payload = data
		p := t.packet
		p.Reply = true
		b.write(g, p, f)
	}
	dispatch := func(now time.Time) {
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
			f := event.frame
			s := sessions[f.Session]
			if s == nil {
				for id, old := range sessions {
					if now.Sub(old.last) > 2*time.Minute {
						delete(sessions, id)
					}
				}
				if len(sessions) >= 8 {
					b.Stats.Dropped.Add(1)
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
			t := ticket{packet: event.packet, frame: f, deadline: now.Add(b.cfg.Hold)}
			if len(requests) >= queueLimit {
				respond(t, nil)
				b.Stats.Dropped.Add(1)
			} else {
				requests = append(requests, t)
			}
		case now := <-timer.C:
			for len(queue) > 0 && now.Sub(queue[0].created) > 5*time.Second {
				queue = queue[1:]
				b.Stats.Dropped.Add(1)
			}
		}
		dispatch(time.Now())
	}
}
