// Package probe measures authenticated raw ICMP without TUN, WireGuard or the
// tunnel's polling scheduler. Payloads are generated test bytes, never user data.
package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/wire"
)

type Options struct {
	Key               [32]byte
	Remote            netip.Addr
	Size, PPS, Window int
	Duration, Timeout time.Duration
	IDMode            string
}

func (o Options) Validate() error {
	if o.Key == ([32]byte{}) || !o.Remote.Is4() || o.Remote.IsUnspecified() || o.Remote.IsMulticast() {
		return errors.New("probe requires a carrier key and unicast IPv4 peer")
	}
	if o.Size < 28+wire.HeaderSize+8 || o.Size > 1500 || o.PPS < 1 || o.PPS > 5000 || o.Window < 1 || o.Window > 1024 || o.Duration < 100*time.Millisecond || o.Duration > 2*time.Minute || o.Timeout < 50*time.Millisecond || o.Timeout > 5*time.Second || (o.IDMode != "stable" && o.IDMode != "rotate") {
		return errors.New("invalid probe limits: size 94..1500, pps 1..5000, window 1..1024, duration 100ms..2m, timeout 50ms..5s, id-mode stable|rotate")
	}
	return nil
}

type Result struct {
	RequestedSeconds   float64 `json:"requested_seconds"`
	RequestedPPS       int     `json:"requested_pps"`
	WireSize           int     `json:"wire_size"`
	IDMode             string  `json:"id_mode"`
	SendSeconds        float64 `json:"send_seconds"`
	ElapsedSeconds     float64 `json:"elapsed_seconds"`
	Sent               uint64  `json:"sent"`
	Verified           uint64  `json:"verified"`
	Expired            uint64  `json:"expired"`
	Unfinished         uint64  `json:"unfinished"`
	WriteErrors        uint64  `json:"write_errors"`
	Invalid            uint64  `json:"invalid"`
	KernelEchoes       uint64  `json:"kernel_echoes"`
	LateOrDuplicate    uint64  `json:"late_or_duplicate"`
	WindowBlocked      uint64  `json:"window_blocked_slots"`
	ScheduleMissed     uint64  `json:"schedule_missed_slots"`
	PeakOutstanding    int     `json:"peak_outstanding"`
	AchievedPPS        float64 `json:"achieved_pps"`
	UnconfirmedPercent float64 `json:"unconfirmed_percent"`
	PayloadMbps        float64 `json:"verified_payload_mbps"`
	WireTxMbps         float64 `json:"wire_tx_mbps"`
	RTTMeanMS          float64 `json:"rtt_mean_ms"`
	RTTP50MS           float64 `json:"rtt_p50_ms"`
	RTTP95MS           float64 `json:"rtt_p95_ms"`
}

type ServerOptions struct {
	Key    [32]byte
	MaxPPS int
}
type ServerResult struct {
	Requests    uint64 `json:"requests"`
	Replies     uint64 `json:"replies"`
	Invalid     uint64 `json:"invalid"`
	Replay      uint64 `json:"replay"`
	Limited     uint64 `json:"limited"`
	WriteErrors uint64 `json:"write_errors"`
}

type readResult struct {
	packet carrier.Echo
	err    error
}

func read(ctx context.Context, s carrier.EchoSocket) <-chan readResult {
	ch := make(chan readResult, 1024)
	go func() {
		defer close(ch)
		for {
			p, err := s.ReadEcho()
			select {
			case ch <- readResult{p, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return ch
}

func pattern(number uint64, size int, response bool) []byte {
	p := make([]byte, size)
	for i := range p {
		p[i] = byte(number>>((i%8)*8)) ^ byte(i*31)
	}
	if response {
		for i := range p {
			p[i] ^= 0xa5
		}
	}
	return p
}

// Serve returns one modified, authenticated response per fresh request, with
// exactly the request's length. It owns and closes the supplied socket.
func Serve(ctx context.Context, s carrier.EchoSocket, o ServerOptions) (ServerResult, error) {
	var result ServerResult
	defer s.Close()
	if o.Key == ([32]byte{}) || o.MaxPPS < 1 || o.MaxPPS > 5000 {
		return result, errors.New("invalid probe server limits")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	packets := read(ctx, s)
	type entry struct {
		replay wire.Window
		last   time.Time
	}
	sessions := make(map[[16]byte]*entry)
	tokens, last := 32.0, time.Now()
	for {
		select {
		case <-ctx.Done():
			return result, nil
		case r, ok := <-packets:
			if !ok || r.err != nil {
				if ctx.Err() != nil {
					return result, nil
				}
				return result, errors.New("probe ICMP read failed")
			}
			p := r.packet
			if p.Reply || len(p.Data) < 4 || string(p.Data[:4]) != "PTPB" {
				continue
			}
			now := time.Now()
			f, err := wire.DecodeProbe(p.Data, o.Key[:], now)
			if err != nil || f.Kind != wire.Request || len(f.Payload) < 8 || !bytes.Equal(f.Payload, pattern(f.Number, len(f.Payload), false)) {
				result.Invalid++
				continue
			}
			// Limit admission before allocating session state or generating replies.
			tokens = math.Min(32, tokens+now.Sub(last).Seconds()*float64(o.MaxPPS))
			last = now
			if tokens < 1 {
				result.Limited++
				continue
			}
			tokens--
			e := sessions[f.Session]
			if e == nil {
				for id, old := range sessions {
					if now.Sub(old.last) > 2*time.Minute {
						delete(sessions, id)
					}
				}
				if len(sessions) >= 8 {
					result.Limited++
					continue
				}
				e = &entry{}
				sessions[f.Session] = e
			}
			if !e.replay.Accept(f.Number) {
				result.Replay++
				continue
			}
			e.last = now
			result.Requests++
			f.Kind = wire.Response
			f.Time = now.Unix()
			f.Payload = pattern(f.Number, len(f.Payload), true)
			p.Reply = true
			p.Data, err = wire.EncodeProbe(f, o.Key[:], len(p.Data))
			if err != nil {
				return result, errors.New("probe response encode failed")
			}
			if s.WriteEcho(p) != nil {
				result.WriteErrors++
			} else {
				result.Replies++
			}
		}
	}
}

type pending struct {
	sent    time.Time
	id, seq uint16
}

// Run paces requests independently of the tunnel scheduler. Unconfirmed requests
// include loss in either direction; it does not mislabel them as one-way loss.
// The socket is closed before returning, including on cancellation.
func Run(ctx context.Context, s carrier.EchoSocket, o Options) (Result, error) {
	defer s.Close()
	r := Result{RequestedPPS: o.PPS, WireSize: o.Size, IDMode: o.IDMode, RequestedSeconds: o.Duration.Seconds()}
	if err := o.Validate(); err != nil {
		return r, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	var session [16]byte
	if _, err := rand.Read(session[:]); err != nil {
		return r, err
	}
	stableID := binary.BigEndian.Uint16(session[:2])
	number := uint64(binary.BigEndian.Uint32(session[2:6]))
	packets := read(ctx, s)
	interval := time.Second / time.Duration(o.PPS)
	tick := interval
	if tick < time.Millisecond {
		tick = time.Millisecond
	}
	timer := time.NewTicker(tick)
	defer timer.Stop()
	started := time.Now()
	end := started.Add(o.Duration)
	drainEnd := end.Add(o.Timeout)
	next := started
	pendingRequests := make(map[uint64]pending)
	rtts := make([]float64, 0, o.PPS*int(math.Ceil(o.Duration.Seconds())))
	var runErr error
	running := true
	for running {
		select {
		case <-ctx.Done():
			runErr = ctx.Err()
			running = false
		case item, ok := <-packets:
			if !ok || item.err != nil {
				runErr = errors.New("probe ICMP read failed")
				running = false
				break
			}
			p := item.packet
			if !p.Reply || p.Addr != o.Remote || len(p.Data) < 4 || string(p.Data[:4]) != "PTPB" {
				continue
			}
			f, err := wire.DecodeProbe(p.Data, o.Key[:], time.Now())
			if err != nil || f.Session != session {
				r.Invalid++
				continue
			}
			if f.Kind == wire.Request {
				r.KernelEchoes++
				continue
			}
			t, ok := pendingRequests[f.Number]
			if !ok {
				r.LateOrDuplicate++
				continue
			}
			if len(p.Data) != o.Size-28 || p.ID != t.id || p.Seq != t.seq || f.Lane != 0 || f.Kind != wire.Response || !bytes.Equal(f.Payload, pattern(f.Number, o.Size-28-wire.HeaderSize, true)) {
				r.Invalid++
				continue
			}
			elapsed := time.Since(t.sent)
			if elapsed > o.Timeout {
				delete(pendingRequests, f.Number)
				r.Expired++
				r.LateOrDuplicate++
				continue
			}
			delete(pendingRequests, f.Number)
			r.Verified++
			rtts = append(rtts, float64(elapsed)/float64(time.Millisecond))
		case now := <-timer.C:
			for n, t := range pendingRequests {
				if now.Sub(t.sent) >= o.Timeout {
					delete(pendingRequests, n)
					r.Expired++
				}
			}
			for burst := 0; burst < 8 && !next.After(now) && next.Before(end); burst++ {
				next = next.Add(interval)
				if len(pendingRequests) >= o.Window {
					r.WindowBlocked++
					continue
				}
				number++
				id, seq := stableID, uint16(number)
				if o.IDMode == "rotate" {
					id, seq = uint16(number), uint16(number>>16)
				}
				f := wire.Frame{Kind: wire.Request, Session: session, Number: number, Time: time.Now().Unix(), Payload: pattern(number, o.Size-28-wire.HeaderSize, false)}
				data, err := wire.EncodeProbe(f, o.Key[:], o.Size-28)
				if err != nil {
					return r, err
				}
				t := time.Now()
				if s.WriteEcho(carrier.Echo{ID: id, Seq: seq, Addr: o.Remote, Data: data}) != nil {
					r.WriteErrors++
					continue
				}
				pendingRequests[number] = pending{t, id, seq}
				r.Sent++
				if len(pendingRequests) > r.PeakOutstanding {
					r.PeakOutstanding = len(pendingRequests)
				}
			}
			if !next.After(now) && next.Before(end) {
				until := now
				if until.After(end) {
					until = end
				}
				missed := uint64(until.Sub(next)/interval) + 1
				r.ScheduleMissed += missed
				next = next.Add(time.Duration(missed) * interval)
			}
			if !now.Before(end) && len(pendingRequests) == 0 {
				running = false
			}
			if !now.Before(drainEnd) {
				r.Expired += uint64(len(pendingRequests))
				running = false
			}
		}
	}
	r.ElapsedSeconds = time.Since(started).Seconds()
	r.SendSeconds = math.Min(r.ElapsedSeconds, o.Duration.Seconds())
	r.Unfinished = r.Sent - r.Verified - r.Expired
	r.AchievedPPS = float64(r.Sent) / r.SendSeconds
	r.WireTxMbps = float64(r.Sent*uint64(o.Size)*8) / r.SendSeconds / 1e6
	// The total measurement interval includes draining late responses.
	r.PayloadMbps = float64(r.Verified*uint64(o.Size-28-wire.HeaderSize)*8) / r.ElapsedSeconds / 1e6
	if r.Sent > 0 {
		r.UnconfirmedPercent = 100 * float64(r.Sent-r.Verified) / float64(r.Sent)
	}
	if len(rtts) > 0 {
		sort.Float64s(rtts)
		for _, v := range rtts {
			r.RTTMeanMS += v
		}
		r.RTTMeanMS /= float64(len(rtts))
		r.RTTP50MS = rtts[(len(rtts)-1)/2]
		r.RTTP95MS = rtts[int(math.Ceil(float64(len(rtts))*.95))-1]
	}
	return r, runErr
}
