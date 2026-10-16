package probe

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/wire"
)

type socket struct {
	in, out      chan carrier.Echo
	done         chan struct{}
	once         sync.Once
	ip           netip.Addr
	dropEvery, n int
}

func (s *socket) Close() error { s.once.Do(func() { close(s.done) }); return nil }
func (s *socket) ReadEcho() (carrier.Echo, error) {
	select {
	case <-s.done:
		return carrier.Echo{}, net.ErrClosed
	case p := <-s.in:
		return p, nil
	}
}
func (s *socket) WriteEcho(p carrier.Echo) error {
	s.n++
	if s.dropEvery > 0 && s.n%s.dropEvery == 0 {
		return nil
	}
	p.Addr = s.ip
	p.Data = append([]byte(nil), p.Data...)
	select {
	case <-s.done:
		return net.ErrClosed
	case s.out <- p:
		return nil
	}
}
func pair() (*socket, *socket) {
	a, b := make(chan carrier.Echo, 1024), make(chan carrier.Echo, 1024)
	return &socket{in: a, out: b, done: make(chan struct{}), ip: netip.MustParseAddr("192.0.2.10")}, &socket{in: b, out: a, done: make(chan struct{}), ip: netip.MustParseAddr("192.0.2.20")}
}
func options() Options {
	var k [32]byte
	k[0] = 7
	return Options{Key: k, Remote: netip.MustParseAddr("192.0.2.20"), Size: 1280, PPS: 100, Window: 64, Duration: 250 * time.Millisecond, Timeout: 100 * time.Millisecond, IDMode: "stable"}
}

func TestAuthenticatedExchangeAndLossAccounting(t *testing.T) {
	for _, mode := range []string{"stable", "rotate"} {
		t.Run(mode, func(t *testing.T) {
			client, server := pair()
			client.dropEvery = 5
			o := options()
			o.IDMode = mode
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type response struct {
				r ServerResult
				e error
			}
			done := make(chan response, 1)
			go func() { r, e := Serve(ctx, server, ServerOptions{Key: o.Key, MaxPPS: 1000}); done <- response{r, e} }()
			r, err := Run(ctx, client, o)
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			s := <-done
			if s.e != nil {
				t.Fatal(s.e)
			}
			if r.Sent < 10 || r.Verified == 0 || r.Expired == 0 || r.Sent != r.Verified+r.Expired || r.Invalid != 0 || s.r.Replies != r.Verified || r.PeakOutstanding > o.Window {
				t.Fatalf("incorrect accounting: client=%+v server=%+v", r, s.r)
			}
		})
	}
}

func TestKernelReflectionIsNotAValidResponse(t *testing.T) {
	client, peer := pair()
	o := options()
	o.Duration = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-peer.in:
				p.Reply = true
				peer.WriteEcho(p)
			}
		}
	}()
	r, err := Run(ctx, client, o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verified != 0 || r.KernelEchoes == 0 || r.Expired != r.Sent {
		t.Fatalf("reflection counted as success: %+v", r)
	}
}

func TestServerRejectsReplayAndWrongKey(t *testing.T) {
	client, server := pair()
	o := options()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan ServerResult, 1)
	go func() { r, _ := Serve(ctx, server, ServerOptions{Key: o.Key, MaxPPS: 1000}); done <- r }()
	f := wire.Frame{Kind: wire.Request, Number: 7, Time: time.Now().Unix(), Payload: pattern(7, 100, false)}
	f.Session[0] = 1
	data, _ := wire.EncodeProbe(f, o.Key[:], 200)
	client.WriteEcho(carrier.Echo{Data: data})
	client.WriteEcho(carrier.Echo{Data: data})
	wrong := o.Key
	wrong[0]++
	data, _ = wire.EncodeProbe(f, wrong[:], 200)
	client.WriteEcho(carrier.Echo{Data: data})
	select {
	case <-client.in:
	case <-time.After(time.Second):
		t.Fatal("response missing")
	}
	// The duplicate and bad key are queued before the barrier request.
	f.Number = 8
	f.Payload = pattern(8, 100, false)
	data, _ = wire.EncodeProbe(f, o.Key[:], 200)
	client.WriteEcho(carrier.Echo{Data: data})
	select {
	case <-client.in:
	case <-time.After(time.Second):
		t.Fatal("barrier missing")
	}
	cancel()
	r := <-done
	if r.Replies != 2 || r.Replay != 1 || r.Invalid != 1 {
		t.Fatalf("bad admission: %+v", r)
	}
}

func TestWindowBoundAndCancellation(t *testing.T) {
	client, _ := pair()
	o := options()
	o.Window = 2
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	r, err := Run(ctx, client, o)
	if err == nil || r.PeakOutstanding > 2 || r.WindowBlocked == 0 {
		t.Fatalf("missing limits/cancellation: %+v err=%v", r, err)
	}
}
