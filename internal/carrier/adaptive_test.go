package carrier

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/bug0000/pingtun/internal/wire"
	"golang.zx2c4.com/wireguard/conn"
)

func TestAdaptiveIdleAndWakeup(t *testing.T) {
	client, server := socketPair()
	cc, sc := testConfig(client, false), testConfig(server, true)
	cc.Adaptive = &AdaptiveConfig{IdleMS: 100, IDMode: "stable"}
	sc.Adaptive = &AdaptiveConfig{}
	cb, _ := New(cc)
	sb, _ := New(sc)
	sf, _, err := sb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	cf, _, err := cb.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	time.Sleep(350 * time.Millisecond)
	client.mu.Lock()
	capture := append([]Echo(nil), client.capture...)
	client.mu.Unlock()
	if len(capture) < 2 || len(capture) > 6 {
		t.Fatalf("idle poll budget exceeded: %d", len(capture))
	}
	for _, p := range capture {
		if len(p.Data) != wire.AdaptiveHeaderSize {
			t.Fatal("full-sized request sent during idle")
		}
	}
	payload := []byte("opaque encrypted data after idle")
	if err = cb.Send([][]byte{payload}, &Endpoint{netip.MustParseAddr("192.0.2.20")}); err != nil {
		t.Fatal(err)
	}
	get := func(fn conn.ReceiveFunc) []byte {
		t.Helper()
		done := make(chan []byte, 1)
		go func() {
			buf := make([]byte, 1500)
			sizes := make([]int, 1)
			if _, e := fn([][]byte{buf}, sizes, make([]conn.Endpoint, 1)); e == nil {
				done <- buf[:sizes[0]]
			}
		}()
		select {
		case b := <-done:
			return b
		case <-time.After(time.Second):
			t.Fatal("idle wakeup stalled")
			return nil
		}
	}
	if !bytes.Equal(get(sf[0]), payload) {
		t.Fatal("upload corrupted")
	}
	if err = sb.Send([][]byte{payload}, &Endpoint{client.ip}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(get(cf[0]), payload) {
		t.Fatal("download corrupted")
	}
	if cb.Stats.PeakOutstanding.Load() > 129 {
		t.Fatal("unbounded credits")
	}
}

func TestAdaptiveServerRestartNotification(t *testing.T) {
	client, server := socketPair()
	cc, sc := testConfig(client, false), testConfig(server, true)
	cc.Adaptive = &AdaptiveConfig{IdleMS: 100}
	sc.Adaptive = &AdaptiveConfig{}
	// A new raw socket is required on reopening a closed bind.
	sc.Socket = func() (EchoSocket, error) {
		return &memorySocket{in: server.in, out: server.out, done: make(chan struct{}), ip: server.ip}, nil
	}
	cb, _ := New(cc)
	sb, _ := New(sc)
	if _, _, err := sb.Open(0); err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	if _, _, err := cb.Open(0); err != nil {
		t.Fatal(err)
	}
	defer cb.Close()
	until := time.Now().Add(time.Second)
	for cb.Stats.RTTUS.Load() == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if cb.Stats.RTTUS.Load() == 0 {
		t.Fatal("initial epoch not learned")
	}
	for i := 0; i < 10; i++ {
		sb.Close()
		if _, _, err := sb.Open(0); err != nil {
			t.Fatal(err)
		}
		select {
		case <-cb.Restarts():
		case <-time.After(time.Second):
			t.Fatal("server restart not detected")
		}
	}
	if cb.Stats.PeerRestarts.Load() != 10 {
		t.Fatal("restart counter mismatch")
	}
}

func TestControllerBoundsAndRecovery(t *testing.T) {
	now := time.Now()
	c := controller{window: 16, rtt: 50 * time.Millisecond, maxWindow: 32, maxPPS: 100, rto: 2 * time.Second, maxRTO: 3 * time.Second}
	for i := 0; i < 10000; i++ {
		c.ack(2*time.Second, true)
	}
	if c.window > 32 || c.rto > 3*time.Second || c.rtt < time.Second {
		t.Fatal("RTT/window bounds broken")
	}
	c.loss(now)
	w := c.window
	c.loss(now.Add(time.Millisecond))
	if c.window != w {
		t.Fatal("one loss batch repeatedly halved window")
	}
	allowed := 0
	for i := 0; i < 100; i++ {
		if c.allow(now) {
			allowed++
		}
	}
	if allowed > 4 {
		t.Fatal("unpaced burst")
	}
}
