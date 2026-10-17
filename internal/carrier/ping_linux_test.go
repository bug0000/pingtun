//go:build linux

package carrier

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type pingDatagram struct {
	data []byte
	addr net.Addr
}
type fakePingConn struct {
	in   chan pingDatagram
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func (f *fakePingConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-f.done:
		return 0, nil, net.ErrClosed
	case p := <-f.in:
		return copy(b, p.data), p.addr, nil
	}
}
func (f *fakePingConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	f.out <- append([]byte(nil), b...)
	return len(b), nil
}
func (f *fakePingConn) Close() error                     { f.once.Do(func() { close(f.done) }); return nil }
func (f *fakePingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (f *fakePingConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePingConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePingConn) SetWriteDeadline(time.Time) error { return nil }

func TestPingSocketRestoresTicketsAndRetainsReflectionMapping(t *testing.T) {
	f := &fakePingConn{in: make(chan pingDatagram, 10), out: make(chan []byte, 10), done: make(chan struct{})}
	remote := netip.MustParseAddr("192.0.2.1")
	s := &PingSocket{conn: f, remote: remote, id: 45001, now: func() int64 { return 1 }}
	defer s.Close()
	original := Echo{ID: 721, Seq: 87, Addr: remote, Data: []byte("authenticated request")}
	if err := s.WriteEcho(original); err != nil {
		t.Fatal(err)
	}
	m, err := icmp.ParseMessage(1, <-f.out)
	if err != nil {
		t.Fatal(err)
	}
	body := m.Body.(*icmp.Echo)
	if body.ID != 45001 || body.Seq != 1 {
		t.Fatal("kernel-visible ticket is not independent")
	}
	m.Type = ipv4.ICMPTypeEchoReply
	data, _ := m.Marshal(nil)
	f.in <- pingDatagram{data, &net.UDPAddr{IP: net.ParseIP("192.0.2.99")}}
	f.in <- pingDatagram{data, &net.UDPAddr{IP: net.IP(remote.AsSlice())}}
	p, err := s.ReadEcho()
	if err != nil || p.ID != original.ID || p.Seq != original.Seq || !bytes.Equal(p.Data, original.Data) {
		t.Fatal("reflection changed carrier ticket")
	}
	body.Data = []byte("authenticated response")
	data, _ = m.Marshal(nil)
	f.in <- pingDatagram{data, &net.UDPAddr{IP: net.IP(remote.AsSlice())}}
	p, err = s.ReadEcho()
	if err != nil || p.ID != original.ID || p.Seq != original.Seq || !bytes.Equal(p.Data, body.Data) {
		t.Fatal("reflection consumed real reply mapping")
	}
	if err = s.WriteEcho(Echo{Reply: true, Addr: remote}); err == nil {
		t.Fatal("client sent a response")
	}
	if err = s.WriteEcho(Echo{Addr: netip.MustParseAddr("192.0.2.99")}); err == nil {
		t.Fatal("client sent to another endpoint")
	}
}
func TestPingSocketBoundAndClose(t *testing.T) {
	f := &fakePingConn{in: make(chan pingDatagram), out: make(chan []byte, 2), done: make(chan struct{})}
	now := int64(1)
	s := &PingSocket{conn: f, remote: netip.MustParseAddr("192.0.2.1"), next: 65535, now: func() int64 { return now }}
	s.tickets[0] = pingTicket{deadline: now + int64(time.Second)}
	if !errors.Is(s.WriteEcho(Echo{Addr: s.remote}), ErrQueueFull) {
		t.Fatal("live mapping overwritten on wrap")
	}
	now += int64(2 * time.Second)
	s.next = 65535
	if err := s.WriteEcho(Echo{Addr: s.remote}); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() { s.ReadEcho(); close(stopped) }()
	s.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("close left read blocked")
	}
}
