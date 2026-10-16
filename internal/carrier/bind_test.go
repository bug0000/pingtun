package carrier

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/bug0000/pingtun/internal/wire"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type memorySocket struct {
	in, out chan Echo
	done    chan struct{}
	once    sync.Once
	ip      netip.Addr
	mu      sync.Mutex
	capture []Echo
}

func (s *memorySocket) ReadEcho() (Echo, error) {
	select {
	case <-s.done:
		return Echo{}, net.ErrClosed
	case p := <-s.in:
		return p, nil
	}
}
func (s *memorySocket) Close() error { s.once.Do(func() { close(s.done) }); return nil }
func (s *memorySocket) WriteEcho(p Echo) error {
	p.Addr = s.ip
	p.Data = append([]byte(nil), p.Data...)
	s.mu.Lock()
	if len(s.capture) < 10000 {
		s.capture = append(s.capture, p)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return net.ErrClosed
	case s.out <- p:
		return nil
	}
}
func socketPair() (*memorySocket, *memorySocket) {
	a, b := make(chan Echo, 1024), make(chan Echo, 1024)
	return &memorySocket{in: a, out: b, done: make(chan struct{}), ip: netip.MustParseAddr("192.0.2.10")}, &memorySocket{in: b, out: a, done: make(chan struct{}), ip: netip.MustParseAddr("192.0.2.20")}
}
func testConfig(s *memorySocket, server bool) Config {
	var key [32]byte
	key[0] = 42
	return Config{Server: server, Remote: netip.MustParseAddr("192.0.2.20"), Key: key, Lanes: 2, Window: 2, WireMTU: 1280, Hold: 50 * time.Millisecond, Timeout: 500 * time.Millisecond, Socket: func() (EchoSocket, error) { return s, nil }}
}
func testPacket(src, dst netip.Addr, n byte) []byte {
	b := make([]byte, 532)
	b[0] = 0x45
	b[8] = 64
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	for i := 20; i < len(b); i++ {
		b[i] = byte(i) ^ n
	}
	return b
}
func TestEncryptedRoundTripAcrossLanes(t *testing.T) {
	clientSocket, serverSocket := socketPair()
	clientBind, e := New(testConfig(clientSocket, false))
	if e != nil {
		t.Fatal(e)
	}
	serverBind, e := New(testConfig(serverSocket, true))
	if e != nil {
		t.Fatal(e)
	}
	clientTun, serverTun := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	client := device.NewDevice(clientTun.TUN(), clientBind, device.NewLogger(device.LogLevelSilent, ""))
	defer client.Close()
	server := device.NewDevice(serverTun.TUN(), serverBind, device.NewLogger(device.LogLevelSilent, ""))
	defer server.Close()
	ck, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sk, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ci := netip.MustParseAddr("10.203.0.2")
	si := netip.MustParseAddr("10.203.0.1")
	if e = client.IpcSet(fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=%s/32\nendpoint=192.0.2.20:1\n", ck.Bytes(), sk.PublicKey().Bytes(), si)); e != nil {
		t.Fatal(e)
	}
	if e = server.IpcSet(fmt.Sprintf("private_key=%x\npublic_key=%x\nallowed_ip=%s/32\n", sk.Bytes(), ck.PublicKey().Bytes(), ci)); e != nil {
		t.Fatal(e)
	}
	if e = server.Up(); e != nil {
		t.Fatal(e)
	}
	if e = client.Up(); e != nil {
		t.Fatal(e)
	}
	deadline := time.After(8 * time.Second)
	for n := byte(0); n < 12; n++ {
		forward := testPacket(ci, si, n)
		reverse := testPacket(si, ci, n+50)
		select {
		case clientTun.Outbound <- forward:
		case <-deadline:
			t.Fatal("client TUN blocked")
		}
		select {
		case got := <-serverTun.Inbound:
			if !bytes.Equal(got, forward) {
				t.Fatal("forward packet corrupted")
			}
		case <-deadline:
			t.Fatal("forward packet timed out")
		}
		select {
		case serverTun.Outbound <- reverse:
		case <-deadline:
			t.Fatal("server TUN blocked")
		}
		select {
		case got := <-clientTun.Inbound:
			if !bytes.Equal(got, reverse) {
				t.Fatal("reverse packet corrupted")
			}
		case <-deadline:
			t.Fatal("reverse packet timed out")
		}
	}
	clientSocket.mu.Lock()
	defer clientSocket.mu.Unlock()
	lanes := map[uint16]bool{}
	for _, p := range clientSocket.capture {
		f, e := wire.Decode(p.Data, clientBind.cfg.Key[:], time.Now())
		if e != nil {
			t.Fatal(e)
		}
		lanes[f.Lane] = true
		if bytes.Contains(p.Data, testPacket(ci, si, 0)[20:52]) {
			t.Fatal("plaintext inner packet found in carrier")
		}
	}
	if len(lanes) != 2 {
		t.Fatal("parallel lanes not exercised")
	}
	if serverBind.Stats.Received.Load() < 12 || clientBind.Stats.Received.Load() < 12 {
		t.Fatal("datagrams not counted")
	}
}
func TestCloseUnblocksReceive(t *testing.T) {
	a, _ := socketPair()
	b, e := New(testConfig(a, false))
	if e != nil {
		t.Fatal(e)
	}
	fns, _, e := b.Open(0)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := fns[0]([][]byte{make([]byte, 1500)}, make([]int, 1), make([]conn.Endpoint, 1))
		done <- e
	}()
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e != net.ErrClosed {
			t.Fatalf("unexpected close: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("receive not unblocked")
	}
}
func TestServerRejectsReplay(t *testing.T) {
	sender, socket := socketPair()
	b, e := New(testConfig(socket, true))
	if e != nil {
		t.Fatal(e)
	}
	fns, _, e := b.Open(0)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	frame := wire.Frame{Kind: wire.Request, Number: 99, Time: time.Now().Unix(), Payload: []byte("opaque encrypted datagram")}
	frame.Session[0] = 1
	encoded, e := wire.Encode(frame, b.cfg.Key[:], b.cfg.WireMTU-28)
	if e != nil {
		t.Fatal(e)
	}
	p := Echo{ID: 99, Addr: socket.ip, Data: encoded}
	if e = sender.WriteEcho(p); e != nil {
		t.Fatal(e)
	}
	if e = sender.WriteEcho(p); e != nil {
		t.Fatal(e)
	}
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		sizes := make([]int, 1)
		_, e := fns[0]([][]byte{buf}, sizes, make([]conn.Endpoint, 1))
		if e == nil {
			got <- buf[:sizes[0]]
		}
	}()
	select {
	case data := <-got:
		if !bytes.Equal(data, frame.Payload) {
			t.Fatal("payload mismatch")
		}
	case <-time.After(time.Second):
		t.Fatal("valid request not received")
	}
	deadline := time.Now().Add(time.Second)
	for b.Stats.Invalid.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if b.Stats.Invalid.Load() == 0 || b.Stats.Received.Load() != 1 {
		t.Fatal("replayed request admitted")
	}
}
