package engine

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/config"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type echo struct {
	in, out chan carrier.Echo
	done    chan struct{}
	once    sync.Once
	ip      netip.Addr
}

func (s *echo) Close() error { s.once.Do(func() { close(s.done) }); return nil }
func (s *echo) ReadEcho() (carrier.Echo, error) {
	select {
	case <-s.done:
		return carrier.Echo{}, net.ErrClosed
	case p := <-s.in:
		return p, nil
	}
}
func (s *echo) WriteEcho(p carrier.Echo) error {
	p.Addr = s.ip
	select {
	case <-s.done:
		return net.ErrClosed
	case s.out <- p:
		return nil
	}
}

func TestEngineHandshakeRestartAndPrivateSnapshot(t *testing.T) {
	a, b := make(chan carrier.Echo, 256), make(chan carrier.Echo, 256)
	clientIP, serverIP := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	factory := func(server bool) func() (carrier.EchoSocket, error) {
		return func() (carrier.EchoSocket, error) {
			s := &echo{in: a, out: b, done: make(chan struct{}), ip: clientIP}
			if server {
				s.in, s.out, s.ip = b, a, serverIP
			}
			return s, nil
		}
	}
	ck, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	key := make([]byte, 32)
	rand.Read(key)
	enc := base64.StdEncoding.EncodeToString
	cc := config.Config{Role: "client", Interface: "test0", Listen: "0.0.0.0", ServerIP: serverIP.String(), PrivateKey: enc(ck.Bytes()), PeerPublicKey: enc(sk.PublicKey().Bytes()), TransportKey: enc(key), AllowedIPs: []string{"10.203.0.1/32"}, MTU: 1280, WireMTU: 1440, Lanes: 2, Window: 4, HoldMS: 50, Adaptive: &carrier.AdaptiveConfig{IDMode: "stable", IdleMS: 100}}
	sc := cc
	sc.Role = "server"
	sc.PrivateKey = enc(sk.Bytes())
	sc.PeerPublicKey = enc(ck.PublicKey().Bytes())
	sc.AllowedIPs = []string{"10.203.0.2/32"}
	ct, st := tuntest.NewChannelTUN(), tuntest.NewChannelTUN()
	server, err := Start(sc, st.TUN(), factory(true))
	if err != nil {
		t.Fatal(err)
	}
	client, err := Start(cc, ct.TUN(), factory(false))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	until := time.Now().Add(8 * time.Second)
	for client.Snapshot()["last_handshake_time_sec"] == nil || client.Snapshot()["last_handshake_time_sec"] == uint64(0) {
		if time.Now().After(until) {
			t.Fatal("startup did not initiate a WireGuard handshake")
		}
		time.Sleep(10 * time.Millisecond)
	}
	snapshot, _ := json.Marshal(client.Snapshot())
	if bytes.Contains(snapshot, []byte(cc.PrivateKey)) || bytes.Contains(snapshot, []byte("private_key")) {
		t.Fatal("snapshot exposed private material")
	}
	server.Close()
	st = tuntest.NewChannelTUN()
	server, err = Start(sc, st.TUN(), factory(true))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	until = time.Now().Add(8 * time.Second)
	for client.bind.Stats.PeerRestarts.Load() == 0 {
		if time.Now().After(until) {
			t.Fatal("server restart was not recovered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Restart detection precedes peer reset on the engine control goroutine.
	// The carrier is best effort; wait for a fresh authenticated handshake before
	// asserting delivery, rather than assuming an in-flight old-key packet survives.
	until = time.Now().Add(8 * time.Second)
	for server.Snapshot()["last_handshake_time_sec"] == nil || server.Snapshot()["last_handshake_time_sec"] == uint64(0) {
		if time.Now().After(until) {
			t.Fatal("fresh post-restart handshake missing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	packet := make([]byte, 80)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], 80)
	copy(packet[12:16], []byte{10, 203, 0, 2})
	copy(packet[16:20], []byte{10, 203, 0, 1})
	select {
	case ct.Outbound <- packet:
	case <-time.After(time.Second):
		t.Fatal("platform TUN was closed on peer reset")
	}
	select {
	case got := <-st.Inbound:
		if !bytes.Equal(got, packet) {
			t.Fatal("post-restart contents differ")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("post-restart packet missing")
	}
	stopped := make(chan struct{})
	go func() { client.Close(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("engine shutdown blocked")
	}
}
