package carrier

import (
	"errors"
	"net"
	"net/netip"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// EchoSocket makes the carrier testable without root or a real network.
type EchoSocket interface {
	ReadEcho() (Echo, error)
	WriteEcho(Echo) error
	Close() error
}
type Echo struct {
	Reply   bool
	ID, Seq uint16
	Addr    netip.Addr
	Data    []byte
}
type rawSocket struct{ conn *icmp.PacketConn }

func Listen(address string) (EchoSocket, error) {
	c, e := icmp.ListenPacket("ip4:icmp", address)
	if e != nil {
		return nil, e
	}
	return &rawSocket{c}, nil
}
func (s *rawSocket) Close() error { return s.conn.Close() }
func (s *rawSocket) ReadEcho() (Echo, error) {
	b := make([]byte, 1500)
	for {
		n, addr, e := s.conn.ReadFrom(b)
		if e != nil {
			return Echo{}, e
		}
		ip, ok := addr.(*net.IPAddr)
		if !ok {
			continue
		}
		a, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			continue
		}
		m, e := icmp.ParseMessage(1, b[:n])
		if e != nil {
			continue
		}
		if m.Code != 0 {
			continue
		}
		if m.Type != ipv4.ICMPTypeEcho && m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		body, ok := m.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		return Echo{m.Type == ipv4.ICMPTypeEchoReply, uint16(body.ID), uint16(body.Seq), a.Unmap(), append([]byte(nil), body.Data...)}, nil
	}
}
func (s *rawSocket) WriteEcho(p Echo) error {
	if !p.Addr.Is4() {
		return errors.New("carrier requires an IPv4 destination")
	}
	t := ipv4.ICMPTypeEcho
	if p.Reply {
		t = ipv4.ICMPTypeEchoReply
	}
	m := icmp.Message{Type: t, Code: 0, Body: &icmp.Echo{ID: int(p.ID), Seq: int(p.Seq), Data: p.Data}}
	b, e := m.Marshal(nil)
	if e != nil {
		return e
	}
	n, e := s.conn.WriteTo(b, &net.IPAddr{IP: net.IP(p.Addr.AsSlice())})
	if e == nil && n != len(b) {
		return errors.New("short ICMP write")
	}
	return e
}
