//go:build linux

package carrier

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// PingSocket is a client-only SOCK_DGRAM/IPPROTO_ICMP endpoint. Linux assigns
// its identifier, so wire sequence numbers map back to the carrier's tickets.
// No raw socket, shell ping process, or CAP_NET_RAW is used. Android's caller
// must protect the descriptor before the VPN starts routing through its TUN.
type PingSocket struct {
	conn    net.PacketConn
	remote  netip.Addr
	id      uint16
	mu      sync.Mutex
	next    uint16
	tickets [65536]pingTicket // Fixed 1 MiB bound; never evict a live request.
	now     func() int64
}
type pingTicket struct {
	deadline int64
	id, seq  uint16
}

func ListenPing(remote netip.Addr, protect func(int) error) (*PingSocket, error) {
	if !remote.Is4() || remote.IsUnspecified() || remote.IsMulticast() {
		return nil, errors.New("ping socket requires a unicast IPv4 server")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, errors.New("ICMP datagram socket unavailable; check network permission and OS ping-socket policy")
	}
	file := os.NewFile(uintptr(fd), "pingtun ICMP datagram")
	defer file.Close()
	if protect != nil {
		if err = protect(fd); err != nil {
			return nil, errors.New("could not exclude ICMP socket from VPN routing")
		}
	}
	if err = unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		return nil, errors.New("ICMP datagram bind failed")
	}
	local, err := unix.Getsockname(fd)
	if err != nil {
		return nil, errors.New("ICMP datagram identifier unavailable")
	}
	addr, ok := local.(*unix.SockaddrInet4)
	if !ok {
		return nil, errors.New("unexpected ICMP socket family")
	}
	conn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, errors.New("ICMP socket polling setup failed")
	}
	start := time.Now()
	return &PingSocket{conn: conn, remote: remote, id: uint16(addr.Port), now: func() int64 { return time.Since(start).Nanoseconds() }}, nil
}
func (s *PingSocket) Close() error { return s.conn.Close() }
func (s *PingSocket) WriteEcho(p Echo) error {
	if p.Reply || p.Addr != s.remote || len(p.Data) > 1472 {
		return errors.New("ping socket only sends bounded requests to its configured peer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	seq := s.next
	now := s.now()
	if s.tickets[seq].deadline > now {
		return ErrQueueFull
	}
	data, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: int(s.id), Seq: int(seq), Data: p.Data}}).Marshal(nil)
	if err != nil {
		return err
	}
	s.tickets[seq] = pingTicket{deadline: now + int64(10*time.Second), id: p.ID, seq: p.Seq}
	n, err := s.conn.WriteTo(data, &net.UDPAddr{IP: net.IP(p.Addr.AsSlice())})
	if err != nil || n != len(data) {
		s.tickets[seq] = pingTicket{}
		if err == nil {
			err = errors.New("short ICMP datagram write")
		}
	}
	return err
}
func (s *PingSocket) ReadEcho() (Echo, error) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return Echo{}, err
		}
		peer, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(peer.IP)
		if !ok || ip.Unmap() != s.remote {
			continue
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply || m.Code != 0 {
			continue
		}
		body, ok := m.Body.(*icmp.Echo)
		if !ok || uint16(body.ID) != s.id {
			continue
		}
		s.mu.Lock()
		t := s.tickets[uint16(body.Seq)]
		valid := t.deadline > s.now()
		s.mu.Unlock()
		if !valid {
			continue
		}
		// Keep mapping until expiry: a reflected kernel echo, invalid MAC or duplicate
		// must not consume the authenticated response ticket in the carrier above us.
		return Echo{Reply: true, ID: t.id, Seq: t.seq, Addr: s.remote, Data: append([]byte(nil), body.Data...)}, nil
	}
}
