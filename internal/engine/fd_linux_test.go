//go:build linux

package engine

import (
	"bytes"
	"golang.org/x/sys/unix"
	"testing"
	"time"
)

func TestFDTUNReadWriteOwnershipAndClose(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	dev, err := NewFDTUN(pair[0], 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	packet := []byte("one complete IP packet")
	if _, err = unix.Write(pair[1], packet); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1280)
	sizes := make([]int, 1)
	if n, e := dev.Read([][]byte{b}, sizes, 17); e != nil || n != 1 || !bytes.Equal(b[17:17+sizes[0]], packet) {
		t.Fatal("descriptor read framing failed", e)
	}
	if n, e := dev.Write([][]byte{append(make([]byte, 12), packet...)}, 12); e != nil || n != 1 {
		t.Fatal("descriptor write framing failed", e)
	}
	if n, e := unix.Read(pair[1], b); e != nil || !bytes.Equal(b[:n], packet) {
		t.Fatal("descriptor write content failed", e)
	}
	stopped := make(chan struct{})
	go func() { dev.Read([][]byte{b}, sizes, 0); close(stopped) }()
	dev.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt VPN read")
	}
	if _, err = unix.Write(pair[0], packet); err != nil {
		t.Fatal("closing engine closed platform-owned descriptor")
	}
}
