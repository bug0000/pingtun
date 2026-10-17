//go:build linux

package engine

import (
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// FDTUN adapts an Android VpnService descriptor without network-administration
// ioctls, netlink, GSO assumptions or access to /dev/net/tun. The original FD
// remains owned by the platform and stays open during engine reconnections.
type FDTUN struct {
	file   *os.File
	mtu    int
	events chan tun.Event
	once   sync.Once
}

func NewFDTUN(fd, mtu int) (*FDTUN, error) {
	if fd < 0 || mtu < 68 || mtu > 1500 {
		return nil, errors.New("invalid VPN descriptor or MTU")
	}
	copyFD, err := unix.Dup(fd)
	if err != nil {
		return nil, errors.New("could not duplicate VPN descriptor")
	}
	unix.CloseOnExec(copyFD)
	if err = unix.SetNonblock(copyFD, true); err != nil {
		unix.Close(copyFD)
		return nil, errors.New("could not configure VPN descriptor")
	}
	t := &FDTUN{file: os.NewFile(uintptr(copyFD), "pingtun VPN"), mtu: mtu, events: make(chan tun.Event, 1)}
	t.events <- tun.EventUp
	return t, nil
}
func (t *FDTUN) File() *os.File           { return t.file }
func (t *FDTUN) Name() (string, error)    { return "platform-vpn", nil }
func (t *FDTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *FDTUN) Events() <-chan tun.Event { return t.events }
func (t *FDTUN) BatchSize() int           { return 1 }
func (t *FDTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) {
		return 0, errors.New("invalid VPN read buffers")
	}
	n, err := t.file.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}
func (t *FDTUN) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 0 || offset > len(b) {
			return i, errors.New("invalid VPN write offset")
		}
		n, err := t.file.Write(b[offset:])
		if err != nil {
			return i, err
		}
		if n != len(b)-offset {
			return i, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}
func (t *FDTUN) Close() error {
	var err error
	t.once.Do(func() { err = t.file.Close(); close(t.events) })
	return err
}
