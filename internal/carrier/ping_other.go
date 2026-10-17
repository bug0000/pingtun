//go:build !linux

package carrier

import (
	"errors"
	"net/netip"
)

func ListenPing(netip.Addr, func(int) error) (EchoSocket, error) {
	return nil, errors.New("unprivileged ping sockets are not supported on this platform")
}
