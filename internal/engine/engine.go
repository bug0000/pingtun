// Package engine owns the encrypted device independently of an operating
// system's TUN creation, routing, user interface, or privilege model.
package engine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/config"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Engine struct {
	dev        *device.Device
	bind       *carrier.Bind
	stop, done chan struct{}
	once       sync.Once
	mu         sync.Mutex
	err        error
}

// Start takes ownership of iface, including on failure. socket may override
// platform transport creation, e.g. a protected Android ICMP datagram socket.
func Start(c config.Config, iface tun.Device, socket func() (carrier.EchoSocket, error)) (*Engine, error) {
	if iface == nil {
		return nil, errors.New("TUN device required")
	}
	if err := c.Validate(); err != nil {
		iface.Close()
		return nil, err
	}
	cc, err := c.Carrier()
	if err != nil {
		iface.Close()
		return nil, err
	}
	if socket != nil {
		cc.Socket = socket
	}
	b, err := carrier.New(cc)
	if err != nil {
		iface.Close()
		return nil, err
	}
	dev := device.NewDevice(iface, b, device.NewLogger(device.LogLevelSilent, ""))
	ipc, err := c.IPC()
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err = dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, errors.New("WireGuard configuration failed")
	}
	if err = dev.Up(); err != nil {
		dev.Close()
		return nil, errors.New("ICMP transport could not start")
	}
	if c.Role == "client" {
		startHandshake(dev, c)
	}
	e := &Engine{dev: dev, bind: b, stop: make(chan struct{}), done: make(chan struct{})}
	go e.run(c, ipc)
	return e, nil
}
func (e *Engine) run(c config.Config, ipc string) {
	defer close(e.done)
	defer e.dev.Close()
	for {
		select {
		case <-e.stop:
			return
		case <-e.bind.Done():
			e.fail(errors.New("ICMP transport stopped"))
			return
		case <-e.bind.Restarts():
			pub, err := config.Key(c.PeerPublicKey)
			if err == nil {
				err = e.dev.IpcSet(fmt.Sprintf("public_key=%x\nremove=true\n", pub))
			}
			if err == nil {
				err = e.dev.IpcSet(ipc)
			}
			if err != nil {
				e.fail(errors.New("encrypted peer recovery failed"))
				return
			}
			startHandshake(e.dev, c)
		}
	}
}
func (e *Engine) fail(err error)        { e.mu.Lock(); e.err = err; e.mu.Unlock() }
func (e *Engine) Done() <-chan struct{} { return e.done }
func (e *Engine) Err() error            { e.mu.Lock(); defer e.mu.Unlock(); return e.err }
func (e *Engine) Close()                { e.once.Do(func() { close(e.stop) }); <-e.done }

func (e *Engine) Snapshot() map[string]any {
	r := e.bind.Snapshot()
	// IPC can contain private keys. Only these three numeric fields are ever
	// exported. Never log IPC or return it to a platform UI.
	if ipc, err := e.dev.IpcGet(); err == nil {
		for _, line := range strings.Split(ipc, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch key {
			case "last_handshake_time_sec", "rx_bytes", "tx_bytes":
				if n, err := strconv.ParseUint(value, 10, 64); err == nil {
					r[key] = n
				}
			}
		}
	}
	r["now_unix"] = time.Now().Unix()
	if err := e.Err(); err != nil {
		r["error"] = err.Error()
	}
	return r
}

func startHandshake(dev *device.Device, c config.Config) {
	pub, err := config.Key(c.PeerPublicKey)
	if err != nil {
		return
	}
	if peer := dev.LookupPeer(device.NoisePublicKey(pub)); peer != nil {
		peer.SendKeepalive()
	}
}
