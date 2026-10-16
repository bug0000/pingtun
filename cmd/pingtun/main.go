//go:build linux

package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/config"
)

const version = "0.1.0-dev"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "pingtun:", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pingtun init --server IPv4 --dir DIR | run --config FILE | check --config FILE | version")
	}
	switch args[0] {
	case "version":
		fmt.Println("pingtun", version)
		return nil
	case "init":
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		server := fs.String("server", "", "server's public IPv4 address")
		dir := fs.String("dir", "configs", "new private directory for config pair")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		return initialize(*server, *dir)
	case "check", "run":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		path := fs.String("config", "", "mode 0600 JSON config")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		c, e := config.Load(*path)
		if e != nil {
			return e
		}
		if args[0] == "check" {
			fmt.Println("Configuration valid; secrets omitted.")
			return nil
		}
		cc, e := c.Carrier()
		if e != nil {
			return e
		}
		bind, e := carrier.New(cc)
		if e != nil {
			return e
		}
		if _, e = net.InterfaceByName(c.Interface); e == nil {
			return errors.New("refusing to attach to an existing network interface")
		}
		iface, e := tun.CreateTUN(c.Interface, c.MTU)
		if e != nil {
			return fmt.Errorf("create TUN: %w", e)
		}
		// WireGuard error output is deliberately disabled: configuration and keys must
		// never reach logs. Startup failures are reported without echoing IPC input.
		dev := device.NewDevice(iface, bind, device.NewLogger(device.LogLevelSilent, ""))
		defer dev.Close()
		ipc, e := c.IPC()
		if e != nil {
			return e
		}
		if e = dev.IpcSet(ipc); e != nil {
			return errors.New("WireGuard configuration failed")
		}
		if e = dev.Up(); e != nil {
			return fmt.Errorf("start ICMP carrier: %w", e)
		}
		fmt.Printf("pingtun %s active on %s (%d logical lanes); addresses and routes remain manual\n", version, c.Interface, c.Lanes)
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(stop)
		select {
		case <-stop:
		case <-bind.Done():
			return errors.New("ICMP carrier stopped unexpectedly")
		}
		fmt.Printf("stopping; echo_sent=%d wg_datagrams_received=%d invalid=%d dropped=%d expired=%d\n", bind.Stats.Sent.Load(), bind.Stats.Received.Load(), bind.Stats.Invalid.Load(), bind.Stats.Dropped.Load(), bind.Stats.Expired.Load())
		return nil
	default:
		return errors.New("unknown subcommand")
	}
}
func pair() (string, string, error) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return "", "", e
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}
func initialize(server, dir string) error {
	ip, e := netip.ParseAddr(server)
	if e != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("--server requires a unicast IPv4 address")
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return fmt.Errorf("create new config directory: %w", e)
	}
	successful := false
	defer func() {
		if !successful {
			os.Remove(filepath.Join(dir, "client.json"))
			os.Remove(filepath.Join(dir, "server.json"))
			os.Remove(dir)
		}
	}()
	sk, sp, e := pair()
	if e != nil {
		return e
	}
	ck, cp, e := pair()
	if e != nil {
		return e
	}
	var transport [32]byte
	if _, e = rand.Read(transport[:]); e != nil {
		return e
	}
	base := config.Config{Interface: "pingtun0", Listen: "0.0.0.0", TransportKey: base64.StdEncoding.EncodeToString(transport[:]), MTU: 1000, WireMTU: 1280, Lanes: 1, Window: 2, HoldMS: 500}
	s := base
	s.Role = "server"
	s.PrivateKey = sk
	s.PeerPublicKey = cp
	s.AllowedIPs = []string{"10.203.0.2/32"}
	c := base
	c.Role = "client"
	c.ServerIP = ip.String()
	c.PrivateKey = ck
	c.PeerPublicKey = sp
	c.AllowedIPs = []string{"0.0.0.0/0"}
	for name, cfg := range map[string]config.Config{"server": s, "client": c} {
		if e = cfg.Validate(); e != nil {
			return e
		}
		data, e := json.MarshalIndent(cfg, "", "  ")
		if e != nil {
			return e
		}
		f, e := os.OpenFile(filepath.Join(dir, name+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, writeErr := f.Write(append(data, '\n'))
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	successful = true
	fmt.Println("Created private config pair in", dir, "— no keys printed.")
	return nil
}
