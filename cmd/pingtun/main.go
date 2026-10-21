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
	"time"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/config"
	"github.com/bug0000/pingtun/internal/engine"
	"golang.zx2c4.com/wireguard/tun"
)

const version = "0.4.0"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "pingtun:", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: pingtun init | mobile-init | run | check | probe | probe-server | version (use COMMAND -h for options)")
	}
	switch args[0] {
	case "version":
		fmt.Println("pingtun", version)
		return nil
	case "probe", "probe-server":
		return probeCommand(args[0], args[1:])
	case "mobile-init":
		fs := flag.NewFlagSet("mobile-init", flag.ContinueOnError)
		server := fs.String("server", "", "dedicated server IPv4 address")
		dir := fs.String("dir", "mobile-configs", "new private directory")
		name := fs.String("name", "pingtun", "profile name")
		address := fs.String("address", "10.203.0.2/30", "mobile VPN IPv4 address/prefix")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return initializeMobile(*server, *dir, *name, *address)
	case "init":
		fs := flag.NewFlagSet("init", flag.ContinueOnError)
		server := fs.String("server", "", "server's public IPv4 address")
		dir := fs.String("dir", "configs", "new private directory for config pair")
		legacy := fs.Bool("legacy", false, "generate legacy v1 instead of the default adaptive v2")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		return initializeWithMode(*server, *dir, *legacy)
	case "check", "run":
		fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
		path := fs.String("config", "", "mode 0600 JSON config")
		statsEvery := fs.Duration("stats-interval", 0, "optional key-free JSON statistics interval (at least 1s)")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		if *statsEvery < 0 || (*statsEvery > 0 && *statsEvery < time.Second) {
			return errors.New("stats-interval must be zero or at least 1s")
		}
		c, e := config.Load(*path)
		if e != nil {
			return e
		}
		if args[0] == "check" {
			fmt.Println("Configuration valid; secrets omitted.")
			return nil
		}
		if _, e = net.InterfaceByName(c.Interface); e == nil {
			return errors.New("refusing to attach to an existing network interface")
		}
		iface, e := tun.CreateTUN(c.Interface, c.MTU)
		if e != nil {
			return fmt.Errorf("create TUN: %w", e)
		}
		vpn, e := engine.Start(c, iface, nil)
		if e != nil {
			return e
		}
		defer vpn.Close()
		fmt.Printf("pingtun %s active on %s (%d logical lanes); addresses and routes remain manual\n", version, c.Interface, c.Lanes)
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
		defer signal.Stop(stop)
		var ticks <-chan time.Time
		if *statsEvery > 0 {
			ticker := time.NewTicker(*statsEvery)
			defer ticker.Stop()
			ticks = ticker.C
		}
		for {
			select {
			case sig := <-stop:
				if sig == syscall.SIGUSR1 {
					json.NewEncoder(os.Stdout).Encode(vpn.Snapshot())
					continue
				}
				json.NewEncoder(os.Stdout).Encode(vpn.Snapshot())
				return nil
			case <-vpn.Done():
				if err := vpn.Err(); err != nil {
					return err
				}
				return errors.New("VPN engine stopped unexpectedly")
			case <-ticks:
				json.NewEncoder(os.Stdout).Encode(vpn.Snapshot())
			}
		}
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
	return initializeWithMode(server, dir, false)
}
func initializeWithMode(server, dir string, legacy bool) error {
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
	base := config.Config{Interface: "pingtun0", Listen: "0.0.0.0", TransportKey: base64.StdEncoding.EncodeToString(transport[:]), MTU: 1280, WireMTU: 1440, Lanes: 2, Window: 4, HoldMS: 500,
		Adaptive: &carrier.AdaptiveConfig{MaxPPS: 250, MaxWindow: 32, IdleMS: 500, IDMode: "stable"}}
	if legacy {
		base.MTU = 1000
		base.WireMTU = 1280
		base.Lanes = 1
		base.Window = 2
		base.Adaptive = nil
	}
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
