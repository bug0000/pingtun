//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/config"
	"github.com/bug0000/pingtun/internal/mobileprofile"
)

func initializeMobile(server, dir, name, address string) error {
	ip, err := netip.ParsePrefix(address)
	if err != nil || !ip.Addr().Is4() || !ip.Addr().IsGlobalUnicast() {
		return errors.New("mobile address must be a unicast IPv4 prefix")
	}
	if strings.TrimSpace(name) == "" || len(name) > 64 {
		return errors.New("invalid mobile profile name")
	}
	if err = initialize(server, dir); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			for _, n := range []string{"server.json", "client.json", "profile.pingtun.json"} {
				os.Remove(filepath.Join(dir, n))
			}
			os.Remove(dir)
		}
	}()
	var client config.Config
	for _, role := range []string{"client", "server"} {
		path := filepath.Join(dir, role+".json")
		c, e := config.Load(path)
		if e != nil {
			return e
		}
		c.MTU = 1280
		c.WireMTU = 1440
		c.Lanes = 2
		c.Window = 4
		c.Adaptive = &carrier.AdaptiveConfig{MaxPPS: 250, MaxWindow: 32, IdleMS: 500, IDMode: "stable"}
		if role == "client" {
			c.SocketMode = "ping"
			client = c
		} else {
			c.AllowedIPs = []string{netip.PrefixFrom(ip.Addr(), 32).String()}
		}
		if e = c.Validate(); e != nil {
			return e
		}
		data, _ := json.MarshalIndent(c, "", "  ")
		if e = os.WriteFile(path, append(data, '\n'), 0600); e != nil {
			return e
		}
	}
	profile := mobileprofile.Profile{Version: 1, Name: name, Address: address, DNS: []string{"1.1.1.1"}, Config: client}
	if err = profile.Validate(); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(profile, "", "  ")
	if err = os.WriteFile(filepath.Join(dir, "profile.pingtun.json"), append(data, '\n'), 0600); err != nil {
		return err
	}
	ok = true
	return nil
}
