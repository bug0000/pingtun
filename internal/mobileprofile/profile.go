// Package mobileprofile validates private client imports. Profiles are not
// public provisioning links and must not be shared between independent peers.
package mobileprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"unicode"

	"github.com/bug0000/pingtun/internal/config"
)

type Profile struct {
	Version int           `json:"version"`
	Name    string        `json:"name"`
	Address string        `json:"address"`
	DNS     []string      `json:"dns"`
	Config  config.Config `json:"config"`
}

func Decode(data []byte) (Profile, error) {
	var p Profile
	if len(data) > 65536 {
		return p, errors.New("profile exceeds 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return Profile{}, errors.New("invalid private profile")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Profile{}, errors.New("trailing profile data")
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}
func (p Profile) Validate() error {
	if p.Version != 1 || len(p.Name) > 64 || strings.TrimSpace(p.Name) == "" || strings.IndexFunc(p.Name, unicode.IsControl) >= 0 {
		return errors.New("unsupported profile version or name")
	}
	a, err := netip.ParsePrefix(p.Address)
	if err != nil || !a.Addr().Is4() || !a.Addr().IsGlobalUnicast() {
		return errors.New("profile requires a unicast IPv4 interface address")
	}
	if len(p.DNS) < 1 || len(p.DNS) > 4 {
		return errors.New("profile requires 1..4 IPv4 DNS servers")
	}
	for _, s := range p.DNS {
		ip, e := netip.ParseAddr(s)
		if e != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
			return errors.New("invalid IPv4 DNS server")
		}
	}
	c := p.Config
	if err = c.Validate(); err != nil {
		return err
	}
	if c.Role != "client" || c.SocketMode != "ping" || c.Listen != "0.0.0.0" || c.MTU < 1280 || c.Adaptive == nil || c.Adaptive.IDMode != "stable" {
		return errors.New("mobile requires an adaptive ping-socket client, wildcard listen and MTU >= 1280")
	}
	if len(c.AllowedIPs) != 1 || c.AllowedIPs[0] != "0.0.0.0/0" {
		return errors.New("mobile client requires full IPv4 routing")
	}
	return nil
}

// Info contains no private keys and is the only profile object exposed to UI.
func (p Profile) Info() map[string]any {
	return map[string]any{"name": p.Name, "address": p.Address, "dns": p.DNS, "server_ip": p.Config.ServerIP, "mtu": p.Config.MTU}
}
