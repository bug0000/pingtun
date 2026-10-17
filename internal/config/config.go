package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/wire"
)

type Config struct {
	Role          string                  `json:"role"`
	Interface     string                  `json:"interface"`
	Listen        string                  `json:"listen"`
	ServerIP      string                  `json:"server_ip,omitempty"`
	PrivateKey    string                  `json:"private_key"`
	PeerPublicKey string                  `json:"peer_public_key"`
	TransportKey  string                  `json:"transport_key"`
	AllowedIPs    []string                `json:"allowed_ips"`
	MTU           int                     `json:"mtu"`
	WireMTU       int                     `json:"wire_mtu"`
	Lanes         int                     `json:"lanes"`
	Window        int                     `json:"window"`
	HoldMS        int                     `json:"hold_ms"`
	Adaptive      *carrier.AdaptiveConfig `json:"adaptive,omitempty"`
	SocketMode    string                  `json:"socket_mode,omitempty"`
}

func Key(s string) ([32]byte, error) {
	var key [32]byte
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return key, errors.New("key must be 32 bytes encoded as base64")
	}
	copy(key[:], b)
	if key == ([32]byte{}) {
		return key, errors.New("zero key rejected")
	}
	return key, nil
}
func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return c, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return c, errors.New("config must be a regular file with mode 0600 or stricter")
	}
	return Decode(io.LimitReader(f, 65537))
}

// Decode accepts private configuration from an already protected source. Errors
// deliberately do not include input bytes, field values or WireGuard IPC.
func Decode(r io.Reader) (Config, error) {
	var c Config
	d := json.NewDecoder(io.LimitReader(r, 65537))
	d.DisallowUnknownFields()
	if e := d.Decode(&c); e != nil {
		return c, errors.New("invalid JSON config")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("trailing config data")
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Role != "client" && c.Role != "server" {
		return errors.New("role must be client or server")
	}
	if c.SocketMode != "" && c.SocketMode != "raw" && c.SocketMode != "ping" {
		return errors.New("socket_mode must be raw or ping")
	}
	if c.SocketMode == "ping" && (c.Role != "client" || c.Adaptive == nil || c.Adaptive.IDMode != "stable") {
		return errors.New("ping socket requires an adaptive client with stable identifier mode")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`).MatchString(c.Interface) {
		return errors.New("invalid TUN interface name")
	}
	for _, s := range []string{c.PrivateKey, c.PeerPublicKey, c.TransportKey} {
		if _, e := Key(s); e != nil {
			return e
		}
	}
	if len(c.AllowedIPs) == 0 {
		return errors.New("allowed_ips must not be empty")
	}
	for _, s := range c.AllowedIPs {
		a, e := netip.ParsePrefix(s)
		if e != nil || !a.Addr().Is4() || a != a.Masked() {
			return errors.New("allowed_ips must contain canonical IPv4 prefixes")
		}
	}
	listen, e := netip.ParseAddr(c.Listen)
	if e != nil || !listen.Is4() {
		return errors.New("listen must be an IPv4 address")
	}
	cc, e := c.Carrier()
	if e != nil {
		return e
	}
	if e = cc.Validate(); e != nil {
		return e
	}
	// WireGuard transport: 16-byte header, 16-byte tag, and inner-IP padding to 16 bytes.
	header := wire.HeaderSize
	if c.Adaptive != nil {
		header = wire.AdaptiveHeaderSize
	}
	if c.MTU < 68 || 32+((c.MTU+15)/16)*16 > c.WireMTU-28-header {
		return errors.New("TUN MTU does not fit the authenticated ICMP carrier")
	}
	return nil
}
func (c Config) Carrier() (carrier.Config, error) {
	key, e := Key(c.TransportKey)
	if e != nil {
		return carrier.Config{}, e
	}
	remote := netip.Addr{}
	if c.Role == "client" {
		remote, e = netip.ParseAddr(c.ServerIP)
		if e != nil {
			return carrier.Config{}, errors.New("invalid server_ip")
		}
	}
	cc := carrier.Config{Server: c.Role == "server", Remote: remote, Key: key, Lanes: c.Lanes, Window: c.Window, WireMTU: c.WireMTU, Hold: time.Duration(c.HoldMS) * time.Millisecond, Timeout: time.Duration(c.HoldMS)*time.Millisecond + 2*time.Second}
	cc.Socket = func() (carrier.EchoSocket, error) { return carrier.Listen(c.Listen) }
	if c.SocketMode == "ping" {
		cc.Socket = func() (carrier.EchoSocket, error) { return carrier.ListenPing(remote, nil) }
	}
	cc.Adaptive = c.Adaptive
	return cc, nil
}
func (c Config) IPC() (string, error) {
	key, e := Key(c.PrivateKey)
	if e != nil {
		return "", e
	}
	peer, e := Key(c.PeerPublicKey)
	if e != nil {
		return "", e
	}
	var s strings.Builder
	fmt.Fprintf(&s, "private_key=%x\npublic_key=%x\nreplace_allowed_ips=true\n", key, peer)
	for _, prefix := range c.AllowedIPs {
		fmt.Fprintf(&s, "allowed_ip=%s\n", prefix)
	}
	if c.Role == "client" {
		fmt.Fprintf(&s, "endpoint=%s:1\npersistent_keepalive_interval=25\n", c.ServerIP)
	}
	return s.String(), nil
}
