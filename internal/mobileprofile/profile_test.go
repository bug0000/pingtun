package mobileprofile

import (
	"encoding/base64"
	"encoding/json"
	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/config"
	"strings"
	"testing"
)

func sample() Profile {
	key := make([]byte, 32)
	key[0] = 1
	k := base64.StdEncoding.EncodeToString(key)
	return Profile{Version: 1, Name: "Test", Address: "10.203.0.2/30", DNS: []string{"1.1.1.1"}, Config: config.Config{Role: "client", Interface: "pingtun0", Listen: "0.0.0.0", ServerIP: "192.0.2.1", PrivateKey: k, PeerPublicKey: k, TransportKey: k, AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1280, WireMTU: 1440, Lanes: 2, Window: 4, HoldMS: 500, SocketMode: "ping", Adaptive: &carrier.AdaptiveConfig{IDMode: "stable"}}}
}
func TestProfileBoundsAndNoSecretsInInfo(t *testing.T) {
	p := sample()
	b, _ := json.Marshal(p)
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := json.Marshal(got.Info())
	if strings.Contains(string(info), p.Config.PrivateKey) || strings.Contains(string(info), "private_key") {
		t.Fatal("private material exposed to UI")
	}
	for _, change := range []func(*Profile){func(p *Profile) { p.Config.SocketMode = "raw" }, func(p *Profile) { p.Config.MTU = 1000 }, func(p *Profile) { p.Config.Adaptive.IDMode = "rotate" }, func(p *Profile) { p.Config.Listen = "192.0.2.2" }, func(p *Profile) { p.DNS = []string{"::1"} }, func(p *Profile) { p.Config.AllowedIPs = []string{"192.0.2.0/24"} }} {
		bad := sample()
		change(&bad)
		b, _ = json.Marshal(bad)
		if _, err = Decode(b); err == nil {
			t.Fatal("unsafe mobile profile accepted")
		}
	}
	if _, err = Decode(append(b, []byte(" {}")...)); err == nil {
		t.Fatal("trailing object accepted")
	}
	if _, err = Decode(make([]byte, 65537)); err == nil {
		t.Fatal("oversized profile accepted")
	}
}
