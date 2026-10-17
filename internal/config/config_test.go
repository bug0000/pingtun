package config

import (
	"encoding/base64"
	"encoding/json"
	"github.com/bug0000/pingtun/internal/carrier"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture() Config {
	key := make([]byte, 32)
	key[0] = 7
	k := base64.StdEncoding.EncodeToString(key)
	return Config{Role: "client", Interface: "pingtun0", Listen: "0.0.0.0", ServerIP: "192.0.2.20", PrivateKey: k, PeerPublicKey: k, TransportKey: k, AllowedIPs: []string{"0.0.0.0/0"}, MTU: 1000, WireMTU: 1280, Lanes: 2, Window: 2, HoldMS: 500}
}

func TestDecodeBoundsWholePrivateInput(t *testing.T) {
	data, err := json.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	limit := string(data) + strings.Repeat(" ", 65536-len(data))
	if _, err := Decode(strings.NewReader(limit)); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(strings.NewReader(limit + " secret trailing bytes")); err == nil {
		t.Fatal("oversized input silently truncated")
	}
}

func TestAdaptiveLimitsAndMTUBudget(t *testing.T) {
	c := fixture()
	c.Adaptive = &carrier.AdaptiveConfig{}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.MTU = 1150
	if err := c.Validate(); err == nil {
		t.Fatal("v2 header overhead ignored")
	}
	c = fixture()
	c.Adaptive = &carrier.AdaptiveConfig{MaxWindow: 129}
	if err := c.Validate(); err == nil {
		t.Fatal("unbounded window accepted")
	}
	c.Adaptive = &carrier.AdaptiveConfig{IDMode: "automatic"}
	if err := c.Validate(); err == nil {
		t.Fatal("unknown identity mode accepted")
	}
}
func TestRejectUnsafeConfig(t *testing.T) {
	c := fixture()
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	mutations := []func(*Config){func(c *Config) { c.MTU = 1500 }, func(c *Config) { c.Interface = "tun;exit" }, func(c *Config) { c.AllowedIPs = []string{"::/0"} }, func(c *Config) { c.Lanes = 9 }, func(c *Config) { c.Window = 1000 }, func(c *Config) { c.ServerIP = "127.0.0.1\nprivate_key=bad" }, func(c *Config) { c.TransportKey = "not a key" }}
	for i, mutate := range mutations {
		bad := fixture()
		mutate(&bad)
		if e := bad.Validate(); e == nil {
			t.Fatalf("unsafe config %d accepted", i)
		}
	}
}
func TestConfigPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	data, e := json.Marshal(fixture())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(path); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(path); e == nil {
		t.Fatal("world-readable private keys accepted")
	}
}
