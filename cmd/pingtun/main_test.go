//go:build linux

package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/bug0000/pingtun/internal/config"
)

func TestInitPair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pair")
	if e := initialize("192.0.2.20", dir); e != nil {
		t.Fatal(e)
	}
	client, e := config.Load(filepath.Join(dir, "client.json"))
	if e != nil {
		t.Fatal(e)
	}
	server, e := config.Load(filepath.Join(dir, "server.json"))
	if e != nil {
		t.Fatal(e)
	}
	if client.TransportKey != server.TransportKey || client.PrivateKey == server.PrivateKey {
		t.Fatal("invalid key separation")
	}
	if client.Adaptive == nil || server.Adaptive == nil || client.Adaptive.IDMode != "stable" || client.MTU != 1280 || client.WireMTU != 1440 {
		t.Fatal("new configs must use the release v2 defaults")
	}
	for _, pair := range [][2]string{{client.PrivateKey, server.PeerPublicKey}, {server.PrivateKey, client.PeerPublicKey}} {
		key, e := config.Key(pair[0])
		if e != nil {
			t.Fatal(e)
		}
		priv, e := ecdh.X25519().NewPrivateKey(key[:])
		if e != nil {
			t.Fatal(e)
		}
		if base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()) != pair[1] {
			t.Fatal("wrong peer public key")
		}
	}
	if e = initialize("192.0.2.20", dir); e == nil {
		t.Fatal("existing config directory overwritten")
	}
	st, e := os.Stat(dir)
	if e != nil || st.Mode().Perm() != 0700 {
		t.Fatal("insecure config directory")
	}
}

func TestLegacyInitRemainsExplicit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "legacy")
	if err := initializeWithMode("192.0.2.20", dir, true); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"server", "client"} {
		c, err := config.Load(filepath.Join(dir, role+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if c.Adaptive != nil || c.MTU != 1000 || c.WireMTU != 1280 {
			t.Fatal("legacy defaults changed")
		}
	}
}
