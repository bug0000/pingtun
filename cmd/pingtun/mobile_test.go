//go:build linux

package main

import (
	"github.com/bug0000/pingtun/internal/config"
	"github.com/bug0000/pingtun/internal/mobileprofile"
	"os"
	"path/filepath"
	"testing"
)

func TestDedicatedMobileProfileGeneration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new")
	if err := initializeMobile("192.0.2.1", dir, "Test phone", "10.203.0.2/30"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "profile.pingtun.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := mobileprofile.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	server, err := config.Load(filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.PeerPublicKey == server.PeerPublicKey || p.Config.PrivateKey == server.PrivateKey || server.SocketMode == "ping" || server.AllowedIPs[0] != "10.203.0.2/32" {
		t.Fatal("mobile and server identities not independent")
	}
	for _, name := range []string{"server.json", "client.json", "profile.pingtun.json"} {
		st, e := os.Stat(filepath.Join(dir, name))
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal("private file permissions")
		}
	}
	if err = initializeMobile("192.0.2.1", dir, "Test phone", "10.203.0.2/30"); err == nil {
		t.Fatal("existing keys overwritten")
	}
}
