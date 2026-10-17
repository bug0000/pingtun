package wire

import (
	"bytes"
	"testing"
	"time"
)

func TestAdaptiveFrameAuthentication(t *testing.T) {
	now := time.Unix(1700000000, 0)
	f := AdaptiveFrame{Kind: Response, Epoch: 7, Number: 2, Time: now.Unix(), Payload: []byte("opaque"), Backlog: 8, DelayUS: 25000}
	f.Session[0] = 1
	b, err := EncodeAdaptive(f, key(), 512)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAdaptive(b, key(), now)
	if err != nil || got.Epoch != 7 || got.Backlog != 8 || got.DelayUS != 25000 || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatal("bad v2 round trip", err)
	}
	for i := range b {
		bad := append([]byte(nil), b...)
		bad[i] ^= 1
		if _, err = DecodeAdaptive(bad, key(), now); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	if _, err = Decode(b, key(), now); err == nil {
		t.Fatal("v2 accepted as v1")
	}
	if _, err = DecodeAdaptive(b, key(), now.Add(31*time.Second)); err == nil {
		t.Fatal("stale frame accepted")
	}
	f.Flags = Control
	if _, err = EncodeAdaptive(f, key(), 512); err == nil {
		t.Fatal("control with payload accepted")
	}
	f.Payload = nil
	f.Kind = Request
	if _, err = EncodeAdaptive(f, key(), 512); err == nil {
		t.Fatal("request with forged server feedback accepted")
	}
}
func FuzzDecodeAdaptive(f *testing.F) {
	s := AdaptiveFrame{Kind: Request, Time: 1700000000}
	s.Session[0] = 1
	b, _ := EncodeAdaptive(s, key(), 512)
	f.Add(b)
	f.Add([]byte("PTUN\x02"))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := DecodeAdaptive(b, key(), time.Unix(1700000000, 0))
		if err == nil && len(v.Payload) > MaxFrame-AdaptiveHeaderSize {
			t.Fatal("unbounded payload")
		}
	})
}
