package wire

import (
	"bytes"
	"testing"
	"time"
)

func key() []byte { return bytes.Repeat([]byte{0x42}, 32) }
func TestFrameAuthentication(t *testing.T) {
	now := time.Unix(1700000000, 0)
	f := Frame{Kind: Request, Lane: 3, Number: 42, Time: now.Unix(), Payload: []byte("payload")}
	f.Session[0] = 9
	b, e := Encode(f, key(), 512)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Decode(b, key(), now)
	if e != nil || !bytes.Equal(got.Payload, f.Payload) || got.Session != f.Session || got.Number != 42 {
		t.Fatal("round trip", e)
	}
	for i := range b {
		bad := append([]byte(nil), b...)
		bad[i] ^= 1
		if _, e := Decode(bad, key(), now); e == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	if _, e = Decode(b, bytes.Repeat([]byte{1}, 32), now); e == nil {
		t.Fatal("wrong key accepted")
	}
	for _, delta := range []time.Duration{-31 * time.Second, 31 * time.Second} {
		if _, e = Decode(b, key(), now.Add(delta)); e == nil {
			t.Fatal("stale/future packet accepted")
		}
	}
}
func TestWindow(t *testing.T) {
	var w Window
	for _, n := range []uint64{100, 102, 101, 2000, 1999, 977} {
		if !w.Accept(n) {
			t.Fatalf("fresh %d rejected", n)
		}
	}
	for _, n := range []uint64{100, 102, 101, 2000, 1999, 977, 976} {
		if w.Accept(n) {
			t.Fatalf("old %d accepted", n)
		}
	}
}

func TestProbeDomainSeparation(t *testing.T) {
	now := time.Unix(1700000000, 0)
	f := Frame{Kind: Request, Number: 1, Time: now.Unix(), Payload: []byte("generated probe payload")}
	probe, err := EncodeProbe(f, key(), 128)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeProbe(probe, key(), now); err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(probe, key(), now); err == nil {
		t.Fatal("probe accepted as tunnel packet")
	}
	copy(probe, "PTUN")
	if _, err = Decode(probe, key(), now); err == nil {
		t.Fatal("magic was not authenticated")
	}
}

func FuzzDecodeProbe(f *testing.F) {
	b, _ := EncodeProbe(Frame{Kind: Request, Time: 1700000000}, key(), 128)
	f.Add(b)
	f.Add([]byte("PTPB"))
	f.Fuzz(func(t *testing.T, b []byte) {
		frame, err := DecodeProbe(b, key(), time.Unix(1700000000, 0))
		if err == nil && len(frame.Payload) > MaxFrame-HeaderSize {
			t.Fatal("unbounded probe payload")
		}
	})
}
func FuzzDecode(f *testing.F) {
	b, _ := Encode(Frame{Kind: Request, Time: 1700000000}, key(), 512)
	f.Add(b)
	f.Add([]byte("PTUN"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		frame, e := Decode(b, key(), time.Unix(1700000000, 0))
		if e == nil && len(frame.Payload) > MaxFrame-HeaderSize {
			t.Fatal("unbounded payload")
		}
	})
}
