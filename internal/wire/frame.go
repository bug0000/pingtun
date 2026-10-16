// Package wire defines the authenticated ICMP carrier. Payload confidentiality
// and IP-packet authentication are provided separately by WireGuard.
package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"
)

const (
	HeaderSize      = 58
	Request    byte = 1
	Response   byte = 2
	MaxFrame        = 1472 // IPv4 MTU 1500 minus IPv4 and ICMP headers.
)

var ErrFrame = errors.New("invalid carrier frame")

type Frame struct {
	Kind    byte
	Lane    uint16
	Session [16]byte
	Number  uint64
	Time    int64
	Payload []byte
}

// Encode pads every request and response to the same configured size, including
// padding in the MAC. No secret or live payload is ever reused as padding.
func Encode(f Frame, key []byte, size int) ([]byte, error) {
	if len(key) != 32 || size < HeaderSize || size > MaxFrame || len(f.Payload) > size-HeaderSize || (f.Kind != Request && f.Kind != Response) {
		return nil, ErrFrame
	}
	b := make([]byte, size)
	copy(b, "PTUN")
	b[4] = 1
	b[5] = f.Kind
	binary.BigEndian.PutUint16(b[6:8], f.Lane)
	copy(b[8:24], f.Session[:])
	binary.BigEndian.PutUint64(b[24:32], f.Number)
	binary.BigEndian.PutUint64(b[32:40], uint64(f.Time))
	binary.BigEndian.PutUint16(b[40:42], uint16(len(f.Payload)))
	copy(b[HeaderSize:], f.Payload)
	mac := hmac.New(sha256.New, key)
	mac.Write(b[:42])
	mac.Write(b[HeaderSize:])
	copy(b[42:58], mac.Sum(nil)[:16])
	return b, nil
}

// Decode verifies the MAC before trusting lengths, timestamps or session IDs.
// A 30-second freshness interval bounds replay-cache lifetime and requires NTP.
func Decode(b, key []byte, now time.Time) (Frame, error) {
	var f Frame
	if len(key) != 32 || len(b) < HeaderSize || len(b) > MaxFrame || string(b[:4]) != "PTUN" || b[4] != 1 {
		return f, ErrFrame
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b[:42])
	mac.Write(b[HeaderSize:])
	if !hmac.Equal(b[42:58], mac.Sum(nil)[:16]) {
		return f, ErrFrame
	}
	if b[5] != Request && b[5] != Response {
		return f, ErrFrame
	}
	n := int(binary.BigEndian.Uint16(b[40:42]))
	if n > len(b)-HeaderSize {
		return f, ErrFrame
	}
	stamp := int64(binary.BigEndian.Uint64(b[32:40]))
	delta := now.Unix() - stamp
	if stamp < 0 || delta < -30 || delta > 30 {
		return f, ErrFrame
	}
	f.Kind = b[5]
	f.Lane = binary.BigEndian.Uint16(b[6:8])
	copy(f.Session[:], b[8:24])
	f.Number = binary.BigEndian.Uint64(b[24:32])
	f.Time = stamp
	f.Payload = append([]byte(nil), b[HeaderSize:HeaderSize+n]...)
	return f, nil
}

// Window tracks a bounded 1024-packet sliding replay window. Unlike an IP-based
// identity, the random authenticated session ID permits parallel lanes at a NAT.
type Window struct {
	highest     uint64
	bits        [16]uint64
	initialized bool
}

func (w *Window) Accept(n uint64) bool {
	if !w.initialized {
		w.initialized = true
		w.highest = n
		w.bits[0] = 1
		return true
	}
	if n > w.highest {
		d := n - w.highest
		if d >= 1024 {
			w.bits = [16]uint64{}
		} else {
			var next [16]uint64
			for i := uint64(0); i < 1024-d; i++ {
				if w.bits[i/64]&(uint64(1)<<(i%64)) != 0 {
					j := i + d
					next[j/64] |= uint64(1) << (j % 64)
				}
			}
			w.bits = next
		}
		w.highest = n
		w.bits[0] |= 1
		return true
	}
	d := w.highest - n
	if d >= 1024 {
		return false
	}
	mask := uint64(1) << (d % 64)
	if w.bits[d/64]&mask != 0 {
		return false
	}
	w.bits[d/64] |= mask
	return true
}
