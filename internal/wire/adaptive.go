package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const AdaptiveHeaderSize = 80
const Control byte = 1

// AdaptiveFrame is an explicit v2 format. It cannot be decoded as legacy v1.
// Epoch detects responder restarts; DelayUS separates server holding time from
// the RTT estimate. Backlog is a hint, never authority to exceed local limits.
type AdaptiveFrame struct {
	Kind    byte
	Lane    uint16
	Session [16]byte
	Number  uint64
	Time    int64
	Payload []byte
	Backlog uint16
	Epoch   uint64
	DelayUS uint32
	Flags   byte
}

func validAdaptive(f AdaptiveFrame) bool {
	if f.Session == ([16]byte{}) || (f.Kind != Request && f.Kind != Response) || f.Flags & ^Control != 0 {
		return false
	}
	if f.Flags&Control != 0 && len(f.Payload) != 0 {
		return false
	}
	if f.Kind == Request && (f.Epoch != 0 || f.Backlog != 0 || f.DelayUS != 0) {
		return false
	}
	return f.Kind != Response || f.Epoch != 0
}
func EncodeAdaptive(f AdaptiveFrame, key []byte, size int) ([]byte, error) {
	if len(key) != 32 || size < AdaptiveHeaderSize || size > MaxFrame || len(f.Payload) > size-AdaptiveHeaderSize || !validAdaptive(f) {
		return nil, ErrFrame
	}
	b := make([]byte, size)
	copy(b, "PTUN")
	b[4] = 2
	b[5] = f.Kind
	binary.BigEndian.PutUint16(b[6:8], f.Lane)
	copy(b[8:24], f.Session[:])
	binary.BigEndian.PutUint64(b[24:32], f.Number)
	binary.BigEndian.PutUint64(b[32:40], uint64(f.Time))
	binary.BigEndian.PutUint16(b[40:42], uint16(len(f.Payload)))
	binary.BigEndian.PutUint16(b[42:44], f.Backlog)
	binary.BigEndian.PutUint64(b[44:52], f.Epoch)
	binary.BigEndian.PutUint32(b[52:56], f.DelayUS)
	b[56] = f.Flags
	copy(b[AdaptiveHeaderSize:], f.Payload)
	m := hmac.New(sha256.New, key)
	m.Write(b[:64])
	m.Write(b[AdaptiveHeaderSize:])
	copy(b[64:80], m.Sum(nil)[:16])
	return b, nil
}
func DecodeAdaptive(b, key []byte, now time.Time) (AdaptiveFrame, error) {
	var f AdaptiveFrame
	if len(key) != 32 || len(b) < AdaptiveHeaderSize || len(b) > MaxFrame || string(b[:4]) != "PTUN" || b[4] != 2 {
		return f, ErrFrame
	}
	m := hmac.New(sha256.New, key)
	m.Write(b[:64])
	m.Write(b[AdaptiveHeaderSize:])
	if !hmac.Equal(b[64:80], m.Sum(nil)[:16]) {
		return f, ErrFrame
	}
	for _, v := range b[57:64] {
		if v != 0 {
			return f, ErrFrame
		}
	}
	n := int(binary.BigEndian.Uint16(b[40:42]))
	if n > len(b)-AdaptiveHeaderSize {
		return f, ErrFrame
	}
	f.Kind = b[5]
	f.Lane = binary.BigEndian.Uint16(b[6:8])
	copy(f.Session[:], b[8:24])
	f.Number = binary.BigEndian.Uint64(b[24:32])
	f.Time = int64(binary.BigEndian.Uint64(b[32:40]))
	f.Backlog = binary.BigEndian.Uint16(b[42:44])
	f.Epoch = binary.BigEndian.Uint64(b[44:52])
	f.DelayUS = binary.BigEndian.Uint32(b[52:56])
	f.Flags = b[56]
	f.Payload = append([]byte(nil), b[AdaptiveHeaderSize:AdaptiveHeaderSize+n]...)
	delta := now.Unix() - f.Time
	if f.Time < 0 || delta < -30 || delta > 30 || !validAdaptive(f) {
		return AdaptiveFrame{}, ErrFrame
	}
	return f, nil
}
