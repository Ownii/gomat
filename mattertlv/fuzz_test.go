package mattertlv

import (
	"testing"
)

// FuzzTLVDecode feeds random bytes to the TLV decoder and asserts it never panics.
// Errors are expected and acceptable — panics are not.
func FuzzTLVDecode(f *testing.F) {
	// Seed corpus with known valid and edge-case TLV payloads.
	f.Add([]byte{0x15, 0x18})                                     // empty struct
	f.Add([]byte{0x15, 0x24, 0x01, 0x42, 0x18})                   // struct with uint8
	f.Add([]byte{0x15, 0x20, 0x01, 0xFF, 0x18})                   // struct with signed int8 -1
	f.Add([]byte{0x15, 0x21, 0x02, 0xFF, 0xFF, 0x18})             // struct with signed int16 -1
	f.Add([]byte{0x15, 0x0a, 0x18})                                // unsupported type 0xa (float)
	f.Add([]byte{0x15, 0x0b, 0x18})                                // unsupported type 0xb (double)
	f.Add([]byte{0x15, 0x1f, 0x18})                                // unknown type 0x1f
	f.Add([]byte{})                                                 // empty input
	f.Add([]byte{0x15})                                             // truncated struct (no end)
	f.Add([]byte{0x15, 0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x18}) // octet string

	f.Fuzz(func(t *testing.T, data []byte) {
		// Decode should never panic — errors are fine.
		_, _ = Decode(data)
	})
}
