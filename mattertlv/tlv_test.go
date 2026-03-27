package mattertlv

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestBasicEmptyAnonStruct(t *testing.T) {
	var encoder TLVBuffer

	encoder.WriteAnonStruct()
	encoder.WriteStructEnd()

	encoded := encoder.Bytes()
	if hex.EncodeToString(encoded) != "1518" {
		t.Fatalf("incorrect %s", hex.EncodeToString(encoded))
	}

	decoded := Decode(encoded)
	if len(decoded.GetChild()) != 0 {
		t.Fatalf("empty struct test failed")
	}
}

func TestBasic(t *testing.T) {
	var encoder TLVBuffer

	encoder.WriteAnonStruct()
	encoder.WriteUInt8(10, 0x12)
	encoder.WriteUInt16(11, 0x1234)
	encoder.WriteUInt32(12, 0x12345678)
	encoder.WriteUInt64(13, 0x123456789abcdef0)
	encoder.WriteUInt64(14, 0xf23456789abcdef0)
	encoder.WriteOctetString(15, []byte{1, 2, 3, 4, 5})
	encoder.WriteBool(16, false)
	encoder.WriteBool(17, true)
	encoder.WriteStructEnd()

	encoded := encoder.Bytes()

	decoded := Decode(encoded)
	if len(decoded.GetChild()) != 8 {
		t.Fatalf("empty struct test failed")
	}

	if hex.EncodeToString(encoded) != "15240a12250b3412260c78563412270df0debc9a78563412270ef0debc9a785634f2300f0501020304052810291118" {
		t.Fatalf("incorrect encoding")
	}

	if decoded.GetItemWithTag(10).GetInt() != 0x12 {
		t.Fatalf("incorrect encoding 10")
	}
	if decoded.GetItemWithTag(11).GetInt() != 0x1234 {
		t.Fatalf("incorrect encoding 11")
	}
	if decoded.GetItemWithTag(12).GetInt() != 0x12345678 {
		t.Fatalf("incorrect encoding 12")
	}
	if decoded.GetItemWithTag(13).GetInt() != 0x123456789abcdef0 {
		t.Fatalf("incorrect encoding 13")
	}
	if decoded.GetItemWithTag(14).GetUint64() != 0xf23456789abcdef0 {
		t.Fatalf("incorrect encoding 14")
	}
	if hex.EncodeToString(decoded.GetItemWithTag(15).GetOctetString()) != "0102030405" {
		t.Fatalf("incorrect encoding 15")
	}
	if decoded.GetItemWithTag(16).GetBool() {
		t.Fatalf("incorrect encoding 16")
	}
	if !decoded.GetItemWithTag(17).GetBool() {
		t.Fatalf("incorrect encoding 17")
	}
}

func TestRec(t *testing.T) {
	var encoder TLVBuffer

	encoder.WriteAnonStruct()
	encoder.WriteOctetString(1, []byte{1, 2, 3, 4, 5})
	encoder.WriteArray(2)
	encoder.WriteAnonStruct()
	encoder.WriteOctetString(2, []byte{1, 2, 3, 4, 5})
	encoder.WriteUInt32(3, 33)
	encoder.WriteStructEnd()
	encoder.WriteStructEnd()
	encoder.WriteStructEnd()

	encoded := encoder.Bytes()
	if hex.EncodeToString(encoded) != "1530010501020304053602153002050102030405260321000000181818" {
		fmt.Printf(hex.EncodeToString(encoded))
		t.Fatal("invalid encode")
	}

	decoded := Decode(encoded)

	i, err := decoded.GetIntRec([]int{2, 0, 3})
	if err != nil {
		t.Fatalf("error %s", err.Error())
	}
	if i != 33 {
		t.Fatal("incorrect value")
	}

	it := decoded.GetItemRec([]int{2, 0, 3})
	if it == nil {
		t.Fatalf("not found")
	}
	if it.GetInt() != 33 {
		t.Fatal("incorrect value")
	}

	it = decoded.GetItemRec([]int{2, 0, 2})
	if it == nil {
		t.Fatalf("not found")
	}
	if hex.EncodeToString(it.GetOctetString()) != "0102030405" {
		t.Fatal("incorrect value")
	}

	os := decoded.GetOctetStringRec([]int{2, 0, 2})
	if hex.EncodeToString(os) != "0102030405" {
		t.Fatal("incorrect value")
	}
}

func TestSignedIntDecoding(t *testing.T) {
	// Matter TLV element types for signed integers:
	//   type 0 = Signed Int, 1-byte
	//   type 1 = Signed Int, 2-byte
	//   type 2 = Signed Int, 4-byte
	//   type 3 = Signed Int, 8-byte
	// Each test wraps a tagged signed int inside an anonymous struct (0x15 ... 0x18).
	// Tag control 0x20 = context-specific tag (1-byte tag number follows).

	tests := []struct {
		name string
		// raw TLV bytes: struct-open + element + struct-end
		raw []byte
		tag int
		val int
	}{
		// Type 0: 1-byte signed int, tag=1, value=127 (0x7F)
		{
			name: "int8 positive 127",
			raw:  []byte{0x15, 0x20, 0x01, 0x7F, 0x18},
			tag:  1, val: 127,
		},
		// Type 0: 1-byte signed int, tag=1, value=-1 (0xFF as signed)
		{
			name: "int8 negative -1",
			raw:  []byte{0x15, 0x20, 0x01, 0xFF, 0x18},
			tag:  1, val: -1,
		},
		// Type 0: 1-byte signed int, tag=1, value=-128 (0x80)
		{
			name: "int8 negative -128",
			raw:  []byte{0x15, 0x20, 0x01, 0x80, 0x18},
			tag:  1, val: -128,
		},
		// Type 1: 2-byte signed int, tag=2, value=256 (0x0100 LE)
		{
			name: "int16 positive 256",
			raw:  []byte{0x15, 0x21, 0x02, 0x00, 0x01, 0x18},
			tag:  2, val: 256,
		},
		// Type 1: 2-byte signed int, tag=2, value=-1 (0xFFFF LE)
		{
			name: "int16 negative -1",
			raw:  []byte{0x15, 0x21, 0x02, 0xFF, 0xFF, 0x18},
			tag:  2, val: -1,
		},
		// Type 1: 2-byte signed int, tag=2, value=-256 (0xFF00 LE = 0x00FF in bytes)
		{
			name: "int16 negative -256",
			raw:  []byte{0x15, 0x21, 0x02, 0x00, 0xFF, 0x18},
			tag:  2, val: -256,
		},
		// Type 2: 4-byte signed int, tag=3, value=100000 (0x000186A0 LE)
		{
			name: "int32 positive 100000",
			raw:  []byte{0x15, 0x22, 0x03, 0xA0, 0x86, 0x01, 0x00, 0x18},
			tag:  3, val: 100000,
		},
		// Type 2: 4-byte signed int, tag=3, value=-1 (0xFFFFFFFF LE)
		{
			name: "int32 negative -1",
			raw:  []byte{0x15, 0x22, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x18},
			tag:  3, val: -1,
		},
		// Type 3: 8-byte signed int, tag=4, value=1000000000000 (0x000000E8D4A51000 LE)
		{
			name: "int64 positive 1000000000000",
			raw:  []byte{0x15, 0x23, 0x04, 0x00, 0x10, 0xA5, 0xD4, 0xE8, 0x00, 0x00, 0x00, 0x18},
			tag:  4, val: 1000000000000,
		},
		// Type 3: 8-byte signed int, tag=4, value=-1 (0xFFFFFFFFFFFFFFFF LE)
		{
			name: "int64 negative -1",
			raw:  []byte{0x15, 0x23, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x18},
			tag:  4, val: -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decoded := Decode(tc.raw)
			item := decoded.GetItemWithTag(tc.tag)
			if item == nil {
				t.Fatalf("tag %d not found", tc.tag)
			}
			got := item.GetInt()
			if got != tc.val {
				t.Fatalf("expected %d, got %d", tc.val, got)
			}
		})
	}
}
