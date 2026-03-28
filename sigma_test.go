package gomat

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/power2go-com-br/gomat/mattertlv"
)

// TestPadAndConcatRS verifies that the ECDSA R||S concatenation is always
// exactly 64 bytes (32-byte R + 32-byte S, zero-padded on the left).
//
// Regression test: big.Int.Bytes() returns minimal representation without
// leading zeros. ~1/256 signatures have a 31-byte R or S, producing a 63-byte
// concatenation that the Matter responder rejects as INVALID_PARAMETER.
func TestPadAndConcatRS(t *testing.T) {
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	hash := make([]byte, 32)
	rand.Read(hash)

	for i := 0; i < 500; i++ {
		r, s, err := ecdsa.Sign(rand.Reader, privkey, hash)
		if err != nil {
			t.Fatalf("iteration %d: Sign: %v", i, err)
		}

		sig := padAndConcatRS(r, s)
		if len(sig) != 64 {
			t.Fatalf("iteration %d: expected 64-byte signature, got %d bytes (R=%d bytes, S=%d bytes)",
				i, len(sig), len(r.Bytes()), len(s.Bytes()))
		}

		// Verify padding didn't corrupt the values.
		rRecovered := new(big.Int).SetBytes(sig[:32])
		sRecovered := new(big.Int).SetBytes(sig[32:])
		if rRecovered.Cmp(r) != 0 {
			t.Fatalf("iteration %d: R value corrupted by padding", i)
		}
		if sRecovered.Cmp(s) != 0 {
			t.Fatalf("iteration %d: S value corrupted by padding", i)
		}
	}
}

// TestPadAndConcatRS_ShortValues tests padding with known short values
// that would fail without zero-padding.
func TestPadAndConcatRS_ShortValues(t *testing.T) {
	tests := []struct {
		name   string
		rBytes []byte // what big.Int.Bytes() would return
		sBytes []byte
	}{
		{
			name:   "31-byte R",
			rBytes: make([]byte, 31), // leading zero was stripped
			sBytes: make([]byte, 32),
		},
		{
			name:   "31-byte S",
			rBytes: make([]byte, 32),
			sBytes: make([]byte, 31),
		},
		{
			name:   "both 31 bytes",
			rBytes: make([]byte, 31),
			sBytes: make([]byte, 31),
		},
		{
			name:   "30-byte R",
			rBytes: make([]byte, 30),
			sBytes: make([]byte, 32),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill with non-zero data so we can verify placement.
			for i := range tt.rBytes {
				tt.rBytes[i] = 0xAA
			}
			for i := range tt.sBytes {
				tt.sBytes[i] = 0xBB
			}

			r := new(big.Int).SetBytes(tt.rBytes)
			s := new(big.Int).SetBytes(tt.sBytes)

			sig := padAndConcatRS(r, s)
			if len(sig) != 64 {
				t.Fatalf("expected 64 bytes, got %d", len(sig))
			}

			// Verify values are right-aligned (zero-padded on left).
			rRecovered := new(big.Int).SetBytes(sig[:32])
			sRecovered := new(big.Int).SetBytes(sig[32:])
			if rRecovered.Cmp(r) != 0 {
				t.Fatal("R value mismatch after padding")
			}
			if sRecovered.Cmp(s) != 0 {
				t.Fatal("S value mismatch after padding")
			}
		})
	}
}

// TestSigma3FullFlow exercises sigma3() with a real fabric to verify
// it produces valid output across many iterations, catching probabilistic
// padding failures.
func TestSigma3FullFlow(t *testing.T) {
	cm := setupTestCertManager(t)
	fabric := NewFabric(cm.fabric, cm)

	var controllerID uint64 = 100
	if createErr := cm.CreateUser(controllerID); createErr != nil {
		t.Fatalf("CreateUser: %v", createErr)
	}

	controllerKey, keyErr := cm.GetPrivkey(controllerID)
	if keyErr != nil {
		t.Fatalf("GetPrivkey: %v", keyErr)
	}
	controllerCert, certErr := cm.GetCertificate(controllerID)
	if certErr != nil {
		t.Fatalf("GetCertificate: %v", certErr)
	}

	for i := 0; i < 50; i++ {
		sc := buildTestSigmaContext(t, fabric, controllerKey, controllerCert)

		result, err := sc.sigma3(fabric)
		if err != nil {
			t.Fatalf("sigma3 iteration %d: %v", i, err)
		}
		if len(result) == 0 {
			t.Fatalf("sigma3 iteration %d: empty result", i)
		}
	}
}

func buildTestSigmaContext(t *testing.T, fabric *Fabric, controllerKey *ecdsa.PrivateKey, controllerCert *x509.Certificate) sigmaContext {
	t.Helper()

	initiatorPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey initiator: %v", err)
	}
	responderPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey responder: %v", err)
	}

	// Build minimal sigma2 TLV.
	var sigma2tlv mattertlv.TLVBuffer
	sigma2tlv.WriteAnonStruct()
	sigma2tlv.WriteOctetString(1, make([]byte, 32))
	sigma2tlv.WriteUInt(2, mattertlv.TYPE_UINT_2, 333)
	sigma2tlv.WriteOctetString(3, responderPriv.PublicKey().Bytes())
	sigma2tlv.WriteOctetString(4, make([]byte, 100))
	sigma2tlv.WriteStructEnd()

	sigma2decoded, err := mattertlv.Decode(sigma2tlv.Bytes())
	if err != nil {
		t.Fatalf("decode sigma2: %v", err)
	}

	return sigmaContext{
		session_privkey:               initiatorPriv,
		controller_key:                controllerKey,
		controller_matter_certificate: SerializeCertificateIntoMatter(fabric, controllerCert),
		sigma2dec: DecodedGeneric{
			Tlv:     sigma2decoded,
			Payload: sigma2tlv.Bytes(),
		},
		sigma1payload: make([]byte, 64),
		exchange:      1234,
	}
}
