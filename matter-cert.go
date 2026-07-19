package gomat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"

	"github.com/tom-code/gomat/mattertlv"
)

type dsaSignature struct {
	R, S *big.Int
}

// derIntegerContent returns the DER content octets of a non-negative ASN.1
// INTEGER: big-endian magnitude with a leading 0x00 byte prepended when the
// high bit of the first byte would otherwise mark the value as negative. The
// value zero is encoded as a single 0x00 byte. This matches the serial number
// bytes that Go's crypto/x509 signs over, so a device reconstructing the TBS
// DER from the Matter TLV recomputes an identical signature input.
func derIntegerContent(i *big.Int) []byte {
	b := i.Bytes()
	if len(b) == 0 {
		return []byte{0x00}
	}
	if b[0]&0x80 != 0 {
		return append([]byte{0x00}, b...)
	}
	return b
}

func caConvertDNValue(in any) uint64 {
	dn_str, ok := in.(string)
	if !ok {
		return 0
	}

	dn_uint64, err := strconv.ParseUint(dn_str, 16, 64)
	if err != nil {
		return 0
	}
	return dn_uint64
}

func caConvertDN(in pkix.Name, out *mattertlv.TLVBuffer) {
	for _, extra := range in.Names {
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}) { //node-id
			out.WriteUInt64(17, caConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}) { //matter-rcac-id
			out.WriteUInt64(20, caConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}) { //matter-fabric-id
			out.WriteUInt64(21, caConvertDNValue(extra.Value))
		}
	}
}

// SerializeCertificateIntoMatter serializes x509 certificate into matter certificate format.
// Matter certificate format is way how to make matter even more weird and complicated.
// Signature of matter vertificate must match signature of  certificate reencoded to DER encoding.
// This requires to handle very carefully order and presence of all elements in original x509.
func SerializeCertificateIntoMatter(fabric *Fabric, in *x509.Certificate) []byte {
	pub := in.PublicKey.(*ecdsa.PublicKey)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)

	cacert := fabric.CertificateManager.GetCaCertificate()
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)
	sha1_stream := sha1.New()
	sha1_stream.Write(capublic_key)
	ca_pubkey_hash := sha1_stream.Sum(nil)

	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	// The Matter serial-num field must carry the DER INTEGER *content octets*,
	// which include a leading 0x00 sign byte when the top bit of the first
	// magnitude byte is set. big.Int.Bytes() strips that sign byte, so for ~50%
	// of random serials the device (which reconstructs the TBS DER by wrapping
	// these bytes verbatim as an INTEGER) would compute a different TBS than the
	// one Go signed, failing signature verification with AddNOC status 3
	// (InvalidNOC).
	tlv.WriteOctetString(1, derIntegerContent(in.SerialNumber)) // serial number
	tlv.WriteUInt8(2, 1)                             // signature algorithm

	tlv.WriteList(3) // issuer
	caConvertDN(in.Issuer, &tlv)
	tlv.WriteStructEnd()

	tlv.WriteUInt32(4, uint32(in.NotBefore.Unix()-946684800))
	tlv.WriteUInt32(5, uint32(in.NotAfter.Unix())-946684800)
	tlv.WriteList(6) // subject
	caConvertDN(in.Subject, &tlv)
	tlv.WriteStructEnd()
	tlv.WriteUInt8(7, 1)
	tlv.WriteUInt8(8, 1)
	//public key:
	tlv.WriteOctetString(9, public_key)
	tlv.WriteList(10)
	tlv.WriteStruct(1)
	tlv.WriteBool(1, in.IsCA) // isCA
	tlv.WriteStructEnd()

	tlv.WriteUInt(2, mattertlv.TYPE_UINT_1, uint64(in.KeyUsage)) // key-usage

	if len(in.ExtKeyUsage) > 0 {
		tlv.WriteArray(3)
		tlv.WriteRaw([]byte{0x04, 0x02, 0x04, 0x01}) // extended key-usage
		tlv.WriteStructEnd()
	}

	tlv.WriteOctetString(4, in.SubjectKeyId) // subject-key-id
	tlv.WriteOctetString(5, ca_pubkey_hash)  // authority-key-id
	tlv.WriteStructEnd()

	var signature dsaSignature
	asn1.Unmarshal(in.Signature, &signature)

	// P-256 R and S must each be exactly 32 bytes, zero-padded on the left.
	// big.Int.Bytes() returns minimal representation without leading zeros.
	r := make([]byte, 32)
	s := make([]byte, 32)
	rBytes := signature.R.Bytes()
	sBytes := signature.S.Bytes()
	copy(r[32-len(rBytes):], rBytes)
	copy(s[32-len(sBytes):], sBytes)
	s4 := append(r, s...)
	tlv.WriteOctetString(11, s4)
	tlv.WriteStructEnd()
	return tlv.Bytes()
}
