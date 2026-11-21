package dnsfast

import (
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strings"
)

// nsec3HashSHA1 is the only hash algorithm RFC 5155 defines.
const nsec3HashSHA1 = 1

// base32hex is the "extended hex" alphabet of RFC 4648 with no padding,
// which is what NSEC3 owner-name labels use.
var base32hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// NSEC3Record is one parsed NSEC3 rdata.
type NSEC3Record struct {
	// HashAlg is the hash algorithm; only SHA-1 (1) is defined.
	HashAlg uint8
	// Flags carries the opt-out bit (bit 0).
	Flags uint8
	// Iterations is how many extra times the hash is applied.
	Iterations uint16
	// Salt is prepended to every hash.
	Salt []byte

	// NextHashedOwner is the raw hash of the next owner in hash order, i.e.
	NextHashedOwner []byte
	// TypeBitmap is the record's type bitmap, left raw.
	TypeBitmap []byte
}

// OptOut reports whether this record may span unsigned delegations, so a gap
// it covers does not prove every name inside it is absent.
func (n NSEC3Record) OptOut() bool { return n.Flags&0x01 != 0 }

// SupportedHash reports whether subio can reproduce this record's hash.
func (n NSEC3Record) SupportedHash() bool { return n.HashAlg == nsec3HashSHA1 }

// NSEC3 decodes an NSEC3 record's rdata.
func (rr RR) NSEC3() (NSEC3Record, error) {
	if rr.Type != TypeNSEC3 || len(rr.Data) < 5 {
		return NSEC3Record{}, ErrBadRData
	}
	d := rr.Data
	n := NSEC3Record{
		HashAlg:    d[0],
		Flags:      d[1],
		Iterations: binary.BigEndian.Uint16(d[2:4]),
	}
	saltLen := int(d[4])
	off := 5
	if off+saltLen > len(d) {
		return NSEC3Record{}, ErrBadRData
	}
	n.Salt = d[off : off+saltLen]
	off += saltLen
	if off >= len(d) {
		return NSEC3Record{}, ErrBadRData
	}
	hashLen := int(d[off])
	off++
	if hashLen == 0 || off+hashLen > len(d) {

		return NSEC3Record{}, ErrBadRData
	}
	n.NextHashedOwner = d[off : off+hashLen]
	off += hashLen
	n.TypeBitmap = d[off:]
	return n, nil
}

// NSEC3Hash computes the RFC 5155 hash of name under the given salt and
// iteration count.
func NSEC3Hash(name string, salt []byte, iterations uint16) ([]byte, error) {
	wire, err := AppendName(nil, strings.ToLower(name))
	if err != nil {
		return nil, err
	}
	h := sha1.New() //nolint:gosec
	h.Write(wire)
	h.Write(salt)
	digest := h.Sum(nil)
	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(digest)
		h.Write(salt)
		digest = h.Sum(digest[:0])
	}
	return digest, nil
}

// DecodeNSEC3Label decodes a base32hex owner-name label into the raw hash
// bytes.
func DecodeNSEC3Label(label string) ([]byte, error) {
	return base32hex.DecodeString(strings.ToUpper(label))
}

// ForEachAuthority invokes fn for every record in the authority section,
// where a denial-of-existence response carries its NSEC and NSEC3 records.
func ForEachAuthority(msg []byte, fn func(rr RR) error) (Header, error) {
	h, err := ParseHeader(msg)
	if err != nil {
		return h, err
	}
	off, err := skipQuestions(msg, HeaderLen, h.QDCount)
	if err != nil {
		return h, err
	}

	off, err = skipRecords(msg, off, h.ANCount)
	if err != nil {
		return h, err
	}
	for i := uint16(0); i < h.NSCount; i++ {
		var rr RR
		rr.nameOff = off
		if off, err = skipName(msg, off); err != nil {
			return h, err
		}
		if off+10 > len(msg) {
			return h, ErrTruncatedRR
		}
		rr.Type = Type(binary.BigEndian.Uint16(msg[off : off+2]))
		rr.Class = binary.BigEndian.Uint16(msg[off+2 : off+4])
		rr.TTL = binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return h, ErrTruncatedRR
		}
		rr.Data = msg[off : off+rdlen]
		rr.dataOff = off
		off += rdlen
		if err := fn(rr); err != nil {
			return h, err
		}
	}
	return h, nil
}

// skipRecords advances past n resource records without decoding them.
func skipRecords(msg []byte, off int, n uint16) (int, error) {
	for i := uint16(0); i < n; i++ {
		var err error
		if off, err = skipName(msg, off); err != nil {
			return 0, err
		}
		if off+10 > len(msg) {
			return 0, ErrTruncatedRR
		}
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10 + rdlen
		if off > len(msg) {
			return 0, ErrTruncatedRR
		}
	}
	return off, nil
}
