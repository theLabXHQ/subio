package dnsfast

import (
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

// optionEDE is the EDNS option code for Extended DNS Errors, RFC 8914.
const optionEDE = 15

// maxEDETextBytes bounds the free-text half of an EDE.
const maxEDETextBytes = 256

// ExtendedError is one Extended DNS Error from a response, RFC 8914 section
// 2.
type ExtendedError struct {

	// Code is the INFO-CODE.
	Code uint16

	// Text is the EXTRA-TEXT, sanitised and possibly truncated.
	Text string
	// Present reports that an EDE option was actually found.
	Present bool
}

// edeNames are the INFO-CODEs registered with IANA at the time of writing.
var edeNames = map[uint16]string{
	0: "other", 1: "unsupported dnskey algorithm", 2: "unsupported ds digest type",
	3: "stale answer", 4: "forged answer", 5: "dnssec indeterminate",
	6: "dnssec bogus", 7: "signature expired", 8: "signature not yet valid",
	9: "dnskey missing", 10: "rrsigs missing", 11: "no zone key bit set",
	12: "nsec missing", 13: "cached error", 14: "not ready", 15: "blocked",
	16: "censored", 17: "filtered", 18: "prohibited", 19: "stale nxdomain answer",
	20: "not authoritative", 21: "not supported", 22: "no reachable authority",
	23: "network error", 24: "invalid data", 25: "signature expired before valid",
	26: "too early", 27: "unsupported nsec3 iterations",
	28: "unable to conform to policy", 29: "synthesized", 30: "invalid query type",
}

// Name is the registered meaning of the code, or an empty string when the
// code is not one this build knows.
func (e ExtendedError) Name() string { return edeNames[e.Code] }

// String renders an EDE for a person reading a run.
func (e ExtendedError) String() string {
	if !e.Present {
		return ""
	}
	name := e.Name()
	switch {
	case name != "" && e.Text != "":
		return name + ": " + e.Text
	case name != "":
		return name
	case e.Text != "":
		return "ede " + itoa16(e.Code) + ": " + e.Text
	}
	return "ede " + itoa16(e.Code)
}

func itoa16(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// ReadExtendedError returns the first Extended DNS Error in a response.
func ReadExtendedError(msg []byte) ExtendedError {
	var out ExtendedError
	_ = forEachOPTOption(msg, func(code uint16, data []byte) bool {
		if code != optionEDE || len(data) < 2 {
			return true
		}
		out.Code = binary.BigEndian.Uint16(data[:2])
		out.Text = sanitiseEDEText(data[2:])
		out.Present = true
		return false
	})
	return out
}

// sanitiseEDEText makes resolver-supplied text safe to print.
func sanitiseEDEText(raw []byte) string {
	if len(raw) > maxEDETextBytes {
		raw = raw[:maxEDETextBytes]
	}
	var b strings.Builder
	b.Grow(len(raw))
	for len(raw) > 0 {
		r, size := utf8.DecodeRune(raw)
		raw = raw[size:]
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteRune('�')
		case r == '\t' || r == ' ':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:

		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// HasOPT reports whether the message carries an OPT record, which is how a
// server shows it understood EDNS at all (RFC 6891).
func HasOPT(msg []byte) bool {
	h, err := ParseHeader(msg)
	if err != nil {
		return false
	}
	off, err := skipQuestions(msg, HeaderLen, h.QDCount)
	if err != nil {
		return false
	}
	if off, err = skipRecords(msg, off, h.ANCount); err != nil {
		return false
	}
	if off, err = skipRecords(msg, off, h.NSCount); err != nil {
		return false
	}
	for i := uint16(0); i < h.ARCount; i++ {
		nameOff := off
		if off, err = skipName(msg, off); err != nil || off+10 > len(msg) {
			return false
		}
		if Type(binary.BigEndian.Uint16(msg[off:off+2])) == typeOPT && msg[nameOff] == 0 {
			return true
		}
		off += 10 + int(binary.BigEndian.Uint16(msg[off+8:off+10]))
	}
	return false
}

// forEachOPTOption walks the options of the first OPT record in the
// additional section, stopping early when fn returns false.
func forEachOPTOption(msg []byte, fn func(code uint16, data []byte) bool) error {
	h, err := ParseHeader(msg)
	if err != nil {
		return err
	}
	off, err := skipQuestions(msg, HeaderLen, h.QDCount)
	if err != nil {
		return err
	}
	if off, err = skipRecords(msg, off, h.ANCount); err != nil {
		return err
	}
	if off, err = skipRecords(msg, off, h.NSCount); err != nil {
		return err
	}
	for i := uint16(0); i < h.ARCount; i++ {
		nameOff := off
		if off, err = skipName(msg, off); err != nil {
			return err
		}
		if off+10 > len(msg) {
			return ErrTruncatedRR
		}
		typ := Type(binary.BigEndian.Uint16(msg[off : off+2]))
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return ErrTruncatedRR
		}

		if typ == typeOPT && nameOff < len(msg) && msg[nameOff] == 0 {
			rd := msg[off : off+rdlen]
			for len(rd) >= 4 {
				code := binary.BigEndian.Uint16(rd[:2])
				olen := int(binary.BigEndian.Uint16(rd[2:4]))
				rd = rd[4:]
				if olen > len(rd) {
					return ErrTruncatedRR
				}
				if !fn(code, rd[:olen]) {
					return nil
				}
				rd = rd[olen:]
			}
			return nil
		}
		off += rdlen
	}
	return nil
}

// QuestionNameExact returns the question's name with its case as it arrived.
func QuestionNameExact(msg []byte) (string, error) {
	h, err := ParseHeader(msg)
	if err != nil {
		return "", err
	}
	if h.QDCount == 0 {
		return "", ErrShortMessage
	}
	off := HeaderLen
	var out []byte
	for {
		if off >= len(msg) {
			return "", ErrTruncatedName
		}
		n := int(msg[off])
		if n == 0 {
			if len(out) == 0 {
				return ".", nil
			}
			return string(out), nil
		}
		if n&0xC0 != 0 {
			return "", ErrBadPointer
		}
		if n > 63 {
			return "", ErrLabelTooLong
		}
		if off+1+n > len(msg) {
			return "", ErrTruncatedName
		}
		if len(out)+n+1 > MaxName {
			return "", ErrNameTooLong
		}
		out = append(out, msg[off+1:off+1+n]...)
		out = append(out, '.')
		off += 1 + n
	}
}
