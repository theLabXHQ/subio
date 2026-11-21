// Package dnsfast is a minimal, allocation-conscious DNS wire codec.
package dnsfast

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// Type is a DNS RR type code.
type Type uint16

const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeCAA   Type = 257

	// TypeRRSIG is the DNSSEC signature of RFC 4034.
	TypeRRSIG Type = 46
	// TypeNSEC is the DNSSEC denial record of RFC 4034, whose data begins with
	// the next name in the zone.
	TypeNSEC Type = 47

	// TypeNSEC3 is the hashed denial record of RFC 5155.
	TypeNSEC3 Type = 50
	// TypeNSEC3PARAM is the apex record of RFC 5155 that states the hash
	// algorithm, iterations and salt a zone's NSEC3 records use.
	TypeNSEC3PARAM Type = 51
)

var typeNames = map[Type]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA",
	TypePTR: "PTR", TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA",
	TypeSRV: "SRV", TypeCAA: "CAA", TypeRRSIG: "RRSIG", TypeNSEC: "NSEC", TypeNSEC3: "NSEC3",
}

func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// TypeByName maps a CLI record-type name to its code.
func TypeByName(s string) (Type, bool) {
	for t, n := range typeNames {
		if strings.EqualFold(n, s) {
			return t, true
		}
	}
	return 0, false
}

// ClassINET is the only class subio queries.
const ClassINET uint16 = 1

// RCode is the DNS response code.
type RCode uint8

const (
	RCodeNoError  RCode = 0
	RCodeFormErr  RCode = 1
	RCodeServFail RCode = 2
	RCodeNXDomain RCode = 3
	RCodeNotImp   RCode = 4
	RCodeRefused  RCode = 5
)

var rcodeNames = [...]string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

func (r RCode) String() string {
	if int(r) < len(rcodeNames) {
		return rcodeNames[r]
	}
	return "RCODE" + strconv.Itoa(int(r))
}

// Answered reports whether the resolver gave a usable response.
func (r RCode) Answered() bool { return r == RCodeNoError || r == RCodeNXDomain }

const (
	// HeaderLen is the fixed DNS header size.
	HeaderLen = 12
	// MaxName is the maximum wire length of an encoded name.
	MaxName = 255
	// maxPointerFollows bounds compression-pointer chasing.
	maxPointerFollows = 16
)

var (
	ErrShortMessage  = errors.New("dnsfast: message shorter than header")
	ErrNameTooLong   = errors.New("dnsfast: encoded name exceeds 255 octets")
	ErrLabelTooLong  = errors.New("dnsfast: label exceeds 63 octets")
	ErrEmptyLabel    = errors.New("dnsfast: empty label")
	ErrBadPointer    = errors.New("dnsfast: compression pointer out of range")
	ErrPointerLoop   = errors.New("dnsfast: compression pointer loop")
	ErrTruncatedName = errors.New("dnsfast: name runs past end of message")
	ErrTruncatedRR   = errors.New("dnsfast: resource record runs past end of message")
	ErrBadRData      = errors.New("dnsfast: rdata does not match record type")
)

// AppendName encodes a dotted name into dst in wire form and returns the
// extended slice.
func AppendName(dst []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(dst, 0), nil
	}
	start := len(dst)
	for len(name) > 0 {
		i := strings.IndexByte(name, '.')
		var label string
		if i < 0 {
			label, name = name, ""
		} else {
			label, name = name[:i], name[i+1:]
		}
		if label == "" {
			return nil, ErrEmptyLabel
		}
		if len(label) > 63 {
			return nil, ErrLabelTooLong
		}
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	dst = append(dst, 0)
	if len(dst)-start > MaxName {
		return nil, ErrNameTooLong
	}
	return dst, nil
}

// AppendQuery writes a complete standard query into dst and returns the
// extended slice.
func AppendQuery(dst []byte, id uint16, name string, qtype Type) ([]byte, error) {
	var hdr [HeaderLen]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	dst = append(dst, hdr[:]...)
	var err error
	if dst, err = AppendName(dst, name); err != nil {
		return nil, err
	}
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], uint16(qtype))
	binary.BigEndian.PutUint16(tail[2:4], ClassINET)
	return append(dst, tail[:]...), nil
}

// DefaultEDNSPayload is the UDP payload size subio advertises.
const DefaultEDNSPayload = 1232

// typeOPT is the EDNS0 pseudo-record of RFC 6891.
const typeOPT = 41

// AppendQueryEDNS is AppendQuery with an OPT record advertising payload
// bytes of UDP buffer.
func AppendQueryEDNS(dst []byte, id uint16, name string, qtype Type, payload uint16) ([]byte, error) {
	start := len(dst)
	dst, err := AppendQuery(dst, id, name, qtype)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(dst[start+10:start+12], 1)
	var opt [11]byte
	binary.BigEndian.PutUint16(opt[1:3], typeOPT)
	binary.BigEndian.PutUint16(opt[3:5], payload)
	return append(dst, opt[:]...), nil
}

// AppendQueryDNSSEC is AppendQueryEDNS with the DO bit set, asking the
// resolver to include DNSSEC records.
func AppendQueryDNSSEC(dst []byte, id uint16, name string, qtype Type, payload uint16) ([]byte, error) {
	dst, err := AppendQueryEDNS(dst, id, name, qtype, payload)
	if err != nil {
		return nil, err
	}
	dst[len(dst)-4] = 0x80
	return dst, nil
}

// Header is a parsed DNS header.
type Header struct {
	ID                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	RCode              RCode
	QDCount            uint16
	ANCount            uint16
	NSCount            uint16
	ARCount            uint16
}

// ParseHeader reads the fixed header.
func ParseHeader(msg []byte) (Header, error) {
	if len(msg) < HeaderLen {
		return Header{}, ErrShortMessage
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	return Header{
		ID:                 binary.BigEndian.Uint16(msg[0:2]),
		Response:           flags&0x8000 != 0,
		Opcode:             uint8(flags >> 11 & 0xF),
		Authoritative:      flags&0x0400 != 0,
		Truncated:          flags&0x0200 != 0,
		RecursionDesired:   flags&0x0100 != 0,
		RecursionAvailable: flags&0x0080 != 0,
		RCode:              RCode(flags & 0xF),
		QDCount:            binary.BigEndian.Uint16(msg[4:6]),
		ANCount:            binary.BigEndian.Uint16(msg[6:8]),
		NSCount:            binary.BigEndian.Uint16(msg[8:10]),
		ARCount:            binary.BigEndian.Uint16(msg[10:12]),
	}, nil
}

// skipName advances past a name at off, following no pointers.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, ErrTruncatedName
		}
		n := int(msg[off])
		switch {
		case n == 0:
			return off + 1, nil
		case n&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, ErrTruncatedName
			}
			return off + 2, nil
		case n&0xC0 != 0:
			return 0, ErrBadPointer
		default:
			if n > 63 {
				return 0, ErrLabelTooLong
			}
			off += 1 + n
		}
	}
}

// appendDecodedName writes the dotted, lowercase form of the name at off
// into dst, following compression pointers under a hard bound.
func appendDecodedName(dst []byte, msg []byte, off int) ([]byte, int, error) {
	end := -1
	follows := 0
	total := 0
	first := true
	for {
		if off >= len(msg) {
			return nil, 0, ErrTruncatedName
		}
		n := int(msg[off])
		switch {
		case n == 0:
			if end < 0 {
				end = off + 1
			}
			if first {
				dst = append(dst, '.')
			}
			return dst, end, nil
		case n&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return nil, 0, ErrTruncatedName
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			if end < 0 {
				end = off + 2
			}
			follows++
			if follows > maxPointerFollows {
				return nil, 0, ErrPointerLoop
			}
			if ptr >= len(msg) || ptr >= off {

				return nil, 0, ErrBadPointer
			}
			off = ptr
		case n&0xC0 != 0:
			return nil, 0, ErrBadPointer
		default:
			if n > 63 {
				return nil, 0, ErrLabelTooLong
			}
			if off+1+n > len(msg) {
				return nil, 0, ErrTruncatedName
			}
			total += n + 1
			if total > MaxName {
				return nil, 0, ErrNameTooLong
			}
			for _, c := range msg[off+1 : off+1+n] {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				dst = append(dst, c)
			}
			dst = append(dst, '.')
			off += 1 + n
			first = false
		}
	}
}

// Name decodes the name at off into a string.
func Name(msg []byte, off int) (string, int, error) {
	buf, next, err := appendDecodedName(make([]byte, 0, 64), msg, off)
	if err != nil {
		return "", 0, err
	}
	return string(buf), next, nil
}

// Question is the parsed question section entry.
type Question struct {
	Name  string
	Type  Type
	Class uint16
}

// RR is a resource record.
type RR struct {
	Type  Type
	Class uint16
	TTL   uint32
	Data  []byte
	// nameOff is the offset of the owner name within the message.
	nameOff int
	// dataOff is the offset of Data within the message, needed to decode
	// compressed names inside rdata (CNAME, NS, MX, SRV, SOA).
	dataOff int
}

// NameString decodes the record's owner name, allocating one string.
func (rr RR) NameString(msg []byte) (string, error) {
	name, _, err := Name(msg, rr.nameOff)
	return name, err
}

// skipQuestions advances past the question section.
func skipQuestions(msg []byte, off int, n uint16) (int, error) {
	for i := uint16(0); i < n; i++ {
		var err error
		if off, err = skipName(msg, off); err != nil {
			return 0, err
		}
		if off+4 > len(msg) {
			return 0, ErrTruncatedRR
		}
		off += 4
	}
	return off, nil
}

// QuestionName decodes the first question's name, type and class.
func QuestionName(msg []byte) (Question, error) {
	h, err := ParseHeader(msg)
	if err != nil {
		return Question{}, err
	}
	if h.QDCount == 0 {
		return Question{}, ErrShortMessage
	}
	name, off, err := Name(msg, HeaderLen)
	if err != nil {
		return Question{}, err
	}
	if off+4 > len(msg) {
		return Question{}, ErrTruncatedRR
	}
	return Question{
		Name:  name,
		Type:  Type(binary.BigEndian.Uint16(msg[off : off+2])),
		Class: binary.BigEndian.Uint16(msg[off+2 : off+4]),
	}, nil
}

// ForEachAnswer parses the header, skips the question section, and invokes
// fn for every answer record.
func ForEachAnswer(msg []byte, fn func(rr RR) error) (Header, error) {
	h, err := ParseHeader(msg)
	if err != nil {
		return h, err
	}
	off, err := skipQuestions(msg, HeaderLen, h.QDCount)
	if err != nil {
		return h, err
	}
	for i := uint16(0); i < h.ANCount; i++ {
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

// Addr decodes an A or AAAA record.
func (rr RR) Addr() (netip.Addr, error) {
	switch rr.Type {
	case TypeA:
		if len(rr.Data) != 4 {
			return netip.Addr{}, ErrBadRData
		}
		return netip.AddrFrom4([4]byte(rr.Data)), nil
	case TypeAAAA:
		if len(rr.Data) != 16 {
			return netip.Addr{}, ErrBadRData
		}
		return netip.AddrFrom16([16]byte(rr.Data)), nil
	}
	return netip.Addr{}, ErrBadRData
}

// Target decodes the name carried by a CNAME, NS or PTR record.
func (rr RR) Target(msg []byte) (string, error) {
	switch rr.Type {
	case TypeCNAME, TypeNS, TypePTR:
		name, _, err := Name(msg, rr.dataOff)
		return name, err
	}
	return "", ErrBadRData
}

// MX decodes a mail exchange record.
func (rr RR) NSECNext(msg []byte) (string, error) {
	if rr.Type != TypeNSEC {
		return "", ErrBadRData
	}
	name, _, err := Name(msg, rr.dataOff)
	return name, err
}

func (rr RR) MX(msg []byte) (pref uint16, host string, err error) {
	if rr.Type != TypeMX || len(rr.Data) < 3 {
		return 0, "", ErrBadRData
	}
	pref = binary.BigEndian.Uint16(rr.Data[0:2])
	host, _, err = Name(msg, rr.dataOff+2)
	return pref, host, err
}

// SRV decodes a service record.
func (rr RR) SRV(msg []byte) (priority, weight, port uint16, target string, err error) {
	if rr.Type != TypeSRV || len(rr.Data) < 7 {
		return 0, 0, 0, "", ErrBadRData
	}
	priority = binary.BigEndian.Uint16(rr.Data[0:2])
	weight = binary.BigEndian.Uint16(rr.Data[2:4])
	port = binary.BigEndian.Uint16(rr.Data[4:6])
	target, _, err = Name(msg, rr.dataOff+6)
	return priority, weight, port, target, err
}

// TXT decodes the character strings of a TXT record.
func (rr RR) TXT() ([]string, error) {
	if rr.Type != TypeTXT {
		return nil, ErrBadRData
	}
	var out []string
	for i := 0; i < len(rr.Data); {
		n := int(rr.Data[i])
		if i+1+n > len(rr.Data) {
			return nil, ErrBadRData
		}
		out = append(out, string(rr.Data[i+1:i+1+n]))
		i += 1 + n
	}
	return out, nil
}

// SOARecord is the parsed start-of-authority rdata.
type SOARecord struct {
	NS      string
	Mbox    string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	MinTTL  uint32
}

// SOA decodes a start-of-authority record.
func (rr RR) SOA(msg []byte) (SOARecord, error) {
	var s SOARecord
	if rr.Type != TypeSOA {
		return s, ErrBadRData
	}
	var err error
	off := rr.dataOff
	if s.NS, off, err = Name(msg, off); err != nil {
		return s, err
	}
	if s.Mbox, off, err = Name(msg, off); err != nil {
		return s, err
	}
	if off+20 > len(msg) {
		return s, ErrBadRData
	}
	s.Serial = binary.BigEndian.Uint32(msg[off : off+4])
	s.Refresh = binary.BigEndian.Uint32(msg[off+4 : off+8])
	s.Retry = binary.BigEndian.Uint32(msg[off+8 : off+12])
	s.Expire = binary.BigEndian.Uint32(msg[off+12 : off+16])
	s.MinTTL = binary.BigEndian.Uint32(msg[off+16 : off+20])
	return s, nil
}

// CAARecord is the parsed certification-authority-authorization rdata.
type CAARecord struct {
	Flag  uint8
	Tag   string
	Value string
}

// CAA decodes a CAA record.
func RRSIGLabels(rr RR) (uint8, bool) {
	if rr.Type != TypeRRSIG || len(rr.Data) < 4 {
		return 0, false
	}
	return rr.Data[3], true
}

// RRSIGCovers reports the record type an RRSIG signs, so a signature over a
// different type in the same answer is not read as proof about this one.
func RRSIGCovers(rr RR) (Type, bool) {
	if rr.Type != TypeRRSIG || len(rr.Data) < 2 {
		return 0, false
	}
	return Type(binary.BigEndian.Uint16(rr.Data[0:2])), true
}

func (rr RR) CAA() (CAARecord, error) {
	var c CAARecord
	if rr.Type != TypeCAA || len(rr.Data) < 2 {
		return c, ErrBadRData
	}
	c.Flag = rr.Data[0]
	n := int(rr.Data[1])
	if 2+n > len(rr.Data) {
		return c, ErrBadRData
	}
	c.Tag = string(rr.Data[2 : 2+n])
	c.Value = string(rr.Data[2+n:])
	return c, nil
}
