package ct

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Log entry types from RFC 6962 §3.1.
const (
	entryTypeX509    = 0
	entryTypePrecert = 1
)

// entriesPerRequest is how many entries one get-entries request asks for.
const entriesPerRequest = 64

// sthDoc is the part of a signed tree head subio reads.
type sthDoc struct {
	TreeSize *int64 `json:"tree_size"`
}

// entriesDoc is a get-entries response.
type entriesDoc struct {
	Entries []struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	} `json:"entries"`
}

// leafCert is one log entry reduced to the certificate subio will read names
// from, plus the log's own timestamp for it.
type leafCert struct {
	Timestamp int64
	EntryType int
	// DER is a parseable certificate.
	DER []byte

	// Reconstructed records that DER was built around the TBSCertificate from
	// the leaf, because the entry's extra_data was missing or unreadable.
	Reconstructed bool
}

// CurrentSizeRFC6962 reads a log's signed tree head and returns its tree size.
func CurrentSizeRFC6962(ctx context.Context, f Fetcher, base string) (int64, error) {
	var doc sthDoc
	if err := f.GetJSON(ctx, strings.TrimSuffix(base, "/")+"/ct/v1/get-sth", &doc); err != nil {
		return 0, fmt.Errorf("ct: reading signed tree head: %w", err)
	}
	if doc.TreeSize == nil || *doc.TreeSize < 0 {
		return 0, errors.New("ct: signed tree head stated no usable tree size")
	}
	return *doc.TreeSize, nil
}

// TailRFC6962 reads an RFC 6962 log's entries from the recorded size up to
// its current size, keeps the in-scope names, and returns the new size to
// record.
func TailRFC6962(ctx context.Context, f Fetcher, scope Scope, cfg Config) (*Result, error) {
	base := strings.TrimSuffix(cfg.Base, "/")
	size, err := CurrentSizeRFC6962(ctx, f, base)
	if err != nil {
		return nil, err
	}
	res := &Result{FromSize: cfg.From, ToSize: size}
	if size <= cfg.From {
		return res, nil
	}

	at := cfg.From
	res.ToSize = at
	for at < size {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if cfg.MaxReads > 0 && int64(res.Reads) >= cfg.MaxReads {

			break
		}
		end := at + entriesPerRequest - 1
		if end > size-1 {
			end = size - 1
		}
		url := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", base, at, end)
		var doc entriesDoc
		rerr := f.GetJSON(ctx, url, &doc)
		res.Reads++
		if rerr != nil {
			return res, fmt.Errorf("ct: reading entries %d-%d: %w", at, end, rerr)
		}
		if len(doc.Entries) == 0 {

			return res, fmt.Errorf("ct: the log returned no entry for %d-%d, inside the tree size %d it reported", at, end, size)
		}
		for i := range doc.Entries {
			e := doc.Entries[i]
			index := at + int64(i)
			res.Entries++
			lc, perr := parseLeafEntry(e.LeafInput, e.ExtraData)
			if perr != nil {
				res.Unreadable++
				continue
			}
			cert, cerr := x509.ParseCertificate(lc.DER)
			if cerr != nil {

				res.Unreadable++
				continue
			}
			res.addNames(cert.DNSNames, cert.Subject.CommonName, index, lc.Timestamp, scope)
		}
		at += int64(len(doc.Entries))
		res.ToSize = at
	}
	return res, nil
}

// parseLeafEntry decodes one get-entries element into a parseable certificate.
func parseLeafEntry(leafB64, extraB64 string) (leafCert, error) {
	leaf, err := base64.StdEncoding.DecodeString(strings.TrimSpace(leafB64))
	if err != nil {
		return leafCert{}, fmt.Errorf("ct: leaf_input is not base64: %w", err)
	}
	r := &byteReader{b: leaf}
	version := r.u8()
	leafType := r.u8()
	if r.err != nil {
		return leafCert{}, r.err
	}
	if version != 0 {
		return leafCert{}, fmt.Errorf("ct: MerkleTreeLeaf version %d is not v1", version)
	}
	if leafType != 0 {
		return leafCert{}, fmt.Errorf("ct: leaf type %d is not a timestamped entry", leafType)
	}
	out := leafCert{Timestamp: int64(r.u64())}
	entryType := int(r.u16())
	out.EntryType = entryType
	switch entryType {
	case entryTypeX509:
		out.DER = r.vector(3)
	case entryTypePrecert:
		r.skip(32)
		tbs := r.vector(3)
		if r.err != nil {
			return leafCert{}, r.err
		}

		if der, derr := precertFromExtraData(extraB64); derr == nil {
			out.DER = der
			break
		}

		der, werr := wrapTBSCertificate(tbs)
		if werr != nil {
			return leafCert{}, werr
		}
		out.DER, out.Reconstructed = der, true
	default:
		return leafCert{}, fmt.Errorf("ct: entry type %d is neither an x509 nor a precert entry", entryType)
	}
	if r.err != nil {
		return leafCert{}, r.err
	}
	if len(out.DER) == 0 {
		return leafCert{}, errors.New("ct: entry carried no certificate")
	}
	return out, nil
}

// precertFromExtraData reads the pre_certificate at the front of a
// PrecertChainEntry.
func precertFromExtraData(extraB64 string) ([]byte, error) {
	extra, err := base64.StdEncoding.DecodeString(strings.TrimSpace(extraB64))
	if err != nil {
		return nil, fmt.Errorf("ct: extra_data is not base64: %w", err)
	}
	r := &byteReader{b: extra}
	der := r.vector(3)
	if r.err != nil {
		return nil, r.err
	}
	if len(der) == 0 {
		return nil, errors.New("ct: extra_data held no precertificate")
	}
	return der, nil
}

// wrapTBSCertificate builds `SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING
// }` around a TBSCertificate, which is the shape crypto/x509 expects.
func wrapTBSCertificate(tbs []byte) ([]byte, error) {
	if len(tbs) == 0 {
		return nil, errors.New("ct: precert entry carried an empty TBSCertificate")
	}
	alg, err := tbsSignatureAlgorithm(tbs)
	if err != nil {
		return nil, err
	}
	sig, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0}, BitLength: 1})
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, len(tbs)+len(alg)+len(sig))
	body = append(body, tbs...)
	body = append(body, alg...)
	body = append(body, sig...)
	return append(derSequenceHeader(len(body)), body...), nil
}

// tbsSignatureAlgorithm returns the AlgorithmIdentifier element of a
// TBSCertificate, verbatim and still DER-encoded.
func tbsSignatureAlgorithm(tbs []byte) ([]byte, error) {
	tag, body, _, err := derElement(tbs)
	if err != nil {
		return nil, err
	}
	if tag != 0x30 {
		return nil, fmt.Errorf("ct: a TBSCertificate must be a SEQUENCE, got tag 0x%02x", tag)
	}
	rest := body

	if t, _, after, err := derElement(rest); err == nil && t == 0xa0 {
		rest = after
	}

	if _, _, after, err := derElement(rest); err == nil {
		rest = after
	} else {
		return nil, err
	}
	t, _, after, err := derElement(rest)
	if err != nil {
		return nil, err
	}
	if t != 0x30 {
		return nil, fmt.Errorf("ct: the TBSCertificate's signature field is tag 0x%02x, not a SEQUENCE", t)
	}
	return rest[:len(rest)-len(after)], nil
}

// derElement reads one DER tag-length-value and returns the tag, the
// contents, and whatever follows.
func derElement(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("ct: DER element is truncated")
	}
	tag = b[0]
	n := int(b[1])
	off := 2
	if n&0x80 != 0 {
		count := n & 0x7f
		if count == 0 || count > 4 {
			return 0, nil, nil, fmt.Errorf("ct: DER length form 0x%02x is not usable", b[1])
		}
		if len(b) < off+count {
			return 0, nil, nil, errors.New("ct: DER length is truncated")
		}
		n = 0
		for _, c := range b[off : off+count] {
			n = n<<8 | int(c)
		}
		off += count
	}
	if n < 0 || len(b) < off+n {
		return 0, nil, nil, errors.New("ct: DER element runs past the end")
	}
	return tag, b[off : off+n], b[off+n:], nil
}

// derSequenceHeader writes a SEQUENCE tag with a definite length.
func derSequenceHeader(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{0x30, byte(n)}
	case n < 1<<8:
		return []byte{0x30, 0x81, byte(n)}
	case n < 1<<16:
		return []byte{0x30, 0x82, byte(n >> 8), byte(n)}
	case n < 1<<24:
		return []byte{0x30, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{0x30, 0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// byteReader reads the big-endian fixed widths and length-prefixed vectors
// of the TLS presentation language.
type byteReader struct {
	b   []byte
	err error
}

func (r *byteReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || len(r.b) < n {
		r.err = fmt.Errorf("ct: structure is truncated: wanted %d more byte(s), %d left", n, len(r.b))
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *byteReader) skip(n int) { r.take(n) }

func (r *byteReader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *byteReader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

func (r *byteReader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// vector reads an opaque vector whose length is held in lenBytes big-endian
// bytes.
func (r *byteReader) vector(lenBytes int) []byte {
	b := r.take(lenBytes)
	if b == nil {
		return nil
	}
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return r.take(n)
}
