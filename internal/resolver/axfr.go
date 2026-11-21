package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/dnsfast"
)

// typeAXFR is the zone transfer query type of RFC 5936.
const typeAXFR dnsfast.Type = 252

// maxTransferNames bounds what one transfer can make subio hold.
const maxTransferNames = 2_000_000

// Transfer asks a nameserver for the whole zone over TCP and returns the
// owner names in it.
func (r *Resolver) Transfer(ctx context.Context, zone, nameserver string) ([]string, error) {
	addrs := r.ResolveAll(ctx, []string{nameserver}, []dnsfast.Type{dnsfast.TypeA})
	var target string
	for _, a := range addrs {
		for _, rr := range a.Records {
			if rr.Type == "A" {
				target = rr.Value
			}
		}
	}
	if target == "" {
		return nil, errors.New("resolver: nameserver has no address")
	}
	return r.transferFrom(ctx, zone, net.JoinHostPort(target, "53"))
}

func (r *Resolver) transferFrom(ctx context.Context, zone, addr string) ([]string, error) {
	d := net.Dialer{Timeout: r.cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	const id = 0x5ab1
	query, err := dnsfast.AppendQuery(nil, id, zone, typeAXFR)
	if err != nil {
		return nil, err
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	seen := map[string]bool{}
	var names []string
	soas := 0
	for soas < 2 && len(names) < maxTransferNames {
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return names, err
		}
		msg := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return names, err
		}
		h, err := dnsfast.ParseHeader(msg)
		if err != nil {
			return names, err
		}
		if !h.Response || h.ID != id {
			return names, errors.New("resolver: transfer answer does not match the query")
		}
		if h.RCode != dnsfast.RCodeNoError {
			return names, errors.New("resolver: transfer refused: " + h.RCode.String())
		}
		if h.ANCount == 0 {
			return names, errors.New("resolver: transfer returned no records")
		}

		_, err = dnsfast.ForEachAnswer(msg, func(rr dnsfast.RR) error {
			if rr.Type == dnsfast.TypeSOA {
				soas++
			}
			owner, err := rr.NameString(msg)
			if err != nil {
				return err
			}
			owner = strings.TrimSuffix(strings.ToLower(owner), ".")

			if owner != zone && !strings.HasSuffix(owner, "."+zone) {
				return nil
			}
			if !seen[owner] {
				seen[owner] = true
				names = append(names, owner)
			}
			return nil
		})
		if err != nil {
			return names, err
		}
	}
	return names, nil
}
