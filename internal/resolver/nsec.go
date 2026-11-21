package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/dnsfast"
)

// WalkNSEC follows a signed zone's NSEC chain from its apex: each record
// names the next name in the zone, so the chain lists all of them.
func (r *Resolver) WalkNSEC(ctx context.Context, zone string, limit int) ([]string, error) {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	conn, err := net.Dial("udp", r.server().text)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	seen := map[string]bool{zone: true}
	var names []string
	cur := zone
	for len(names) < limit {
		if err := ctx.Err(); err != nil {
			return names, err
		}
		if r.lim != nil {
			if err := r.lim.Wait(ctx); err != nil {
				return names, err
			}
		}
		next, err := r.nsecNext(conn, buf, cur)
		if err != nil {
			return names, err
		}
		next = strings.TrimSuffix(strings.ToLower(next), ".")
		if next == "" || next == zone || seen[next] || !strings.HasSuffix(next, "."+zone) {
			return names, nil
		}
		seen[next] = true
		names = append(names, next)
		cur = next
	}
	return names, nil
}

func (r *Resolver) nsecNext(conn net.Conn, buf []byte, name string) (string, error) {
	id := uint16(time.Now().UnixNano())
	query, err := dnsfast.AppendQueryDNSSEC(nil, id, name, dnsfast.TypeNSEC, dnsfast.DefaultEDNSPayload)
	if err != nil {
		return "", err
	}
	_ = conn.SetDeadline(time.Now().Add(r.cfg.Timeout))
	if _, err := conn.Write(query); err != nil {
		return "", err
	}
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	msg := buf[:n]
	h, err := dnsfast.ParseHeader(msg)
	if err != nil {
		return "", err
	}
	if !h.Response || h.ID != id {
		return "", errors.New("resolver: NSEC answer does not match the query")
	}
	var next string
	_, err = dnsfast.ForEachAnswer(msg, func(rr dnsfast.RR) error {
		if rr.Type != dnsfast.TypeNSEC || next != "" {
			return nil
		}
		var err error
		next, err = rr.NSECNext(msg)
		return err
	})
	return next, err
}
