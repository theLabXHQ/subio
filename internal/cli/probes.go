package cli

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/sched"
)

const (
	// maxNSECNames bounds one zone walk.
	maxNSECNames = 1_000_000
	// tlsConcurrency and tlsPerSecond keep certificate reads gentle: this
	// touches the target's own servers rather than its nameservers.
	tlsConcurrency = 16
	tlsPerSecond   = 20
	tlsTimeout     = 4 * time.Second
)

// walkNSEC asks each root's NSEC chain for the names in the zone.
func (d *dnsStage) walkNSEC(ctx context.Context) {
	var found []string
	for _, root := range d.o.RootList {
		names, err := d.res.WalkNSEC(ctx, root, maxNSECNames)
		d.records.queries += len(names) + 1
		if err != nil {
			d.log.Logf("verbose", "nsec walk of %s stopped: %v", root, err)
		}
		for _, n := range names {
			a := resolver.Answer{Name: root, Records: []resolver.Record{{Type: "NSEC", Value: n}}}
			found = append(found, d.harvest(a)...)
		}

		if len(names) == 0 {
			if chain := d.nsec3Walk(ctx, root); chain != nil {
				d.nsec3Surface(ctx, root, chain)
			}
		}
	}
	d.followRecords(ctx, found)
}

// reverse reads PTR records for every address found.
func (d *dnsStage) reverse(ctx context.Context) {
	seen := map[string]bool{}
	var jobs []resolver.Job
	for _, f := range d.led.Findings() {
		if f.WildcardSuspected {
			continue
		}
		for _, addr := range d.addressesOf(f.RootDomain, f.FQDN) {
			if name := reverseName(addr); name != "" && !seen[name] {
				seen[name] = true
				jobs = append(jobs, resolver.Job{Name: name, Type: dnsfast.TypePTR})
			}
		}
	}
	d.records.queries += len(jobs)
	var found []string
	for _, a := range d.res.ResolveJobs(ctx, jobs) {
		switch a.Outcome {
		case resolver.Resolved:
			found = append(found, d.harvest(a)...)
		case resolver.NXDomain, resolver.NoData:
		default:
			d.records.errors++
		}
	}
	d.followRecords(ctx, found)
}

func (d *dnsStage) addressesOf(root, name string) []netip.Addr {
	var out []netip.Addr
	for _, obs := range d.led.DNSFor(root, name) {
		for _, r := range obs.Records {
			if r.Type == "A" || r.Type == "AAAA" {
				if a, err := netip.ParseAddr(r.Value); err == nil {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

// reverseName is the in-addr.arpa or ip6.arpa name of an address.
func reverseName(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
			strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) + ".in-addr.arpa"
	}
	if !a.Is6() {
		return ""
	}
	const hex = "0123456789abcdef"
	b := a.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	sb.WriteString("ip6.arpa")
	return sb.String()
}

// grabCertificates reads the certificate each found host serves on port 443
// and keeps the in-scope names on it.
func (d *dnsStage) grabCertificates(ctx context.Context) {
	type target struct{ name, addr string }
	var targets []target
	for _, f := range d.led.Findings() {
		if f.WildcardSuspected {
			continue
		}
		addrs := d.addressesOf(f.RootDomain, f.FQDN)
		if len(addrs) > 0 {
			targets = append(targets, target{f.FQDN, addrs[0].String()})
		}
	}

	lim := sched.NewLimiter(tlsPerSecond, time.Second, tlsConcurrency, nil)
	sem := make(chan struct{}, tlsConcurrency)
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		found []string
	)
	for _, t := range targets {
		if lim.Wait(ctx) != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(name, addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			names := certificateNames(ctx, name, addr)
			mu.Lock()
			defer mu.Unlock()
			d.records.queries++
			for _, n := range names {
				a := resolver.Answer{Name: name, Records: []resolver.Record{{Type: "TLS", Value: strings.TrimPrefix(n, "*.")}}}
				found = append(found, d.harvest(a)...)
			}
		}(t.name, t.addr)
	}
	wg.Wait()
	d.followRecords(ctx, found)
}

// certificateNames completes a handshake and reads the names on the leaf
// certificate.
func certificateNames(ctx context.Context, sni, addr string) []string {
	dctx, cancel := context.WithTimeout(ctx, tlsTimeout)
	defer cancel()
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: tlsTimeout},
		Config:    &tls.Config{ServerName: sni, InsecureSkipVerify: true}, //nolint:gosec
	}
	conn, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(addr, "443"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]
	return append([]string{leaf.Subject.CommonName}, leaf.DNSNames...)
}
