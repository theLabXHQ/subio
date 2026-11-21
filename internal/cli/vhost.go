package cli

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/theLabXHQ/subio/internal/gen"
	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/sched"
	"github.com/theLabXHQ/subio/internal/source"
)

// randLabel returns a label that cannot plausibly be a real virtual host,
// for a baseline the server answers as it answers any unknown host.
func randLabel() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "zzsubiovhostbaseline"
	}
	return "zz" + hex.EncodeToString(b[:]) + "zz"
}

const (
	sourceVhost = "vhost"
	// maxVhostIPs bounds how many distinct addresses are probed, and
	// maxVhostLabels how many candidate labels per root, so one run stays
	// bounded.
	maxVhostIPs    = 32
	maxVhostLabels = 2000
	maxVhostProbes = 50000

	vhostConcurrency = 16
	vhostPerSecond   = 20
	vhostTimeout     = 6 * time.Second
	vhostMaxBody     = 1 << 20
)

// vhostStats is what the vhost prober did.
type vhostStats struct {
	ips, probes, hits, unstable, errors int
}

// vhostSig is the part of a response that distinguishes one virtual host's
// site from the server's default.
type vhostSig struct {
	status int
	length int
}

// differ reports whether two responses are different enough to be different
// sites.
func (s vhostSig) differ(o vhostSig) bool {
	if s.status != o.status {
		return true
	}
	d := s.length - o.length
	if d < 0 {
		d = -d
	}
	thresh := o.length / 5
	if thresh < 512 {
		thresh = 512
	}
	return d > thresh
}

// vhostProbe looks for virtual hosts: names a found server serves a distinct
// site for, even though no DNS record points to them.
func (d *dnsStage) vhostProbe(ctx context.Context) {
	ips := d.foundAddresses()
	if len(ips) == 0 {
		return
	}
	hosts := d.vhostCandidates()
	if len(hosts) == 0 {
		return
	}

	lim := sched.NewLimiter(vhostPerSecond, time.Second, vhostConcurrency, nil)
	sem := make(chan struct{}, vhostConcurrency)
	var mu sync.Mutex

	for _, ip := range ips {
		if ctx.Err() != nil || d.vh.probes >= maxVhostProbes {
			break
		}
		baseRoot := d.o.RootList[0]
		b1 := d.vhostFetch(ctx, lim, ip, randLabel()+"."+baseRoot)
		b2 := d.vhostFetch(ctx, lim, ip, randLabel()+"."+baseRoot)
		mu.Lock()
		d.vh.ips++
		mu.Unlock()
		if b1 == nil || b2 == nil {
			mu.Lock()
			d.vh.errors++
			mu.Unlock()
			continue
		}
		if b1.differ(*b2) {

			mu.Lock()
			d.vh.unstable++
			mu.Unlock()
			d.log.Logf("verbose", "vhost: %s varies its answers; skipped", ip)
			continue
		}
		base1, base2 := *b1, *b2

		var wg sync.WaitGroup
		for _, host := range hosts {
			mu.Lock()
			capped := d.vh.probes >= maxVhostProbes
			mu.Unlock()
			if capped || ctx.Err() != nil {
				break
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				defer func() { <-sem }()
				sig := d.vhostFetch(ctx, lim, ip, host)
				mu.Lock()
				defer mu.Unlock()
				d.vh.probes++
				if sig == nil {
					d.vh.errors++
					return
				}
				if sig.differ(base1) && sig.differ(base2) {
					d.recordVhost(host, ip, base1, *sig)
				}
			}(host)
		}
		wg.Wait()
	}
	d.addVhostRun()
}

// foundAddresses is the distinct IP addresses of the found hosts, bounded.
func (d *dnsStage) foundAddresses() []string {
	seen := map[string]bool{}
	var ips []string
	for _, f := range d.led.Findings() {
		if f.WildcardSuspected {
			continue
		}
		for _, a := range d.addressesOf(f.RootDomain, f.FQDN) {
			s := a.String()
			if !seen[s] {
				seen[s] = true
				ips = append(ips, s)
			}
		}
		if len(ips) >= maxVhostIPs {
			break
		}
	}
	sort.Strings(ips)
	return ips
}

// vhostCandidates is the in-scope host names to try as virtual hosts: the
// operator's lists or the built-in one, plus the labels of known names,
// under each root, bounded.
func (d *dnsStage) vhostCandidates() []string {
	lists := d.o.Wordlists
	if len(lists) == 0 {
		lists = []*gen.Wordlist{gen.Builtin()}
	}
	labels := gen.Merge(lists...)
	var mined []string
	for _, root := range d.o.RootList {
		mined = append(mined, gen.Labels(d.knownNames(root), root)...)
	}
	labels = gen.Merge(&gen.Wordlist{Labels: mined}, &gen.Wordlist{Labels: labels})
	if len(labels) > maxVhostLabels {
		labels = labels[:maxVhostLabels]
	}
	var hosts []string
	for _, root := range d.o.RootList {
		for _, l := range labels {
			hosts = append(hosts, l+"."+root)
		}
	}
	return hosts
}

// vhostFetch requests host at the given address and returns its response
// signature.
func (d *dnsStage) vhostFetch(ctx context.Context, lim *sched.Limiter, ip, host string) *vhostSig {
	if lim != nil {
		if lim.Wait(ctx) != nil {
			return nil
		}
	}
	dialer := &net.Dialer{Timeout: vhostTimeout}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, "443"))
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec
		TLSHandshakeTimeout: vhostTimeout,
		DisableKeepAlives:   true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   vhostTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", webUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, vhostMaxBody))
	return &vhostSig{status: resp.StatusCode, length: int(n)}
}

// recordVhost records a virtual-host hit as a finding with HTTP evidence.
func (d *dnsStage) recordVhost(host, ip string, base, hit vhostSig) {
	canon, root, err := d.o.Roots.Admit(host)
	if err != nil {
		return
	}
	d.vh.hits++
	d.led.Observe(canon, root.String(), source.FamilyActiveHTTP, source.Observation{
		Hostname: canon, SourceID: sourceVhost, Method: "vhost-probe",
		Attrs: map[string]string{
			"address":         ip,
			"baseline_status": strconv.Itoa(base.status),
			"baseline_length": strconv.Itoa(base.length),
			"hit_status":      strconv.Itoa(hit.status),
			"hit_length":      strconv.Itoa(hit.length),
		},
	})
}

// addVhostRun records what the vhost prober did.
func (d *dnsStage) addVhostRun() {
	if d.vh.ips == 0 {
		return
	}
	status := source.StatusComplete
	switch {
	case d.vh.errors > 0:
		status = source.StatusPartial
	case d.vh.hits == 0:
		status = source.StatusEmpty
	}
	d.led.AddSourceRun(ledger.SourceRun{
		SourceID: sourceVhost, Family: string(source.FamilyActiveHTTP), Status: string(status),
		TermsState: termsNotApplicable, Requests: d.vh.probes, RawObservation: d.vh.hits,
		InScope: d.vh.hits, UniqueNames: d.vh.hits, MarginalNames: d.vh.hits,
		QuotaRemaining: -1,
	})
	if d.vh.unstable > 0 {
		d.log.Logf("info", "vhost: %d server(s) varied their answers and were skipped", d.vh.unstable)
	}
}
