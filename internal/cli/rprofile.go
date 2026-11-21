package cli

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/resolver"
)

const resolverProfileSchema = "subio.resolver-profile.v1"

// Verdicts a profile gives a resolver.
const (
	verdictUse        = "use"
	verdictSlow       = "slow"
	verdictDrop       = "drop"
	verdictUnmeasured = "unmeasured"
)

type resolverProfile struct {
	Schema     string         `json:"schema"`
	MeasuredAt time.Time      `json:"measured_at"`
	Servers    []profileEntry `json:"servers"`
}

type profileEntry struct {
	Server      string  `json:"server"`
	Verdict     string  `json:"verdict"`
	Reason      string  `json:"reason,omitempty"`
	Sent        int64   `json:"sent"`
	Answered    int64   `json:"answered"`
	Timeouts    int64   `json:"timeouts"`
	Refused     int64   `json:"refused"`
	TimeoutRate float64 `json:"timeout_rate"`
	RefusedRate float64 `json:"refused_rate"`
	Throttles   int64   `json:"throttles,omitempty"`

	// SustainableQPS is the rate the resolver tolerated after being throttled.
	SustainableQPS float64 `json:"sustainable_qps,omitempty"`
	FoldsCase      bool    `json:"folds_case,omitempty"`
	VetProblem     string  `json:"vet_problem,omitempty"`
	// MeasuredAt is when this entry's numbers were taken: an entry carried over
	// from an earlier profile keeps its own date.
	MeasuredAt time.Time `json:"measured_at"`
}

// judge turns one resolver's counters into a verdict.
func judge(st resolver.ServerStat) (verdict, reason string) {
	switch {
	case st.VetProblem != "":
		return verdictDrop, "failed the .invalid check: " + st.VetProblem
	case st.Disabled:
		return verdictDrop, "stopped being asked because it mostly timed out"
	case st.FoldsCase:
		return verdictDrop, "returns the question with its case changed, so DNS-0x20 verifies nothing it answers"
	case st.Sent == 0:
		return verdictUnmeasured, "sent nothing this run"
	case st.Throttles > 0 && st.FinalQPS > 0:
		return verdictSlow, fmt.Sprintf("refused at speed; tolerated %.1f q/s after %d throttle(s)", st.FinalQPS, st.Throttles)
	}
	return verdictUse, ""
}

// buildProfile records this run's resolvers, and carries over every entry of
// the previous profile this run did not ask - which is every resolver that
// profile dropped.
func buildProfile(stats []resolver.ServerStat, prev *resolverProfile, now time.Time) resolverProfile {
	p := resolverProfile{Schema: resolverProfileSchema, MeasuredAt: now}
	seen := map[string]bool{}
	for _, st := range stats {
		v, why := judge(st)
		e := profileEntry{
			Server: st.Server, Verdict: v, Reason: why,
			Sent: st.Sent, Answered: st.Answered, Timeouts: st.Timeouts, Refused: st.Refused,
			Throttles: st.Throttles, FoldsCase: st.FoldsCase, VetProblem: st.VetProblem,
			MeasuredAt: now,
		}
		if st.Sent > 0 {
			e.TimeoutRate = round3(float64(st.Timeouts) / float64(st.Sent))
			e.RefusedRate = round3(float64(st.Refused) / float64(st.Sent))
		}
		if v == verdictSlow {
			e.SustainableQPS = round3(st.FinalQPS)
		}
		if v == verdictUnmeasured && prev != nil {

			if old, ok := prev.entry(st.Server); ok {
				e = old
			}
		}
		seen[st.Server] = true
		p.Servers = append(p.Servers, e)
	}
	if prev != nil {
		for _, old := range prev.Servers {
			if !seen[old.Server] {
				p.Servers = append(p.Servers, old)
			}
		}
	}
	sort.Slice(p.Servers, func(i, j int) bool { return p.Servers[i].Server < p.Servers[j].Server })
	return p
}

func (p *resolverProfile) entry(server string) (profileEntry, bool) {
	for _, e := range p.Servers {
		if e.Server == server {
			return e, true
		}
	}
	return profileEntry{}, false
}

func round3(f float64) float64 { return float64(int64(f*1000+0.5)) / 1000 }

// loadProfile reads a profile and refuses one it does not understand: a
// misread profile could drop every good resolver in a list.
func loadProfile(path string) (*resolverProfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p resolverProfile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: not a resolver profile: %w", path, err)
	}
	if p.Schema != resolverProfileSchema {
		return nil, fmt.Errorf("%s: schema %q, want %q", path, p.Schema, resolverProfileSchema)
	}
	return &p, nil
}

// applyProfile filters servers by the profile and returns the starting rate
// for each resolver it slowed.
func applyProfile(servers []netip.AddrPort, p *resolverProfile) (kept []netip.AddrPort, qps map[netip.AddrPort]float64, dropped []profileEntry, allDropped bool) {
	qps = map[netip.AddrPort]float64{}
	for _, s := range servers {
		e, ok := p.entry(s.String())
		switch {
		case !ok:
			kept = append(kept, s)
		case e.Verdict == verdictDrop:
			dropped = append(dropped, e)
		default:
			kept = append(kept, s)
			if e.Verdict == verdictSlow && e.SustainableQPS > 0 {
				qps[s] = e.SustainableQPS
			}
		}
	}
	if len(kept) == 0 && len(servers) > 0 {
		return servers, qps, dropped, true
	}
	return kept, qps, dropped, false
}

// writeProfile writes atomically, so an interrupted run cannot leave half a
// profile for the next one to refuse.
func writeProfile(path string, p resolverProfile) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// applyResolverProfile is applyProfile with the operator told what it did.
func applyResolverProfile(servers []netip.AddrPort, p *resolverProfile, path string, log *logx.Logger) ([]netip.AddrPort, map[netip.AddrPort]float64) {
	kept, qps, dropped, all := applyProfile(servers, p)
	if all {
		log.Logf("warn", "%s drops every one of the %d resolver(s) given; using them all anyway rather than asking nothing", path, len(servers))
		return kept, qps
	}
	for _, e := range dropped {
		log.Logf("info", "resolver %s left out by %s: %s (measured %s)", e.Server, path, e.Reason, e.MeasuredAt.Format("2006-01-02"))
	}
	if len(dropped)+len(qps) > 0 {
		log.Logf("info", "%s: %d resolver(s) left out, %d starting at a measured rate, %d in use", path, len(dropped), len(qps), len(kept))
	}
	return kept, qps
}
