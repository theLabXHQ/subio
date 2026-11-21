package resolver

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/theLabXHQ/subio/internal/dnsfast"
)

// Problem says why a resolver should not be trusted with a run.
type Problem struct {
	Server string `json:"server"`
	Reason string `json:"reason"`
}

// vetConcurrency bounds how many resolvers are checked at once.
const vetConcurrency = 64

// Vet asks every resolver about a name that cannot exist, under the .invalid
// TLD that RFC 6761 reserves, and stops using any that answers it or does
// not reply.
func (r *Resolver) Vet(ctx context.Context) []Problem {
	var (
		mu       sync.Mutex
		problems []Problem
		wg       sync.WaitGroup
		sem      = make(chan struct{}, vetConcurrency)
	)
	for _, s := range r.servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(s *serverState) {
			defer wg.Done()
			defer func() { <-sem }()
			reason := r.vetOne(ctx, s)
			if reason == "" {
				return
			}
			mu.Lock()
			problems = append(problems, Problem{Server: s.text, Reason: reason})
			mu.Unlock()
		}(s)
	}
	wg.Wait()

	bad := make(map[string]bool, len(problems))
	for _, p := range problems {
		bad[p.Server] = true
	}
	kept := false
	for _, s := range r.servers {
		kept = kept || !bad[s.text]
	}
	for i, s := range r.servers {
		if bad[s.text] && (kept || i < len(r.servers)-1) {
			s.disabled.Store(true)
		}
	}
	for _, p := range problems {
		for _, s := range r.servers {
			if s.text == p.Server {
				reason := p.Reason
				s.vetProblem.Store(&reason)
			}
		}
	}
	return problems
}

func (r *Resolver) vetOne(ctx context.Context, s *serverState) string {
	conn, err := net.Dial("udp", s.text)
	if err != nil {
		return "cannot open a socket to it"
	}
	defer conn.Close()
	buf := make([]byte, 1500)
	for attempt := 0; attempt <= r.cfg.Retries; attempt++ {
		if ctx.Err() != nil {
			return ""
		}
		name := randomLabel() + ".invalid"
		id := uint16(time.Now().UnixNano())
		query, err := dnsfast.AppendQuery(nil, id, name, dnsfast.TypeA)
		if err != nil {
			return ""
		}
		_ = conn.SetDeadline(time.Now().Add(r.cfg.Timeout))
		if _, err := conn.Write(query); err != nil {
			continue
		}
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		h, err := dnsfast.ParseHeader(buf[:n])
		if err != nil || h.ID != id {
			continue
		}
		if h.RCode == dnsfast.RCodeNXDomain {
			return ""
		}
		if h.RCode == dnsfast.RCodeNoError && h.ANCount > 0 {
			return "it answers for names that do not exist"
		}

		return ""
	}
	return "it did not answer"
}
