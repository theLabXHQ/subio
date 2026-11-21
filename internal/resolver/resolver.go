// Package resolver is subio's DNS observation stage.
package resolver

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/sched"
)

// Outcome is the classified result of one query.
type Outcome string

const (

	// Resolved means the resolver returned at least one answer record.
	Resolved Outcome = "resolved"
	// NXDomain means the name does not exist, per the resolver.
	NXDomain Outcome = "nxdomain"
	// NoData means the name exists but has no record of the queried type.
	NoData Outcome = "nodata"
	// Error means the resolver could not answer.
	Error Outcome = "resolution_error"
)

// Record is one answer resource record.
type Record struct {
	Type  string
	Value string
	TTL   uint32
}

// Job is one query request.
type Job struct {
	Name string
	Type dnsfast.Type

	// Avoid names a resolver ("addr:port") this query must not go to, for a
	// second opinion.
	Avoid string
}

// Answer is one observation.
type Answer struct {
	Name    string
	Type    dnsfast.Type
	Outcome Outcome

	// RCode is meaningful only when Responded is true.
	RCode      dnsfast.RCode
	Responded  bool
	Records    []Record
	CNAMEChain []string
	Resolver   string
	CheckedAt  time.Time
	ErrorClass string
	// Tries is how many datagrams were sent for this query.
	Tries int

	// SignedLabels is the smallest label count an RRSIG over this answer's type
	// was made with, or 0 when the answer carried no usable RRSIG (unsigned
	// zone, or the query did not ask for DNSSEC records).
	SignedLabels int

	// EDE is the Extended DNS Error the resolver attached, RFC 8914, or a zero
	// value when it attached none.
	EDE dnsfast.ExtendedError
	// Truncated reports that the UDP answer had TC set and the TCP retry either
	// was not attempted or also failed.
	Truncated bool

	// InferredFrom is set when this NXDOMAIN was not asked but inferred: it
	// names the name, this one or an ancestor, that a resolver had just answered
	// NXDOMAIN for, in a zone that had kept the RFC 8020 rule when checked.
	InferredFrom string
}

// RCodeText is the response code as text, empty when no response was read.
func (a Answer) RCodeText() string {
	if !a.Responded {
		return ""
	}
	return a.RCode.String()
}

// Config parameterizes a Resolver.
type Config struct {
	// Servers is the recursive resolver set.
	Servers []netip.AddrPort

	// Case0x20 randomises the case of each query name and checks the echo,
	// RFC-compatible spoofing resistance that costs nothing on the wire.
	Case0x20 bool
	// Workers is the number of sockets.
	Workers int

	// Window is the outstanding queries per worker.
	Window int
	// Timeout bounds one attempt.
	Timeout time.Duration
	// Retries is additional attempts after the first.
	Retries int

	// QPS caps queries per second across all workers.
	QPS int

	// DNSSEC asks for DNSSEC records alongside each answer, so an RRSIG's label
	// count can settle whether a name was expanded from a wildcard.
	DNSSEC bool

	// PerResolverQPS caps queries per second to each resolver individually.
	PerResolverQPS int

	// ServerQPS starts named resolvers at a measured rate instead, read from a
	// resolver profile an earlier run wrote.
	ServerQPS map[netip.AddrPort]float64
	// TCPOnTruncate retries over TCP when the UDP answer sets TC.
	TCPOnTruncate bool
	// MaxCNAME bounds chain following inside one answer.
	MaxCNAME int

	// NoEDNS sends plain queries.
	NoEDNS bool

	// NoNegativeCache asks every query, instead of answering NXDOMAIN for a name
	// at or beneath one a resolver has just answered NXDOMAIN for.
	NoNegativeCache bool
	Clock           sched.Clock
}

// Resolver issues bounded, rate-limited DNS queries.
type Resolver struct {
	// drops counts datagrams the kernel discarded before a worker could read
	// them, and dropsKnown whether the platform could tell us at all.
	drops      atomic.Int64
	dropsKnown atomic.Bool

	// caseFolders counts resolvers that returned a question with its case
	// changed, so a run can say where DNS-0x20 bought it nothing.
	caseFolders atomic.Int64

	// edeSeen counts Extended DNS Error reasons across the run, and edeOther
	// those whose code this build does not know.
	edeSeen  [edeSlots]atomic.Int64
	edeOther atomic.Int64

	cfg     Config
	lim     *sched.Limiter
	servers []*serverState
	next    atomic.Uint64
	// perResolver is true when each server carries its own rate limiter, so the
	// send path binds a query to a resolver that has a token now.
	perResolver bool
	// tcp bounds concurrent TCP retries across all workers.
	tcp chan struct{}
	// noEDNSServers counts resolvers that only answer without EDNS.
	noEDNSServers atomic.Int64
	// benchFor is how long a timing-out resolver is left out; benchFor the
	// constant, shortened only by tests.
	benchFor time.Duration
	// neg is the negative cache, nil when it is off.
	neg *negCache
}

// serverState is one resolver's share of the run.
type serverState struct {
	addr     netip.AddrPort
	text     string
	sent     atomic.Int64
	answered atomic.Int64
	timeouts atomic.Int64
	refused  atomic.Int64
	disabled atomic.Bool
	// health is the recent answer and timeout record, benchedUntil when a
	// resolver benched for timing out is asked again (unix nanoseconds), and
	// benches how many times that happened.
	health       health
	benchedUntil atomic.Int64
	benches      atomic.Int64

	// foldsCase records that this resolver returned the question with its case
	// changed, so DNS-0x20 proves nothing about answers from it.
	foldsCase atomic.Bool

	// lim caps this one resolver's query rate.
	lim *sched.Limiter
	// baseQPS is the rate lim started at, so easing back has somewhere to return
	// to and cannot overshoot the operator's own ceiling.
	baseQPS float64

	// refusedRun counts refusals since the last answer; answeredRun counts
	// answers since the last throttle.
	refusedRun  atomic.Int64
	answeredRun atomic.Int64
	// throttles counts how many times this resolver's rate was cut, which is
	// what an operator needs to see to know a list member is unhappy.
	throttles atomic.Int64
	// slowestQPS is the lowest rate this resolver was driven to.
	slowestQPS atomic.Int64

	// noEDNS is set once this resolver answered a plain query after rejecting
	// the same query with EDNS, FORMERR and no OPT record of its own.
	noEDNS atomic.Bool
	// vetProblem is why Vet refused this resolver, if it did.
	vetProblem atomic.Pointer[string]
}

// ServerStat reports how one resolver behaved.
type ServerStat struct {
	Server   string `json:"server"`
	Sent     int64  `json:"sent"`
	Answered int64  `json:"answered"`
	Timeouts int64  `json:"timeouts"`
	// Refused counts SERVFAIL and REFUSED answers.
	Refused int64 `json:"refused"`
	// Disabled means it was not being asked when the run ended: refused by Vet,
	// or benched for mostly timing out and not yet back.
	Disabled bool `json:"disabled,omitempty"`

	// Throttles counts how often this resolver's rate was cut after a run of
	// refusals, and SlowestQPS the lowest rate it was driven to.
	Throttles  int64   `json:"throttles,omitempty"`
	SlowestQPS float64 `json:"slowest_qps,omitempty"`

	// FoldsCase means this resolver returned a question with its case changed,
	// so DNS-0x20 could not verify anything about its answers.
	FoldsCase bool `json:"folds_case,omitempty"`
	// NoEDNS reports a resolver that rejects EDNS and answers only plain
	// queries, so it can carry no DNSSEC records and no Extended DNS Error.
	NoEDNS bool `json:"no_edns,omitempty"`
	// Benches is how many times the resolver was left out for a while for mostly
	// timing out, and then asked again.
	Benches int64 `json:"benches,omitempty"`
	// FinalQPS is the rate this resolver's own limiter ended the run at; 0 when
	// it had none.
	FinalQPS float64 `json:"final_qps,omitempty"`
	// VetProblem is why the .invalid check refused it, if it did.
	VetProblem string `json:"vet_problem,omitempty"`
}

// Stats returns each resolver's counters.
func (r *Resolver) Stats() []ServerStat {
	out := make([]ServerStat, 0, len(r.servers))
	for _, s := range r.servers {
		st := ServerStat{
			Server: s.text, Sent: s.sent.Load(), Answered: s.answered.Load(),
			Timeouts: s.timeouts.Load(), Refused: s.refused.Load(), Disabled: !s.asked(time.Now()),
			Benches:   s.benches.Load(),
			Throttles: s.throttles.Load(), SlowestQPS: float64(s.slowestQPS.Load()) / 1000,
			FoldsCase: s.foldsCase.Load(),
			NoEDNS:    s.noEDNS.Load(),
		}
		if s.lim != nil {
			st.FinalQPS = s.lim.Rate()
		}
		if p := s.vetProblem.Load(); p != nil {
			st.VetProblem = *p
		}
		out = append(out, st)
	}
	return out
}

const (

	// maxTCPRetries bounds concurrent TCP retries.
	maxTCPRetries = 32
)

const (

	// throttleAfterRefusals is how many refusals in a row mean "slow down"
	// rather than "that name is broken".
	throttleAfterRefusals = 8

	// throttleFactor halves the rate, and easeFactor gives a twentieth of it
	// back.
	throttleFactor = 0.5
	easeFactor     = 1.05
	// easeAfterAnswers is how many clean answers earn a step back up.
	easeAfterAnswers = 512

	// minResolverQPS is the floor.
	minResolverQPS = 1
)

// noteRefused closes the loop on the only signal a public resolver gives
// that it is being asked too fast.
const edeSlots = 64

// noteEDE tallies one Extended DNS Error.
func (r *Resolver) queryName(name string) string {
	if r.cfg.Case0x20 {
		return mixCase(canonicalQName(name))
	}
	return canonicalQName(name)
}

// CaseFolders is how many resolvers answered without echoing the case they
// were sent, and so gave DNS-0x20 nothing to verify.
func (r *Resolver) CaseFolders() int64 { return r.caseFolders.Load() }

func (r *Resolver) noteEDE(e dnsfast.ExtendedError) {
	if !e.Present {
		return
	}
	if e.Code < edeSlots {
		r.edeSeen[e.Code].Add(1)
		return
	}
	r.edeOther.Add(1)
}

// EDEReasons returns how often each Extended DNS Error reason was seen,
// keyed by the registered name of the code.
func (r *Resolver) EDEReasons() map[string]int64 {
	out := map[string]int64{}
	for code := 0; code < edeSlots; code++ {
		if n := r.edeSeen[code].Load(); n > 0 {
			out[dnsfast.ExtendedError{Code: uint16(code), Present: true}.String()] = n
		}
	}
	if n := r.edeOther.Load(); n > 0 {
		out["an unregistered reason code"] = n
	}
	return out
}

func (r *Resolver) noteRefused(s *serverState) {
	if s.lim == nil || s.refusedRun.Add(1) < throttleAfterRefusals {
		return
	}
	s.refusedRun.Store(0)
	s.answeredRun.Store(0)
	now := s.lim.Scale(throttleFactor, minResolverQPS, s.baseQPS)
	s.throttles.Add(1)

	milli := int64(now * 1000)
	for {
		old := s.slowestQPS.Load()
		if old != 0 && old <= milli {
			break
		}
		if s.slowestQPS.CompareAndSwap(old, milli) {
			break
		}
	}
}

// noteAnswered eases a throttled resolver back up after a long clean run.
func (r *Resolver) noteAnswered(s *serverState) {
	if s.lim == nil || s.throttles.Load() == 0 {
		return
	}
	if s.answeredRun.Add(1) < easeAfterAnswers {
		return
	}
	s.answeredRun.Store(0)
	s.lim.Scale(easeFactor, minResolverQPS, s.baseQPS)
}

// noteTimeout disables a resolver that has mostly stopped answering, unless
// it is the last one.
func (r *Resolver) noteTimeout(s *serverState) {
	s.timeouts.Add(1)
	now := time.Now()
	if s.health.note(true) < benchAtTimeoutShare || !s.asked(now) {
		return
	}
	alive := 0
	for _, o := range r.servers {
		if o.asked(now) {
			alive++
		}
	}

	if alive > 1 {
		s.benchedUntil.Store(now.Add(r.benchFor).UnixNano())
		s.benches.Add(1)
		s.health.reset()
	}
}

// DefaultServers are used when the operator supplies none.
var DefaultServers = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// New builds a Resolver, filling in conservative defaults.
func New(cfg Config) (*Resolver, error) {
	if len(cfg.Servers) == 0 {
		return nil, errors.New("resolver: no servers configured")
	}
	if cfg.Workers < 1 {
		cfg.Workers = 8
	}
	if cfg.Window < 1 {
		cfg.Window = 256
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.MaxCNAME < 1 {
		cfg.MaxCNAME = 16
	}
	if cfg.Clock == nil {
		cfg.Clock = sched.RealClock{}
	}
	r := &Resolver{cfg: cfg, tcp: make(chan struct{}, maxTCPRetries), benchFor: benchFor}
	if !cfg.NoNegativeCache {
		r.neg = newNegCache()
	}
	for _, addr := range cfg.Servers {
		s := &serverState{addr: addr, text: addr.String()}
		start, ceiling := cfg.PerResolverQPS, float64(cfg.PerResolverQPS)
		if q, ok := cfg.ServerQPS[addr]; ok && q > 0 {

			if q < minResolverQPS {
				q = minResolverQPS
			}
			if ceiling > 0 && q > ceiling {
				q = ceiling
			}
			start = int(q + 0.5)
			if ceiling == 0 {
				ceiling = q
			}
		}
		if start > 0 {
			burst := start / 10
			if burst < 1 {
				burst = 1
			}
			s.lim = sched.NewLimiter(start, time.Second, burst, cfg.Clock)
			s.baseQPS = ceiling
			r.perResolver = true
		}
		r.servers = append(r.servers, s)
	}
	if cfg.QPS > 0 {
		burst := cfg.QPS / 10
		if burst < 1 {
			burst = 1
		}
		r.lim = sched.NewLimiter(cfg.QPS, time.Second, burst, cfg.Clock)
	}
	return r, nil
}

// Stream consumes jobs and emits answers until jobs is closed and every
// outstanding query has been answered or has expired.
func (r *Resolver) Stream(ctx context.Context, jobs <-chan Job, out chan<- Answer) {
	var wg sync.WaitGroup
	for i := 0; i < r.cfg.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			w, err := r.newWorker(id)
			if err != nil {

				for {
					select {
					case j, ok := <-jobs:
						if !ok {
							return
						}
						out <- Answer{Name: j.Name, Type: j.Type, Outcome: Error,
							ErrorClass: "socket: " + err.Error(), CheckedAt: time.Now().UTC()}
					case <-ctx.Done():
						return
					}
				}
			}
			defer w.close()
			w.loop(ctx, jobs, out)
			w.tcpDone.Wait()
		}(i)
	}
	wg.Wait()
	close(out)
}

// ResolveAll is the batch convenience wrapper.
func (r *Resolver) ResolveAll(ctx context.Context, names []string, types []dnsfast.Type) []Answer {
	js := make([]Job, 0, len(names)*len(types))
	for _, n := range names {
		for _, t := range types {
			js = append(js, Job{Name: n, Type: t})
		}
	}
	return r.ResolveJobs(ctx, js)
}

// ResolveJobs answers a list of queries that may differ in type.
func (r *Resolver) ResolveJobs(ctx context.Context, list []Job) []Answer {
	jobs := make(chan Job, 1024)
	out := make(chan Answer, 1024)
	go func() {
		defer close(jobs)
		for _, j := range list {
			select {
			case jobs <- j:
			case <-ctx.Done():
				return
			}
		}
	}()
	go r.Stream(ctx, jobs, out)
	var answers []Answer
	for a := range out {
		answers = append(answers, a)
	}
	return answers
}

// server picks the next resolver that is still being asked.
func (r *Resolver) server() *serverState { return r.serverAvoiding("") }

// serverAvoiding is server, never returning the resolver named avoid unless
// it is the only one there is.
func (r *Resolver) serverAvoiding(avoid string) *serverState {
	n := uint64(len(r.servers))
	now := time.Now()
	for i := uint64(0); i < n; i++ {
		s := r.servers[(r.next.Add(1)-1)%n]
		if s.asked(now) && s.text != avoid {
			return s
		}
	}
	for i := uint64(0); i < n; i++ {
		s := r.servers[(r.next.Add(1)-1)%n]
		if s.text != avoid {
			return s
		}
	}
	return r.servers[(r.next.Add(1)-1)%n]
}

// ServerCount is how many resolvers the run was given.
func (r *Resolver) ServerCount() int { return len(r.servers) }

// sendableServer returns the next enabled resolver with a rate token free
// now, consuming that token, or nil when every resolver is rate-limited this
// instant.
func (r *Resolver) sendableServer(avoid string) *serverState {
	n := len(r.servers)
	now := time.Now()
	for i := 0; i < n; i++ {
		s := r.servers[int(r.next.Add(1)-1)%n]
		if !s.asked(now) || (s.text == avoid && n > 1) {
			continue
		}
		if s.lim == nil || s.lim.TryTake() {
			return s
		}
	}
	return nil
}

// pending is one outstanding query.
type pending struct {
	job      Job
	qname    string
	server   *serverState
	deadline time.Time

	// plain sends no EDNS option, after a server rejected one with FORMERR.
	plain bool
	// negZone is set on a query the negative cache could have answered but was
	// sent to check that the zone keeps the rule; its answer is the check.
	negZone string
	tries   int
	// id is the transaction id currently outstanding for this query.
	id uint16

	// done marks a query that has been answered.
	done bool
}

type worker struct {
	r        *Resolver
	conn     *net.UDPConn
	inflight map[uint16]*pending

	// queue holds outstanding queries in send order.
	queue []*pending
	head  int

	// ready holds queries waiting for a token, oldest first, and readyHead is
	// the oldest.
	ready     []*pending
	readyHead int
	wbuf      []byte
	rbuf      []byte
	// tcpDone waits for this worker's TCP retries, which send on the same out.
	tcpDone sync.WaitGroup
}

func (r *Resolver) newWorker(id int) (*worker, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(1 << 20)
	return &worker{
		r:        r,
		conn:     conn,
		inflight: make(map[uint16]*pending, r.cfg.Window),
		queue:    make([]*pending, 0, r.cfg.Window*2),
		wbuf:     make([]byte, 0, 768),
		rbuf:     make([]byte, 4096),
	}, nil
}

func (w *worker) close() {

	w.noteKernelDrops()
	_ = w.conn.Close()
}

// newID picks an unused transaction ID for this worker.
func (w *worker) newID() (uint16, bool) {
	var b [2]byte
	for i := 0; i < 64; i++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, false
		}
		id := binary.BigEndian.Uint16(b[:])
		if _, taken := w.inflight[id]; !taken {
			return id, true
		}
	}
	return 0, false
}

// waiting is how many queries are waiting for a token.
func (w *worker) waiting() int { return len(w.ready) - w.readyHead }

// pump sends waiting queries while the window and the rate ceiling allow.
func (w *worker) pump(out chan<- Answer) {
sending:
	for w.readyHead < len(w.ready) && len(w.inflight) < w.r.cfg.Window {
		p := w.ready[w.readyHead]

		switch {
		case w.r.perResolver && p.plain:

			if p.server.lim != nil && !p.server.lim.TryTake() {
				break sending
			}
		case w.r.perResolver:
			srv := w.r.sendableServer(p.job.Avoid)
			if srv == nil {
				break sending
			}
			p.server = srv
		}
		if w.r.lim != nil && !w.r.lim.TryTake() {
			break sending
		}
		w.ready[w.readyHead] = nil
		w.readyHead++
		if err := w.send(p); err != nil {
			out <- Answer{
				Name: p.job.Name, Type: p.job.Type, Outcome: Error,
				ErrorClass: "send: " + err.Error(), Resolver: p.server.text,
				CheckedAt: time.Now().UTC(), Tries: p.tries,
			}
		}
	}

	if w.readyHead == len(w.ready) {
		w.ready = w.ready[:0]
		w.readyHead = 0
	} else if w.readyHead >= 1024 && w.readyHead*2 >= len(w.ready) {
		n := copy(w.ready, w.ready[w.readyHead:])
		clear(w.ready[n:])
		w.ready = w.ready[:n]
		w.readyHead = 0
	}
}

// admit queues a new job for sending, or answers it from the negative cache.
func (w *worker) admit(j Job, out chan<- Answer) {
	p := &pending{job: j, qname: w.r.queryName(j.Name), server: w.r.serverAvoiding(j.Avoid)}
	if w.r.neg != nil && j.Avoid == "" {
		switch d, cut, e := w.r.neg.decide(j.Name); d {
		case negInfer:
			w.r.neg.inferred.Add(1)
			out <- Answer{
				Name: j.Name, Type: j.Type, Outcome: NXDomain, RCode: dnsfast.RCodeNXDomain,
				Responded: true, Resolver: e.resolver, CheckedAt: time.Now().UTC(), InferredFrom: cut,
			}
			return
		case negCheck:
			w.r.neg.checks.Add(1)
			p.negZone = e.zone
		}
	}
	w.ready = append(w.ready, p)
}

func (w *worker) send(p *pending) error {
	id, ok := w.newID()
	if !ok {
		return errors.New("no free transaction id")
	}
	var err error
	w.wbuf = w.wbuf[:0]
	switch {
	case w.r.cfg.NoEDNS || p.plain || p.server.noEDNS.Load():
		w.wbuf, err = dnsfast.AppendQuery(w.wbuf, id, p.qname, p.job.Type)
	case w.r.cfg.DNSSEC:

		w.wbuf, err = dnsfast.AppendQueryDNSSEC(w.wbuf, id, p.qname, p.job.Type, dnsfast.DefaultEDNSPayload)
	default:
		w.wbuf, err = dnsfast.AppendQueryEDNS(w.wbuf, id, p.qname, p.job.Type, dnsfast.DefaultEDNSPayload)
	}
	if err != nil {
		return err
	}
	if _, err := w.conn.WriteToUDPAddrPort(w.wbuf, p.server.addr); err != nil {
		return err
	}
	p.server.sent.Add(1)
	p.tries++
	p.id = id
	p.deadline = time.Now().Add(w.r.cfg.Timeout)
	w.inflight[id] = p
	w.queue = append(w.queue, p)
	return nil
}

func (w *worker) loop(ctx context.Context, jobs <-chan Job, out chan<- Answer) {
	draining := false
	for {
		if ctx.Err() != nil {
			w.flushError(out, "cancelled")
			return
		}

	fill:
		for !draining && len(w.inflight)+w.waiting() < w.r.cfg.Window {
			select {
			case j, ok := <-jobs:
				if !ok {
					draining = true
					break fill
				}
				w.admit(j, out)
			case <-ctx.Done():
				w.flushError(out, "cancelled")
				return
			default:
				break fill
			}
		}

		w.pump(out)

		if len(w.inflight) == 0 && w.waiting() == 0 {
			if draining {
				return
			}

			select {
			case j, ok := <-jobs:
				if !ok {
					return
				}
				w.admit(j, out)
			case <-ctx.Done():
				return
			}
			continue
		}

		_ = w.conn.SetReadDeadline(w.nextDeadline())
		n, from, err := w.conn.ReadFromUDPAddrPort(w.rbuf)
		if err == nil && n > 0 {
			w.handle(ctx, from, w.rbuf[:n], out)
		} else if err != nil && !isTimeout(err) {

			w.flushError(out, "socket: "+err.Error())
			return
		}
		w.sweep(out)
	}
}

// nextDeadline is the earliest pending expiry, read from the head of the
// queue in constant time and bounded so the loop stays responsive to new work.
func (w *worker) nextDeadline() time.Time {
	now := time.Now()
	best := now.Add(5 * time.Millisecond)
	w.trimQueue()
	if w.head < len(w.queue) && w.queue[w.head].deadline.Before(best) {
		best = w.queue[w.head].deadline
	}
	if best.Before(now.Add(time.Millisecond)) {
		best = now.Add(time.Millisecond)
	}
	return best
}

// trimQueue advances past answered entries so the head is always a genuinely
// outstanding query, and reclaims the backing array once most of it is stale.
func (w *worker) trimQueue() {
	for w.head < len(w.queue) && w.queue[w.head].done {
		w.queue[w.head] = nil
		w.head++
	}
	if w.head == len(w.queue) {
		w.queue = w.queue[:0]
		w.head = 0
		return
	}

	if w.head >= 1024 && w.head*2 >= len(w.queue) {
		n := copy(w.queue, w.queue[w.head:])
		for i := n; i < len(w.queue); i++ {
			w.queue[i] = nil
		}
		w.queue = w.queue[:n]
		w.head = 0
	}
}

func (w *worker) handle(ctx context.Context, from netip.AddrPort, msg []byte, out chan<- Answer) {
	h, err := dnsfast.ParseHeader(msg)
	if err != nil || !h.Response {
		return
	}
	p, ok := w.inflight[h.ID]
	if !ok {
		return
	}

	if from.Port() != p.server.addr.Port() || from.Addr().Unmap() != p.server.addr.Addr().Unmap() {
		return
	}

	q, err := dnsfast.QuestionName(msg)
	if err != nil || !strings.EqualFold(q.Name, p.qname) || q.Type != p.job.Type {
		return
	}

	if exact, eerr := dnsfast.QuestionNameExact(msg); w.r.cfg.Case0x20 && eerr == nil &&
		!sameNameExactly(exact, p.qname) {
		if !p.server.foldsCase.Swap(true) {
			w.r.caseFolders.Add(1)
		}
	}
	delete(w.inflight, h.ID)
	p.done = true
	p.server.answered.Add(1)
	p.server.health.note(false)

	if p.plain && h.RCode != dnsfast.RCodeFormErr && !p.server.noEDNS.Swap(true) {
		w.r.noEDNSServers.Add(1)
	}
	if h.RCode != dnsfast.RCodeServFail && h.RCode != dnsfast.RCodeRefused {
		p.server.refusedRun.Store(0)
		w.r.noteAnswered(p.server)
	}

	w.r.noteEDE(dnsfast.ReadExtendedError(msg))

	switch h.RCode {
	case dnsfast.RCodeServFail, dnsfast.RCodeRefused:

		p.server.refused.Add(1)
		w.r.noteRefused(p.server)
		if p.tries <= w.r.cfg.Retries {
			w.ready = append(w.ready, &pending{job: p.job, qname: p.qname, server: w.r.serverAvoiding(p.job.Avoid), tries: p.tries, negZone: p.negZone})
			return
		}
	case dnsfast.RCodeFormErr:

		if !w.r.cfg.NoEDNS && !p.plain && !p.server.noEDNS.Load() && !dnsfast.HasOPT(msg) {
			w.ready = append(w.ready, &pending{job: p.job, qname: p.qname, server: p.server, tries: p.tries, plain: true, negZone: p.negZone})
			return
		}
	}

	if h.Truncated && w.r.cfg.TCPOnTruncate {

		w.retryTCPAsync(ctx, p, append([]byte(nil), msg...), h, out)
		return
	}
	a := truncatedAnswer(msg, h, p, w.r.cfg.MaxCNAME)
	if w.r.neg != nil {
		if p.negZone != "" {
			w.r.neg.verdict(p.negZone, a)
		}
		w.r.neg.learn(msg, p.qname, p.server.text)
	}
	out <- a
}

// truncatedAnswer classifies a UDP answer, flagging one that was cut.
func truncatedAnswer(msg []byte, h dnsfast.Header, p *pending, maxCNAME int) Answer {
	a := buildAnswer(msg, h, p, maxCNAME)
	a.Truncated = h.Truncated
	if a.Truncated && a.Outcome == NoData {

		a.Outcome = Error
		a.ErrorClass = "truncated"
	}
	return a
}

// retryTCPAsync re-asks over TCP beside the pipeline.
func (w *worker) retryTCPAsync(ctx context.Context, p *pending, msg []byte, h dnsfast.Header, out chan<- Answer) {
	w.tcpDone.Add(1)
	go func() {
		defer w.tcpDone.Done()
		select {
		case w.r.tcp <- struct{}{}:
			defer func() { <-w.r.tcp }()
		case <-ctx.Done():
			out <- truncatedAnswer(msg, h, p, w.r.cfg.MaxCNAME)
			return
		}

		if w.r.lim != nil {
			if err := w.r.lim.Wait(ctx); err != nil {
				out <- truncatedAnswer(msg, h, p, w.r.cfg.MaxCNAME)
				return
			}
		}
		a, err := w.retryTCP(ctx, p)
		if err != nil {
			a = truncatedAnswer(msg, h, p, w.r.cfg.MaxCNAME)
		}
		out <- a
	}()
}

// retryTCP re-asks over TCP, which is the only correct response to TC=1.
func (w *worker) retryTCP(ctx context.Context, p *pending) (Answer, error) {
	d := net.Dialer{Timeout: w.r.cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", p.server.text)
	if err != nil {
		return Answer{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(w.r.cfg.Timeout))

	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return Answer{}, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	var buf []byte

	buf, err = dnsfast.AppendQuery(buf, id, p.qname, p.job.Type)
	if err != nil {
		return Answer{}, err
	}

	framed := make([]byte, 2+len(buf))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(buf)))
	copy(framed[2:], buf)
	if _, err := conn.Write(framed); err != nil {
		return Answer{}, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return Answer{}, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return Answer{}, errors.New("bad tcp length")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return Answer{}, err
	}
	h, err := dnsfast.ParseHeader(resp)
	if err != nil {
		return Answer{}, err
	}

	q, err := dnsfast.QuestionName(resp)
	if err != nil {
		return Answer{}, err
	}
	exactTCP, exactErr := dnsfast.QuestionNameExact(resp)
	if h.Response && h.ID == id && w.r.cfg.Case0x20 && exactErr == nil &&
		strings.EqualFold(q.Name, p.qname) && !sameNameExactly(exactTCP, p.qname) {
		if !p.server.foldsCase.Swap(true) {
			w.r.caseFolders.Add(1)
		}
	}
	if !h.Response || h.ID != id || !strings.EqualFold(q.Name, p.qname) || q.Type != p.job.Type {
		return Answer{}, errors.New("tcp answer does not match the query")
	}
	return buildAnswer(resp, h, p, w.r.cfg.MaxCNAME), nil
}

// sweep retries or expires overdue queries.
func (w *worker) sweep(out chan<- Answer) {
	now := time.Now()
	for w.head < len(w.queue) {
		p := w.queue[w.head]
		if p.done {
			w.queue[w.head] = nil
			w.head++
			continue
		}
		if now.Before(p.deadline) {
			return
		}
		w.queue[w.head] = nil
		w.head++
		delete(w.inflight, p.id)
		p.done = true
		w.r.noteTimeout(p.server)
		if p.tries <= w.r.cfg.Retries {

			w.ready = append(w.ready, &pending{job: p.job, qname: p.qname, server: w.r.serverAvoiding(p.job.Avoid), tries: p.tries, negZone: p.negZone})
			continue
		}
		out <- Answer{
			Name: p.job.Name, Type: p.job.Type, Outcome: Error, ErrorClass: "timeout",
			Resolver: p.server.text, CheckedAt: now.UTC(), Tries: p.tries,
		}
	}
}

func (w *worker) flushError(out chan<- Answer, class string) {
	now := time.Now().UTC()
	for id, p := range w.inflight {
		delete(w.inflight, id)
		p.done = true
		out <- Answer{Name: p.job.Name, Type: p.job.Type, Outcome: Error,
			ErrorClass: class, Resolver: p.server.text, CheckedAt: now, Tries: p.tries}
	}
	w.queue = w.queue[:0]
	w.head = 0
	for _, p := range w.ready[w.readyHead:] {
		out <- Answer{Name: p.job.Name, Type: p.job.Type, Outcome: Error,
			ErrorClass: class, Resolver: p.server.text, CheckedAt: now, Tries: p.tries}
	}
	w.ready = w.ready[:0]
	w.readyHead = 0
}

// buildAnswer classifies a response.
func buildAnswer(msg []byte, h dnsfast.Header, p *pending, maxCNAME int) Answer {
	a := Answer{
		Name: p.job.Name, Type: p.job.Type, RCode: h.RCode, Responded: true,
		Resolver: p.server.text, CheckedAt: time.Now().UTC(), Tries: p.tries,
	}

	a.EDE = dnsfast.ReadExtendedError(msg)

	switch h.RCode {
	case dnsfast.RCodeNXDomain:
		a.Outcome = NXDomain
		return a
	case dnsfast.RCodeNoError:

	default:
		a.Outcome = Error
		a.ErrorClass = strings.ToLower(h.RCode.String())
		return a
	}

	_, err := dnsfast.ForEachAnswer(msg, func(rr dnsfast.RR) error {
		switch rr.Type {
		case dnsfast.TypeRRSIG:

			if n, ok := dnsfast.RRSIGLabels(rr); ok {
				if covers, ok := dnsfast.RRSIGCovers(rr); ok && (covers == a.Type || covers == dnsfast.TypeCNAME) {
					if a.SignedLabels == 0 || int(n) < a.SignedLabels {
						a.SignedLabels = int(n)
					}
				}
			}
		case dnsfast.TypeA, dnsfast.TypeAAAA:
			if addr, err := rr.Addr(); err == nil {
				a.Records = append(a.Records, Record{Type: rr.Type.String(), Value: addr.String(), TTL: rr.TTL})
			}
		case dnsfast.TypeCNAME:
			if t, err := rr.Target(msg); err == nil {
				if len(a.CNAMEChain) < maxCNAME {
					a.CNAMEChain = append(a.CNAMEChain, strings.TrimSuffix(t, "."))
				}
				a.Records = append(a.Records, Record{Type: "CNAME", Value: strings.TrimSuffix(t, "."), TTL: rr.TTL})
			}
		case dnsfast.TypeNS, dnsfast.TypePTR:
			if t, err := rr.Target(msg); err == nil {
				a.Records = append(a.Records, Record{Type: rr.Type.String(), Value: strings.TrimSuffix(t, "."), TTL: rr.TTL})
			}
		case dnsfast.TypeMX:
			if pref, host, err := rr.MX(msg); err == nil {
				a.Records = append(a.Records, Record{Type: "MX",
					Value: fmt.Sprintf("%d %s", pref, strings.TrimSuffix(host, ".")), TTL: rr.TTL})
			}
		case dnsfast.TypeTXT:
			if vals, err := rr.TXT(); err == nil {
				a.Records = append(a.Records, Record{Type: "TXT", Value: strings.Join(vals, ""), TTL: rr.TTL})
			}
		case dnsfast.TypeSRV:
			if prio, weight, port, target, err := rr.SRV(msg); err == nil {
				a.Records = append(a.Records, Record{Type: "SRV",
					Value: fmt.Sprintf("%d %d %d %s", prio, weight, port, strings.TrimSuffix(target, ".")), TTL: rr.TTL})
			}
		case dnsfast.TypeSOA:
			if soa, err := rr.SOA(msg); err == nil {
				a.Records = append(a.Records, Record{Type: "SOA",
					Value: fmt.Sprintf("%s %s %d", strings.TrimSuffix(soa.NS, "."), strings.TrimSuffix(soa.Mbox, "."), soa.Serial), TTL: rr.TTL})
			}
		case dnsfast.TypeCAA:
			if caa, err := rr.CAA(); err == nil {
				a.Records = append(a.Records, Record{Type: "CAA",
					Value: fmt.Sprintf("%d %s %q", caa.Flag, caa.Tag, caa.Value), TTL: rr.TTL})
			}
		}
		return nil
	})
	if err != nil {
		a.Outcome = Error
		a.ErrorClass = "malformed_response"
		return a
	}
	if len(a.Records) == 0 {

		a.Outcome = NoData
		return a
	}
	a.Outcome = Resolved
	return a
}

func canonicalQName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "."
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ParseServers accepts "1.1.1.1", "1.1.1.1:53" or "[2001:db8::1]:53" and
// defaults the port to 53.
func ParseServers(in []string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		ap, err := netip.ParseAddrPort(s)
		if err == nil {
			out = append(out, ap)
			continue
		}
		addr, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return nil, fmt.Errorf("resolver: %q is not an IP or IP:port", s)
		}
		out = append(out, netip.AddrPortFrom(addr, 53))
	}
	if len(out) == 0 {
		return nil, errors.New("resolver: no usable servers")
	}
	return out, nil
}

// LoadResolvers reads one resolver per line, ignoring blanks and # comments.
func LoadResolvers(path string) ([]netip.AddrPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return ParseServers(lines)
}
