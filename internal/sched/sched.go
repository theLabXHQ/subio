// Package sched bounds and fairly shares outbound request capacity.
package sched

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrBreakerOpen reports that a source is in a cooldown after repeated
// transport or 5xx failures.
var ErrBreakerOpen = errors.New("sched: source circuit breaker is open")

// Clock allows deterministic tests.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// RealClock is the wall clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

func (RealClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Limiter is a token bucket sized from a provider's documented rate ceiling.
type Limiter struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	perSec   float64
	last     time.Time
	clk      Clock
}

// NewLimiter builds a bucket allowing n requests per window with the given
// burst.
func NewLimiter(n int, window time.Duration, burst int, clk Clock) *Limiter {
	if clk == nil {
		clk = RealClock{}
	}
	if n <= 0 || window <= 0 {
		return &Limiter{clk: clk}
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		tokens:   float64(burst),
		capacity: float64(burst),
		perSec:   float64(n) / window.Seconds(),
		last:     clk.Now(),
		clk:      clk,
	}
}

// Unlimited reports a limiter that never delays.
func (l *Limiter) Unlimited() bool { return l.perSec == 0 }

// reserve returns how long the caller must wait before its token is
// available, having already consumed that token.
func (l *Limiter) reserve() time.Duration {
	if l.Unlimited() {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens += elapsed * l.perSec
		if l.tokens > l.capacity {
			l.tokens = l.capacity
		}
		l.last = now
	}
	l.tokens--
	if l.tokens >= 0 {
		return 0
	}

	return time.Duration(-l.tokens / l.perSec * float64(time.Second))
}

// Delay reports how long a request made now would wait for its token,
// without taking one.
func (l *Limiter) Delay() time.Duration {
	if l.Unlimited() {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	tokens := l.tokens
	if elapsed := l.clk.Now().Sub(l.last).Seconds(); elapsed > 0 {
		tokens = min(tokens+elapsed*l.perSec, l.capacity)
	}
	tokens--
	if tokens >= 0 {
		return 0
	}
	return time.Duration(-tokens / l.perSec * float64(time.Second))
}

// Wait blocks until this source may issue one request.
func (l *Limiter) Wait(ctx context.Context) error {
	d := l.reserve()
	if d <= 0 {
		return ctx.Err()
	}
	return l.clk.Sleep(ctx, d)
}

// TryTake takes a token if one is free now and reports whether it did.
func (l *Limiter) TryTake() bool {
	if l.Unlimited() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens = min(l.tokens+elapsed*l.perSec, l.capacity)
		l.last = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// Penalize pushes the next allowed request out by at least d, used to honor
// a provider-sent Retry-After without pretending it is a normal token delay.
func (l *Limiter) Penalize(d time.Duration) {
	if l.Unlimited() || d <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens -= d.Seconds() * l.perSec
}

// Scale multiplies the limiter's rate, bounded so a closed loop cannot drive
// it to zero or let it run away.
func (l *Limiter) Scale(factor, minPerSec, maxPerSec float64) float64 {
	if l.Unlimited() || factor <= 0 {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ratio := l.capacity / l.perSec
	l.perSec *= factor
	if l.perSec < minPerSec {
		l.perSec = minPerSec
	}
	if maxPerSec > 0 && l.perSec > maxPerSec {
		l.perSec = maxPerSec
	}
	l.capacity = l.perSec * ratio
	if l.tokens > l.capacity {
		l.tokens = l.capacity
	}
	return l.perSec
}

// Rate reports the limiter's current requests per second; 0 means unlimited.
func (l *Limiter) Rate() float64 {
	if l.Unlimited() {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.perSec
}

// Breaker trips a source after consecutive hard failures and keeps it
// tripped for a cooldown.
type Breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	fails     int
	openUntil time.Time
	clk       Clock
}

// NewBreaker builds a breaker.
func NewBreaker(threshold int, cooldown time.Duration, clk Clock) *Breaker {
	if clk == nil {
		clk = RealClock{}
	}
	return &Breaker{threshold: threshold, cooldown: cooldown, clk: clk}
}

// Allow reports whether the source may be attempted.
func (b *Breaker) Allow() bool {
	if b.threshold < 1 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() {
		return true
	}
	if b.clk.Now().Before(b.openUntil) {
		return false
	}

	b.openUntil = time.Time{}
	b.fails = 0
	return true
}

// Fail records a hard failure.
func (b *Breaker) Fail() {
	if b.threshold < 1 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fails++
	if b.fails >= b.threshold {
		b.openUntil = b.clk.Now().Add(b.cooldown)
	}
}

// Succeed clears the failure streak.
func (b *Breaker) Succeed() {
	if b.threshold < 1 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fails = 0
	b.openUntil = time.Time{}
}

// Config parameterizes a Scheduler.
type Config struct {
	// GlobalConcurrency caps in-flight requests across every source.
	GlobalConcurrency int
	// PerSourceConcurrency caps in-flight requests for one source.
	PerSourceConcurrency int
	// BreakerThreshold is consecutive hard failures before cooldown.
	BreakerThreshold int
	// BreakerCooldown is how long a tripped source stays out.
	BreakerCooldown time.Duration
	Clock           Clock
}

// Scheduler hands out permission to issue one request.
type Scheduler struct {
	cfg      Config
	global   chan struct{}
	mu       sync.Mutex
	limiters map[string]*Limiter
	breakers map[string]*Breaker
	perSrc   map[string]chan struct{}
	clk      Clock
}

// New builds a Scheduler.
func New(cfg Config) *Scheduler {
	if cfg.GlobalConcurrency < 1 {
		cfg.GlobalConcurrency = 8
	}
	if cfg.PerSourceConcurrency < 1 {
		cfg.PerSourceConcurrency = 2
	}
	if cfg.BreakerCooldown <= 0 {
		cfg.BreakerCooldown = 30 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = RealClock{}
	}
	return &Scheduler{
		cfg:      cfg,
		global:   make(chan struct{}, cfg.GlobalConcurrency),
		limiters: make(map[string]*Limiter),
		breakers: make(map[string]*Breaker),
		perSrc:   make(map[string]chan struct{}),
		clk:      cfg.Clock,
	}
}

// Register declares a source's documented rate ceiling.
func (s *Scheduler) Register(sourceID string, n int, window time.Duration, burst int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.limiters[sourceID]; ok {
		return
	}
	s.limiters[sourceID] = NewLimiter(n, window, burst, s.clk)
	s.breakers[sourceID] = NewBreaker(s.cfg.BreakerThreshold, s.cfg.BreakerCooldown, s.clk)
	s.perSrc[sourceID] = make(chan struct{}, s.cfg.PerSourceConcurrency)
}

func (s *Scheduler) parts(sourceID string) (*Limiter, *Breaker, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.limiters[sourceID]; !ok {
		s.limiters[sourceID] = NewLimiter(0, 0, 0, s.clk)
		s.breakers[sourceID] = NewBreaker(s.cfg.BreakerThreshold, s.cfg.BreakerCooldown, s.clk)
		s.perSrc[sourceID] = make(chan struct{}, s.cfg.PerSourceConcurrency)
	}
	return s.limiters[sourceID], s.breakers[sourceID], s.perSrc[sourceID]
}

// Acquire grants permission to issue one request for sourceID.
func (s *Scheduler) Acquire(ctx context.Context, sourceID string) (release func(), err error) {
	lim, br, slot := s.parts(sourceID)
	if !br.Allow() {
		return nil, ErrBreakerOpen
	}
	if err := lim.Wait(ctx); err != nil {
		return nil, err
	}
	select {
	case slot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case s.global <- struct{}{}:
	case <-ctx.Done():
		<-slot
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-s.global
			<-slot
		})
	}, nil
}

// Delay reports how long a request for sourceID would wait for its rate token.
func (s *Scheduler) Delay(sourceID string) time.Duration {
	lim, _, _ := s.parts(sourceID)
	return lim.Delay()
}

// Penalize applies a provider-sent Retry-After to a source's bucket.
func (s *Scheduler) Penalize(sourceID string, d time.Duration) {
	lim, _, _ := s.parts(sourceID)
	lim.Penalize(d)
}

// Fail and Succeed drive the per-source breaker.
func (s *Scheduler) Fail(sourceID string)    { _, br, _ := s.parts(sourceID); br.Fail() }
func (s *Scheduler) Succeed(sourceID string) { _, br, _ := s.parts(sourceID); br.Succeed() }

// InFlight reports current global usage, for diagnostics output.
func (s *Scheduler) InFlight() int { return len(s.global) }
