// Package store keeps what previous runs observed, so a later run can say
// what changed.
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FormatVersion identifies the on-disk contract.
const FormatVersion = "subio.store.v1"

const (
	runsFile   = "runs.jsonl"
	assetsFile = "assets.jsonl"
	metaFile   = "meta.json"
)

// RR is one DNS answer record, as persisted.
type RR struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Key identifies an asset: a hostname inside an authorization root.
type Key struct {
	Root string `json:"root"`
	FQDN string `json:"fqdn"`
}

func (k Key) String() string { return k.Root + "|" + k.FQDN }

// Asset is the accumulated state of one hostname across runs.
type Asset struct {
	FormatVersion string `json:"format_version"`
	Key

	// FirstRun and LastRun are the runs that first and most recently observed
	// it.
	FirstRun  string    `json:"first_run"`
	LastRun   string    `json:"last_run"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Sources are the adapters that reported it in its most recent sighting.
	Sources []string `json:"sources"`

	// EverSources is every adapter that has ever reported it.
	EverSources []string `json:"ever_sources"`
	// ProviderFirstSeen and ProviderLastSeen are provider-stated times, null
	// when no provider stated any.
	ProviderFirstSeen *time.Time `json:"provider_first_seen,omitempty"`
	ProviderLastSeen  *time.Time `json:"provider_last_seen,omitempty"`

	// Verification and Records are the last answer a resolver actually gave.
	Verification string `json:"verification_status"`
	Records      []RR   `json:"records,omitempty"`
	Wildcard     bool   `json:"wildcard_suspected,omitempty"`

	// DNSTypes are the record types a resolver has answered for this name.
	DNSTypes []string `json:"dns_types,omitempty"`

	// MissingRuns counts consecutive *complete* runs that did not observe it.
	MissingRuns int `json:"missing_runs"`

	// Retired marks an asset dropped by retention.
	Retired bool `json:"retired,omitempty"`
}

// Run is the record of one discovery run.
type Run struct {
	FormatVersion string    `json:"format_version"`
	ID            string    `json:"run_id"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	ScopeID       string    `json:"scope_id"`
	Roots         []string  `json:"roots"`
	Profile       string    `json:"profile"`
	DNSStage      bool      `json:"dns_stage"`
	Findings      int       `json:"findings"`
	// DNSErrors counts names with a query no resolver could answer.
	DNSErrors int `json:"dns_errors,omitempty"`
	// SourceStatus maps adapter id to its terminal status for this run.
	SourceStatus map[string]string `json:"source_status"`
	// Tool records what produced the run.
	Tool string `json:"tool_version"`
}

// CompletedSources returns the adapters whose result set was whole.
func (r Run) CompletedSources() map[string]bool {
	out := make(map[string]bool, len(r.SourceStatus))
	for id, st := range r.SourceStatus {
		if st == "complete" || st == "empty" {
			out[id] = true
		}
	}
	return out
}

// IncompleteSources returns adapter ids whose results were not whole, with
// their status, sorted for a stable report.
func (r Run) IncompleteSources() []string {
	var out []string
	for id, st := range r.SourceStatus {
		if st != "complete" && st != "empty" {
			out = append(out, id+"="+st)
		}
	}
	sort.Strings(out)
	return out
}

// Complete reports whether every selected source finished.
func (r Run) Complete() bool { return len(r.IncompleteSources()) == 0 }

// PersistentFailure is a source that has not finished for several
// consecutive runs, which is a different thing from one that failed once.
type PersistentFailure struct {
	SourceID string
	// Runs is how many consecutive runs that selected this source saw it not
	// finish, counting the current one.
	Runs int
	// Status is what it reported in the current run.
	Status string
}

// PersistentFailures reports sources that did not finish in the current run
// and have not finished in the runs before it either.
func PersistentFailures(runs []Run, current map[string]string, window, threshold int) []PersistentFailure {
	if threshold < 2 || window < threshold {
		return nil
	}
	var out []PersistentFailure
	for id, st := range current {
		if st == "complete" || st == "empty" {
			continue
		}
		streak, looked := 1, 0
		for i := len(runs) - 1; i >= 0 && looked < window-1; i-- {
			prev, ok := runs[i].SourceStatus[id]
			if !ok {
				continue
			}
			looked++
			if prev == "complete" || prev == "empty" {
				break
			}
			streak++
		}
		if streak >= threshold {
			out = append(out, PersistentFailure{SourceID: id, Runs: streak, Status: st})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Runs != out[j].Runs {
			return out[i].Runs > out[j].Runs
		}
		return out[i].SourceID < out[j].SourceID
	})
	return out
}

// Snapshot is the folded state of the store.
type Snapshot struct {
	Assets map[string]Asset
	Runs   []Run
	// SkippedLines counts torn or unreadable log lines, surfaced rather than
	// hidden: a store that silently drops records is worse than one that says it
	// did.
	SkippedLines int
}

// LastRun returns the most recent run, if any.
func (s *Snapshot) LastRun() (Run, bool) {
	if len(s.Runs) == 0 {
		return Run{}, false
	}
	return s.Runs[len(s.Runs)-1], true
}

// Store is an append-only run history on disk.
type Store struct {
	dir string
}

// Open creates or opens a store directory.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("store: directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	meta := filepath.Join(dir, metaFile)
	if _, err := os.Stat(meta); errors.Is(err, os.ErrNotExist) {
		b, _ := json.MarshalIndent(map[string]string{
			"format_version": FormatVersion,
			"created_at":     time.Now().UTC().Format(time.RFC3339),
		}, "", "  ")
		if err := os.WriteFile(meta, append(b, '\n'), 0o600); err != nil {
			return nil, err
		}
	} else if err == nil {
		if err := s.checkVersion(meta); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// OpenExisting opens a store that must already exist.
func OpenExisting(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("store: directory is required")
	}
	meta := filepath.Join(dir, metaFile)
	if _, err := os.Stat(meta); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("store: no run history at %s", dir)
		}
		return nil, err
	}
	s := &Store{dir: dir}
	if err := s.checkVersion(meta); err != nil {
		return nil, err
	}
	return s, nil
}

// checkVersion refuses a store written by an incompatible version rather
// than reinterpreting its records.
func (s *Store) checkVersion(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("store: %s is unreadable: %w", path, err)
	}
	if v := m["format_version"]; v != FormatVersion {
		return fmt.Errorf("store: %s was written in format %q, this build speaks %q",
			s.dir, v, FormatVersion)
	}
	return nil
}

// Dir returns the store location.
func (s *Store) Dir() string { return s.dir }

// Load folds the append-only logs into a snapshot.
func (s *Store) Load() (*Snapshot, error) {
	snap := &Snapshot{Assets: map[string]Asset{}}

	skipped, err := readLines(filepath.Join(s.dir, runsFile), func(line []byte) error {
		var r Run
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		snap.Runs = append(snap.Runs, r)
		return nil
	})
	if err != nil {
		return nil, err
	}
	snap.SkippedLines += skipped

	skipped, err = readLines(filepath.Join(s.dir, assetsFile), func(line []byte) error {
		var a Asset
		if err := json.Unmarshal(line, &a); err != nil {
			return err
		}
		if a.Retired {
			delete(snap.Assets, a.Key.String())
			return nil
		}
		snap.Assets[a.Key.String()] = a
		return nil
	})
	if err != nil {
		return nil, err
	}
	snap.SkippedLines += skipped

	sort.Slice(snap.Runs, func(i, j int) bool {
		if !snap.Runs[i].StartedAt.Equal(snap.Runs[j].StartedAt) {
			return snap.Runs[i].StartedAt.Before(snap.Runs[j].StartedAt)
		}
		return snap.Runs[i].ID < snap.Runs[j].ID
	})
	return snap, nil
}

// readLines calls fn for each line, returning how many were unreadable.
func readLines(path string, fn func([]byte) error) (skipped int, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			skipped++
		}
	}
	if err := sc.Err(); err != nil {

		if errors.Is(err, bufio.ErrTooLong) {
			return skipped + 1, nil
		}
		return skipped, err
	}
	return skipped, nil
}

// Commit appends a run and the assets it changed.
func (s *Store) Commit(run Run, assets []Asset) error {
	run.FormatVersion = FormatVersion
	if err := appendJSONL(filepath.Join(s.dir, assetsFile), func(enc *json.Encoder) error {
		for _, a := range assets {
			a.FormatVersion = FormatVersion
			if err := enc.Encode(a); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return appendJSONL(filepath.Join(s.dir, runsFile), func(enc *json.Encoder) error {
		return enc.Encode(run)
	})
}

func appendJSONL(path string, write func(*json.Encoder) error) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	if err := terminateLine(f); err != nil {
		_ = f.Close()
		return err
	}
	w := bufio.NewWriterSize(f, 64<<10)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := write(enc); err != nil {
		_ = f.Close()
		return err
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// terminateLine ends a torn trailing line.
func terminateLine(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() == 0 {
		return nil
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], fi.Size()-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	_, err = f.Write([]byte{'\n'})
	return err
}

// Stats describes the store on disk.
type Stats struct {
	Assets       int   `json:"assets"`
	Runs         int   `json:"runs"`
	AssetLogSize int64 `json:"asset_log_bytes"`
	RunLogSize   int64 `json:"run_log_bytes"`
	SkippedLines int   `json:"skipped_lines"`
}

// Stat reports the store's size.
func (s *Store) Stat() (Stats, error) {
	snap, err := s.Load()
	if err != nil {
		return Stats{}, err
	}
	st := Stats{Assets: len(snap.Assets), Runs: len(snap.Runs), SkippedLines: snap.SkippedLines}
	if fi, err := os.Stat(filepath.Join(s.dir, assetsFile)); err == nil {
		st.AssetLogSize = fi.Size()
	}
	if fi, err := os.Stat(filepath.Join(s.dir, runsFile)); err == nil {
		st.RunLogSize = fi.Size()
	}
	return st, nil
}

// Compact rewrites the asset log with one record per live asset, which an
// append-only log needs once its history outweighs its state.
func (s *Store) Compact() (before, after int64, err error) {
	snap, err := s.Load()
	if err != nil {
		return 0, 0, err
	}
	path := filepath.Join(s.dir, assetsFile)
	if fi, err := os.Stat(path); err == nil {
		before = fi.Size()
	}

	keys := make([]string, 0, len(snap.Assets))
	for k := range snap.Assets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	err = s.rewrite(path, func(enc *json.Encoder) error {
		for _, k := range keys {
			if err := enc.Encode(snap.Assets[k]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return before, 0, err
	}
	if fi, statErr := os.Stat(path); statErr == nil {
		after = fi.Size()
	}
	if len(snap.Runs) == 0 {
		return before, after, nil
	}
	err = s.rewrite(filepath.Join(s.dir, runsFile), func(enc *json.Encoder) error {
		for _, r := range snap.Runs {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	})
	return before, after, err
}

// rewrite replaces a log through a temporary file in the same directory.
func (s *Store) rewrite(path string, write func(*json.Encoder) error) (err error) {
	tmp, err := os.CreateTemp(s.dir, "rewrite-*.jsonl")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	w := bufio.NewWriterSize(tmp, 64<<10)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err = write(enc); err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Retire drops assets not observed for at least minMissing complete runs.
func (s *Store) Retire(minMissing int, runID string, now time.Time) (int, error) {
	if minMissing < 1 {
		return 0, errors.New("store: retention threshold must be at least 1 complete run")
	}
	snap, err := s.Load()
	if err != nil {
		return 0, err
	}
	var retire []Asset
	for _, a := range snap.Assets {
		if a.MissingRuns >= minMissing {
			a.Retired = true
			a.LastRun = runID
			retire = append(retire, a)
		}
	}
	if len(retire) == 0 {
		return 0, nil
	}
	sort.Slice(retire, func(i, j int) bool { return retire[i].Key.String() < retire[j].Key.String() })
	if err := appendJSONL(filepath.Join(s.dir, assetsFile), func(enc *json.Encoder) error {
		for _, a := range retire {
			a.FormatVersion = FormatVersion
			if err := enc.Encode(a); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return len(retire), nil
}

// Export writes every live asset as JSON lines, so the store is never a
// one-way destination.
func (s *Store) Export(w io.Writer) (int, error) {
	snap, err := s.Load()
	if err != nil {
		return 0, err
	}
	keys := make([]string, 0, len(snap.Assets))
	for k := range snap.Assets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	bw := bufio.NewWriterSize(w, 64<<10)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	for _, k := range keys {
		if err := enc.Encode(snap.Assets[k]); err != nil {
			return 0, err
		}
	}
	return len(keys), bw.Flush()
}

// SortRecords orders answer records so two runs can be compared bytewise.
func SortRecords(rs []RR) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Type != rs[j].Type {
			return rs[i].Type < rs[j].Type
		}
		return rs[i].Value < rs[j].Value
	})
}

// RecordsEqual compares two answer sets order-independently.
func RecordsEqual(a, b []RR) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]RR(nil), a...)
	y := append([]RR(nil), b...)
	SortRecords(x)
	SortRecords(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// FormatRecords renders an answer set for a report line.
func FormatRecords(rs []RR) string {
	if len(rs) == 0 {
		return "-"
	}
	cp := append([]RR(nil), rs...)
	SortRecords(cp)
	parts := make([]string, 0, len(cp))
	for _, r := range cp {
		parts = append(parts, r.Type+":"+r.Value)
	}
	return strings.Join(parts, " ")
}
