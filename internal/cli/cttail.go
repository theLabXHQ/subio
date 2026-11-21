package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/theLabXHQ/subio/internal/fetch"
	"github.com/theLabXHQ/subio/internal/scope"
	"github.com/theLabXHQ/subio/internal/source"
)

// ctSourceMeta describes the pseudo-source the CT tail uses, so its requests
// go through subio's budgeted, size-capped HTTP path.
func ctSourceMeta() source.Metadata {
	return source.Metadata{
		ID:     "cttail",
		Family: source.FamilyCT,
		Key:    source.NoKey,
		Terms:  source.TermsReviewRequired,
		Limits: source.Limits{
			RequestsPerWindow: 20,
			Window:            time.Minute,
			Burst:             4,
			RequestTimeout:    60 * time.Second,

			MaxResponseBytes: 64 << 20,
		},
	}
}

// ctFetcher adapts subio's fetch client to the ct package's Fetcher.
type ctFetcher struct{ client *fetch.Client }

// Get reads a whole resource by streaming its lines and rejoining them,
// which is all the checkpoint needs.
func (c ctFetcher) Get(ctx context.Context, url string) ([]byte, error) {
	var buf []byte
	_, _, err := c.client.GetLines(ctx, "cttail", url, nil, func(line []byte) error {
		buf = append(buf, line...)
		buf = append(buf, '\n')
		return nil
	})
	return buf, err
}

// Lines streams a tile's JSON lines.
func (c ctFetcher) Lines(ctx context.Context, url string, fn func(line []byte) error) error {
	_, _, err := c.client.GetLines(ctx, "cttail", url, nil, fn)
	return err
}

// GetJSON decodes a JSON resource.
func (c ctFetcher) GetJSON(ctx context.Context, url string, out any) error {
	_, _, err := c.client.GetJSON(ctx, "cttail", url, nil, out)
	return err
}

// ctScope adapts subio's authorization scope to the ct package's Scope, so a
// log's unrelated names are dropped by the same rule discovery uses.
type ctScope struct{ set *scope.Set }

func (s ctScope) Admit(raw string) (string, bool) {
	host, _, err := s.set.Admit(raw)
	return host, err == nil
}

// ctCheckpoints is the per-log tree size a store records, keyed by log prefix.
type ctCheckpoints map[string]int64

func ctCheckpointPath(dir string) string { return filepath.Join(dir, "cttail.json") }

// loadCTCheckpoint returns the recorded tree size for a log, if any.
func loadCTCheckpoint(dir, logBase string) (int64, bool) {
	b, err := os.ReadFile(ctCheckpointPath(dir))
	if err != nil {
		return 0, false
	}
	var m ctCheckpoints
	if json.Unmarshal(b, &m) != nil {
		return 0, false
	}
	size, ok := m[logKey(logBase)]
	return size, ok
}

// saveCTCheckpoint records a log's tree size, merging with any others
// already stored, and writes it atomically so an interrupted write cannot corrupt it.
func saveCTCheckpoint(dir, logBase string, size int64) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	m := ctCheckpoints{}
	if b, err := os.ReadFile(ctCheckpointPath(dir)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	m[logKey(logBase)] = size
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := ctCheckpointPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ctCheckpointPath(dir))
}

// logKey normalises a log prefix to a stable key, so a trailing slash or
// case does not split one log's checkpoint into two.
func logKey(logBase string) string {
	h := sha256.Sum256([]byte(logBase))
	return hex.EncodeToString(h[:8])
}
