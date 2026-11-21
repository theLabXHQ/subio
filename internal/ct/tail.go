package ct

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Fetcher is the minimal HTTP surface the tail needs.
type Fetcher interface {
	// Get fetches a whole small resource (the checkpoint).
	Get(ctx context.Context, url string) ([]byte, error)
	// Lines streams a line-delimited resource (a names tile).
	Lines(ctx context.Context, url string, fn func(line []byte) error) error

	// GetJSON decodes a JSON resource.
	GetJSON(ctx context.Context, url string, out any) error
}

// Scope decides whether a name belongs to the target.
type Scope interface {
	// Admit reports the in-scope canonical name, or false.
	Admit(raw string) (string, bool)
}

// entry is one line of a names tile: the certificate's subject common name
// and its DNS SANs, with the log's timestamp.
type entry struct {
	Timestamp int64 `json:"Timestamp"`
	Subject   struct {
		CommonName string `json:"CommonName"`
	} `json:"Subject"`
	DNS []string `json:"DNS"`
}

// Name is one in-scope hostname a log named, with where it came from.
type Name struct {
	Host string
	// Index is the certificate's entry index in the log, which is provenance
	// both protocols can express: a tiled log's tile number is derivable from it
	// (Index / EntriesPerTile) while the reverse is not.
	Index     int64
	Timestamp int64
	Method    string
}

// Result is what one tail run read.
type Result struct {
	// Names is the in-scope names found, in tile order.
	Names []Name
	// FromSize and ToSize bound what was read; ToSize is the new checkpoint to
	// store so the next run starts here.
	FromSize int64
	ToSize   int64
	// Entries is how many certificate entries were scanned and Unreadable how
	// many of those could not be parsed.
	Entries    int
	Unreadable int

	// Reads is how many data resources were fetched: tiles for a tiled log,
	// get-entries requests for an RFC 6962 one.
	Reads int
}

// Config parameterises a tail.
type Config struct {

	// Base is the log's monitoring prefix, e.g.
	Base string
	// From is the tree size a previous run recorded, so only newer tiles are
	// read.
	From int64

	// MaxReads bounds how many resources a run fetches, so a first run against a
	// huge log does not scan it whole.
	MaxReads int64
}

// Tail reads a log's names tiles from the recorded size up to its current
// size, keeps the in-scope names, and returns the new size to record.
func Tail(ctx context.Context, f Fetcher, scope Scope, cfg Config) (*Result, error) {
	base := strings.TrimSuffix(cfg.Base, "/")
	cpBytes, err := f.Get(ctx, base+"/checkpoint")
	if err != nil {
		return nil, fmt.Errorf("ct: reading checkpoint: %w", err)
	}
	cp, err := ParseCheckpoint(cpBytes)
	if err != nil {
		return nil, err
	}

	res := &Result{FromSize: cfg.From, ToSize: cfg.From}
	if cp.TreeSize <= cfg.From {

		res.ToSize = cp.TreeSize
		return res, nil
	}

	startTile, endTile, lastWidth := tileRange(cfg.From, cp.TreeSize)
	for tile := startTile; tile <= endTile; tile++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if cfg.MaxReads > 0 && int64(res.Reads) >= cfg.MaxReads {

			break
		}
		width := EntriesPerTile
		if tile == endTile {
			width = lastWidth
		}
		url := base + "/" + namesTilePath(int(tile), width)
		seen := res.Entries

		pos := int64(0)
		err := f.Lines(ctx, url, func(line []byte) error {
			line = trimSpace(line)
			if len(line) == 0 {
				return nil
			}
			index := tile*EntriesPerTile + pos
			pos++
			res.Entries++
			var e entry
			if json.Unmarshal(line, &e) != nil {
				res.Unreadable++
				return nil
			}
			res.collect(e, index, scope)
			return nil
		})
		res.Reads++
		if err != nil {
			return res, fmt.Errorf("ct: reading tile %d: %w", tile, err)
		}

		if done := (tile + 1) * EntriesPerTile; done < cp.TreeSize {
			res.ToSize = done
		} else {
			res.ToSize = cp.TreeSize
		}
		if res.Entries == seen && tile < endTile {

			return res, fmt.Errorf("ct: tile %d held no readable entry", tile)
		}
	}
	return res, nil
}

// collect keeps the in-scope DNS SANs and common name of one entry.
func (res *Result) collect(e entry, index int64, scope Scope) {
	res.addNames(e.DNS, e.Subject.CommonName, index, e.Timestamp, scope)
}

// addNames is the one place a certificate's names become in-scope results,
// so the tiled and RFC 6962 paths cannot drift on wildcard handling or on
// which field becomes which method.
func (res *Result) addNames(dns []string, commonName string, index, timestamp int64, scope Scope) {
	add := func(raw, method string) {
		raw = strings.TrimPrefix(strings.TrimSpace(raw), "*.")
		if raw == "" {
			return
		}
		if host, ok := scope.Admit(raw); ok {
			res.Names = append(res.Names, Name{Host: host, Index: index, Timestamp: timestamp, Method: method})
		}
	}
	for _, d := range dns {
		add(d, "certificate-san")
	}
	if commonName != "" {
		add(commonName, "certificate-cn")
	}
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\r' || b[0] == '\n') {
		b = b[1:]
	}
	for len(b) > 0 {
		c := b[len(b)-1]
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}
