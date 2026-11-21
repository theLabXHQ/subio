package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
)

// Format selects the serialization.
type Format int

const (
	FormatPlain Format = iota
	FormatJSONL
	FormatCSV
)

// ParseFormat maps a CLI name to a Format.
func ParseFormat(s string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "plain", "text", "txt":
		return FormatPlain, true
	case "jsonl", "json", "ndjson":
		return FormatJSONL, true
	case "csv":
		return FormatCSV, true
	}
	return 0, false
}

// Config configures a Writer.
type Config struct {
	Format Format
	Fields Fields
	// Color applies to Stdout only; File never gets escape codes.
	Color  bool
	Stdout io.Writer
	File   io.Writer

	// OnError is called once if writing fails (a closed pipe, a full disk).
	OnError func(error)
}

// Writer serializes records from a bounded channel on one goroutine.
type Writer struct {
	cfg   Config
	in    chan *Record
	out   *bufio.Writer
	file  *bufio.Writer
	csvO  *csv.Writer
	csvF  *csv.Writer
	jsonO *json.Encoder
	jsonF *json.Encoder
	count int64
	// written holds the OnWritten callbacks of records not yet flushed.
	written []func()
}

// New creates a Writer with a queue of the given size.
func New(cfg Config, queue int) *Writer {
	if queue < 1 {
		queue = 1024
	}
	w := &Writer{cfg: cfg, in: make(chan *Record, queue)}
	if cfg.Stdout != nil {
		w.out = bufio.NewWriterSize(cfg.Stdout, 64<<10)
	}
	if cfg.File != nil {
		w.file = bufio.NewWriterSize(cfg.File, 64<<10)
	}
	switch cfg.Format {
	case FormatJSONL:
		if w.out != nil {
			w.jsonO = json.NewEncoder(w.out)
			w.jsonO.SetEscapeHTML(false)
		}
		if w.file != nil {
			w.jsonF = json.NewEncoder(w.file)
			w.jsonF.SetEscapeHTML(false)
		}
	case FormatCSV:
		if w.out != nil {
			w.csvO = csv.NewWriter(w.out)
		}
		if w.file != nil {
			w.csvF = csv.NewWriter(w.file)
		}
	}
	return w
}

// In returns the channel records are sent on.
func (w *Writer) In() chan<- *Record { return w.in }

// Run consumes records until In is closed and returns the first write error.
func (w *Writer) Run() error {
	var firstErr error
	fail := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
			if w.cfg.OnError != nil {
				w.cfg.OnError(err)
			}
		}
	}
	if w.cfg.Format == FormatCSV {
		fail(w.writeCSVHeader())
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case r, ok := <-w.in:
			if !ok {
				if firstErr == nil {
					fail(w.flush())
				}
				return firstErr
			}
			if firstErr != nil {
				continue
			}
			fail(w.write(r))
			w.count++
			if r.OnWritten != nil {
				w.written = append(w.written, r.OnWritten)
			}
			if len(w.in) == 0 {
				fail(w.flush())
			}
		case <-ticker.C:
			if firstErr == nil {
				fail(w.flush())
			}
		}
	}
}

func (w *Writer) flush() error {
	if err := w.flushBuffers(); err != nil {
		return err
	}
	for _, f := range w.written {
		f()
	}
	clear(w.written)
	w.written = w.written[:0]
	return nil
}

func (w *Writer) flushBuffers() error {
	for _, c := range []*csv.Writer{w.csvO, w.csvF} {
		if c != nil {
			c.Flush()
			if err := c.Error(); err != nil {
				return err
			}
		}
	}
	if w.out != nil {
		if err := w.out.Flush(); err != nil {
			return err
		}
	}
	if w.file != nil {
		return w.file.Flush()
	}
	return nil
}

func (w *Writer) write(r *Record) error {
	switch w.cfg.Format {
	case FormatJSONL:
		if w.jsonO != nil {
			if err := w.jsonO.Encode(r); err != nil {
				return err
			}
		}
		if w.jsonF != nil {
			return w.jsonF.Encode(r)
		}
	case FormatCSV:
		rec := csvRecord(r)
		if w.csvO != nil {
			if err := w.csvO.Write(rec); err != nil {
				return err
			}
		}
		if w.csvF != nil {
			return w.csvF.Write(rec)
		}
	default:
		if w.out != nil {
			if _, err := w.out.WriteString(FormatText(r, w.cfg.Fields, w.cfg.Color) + "\n"); err != nil {
				return err
			}
		}
		if w.file != nil {
			_, err := w.file.WriteString(FormatText(r, w.cfg.Fields, false) + "\n")
			return err
		}
	}
	return nil
}

var csvHeader = []string{
	"timestamp", "host", "root", "sources", "families", "evidence_count",
	"first_seen", "last_seen", "verification_status", "rcode", "records",
	"cname_chain", "resolver", "wildcard_suspected", "error_class", "edge",
}

func (w *Writer) writeCSVHeader() error {
	if w.csvO != nil {
		if err := w.csvO.Write(csvHeader); err != nil {
			return err
		}
	}
	if w.csvF != nil {
		return w.csvF.Write(csvHeader)
	}
	return nil
}

func csvRecord(r *Record) []string {
	var first, last string
	if r.FirstSeen != nil {
		first = r.FirstSeen.UTC().Format(time.RFC3339)
	}
	if r.LastSeen != nil {
		last = r.LastSeen.UTC().Format(time.RFC3339)
	}
	vals := make([]string, 0, len(r.Records))
	for _, rr := range r.Records {
		vals = append(vals, rr.Type+":"+rr.Value)
	}
	rec := []string{
		r.Timestamp.UTC().Format(time.RFC3339Nano), r.Host, r.Root,
		strings.Join(r.Sources, ";"), strings.Join(r.Families, ";"),
		strconv.Itoa(r.Evidence), first, last, r.Verification, r.RCode,
		strings.Join(vals, ";"), strings.Join(r.CNAMEChain, ";"), r.Resolver,
		strconv.FormatBool(r.Wildcard), r.ErrorClass, edgeText(r),
	}
	for i, f := range rec {
		f = clean(f)
		rec[i] = f

		if f != "" && strings.ContainsRune("=+-@\t\r", rune(f[0])) {
			rec[i] = "'" + f
		}
	}
	return rec
}

// edgeText is kind:provider, or empty when nothing was identified.
func edgeText(r *Record) string {
	if r.Edge == nil {
		return ""
	}
	return string(r.Edge.Kind) + ":" + r.Edge.Provider
}

// clean strips control characters that would break a line-oriented or CSV
// consumer.
func clean(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
