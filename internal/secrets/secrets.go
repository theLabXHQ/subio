// Package secrets resolves provider credentials without ever handing them to
// code that logs.
package secrets

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Env holds credentials resolved from the environment and an optional config
// file.
type Env struct {
	values map[string]string
}

// fallbacks maps a source ID to the conventional environment variable names
// other tools already use, so an operator does not have to re-export keys
// they already have.
var fallbacks = map[string][]string{
	"github":         {"GITHUB_TOKEN", "GH_TOKEN"},
	"shodan":         {"SHODAN_API_KEY"},
	"censys":         {"CENSYS_API_KEY"},
	"chaos":          {"CHAOS_KEY", "PDCP_API_KEY"},
	"certspotter":    {"CERTSPOTTER_TOKEN"},
	"securitytrails": {"SECURITYTRAILS_KEY"},
	"netlas":         {"NETLAS_API_KEY"},
	"fofa":           {"FOFA_KEY"},
}

// New reads credentials from the environment.
func New() *Env {
	e := &Env{values: map[string]string{}}
	for _, kv := range os.Environ() {
		name, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}

		if id, ok := strings.CutPrefix(name, "SUBIO_KEY_"); ok && val != "" {
			e.values[strings.ToLower(id)] = val
		}
	}
	for id, names := range fallbacks {
		if _, taken := e.values[id]; taken {
			continue
		}
		for _, n := range names {
			if v := os.Getenv(n); v != "" {
				e.values[id] = v
				break
			}
		}
	}
	return e
}

// LoadFile merges a `source_id: value` or `source_id=value` file.
func (e *Env) LoadFile(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("secrets: %s is readable by other users (mode %o); run: chmod 600 %s",
			filepath.Base(path), st.Mode().Perm(), path)
	}
	return e.merge(f)
}

func (e *Env) merge(r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 1<<16)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		i := strings.IndexAny(text, "=:")
		if i < 0 {

			return fmt.Errorf("secrets: line %d is not `source_id = value`", line)
		}
		id := strings.ToLower(strings.TrimSpace(text[:i]))
		val := strings.Trim(strings.TrimSpace(text[i+1:]), `"'`)
		if id == "" || val == "" {
			continue
		}

		if _, taken := e.values[id]; !taken {
			e.values[id] = val
		}
	}
	return sc.Err()
}

// Secret implements source.SecretSource.
func (e *Env) Secret(sourceID string) (string, bool) {
	v, ok := e.values[strings.ToLower(sourceID)]
	return v, ok && v != ""
}

// Has reports presence without returning the value, for `subio sources`.
func (e *Env) Has(sourceID string) bool {
	_, ok := e.Secret(sourceID)
	return ok
}

// Set injects a credential, used by tests.
func (e *Env) Set(sourceID, value string) {
	e.values[strings.ToLower(sourceID)] = value
}
