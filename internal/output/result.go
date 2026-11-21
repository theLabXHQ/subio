// Package output serializes findings as plain text, JSON lines or CSV.
package output

import (
	"time"

	"github.com/theLabXHQ/subio/internal/cdn"
	"github.com/theLabXHQ/subio/internal/version"
)

// Record is one hostname and what subio knows about it.
type Record struct {
	SchemaVersion string    `json:"schema_version"`
	Timestamp     time.Time `json:"timestamp"`
	Host          string    `json:"host"`
	Root          string    `json:"root"`

	// Sources and Families are the distinct providers and evidence families that
	// reported this name.
	Sources  []string `json:"sources,omitempty"`
	Families []string `json:"families,omitempty"`
	Evidence int      `json:"evidence_count,omitempty"`

	// FirstSeen and LastSeen are provider-stated times.
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`

	// Verification is the DNS state: not_checked until the DNS stage runs.
	Verification string `json:"verification_status"`
	// DNS fields are present only when --resolve ran.
	RCode      string     `json:"rcode,omitempty"`
	Records    []RR       `json:"records,omitempty"`
	CNAMEChain []string   `json:"cname_chain,omitempty"`
	Resolver   string     `json:"resolver,omitempty"`
	CheckedAt  *time.Time `json:"checked_at,omitempty"`
	ErrorClass string     `json:"error_class,omitempty"`

	// Wildcard marks a name whose answer is indistinguishable from what the
	// parent zone synthesizes for random labels.
	Wildcard bool `json:"wildcard_suspected,omitempty"`
	// WildcardControls are the random names whose answers produced that verdict,
	// kept so the classification can be audited.
	WildcardControls []string `json:"wildcard_controls,omitempty"`

	// Edge names the CDN, WAF or cloud provider in front of the name, from its
	// CNAME chain or, with -cdn, the AS routing its addresses.
	Edge *cdn.Edge `json:"edge,omitempty"`

	// Change is the classification against the stored history, present only when
	// a store was used.
	Change string `json:"change,omitempty"`
	// MissingRuns is how many consecutive complete runs have not seen it.
	MissingRuns int `json:"missing_runs,omitempty"`
	// PrevRecords is the previous answer set, present on a DNS change.
	PrevRecords []RR `json:"previous_records,omitempty"`
	// ChangeReason explains an unconfirmed classification.
	ChangeReason string `json:"change_reason,omitempty"`

	// OnWritten, if set, is called once the record has been flushed.
	OnWritten func() `json:"-"`
}

// RR is one answer resource record.
type RR struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

// NewRecord stamps the schema version and timestamp.
func NewRecord(host, root string, at time.Time) *Record {
	return &Record{SchemaVersion: version.SchemaVersion, Timestamp: at, Host: host, Root: root}
}
