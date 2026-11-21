package ct

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The CT log list, as Chrome publishes it at
// https://www.gstatic.com/ct/log_list/v3/log_list.json.
//
//go:embed loglist.json
var embeddedLogList []byte

// LogListURL is where a current list comes from, so the tool can say it
// rather than leave an operator to search for it.
const LogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// Log is one monitorable log.
type Log struct {
	Operator    string
	Description string
	// URL is the monitoring prefix: monitoring_url for a tiled log, url for an
	// RFC 6962 one.
	URL string
	// Protocol comes from which array the log was listed in, so a listed log
	// needs no Detect probe before it is read.
	Protocol Protocol
	State    string

	// Start and End bound the certificates a log accepts.
	Start, End time.Time
}

// LogList is a parsed log list.
type LogList struct {
	Version   string
	Timestamp time.Time
	Logs      []Log
}

type rawList struct {
	Version   string `json:"version"`
	Timestamp string `json:"log_list_timestamp"`
	Operators []struct {
		Name      string   `json:"name"`
		Logs      []rawLog `json:"logs"`
		TiledLogs []rawLog `json:"tiled_logs"`
	} `json:"operators"`
}

type rawLog struct {
	Description   string                     `json:"description"`
	URL           string                     `json:"url"`
	MonitoringURL string                     `json:"monitoring_url"`
	State         map[string]json.RawMessage `json:"state"`
	Temporal      *struct {
		Start string `json:"start_inclusive"`
		End   string `json:"end_exclusive"`
	} `json:"temporal_interval"`
}

// Builtin returns the snapshot compiled into this binary.
func Builtin() (*LogList, error) { return ParseLogList(embeddedLogList) }

// ParseLogList reads a v3 log list.
func ParseLogList(data []byte) (*LogList, error) {
	var raw rawList
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("ct: log list: %w", err)
	}
	out := &LogList{Version: raw.Version}
	if raw.Timestamp != "" {
		t, err := time.Parse(time.RFC3339, raw.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("ct: log list timestamp: %w", err)
		}
		out.Timestamp = t
	}
	for _, op := range raw.Operators {
		for _, l := range op.Logs {
			out.add(op.Name, l, l.URL, ProtoRFC6962)
		}
		for _, l := range op.TiledLogs {
			out.add(op.Name, l, l.MonitoringURL, ProtoStaticCT)
		}
	}
	if len(out.Logs) == 0 {
		return nil, fmt.Errorf("ct: log list names no log")
	}
	sort.Slice(out.Logs, func(i, j int) bool { return out.Logs[i].URL < out.Logs[j].URL })
	return out, nil
}

func (ll *LogList) add(operator string, raw rawLog, url string, p Protocol) {
	if url == "" {
		return
	}
	l := Log{
		Operator: operator, Description: raw.Description,
		URL: strings.TrimSuffix(url, "/"), Protocol: p,
	}

	for k := range raw.State {
		l.State = k
		break
	}
	if raw.Temporal != nil {
		l.Start, _ = time.Parse(time.RFC3339, raw.Temporal.Start)
		l.End, _ = time.Parse(time.RFC3339, raw.Temporal.End)
	}
	ll.Logs = append(ll.Logs, l)
}

// Monitorable returns the logs worth reading for certificates issued at
// `at`: accepting submissions, and sharded over a period that contains that
// instant.
func (ll *LogList) Monitorable(at time.Time) []Log {
	var out []Log
	for _, l := range ll.Logs {
		if l.State != "usable" && l.State != "qualified" {
			continue
		}
		if !l.Start.IsZero() && at.Before(l.Start) {
			continue
		}
		if !l.End.IsZero() && !at.Before(l.End) {
			continue
		}
		out = append(out, l)
	}
	return out
}

// Age is how long ago the list was published, which is the number that
// decides whether the built-in snapshot still covers the current shards.
func (ll *LogList) Age(now time.Time) time.Duration {
	if ll.Timestamp.IsZero() {
		return 0
	}
	return now.Sub(ll.Timestamp)
}
