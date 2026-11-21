package ct

import (
	"context"
	"fmt"
	"strings"
)

// Protocol is the API a CT log speaks.
type Protocol string

const (
	// ProtoStaticCT is c2sp.org/static-ct-api: a signed checkpoint and tiles.
	ProtoStaticCT Protocol = "static-ct"
	// ProtoRFC6962 is the original queryable API: get-sth and get-entries.
	ProtoRFC6962 Protocol = "rfc6962"
	// ProtoUnknown means neither endpoint answered in a readable form, so
	// nothing should be assumed about the log.
	ProtoUnknown Protocol = "unknown"
)

// Detect asks a log which API it speaks and how large its tree is.
func Detect(ctx context.Context, f Fetcher, base string) (Protocol, int64, error) {
	base = strings.TrimSuffix(base, "/")

	if b, err := f.Get(ctx, base+"/checkpoint"); err == nil {
		if cp, perr := ParseCheckpoint(b); perr == nil {
			return ProtoStaticCT, cp.TreeSize, nil
		}
	}
	if size, err := CurrentSizeRFC6962(ctx, f, base); err == nil {
		return ProtoRFC6962, size, nil
	}

	if ctx.Err() != nil {
		return ProtoUnknown, 0, fmt.Errorf("ct: %s was not probed before the run's time ran out: %w", base, ctx.Err())
	}
	return ProtoUnknown, 0, fmt.Errorf("ct: %s answered neither a tiled checkpoint nor an RFC 6962 signed tree head", base)
}
