// Package ct reads certificate transparency logs in both protocols a log can
// speak, because which one a log speaks decides what a monitor can ask for.
package ct

import (
	"fmt"
	"strconv"
	"strings"
)

// TileHeight is fixed at 8 for CT tiles, so a full tile holds 256 entries.
const (
	TileHeight     = 8
	EntriesPerTile = 1 << TileHeight
)

// namesTilePath returns the path of the names tile at index n, holding width
// entries.
func namesTilePath(n, width int) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		s = fmt.Sprintf("x%03d/%s", n%1000, s)
	}
	path := "tile/names/" + s
	if width != EntriesPerTile {
		path += ".p/" + strconv.Itoa(width)
	}
	return path
}

// Checkpoint is the part of a signed checkpoint subio reads: the origin line
// that identifies the log, and the tree size, which is how many entries the
// log holds.
type Checkpoint struct {
	Origin   string
	TreeSize int64
}

// ParseCheckpoint reads a checkpoint note (RFC-style signed note): the first
// line is the origin, the second is the decimal tree size, the third is the
// base64 root hash, then a blank line and signature lines.
func ParseCheckpoint(b []byte) (Checkpoint, error) {
	lines := strings.Split(string(b), "\n")
	if len(lines) < 3 {
		return Checkpoint{}, fmt.Errorf("ct: checkpoint has %d lines, want at least 3", len(lines))
	}
	size, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil || size < 0 {
		return Checkpoint{}, fmt.Errorf("ct: checkpoint tree size %q is not a non-negative integer", lines[1])
	}
	return Checkpoint{Origin: strings.TrimSpace(lines[0]), TreeSize: size}, nil
}

// tileRange returns the tile indexes to read to cover entries [from, to),
// and the width of the last tile.
func tileRange(from, to int64) (startTile, endTile int64, lastWidth int) {
	if to <= from {
		return 0, 0, 0
	}
	startTile = from / EntriesPerTile
	endTile = to / EntriesPerTile
	lastWidth = int(to % EntriesPerTile)
	if lastWidth == 0 {

		endTile--
		lastWidth = EntriesPerTile
	}
	return startTile, endTile, lastWidth
}
