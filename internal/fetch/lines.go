package fetch

import (
	"bufio"
	"errors"
	"io"
)

// maxLineBytes bounds a single logical line.
const maxLineBytes = 1 << 20

// ErrLineTooLong reports a line beyond maxLineBytes.
var ErrLineTooLong = errors.New("fetch: response line exceeds 1 MiB")

// scanLines invokes fn for each non-empty line.
func scanLines(r io.Reader, fn func(line []byte) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return ErrLineTooLong
		}

		return err
	}
	return nil
}
