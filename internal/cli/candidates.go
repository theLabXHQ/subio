package cli

import (
	"context"
	"time"

	"github.com/theLabXHQ/subio/internal/gen"
)

// sourceCandidates is the active-dns source for names an external generator
// produced and subio resolved.
const sourceCandidates = "candidate-file"

// candidateFiles resolves the names from the supplied candidate files.
func (d *dnsStage) candidateFiles(ctx context.Context) {
	names := gen.Merge(d.o.Candidates...)
	if len(names) == 0 {
		return
	}
	res := &generatorResult{started: time.Now()}
	found := d.generate(ctx, sourceCandidates, "candidate-file", res, func(yield func(string) bool) {
		for _, n := range names {
			if !yield(n) {
				return
			}
		}
	})

	d.followRecords(ctx, recordsOnly(d, found))
	d.addGeneratorRun(sourceCandidates, res)
}
