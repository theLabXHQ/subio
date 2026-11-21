package cli

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/theLabXHQ/subio/internal/logx"
)

// exitInterrupted is the conventional code for a process ended by SIGINT
// (128 + 2).
const exitInterrupted = 130

// interruptible returns a context that is cancelled on the first interrupt,
// and arranges for a second one to end the process at once.
func interruptible(timeout time.Duration, log *logx.Logger) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	}

	ch := make(chan os.Signal, 2)

	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		case <-ch:
		}
		log.Logf("warn", "interrupted: stopping work and writing what was collected, with each source's real status; interrupt again to exit immediately")
		cancel()
		select {
		case <-done:
		case <-ch:

			log.Logf("warn", "interrupted again: exiting now, so the artifacts of this run are incomplete or absent")
			os.Exit(exitInterrupted)
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		close(done)
		cancel()
	}
}

// stoppedEarly names why a context is dead, or returns "" when it is alive.
func stoppedEarly(ctx context.Context) string {
	switch {
	case ctx.Err() == nil:
		return ""
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "the deadline was reached"
	case errors.Is(ctx.Err(), context.Canceled):
		return "it was interrupted"
	default:
		return ctx.Err().Error()
	}
}
