// Package idlerestart decides when a restart the operator asked for (SIGUSR2, sent by the
// package's post-install script after an upgrade) can go ahead: once no community voice
// calls are active, or after a longest wait. The server then exits with ExitCode, and the
// service manager starts the new binary.
package idlerestart

import (
	"context"
	"sync/atomic"
	"time"
)

// ExitCode is the exit status for a restart when idle (EX_TEMPFAIL). The systemd units
// restart rerouted on it.
const ExitCode = 75

// Outcome says why Wait returned.
type Outcome int

const (
	Idle      Outcome = iota // nothing was active
	TimedOut                 // maxWait passed with calls still active
	Cancelled                // ctx ended first
)

// Wait checks active every interval, and returns once it reports 0, once maxWait has
// passed, or when ctx ends. It checks once straight away.
func Wait(ctx context.Context, active func() int, every, maxWait time.Duration) Outcome {
	deadline := time.NewTimer(maxWait)
	defer deadline.Stop()
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if active() == 0 {
			return Idle
		}
		select {
		case <-ctx.Done():
			return Cancelled
		case <-deadline.C:
			return TimedOut
		case <-tick.C:
		}
	}
}

// Controller holds a pending restart. Asking again while one is pending changes nothing.
type Controller struct {
	pending atomic.Bool
}

// Pending reports whether a restart is waiting.
func (c *Controller) Pending() bool { return c.pending.Load() }

// Request marks a restart pending and starts waiting, in a goroutine, for active to reach 0.
// Then, unless ctx ended first, it calls ready with Idle or TimedOut. It returns false, and
// does nothing, if a restart was already pending.
func (c *Controller) Request(ctx context.Context, active func() int, every, maxWait time.Duration, ready func(Outcome)) bool {
	if !c.pending.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		if o := Wait(ctx, active, every, maxWait); o != Cancelled {
			ready(o)
		}
	}()
	return true
}
