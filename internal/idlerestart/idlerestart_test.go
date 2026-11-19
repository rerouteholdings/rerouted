package idlerestart

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestWait(t *testing.T) {
	var calls atomic.Int64
	calls.Store(2)
	checks := 0
	active := func() int {
		checks++
		if checks == 3 {
			calls.Store(0) // the last call ends
		}
		return int(calls.Load())
	}
	if got := Wait(t.Context(), active, time.Millisecond, time.Minute); got != Idle || checks != 3 {
		t.Fatalf("Wait = %v after %d checks", got, checks)
	}
	if got := Wait(t.Context(), func() int { return 0 }, time.Hour, time.Hour); got != Idle {
		t.Fatal("idle from the start didn't return at once")
	}
	if got := Wait(t.Context(), func() int { return 1 }, time.Millisecond, 20*time.Millisecond); got != TimedOut {
		t.Fatalf("busy forever: %v", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := Wait(ctx, func() int { return 1 }, time.Hour, time.Hour); got != Cancelled {
		t.Fatalf("cancelled: %v", got)
	}
}

func TestController(t *testing.T) {
	var c Controller
	var voice atomic.Int64
	voice.Store(1)
	got := make(chan Outcome, 2)
	if !c.Request(t.Context(), func() int { return int(voice.Load()) }, time.Millisecond, time.Minute, func(o Outcome) { got <- o }) {
		t.Fatal("the first request was refused")
	}
	if !c.Pending() {
		t.Fatal("not pending")
	}
	if c.Request(t.Context(), func() int { return 0 }, time.Millisecond, time.Minute, func(o Outcome) { got <- o }) {
		t.Fatal("a second request started another wait")
	}
	select {
	case o := <-got:
		t.Fatalf("restarted with a call active: %v", o)
	case <-time.After(20 * time.Millisecond):
	}
	voice.Store(0)
	if o := <-got; o != Idle {
		t.Fatalf("outcome %v", o)
	}
	select {
	case o := <-got:
		t.Fatalf("ready twice: %v", o)
	case <-time.After(20 * time.Millisecond):
	}
}
