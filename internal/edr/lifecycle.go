// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Lifecycle registry: background services register a stopper that stops their goroutine and
// flushes pending state. StopAll runs them in reverse registration order (dependants first).

// StopTimeout bounds each individual stopper (further bounded by the StopAll context deadline).
var StopTimeout = 2 * time.Second

// StopResult reports how one stopper finished.
type StopResult struct {
	Name     string        `json:"name"`
	Err      string        `json:"error,omitempty"`
	TimedOut bool          `json:"timed_out,omitempty"`
	Panicked bool          `json:"panicked,omitempty"`
	Took     time.Duration `json:"took_ns"`
}

type stopper struct {
	name string
	fn   func(context.Context) error
}

var lc struct {
	mu       sync.Mutex
	stoppers []stopper
	stopping bool
	results  []StopResult
	ctx      context.Context
	cancel   context.CancelFunc
	bg       sync.WaitGroup
}

func lcInitLocked() {
	if lc.ctx == nil {
		lc.ctx, lc.cancel = context.WithCancel(context.Background())
	}
}

// RegisterStopper adds a stopper. Registrations after StopAll has started are ignored so a late
// registration cannot hang shutdown.
func RegisterStopper(name string, fn func(context.Context) error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if lc.stopping {
		return
	}
	lc.stoppers = append(lc.stoppers, stopper{name, fn})
}

// LifecycleContext is cancelled when StopAll starts; context-driven loops should derive from it.
func LifecycleContext() context.Context {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lcInitLocked()
	return lc.ctx
}

// lcGo runs fn as a tracked goroutine that StopAll waits for (bounded) after cancelling the context.
func lcGo(fn func()) {
	lc.bg.Add(1)
	go func() { defer lc.bg.Done(); fn() }()
}

// lcSleep sleeps d or until ctx is done; reports whether the full sleep elapsed.
func lcSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ShuttingDown reports whether shutdown has begun (drives /readyz).
func ShuttingDown() bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.stopping
}

// BeginShutdown flips readiness to 503 without running stoppers (the server calls it before
// draining HTTP connections; StopAll also sets it).
func BeginShutdown() {
	lc.mu.Lock()
	lc.stopping = true
	lc.mu.Unlock()
}

// StopAll stops every registered service in reverse registration order. Each stopper gets at most
// StopTimeout (and never more than ctx allows); panics are contained; a timed-out stopper is
// reported and abandoned. Idempotent: later calls return the first call's results.
func StopAll(ctx context.Context) []StopResult {
	lc.mu.Lock()
	if lc.results != nil {
		r := append([]StopResult(nil), lc.results...)
		lc.mu.Unlock()
		return r
	}
	lcInitLocked()
	lc.stopping = true
	sts := lc.stoppers
	lc.stoppers = nil
	cancel := lc.cancel
	lc.mu.Unlock()

	// Stop ctx-driven loops first so they stop producing work while stoppers flush.
	cancel()
	res := make([]StopResult, 0, len(sts)+1)
	for i := len(sts) - 1; i >= 0; i-- {
		res = append(res, runStopper(ctx, sts[i]))
	}
	t0 := time.Now()
	done := make(chan struct{})
	go func() { lc.bg.Wait(); close(done) }()
	wait := StopTimeout
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait {
		wait = time.Until(dl)
	}
	select {
	case <-done:
		res = append(res, StopResult{Name: "background-goroutines", Took: time.Since(t0)})
	case <-time.After(max(wait, 0)):
		res = append(res, StopResult{Name: "background-goroutines", TimedOut: true, Err: "timed out", Took: time.Since(t0)})
	}
	lc.mu.Lock()
	lc.results = res
	lc.mu.Unlock()
	return append([]StopResult(nil), res...)
}

func runStopper(ctx context.Context, s stopper) StopResult {
	start := time.Now()
	sctx, cancel := context.WithTimeout(ctx, StopTimeout)
	defer cancel()
	ch := make(chan StopResult, 1)
	go func() {
		out := StopResult{Name: s.name}
		defer func() {
			if p := recover(); p != nil {
				out.Panicked, out.Err = true, fmt.Sprint("panic: ", p)
			}
			ch <- out
		}()
		if err := s.fn(sctx); err != nil {
			out.Err = err.Error()
		}
	}()
	var r StopResult
	select {
	case r = <-ch:
	case <-sctx.Done():
		r = StopResult{Name: s.name, TimedOut: true, Err: "timed out"}
	}
	r.Took = time.Since(start)
	return r
}

// StopAllForTest stops everything, then resets the registry so tests can register again.
func StopAllForTest() []StopResult {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := StopAll(ctx)
	lc.mu.Lock()
	lc.stopping, lc.results, lc.stoppers = false, nil, nil
	lc.ctx, lc.cancel = nil, nil
	lc.mu.Unlock()
	return r
}
