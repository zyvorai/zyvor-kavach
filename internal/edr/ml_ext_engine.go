// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Extended local models: DNS tunneling/DGA bursts, per-user behaviour, peer-group outliers and the
// alert-fatigue advisor. Statistical, local, no network, no LLM. State is counts and hashes only,
// capped, persisted to <store>.mlext.json, and resettable. Observation only: nothing here acts.

const (
	mlExtVersion   = 1
	mlExtMaxHosts  = 128
	mlExtMaxUsers  = 256
	mlExtMaxItems  = 200 // per-host / per-user vocabulary cap
	mlExtMaxBatch  = 50000
	mlExtSaveEvery = 30 * time.Second
	mlExtPollEvery = 2 * time.Second
)

type mlExtState struct {
	Version int                    `json:"version"`
	Method  string                 `json:"method"`
	Updated time.Time              `json:"updated"`
	DNS     map[string]*mlDNSHost  `json:"dns"`
	Users   map[string]*mlUser     `json:"users"`
	Peers   map[string]*mlPeerHost `json:"peers"`
	Cursor  map[string]string      `json:"cursor"`
	Learned map[string]int         `json:"learned"`
	Dropped map[string]int         `json:"dropped"` // events not learned because a cap was reached
}

func newMLExtState() *mlExtState {
	return &mlExtState{Version: mlExtVersion, Method: mlMethod, DNS: map[string]*mlDNSHost{}, Users: map[string]*mlUser{},
		Peers: map[string]*mlPeerHost{}, Cursor: map[string]string{}, Learned: map[string]int{}, Dropped: map[string]int{}}
}

type mlExtEngine struct {
	op    sync.Mutex // serialises poll/replay/reset
	mu    sync.Mutex // guards st
	st    *mlExtState
	path  string
	store *Store
	dirty bool
	saved time.Time
	quit  chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newMLExtEngine(store *Store) *mlExtEngine {
	e := &mlExtEngine{store: store, st: newMLExtState(), quit: make(chan struct{}), done: make(chan struct{})}
	if store != nil {
		e.path = store.path + ".mlext.json"
		if b, err := os.ReadFile(e.path); err == nil {
			var s mlExtState
			if json.Unmarshal(b, &s) == nil && s.Version == mlExtVersion {
				n := newMLExtState()
				for k, v := range s.DNS {
					if v != nil {
						n.DNS[k] = v
					}
				}
				for k, v := range s.Users {
					if v != nil {
						if v.Procs == nil {
							v.Procs = map[string]int{}
						}
						if v.Anom == nil {
							v.Anom = map[string]int{}
						}
						n.Users[k] = v
					}
				}
				for k, v := range s.Peers {
					if v != nil {
						if v.Proc == nil {
							v.Proc = map[string]int{}
						}
						if v.Dest == nil {
							v.Dest = map[string]int{}
						}
						n.Peers[k] = v
					}
				}
				for k, v := range s.Cursor {
					n.Cursor[k] = v
				}
				for k, v := range s.Learned {
					n.Learned[k] = v
				}
				for k, v := range s.Dropped {
					n.Dropped[k] = v
				}
				n.Updated = s.Updated
				e.st = n
			}
		}
	}
	return e
}

func (e *mlExtEngine) saveLocked() {
	if e.path == "" {
		return
	}
	e.st.Updated = time.Now().UTC()
	b, err := json.Marshal(e.st)
	if err != nil {
		return
	}
	tmp := e.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, e.path) == nil {
		e.dirty = false
		e.saved = time.Now()
	}
}

// ---------- learning ----------

func mlKeyT(t TelemetryEvent) string {
	return strconv.FormatInt(t.Time.UnixNano(), 10) + "|" + t.Host + "|" + t.User + "|" + t.Query + "|" + t.Outcome + "|" + t.Method + "|" + strconv.Itoa(t.PID)
}

// telemetryTail copies the ring for typ under the telemetry store's lock and returns the part after last.
func telemetryTail(typ, last string, max int) ([]TelemetryEvent, string) {
	defaultTelemetryMu.RLock()
	ts := DefaultTelemetry
	defaultTelemetryMu.RUnlock()
	if ts == nil {
		return nil, last
	}
	ts.mu.Lock()
	out, nk := mlTail(ts.ring[typ], mlKeyT, last, max)
	ts.mu.Unlock()
	return out, nk
}

// apply* learn one event. Callers hold e.mu. They never read the wall clock, so replaying the same
// event sequence yields the same state.
func (e *mlExtEngine) applyProcess(ev Event) {
	e.st.Learned["process"]++
	e.learnUserProc(ev)
	e.learnPeerProc(ev)
}

func (e *mlExtEngine) applyNetwork(n NetworkEvent) {
	e.st.Learned["network"]++
	e.learnPeerDest(n)
	if name := mlDestHostname(n.Destination); name != "" {
		e.learnDNS(n.Host, name, n.Time)
	}
}

func (e *mlExtEngine) applyTelemetry(typ string, t TelemetryEvent) {
	switch typ {
	case "dns":
		e.st.Learned["dns"]++
		e.learnDNS(t.Host, t.Query, t.Time)
	case "auth":
		e.st.Learned["auth"]++
		e.learnUserAuth(t)
	}
}

// mlDestHostname returns the host part of a destination when it looks like a name (not an IP).
func mlDestHostname(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return ""
	}
	if i := strings.LastIndex(d, ":"); i > 0 && !strings.Contains(d[:i], ":") {
		d = d[:i]
	}
	if !strings.Contains(d, ".") || strings.Trim(d, "0123456789.") == "" || strings.Contains(d, ":") {
		return ""
	}
	return d
}

func (e *mlExtEngine) poll() {
	if e.store == nil {
		return
	}
	e.op.Lock()
	defer e.op.Unlock()
	e.mu.Lock()
	cp, cn, cd, ca := e.st.Cursor["p"], e.st.Cursor["n"], e.st.Cursor["d"], e.st.Cursor["a"]
	e.mu.Unlock()
	e.store.mu.Lock()
	ps, np := mlTail(e.store.recentEvents, mlKeyP, cp, mlExtMaxBatch)
	ns, nn := mlTail(e.store.networkEvents, mlKeyN, cn, mlExtMaxBatch)
	e.store.mu.Unlock()
	ds, nd := telemetryTail("dns", cd, mlExtMaxBatch)
	as, na := telemetryTail("auth", ca, mlExtMaxBatch)
	if len(ps)+len(ns)+len(ds)+len(as) == 0 {
		e.maybeSave()
		return
	}
	e.mu.Lock()
	for _, x := range ps {
		e.applyProcess(x)
	}
	for _, x := range ns {
		e.applyNetwork(x)
	}
	for _, x := range ds {
		e.applyTelemetry("dns", x)
	}
	for _, x := range as {
		e.applyTelemetry("auth", x)
	}
	e.st.Cursor["p"], e.st.Cursor["n"], e.st.Cursor["d"], e.st.Cursor["a"] = np, nn, nd, na
	e.dirty = true
	e.mu.Unlock()
	e.maybeSave()
}

func (e *mlExtEngine) maybeSave() {
	e.mu.Lock()
	if e.dirty && time.Since(e.saved) >= mlExtSaveEvery {
		e.saveLocked()
	}
	e.mu.Unlock()
}

func (e *mlExtEngine) run() {
	t := time.NewTicker(mlExtPollEvery)
	defer t.Stop()
	defer close(e.done)
	for {
		select {
		case <-e.quit:
			return
		case <-t.C:
			e.poll()
		}
	}
}

// Shutdown stops the poll loop and flushes state if dirty.
func (e *mlExtEngine) Shutdown(ctx context.Context) error {
	e.once.Do(func() { close(e.quit) })
	select {
	case <-e.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	e.poll()
	e.op.Lock()
	defer e.op.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dirty {
		e.saveLocked()
	}
	return nil
}

// reset discards learned state and moves the cursors to the current tails so retained events are
// not re-learned (same contract as POST /v1/ml/reset).
func (e *mlExtEngine) reset() {
	e.op.Lock()
	defer e.op.Unlock()
	st := newMLExtState()
	if e.store != nil {
		e.store.mu.Lock()
		if n := len(e.store.recentEvents); n > 0 {
			st.Cursor["p"] = mlKeyP(e.store.recentEvents[n-1])
		}
		if n := len(e.store.networkEvents); n > 0 {
			st.Cursor["n"] = mlKeyN(e.store.networkEvents[n-1])
		}
		e.store.mu.Unlock()
		defaultTelemetryMu.RLock()
		ts := DefaultTelemetry
		defaultTelemetryMu.RUnlock()
		if ts != nil {
			ts.mu.Lock()
			if r := ts.ring["dns"]; len(r) > 0 {
				st.Cursor["d"] = mlKeyT(r[len(r)-1])
			}
			if r := ts.ring["auth"]; len(r) > 0 {
				st.Cursor["a"] = mlKeyT(r[len(r)-1])
			}
			ts.mu.Unlock()
		}
	}
	e.mu.Lock()
	e.st = st
	e.dirty = true
	e.saveLocked()
	e.mu.Unlock()
}

// replay rebuilds the models from the retained events only.
func (e *mlExtEngine) replay() map[string]int {
	e.op.Lock()
	e.mu.Lock()
	e.st = newMLExtState()
	e.mu.Unlock()
	e.op.Unlock()
	e.poll()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dirty = true
	e.saveLocked()
	out := map[string]int{}
	for k, v := range e.st.Learned {
		out[k] = v
	}
	return out
}

func mlSortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	sort.Strings(k)
	return k
}

// ---------- optional priority-fusion factors ----------

// mlExtFactorFn contributes optional factors (and omission notes) to /v1/ml/priority.
type mlExtFactorFn func(f Finding, c *priorityCtx) ([]PriorityFactor, []string)

var mlExtFactorHook atomic.Pointer[mlExtFactorFn]

// Hooks that let the existing reset/replay endpoints cascade to the extended models.
var (
	mlExtResetHook  atomic.Pointer[func()]
	mlExtReplayHook atomic.Pointer[func()]
)

// Weights of the optional factors, appended to mlPriorityWeights. Small on purpose: advisory.
var mlExtWeights = []struct {
	Name   string
	Weight float64
}{
	{"dns_anomaly", 0.10},
	{"user_behaviour", 0.08},
	{"peer_outlier", 0.07},
	{"rule_fatigue", 0.05},
}

func init() {
	mlPriorityWeights = append(mlPriorityWeights, mlExtWeights...)
}

func mlExtWeight(n string) float64 {
	for _, x := range mlExtWeights {
		if x.Name == n {
			return x.Weight
		}
	}
	return 0
}

func (e *mlExtEngine) factors(f Finding, c *priorityCtx) ([]PriorityFactor, []string) {
	var fs []PriorityFactor
	var om []string
	if v, note, ok := e.dnsFactor(f.Host, f.Time); ok {
		fs = append(fs, PriorityFactor{"dns_anomaly", v, mlExtWeight("dns_anomaly"), note})
	} else {
		om = append(om, "dns_anomaly: "+note)
	}
	if v, note, ok := e.userFactor(f); ok {
		fs = append(fs, PriorityFactor{"user_behaviour", v, mlExtWeight("user_behaviour"), note})
	} else {
		om = append(om, "user_behaviour: "+note)
	}
	if v, note, ok := e.peerFactor(c, f.Host); ok {
		fs = append(fs, PriorityFactor{"peer_outlier", v, mlExtWeight("peer_outlier"), note})
	} else {
		om = append(om, "peer_outlier: "+note)
	}
	if h, ok := c.health[f.Rule]; ok {
		if fr := fatigueFor(h, c.fb[f.Rule]); fr.Status == "ok" {
			fs = append(fs, PriorityFactor{"rule_fatigue", 1 - fr.Score/100, mlExtWeight("rule_fatigue"),
				"alert-fatigue score " + f2(fr.Score) + "/100 for this rule (advisory; overlaps rule_trust, kept small)"})
		} else {
			om = append(om, "rule_fatigue: not enough data for this rule")
		}
	} else {
		om = append(om, "rule_fatigue: no rule health for this rule")
	}
	return fs, om
}

// RegisterMLExt wires the extended local models and starts the incremental learner.
func RegisterMLExt(mux *http.ServeMux, token string, store *Store) {
	eng := newMLExtEngine(store)
	go eng.run()
	RegisterStopper("ml-ext", eng.Shutdown)
	fn := mlExtFactorFn(eng.factors)
	mlExtFactorHook.Store(&fn)
	rs, rp := eng.reset, func() { eng.replay() }
	mlExtResetHook.Store(&rs)
	mlExtReplayHook.Store(&rp)
	RegisterStopper("ml-ext-hooks", func(context.Context) error {
		mlExtFactorHook.CompareAndSwap(&fn, nil)
		mlExtResetHook.CompareAndSwap(&rs, nil)
		mlExtReplayHook.CompareAndSwap(&rp, nil)
		return nil
	})
	registerMLExtHTTP(mux, token, store, eng)
}
