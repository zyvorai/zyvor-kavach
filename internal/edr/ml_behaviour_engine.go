// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"hash/fnv"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fleet-learned local behaviour models: statistical, local, explainable. No external calls, no LLM.
// State is counts and hashed n-gram vectors only; raw command lines are never stored.

const (
	mlMethod = "statistical, learned from this deployment"

	mlMinLineageFleet = 200 // below this many transitions the fleet lineage model returns not_enough_data
	mlMinLineageHost  = 100 // ... and the per-host scope
	mlSmoothing       = 0.5 // additive (Lidstone) smoothing
	mlSurprisalBits   = 7.0 // documented "novel transition" threshold
	mlMaxHosts        = 64
	mlMaxEdgesHost    = 1000
	mlMaxEdgesFleet   = 5000
	mlMaxName         = 64

	mlVecDim       = 1 << 14
	mlHistCap      = 128 // reservoir size per host
	mlHistHosts    = 32
	mlHistKeep     = 64 // non-zero features kept per stored history vector
	mlHistMin      = 20 // minimum history vectors before host-history similarity is reported
	mlMaxQuery     = 2048
	mlSimThreshold = 0.70 // documented "similar to known bad" cosine threshold

	mlAlpha        = 0.3 // EWMA weight
	mlSlots        = 168
	mlMinSlotN     = 4  // minimum samples in an hour-of-week slot
	mlMinHostHours = 48 // minimum closed hours for a host/metric
	mlZThreshold   = 3.0
	mlMaxDests     = 4096
	mlSaveEvery    = 30 * time.Second
	mlPollEvery    = 2 * time.Second
	mlMaxBatch     = 50000
)

var mlMetrics = []string{"exec_count", "new_destination_count", "file_event_burst"}

type mlLinScope struct {
	Total   int                       `json:"total"`
	Edges   int                       `json:"edges"`
	Dropped int                       `json:"dropped,omitempty"`
	P       map[string]map[string]int `json:"p"` // parent basename -> child basename -> count
	PT      map[string]int            `json:"pt"`
}

func newLinScope() *mlLinScope {
	return &mlLinScope{P: map[string]map[string]int{}, PT: map[string]int{}}
}

type mlVec struct {
	Idx []uint16 `json:"i"`
	W   []uint8  `json:"w"`
}

type mlHist struct {
	Seen int     `json:"seen"`
	Vecs []mlVec `json:"v"`
}

type mlSlot struct {
	N    int     `json:"n"`
	Mean float64 `json:"m"`
	Var  float64 `json:"v"`
}

type mlMetricState struct {
	Slots     [mlSlots]mlSlot `json:"slots"`
	OpenHas   bool            `json:"open_has,omitempty"`
	OpenHour  int64           `json:"open_hour,omitempty"`
	OpenCount float64         `json:"open_count,omitempty"`
	Closed    int             `json:"closed"`
	LastHour  int64           `json:"last_hour,omitempty"`
	LastCount float64         `json:"last_count,omitempty"`
	LastZ     float64         `json:"last_z,omitempty"`
	LastZOK   bool            `json:"last_z_ok,omitempty"`
	Anomalies int             `json:"anomalies,omitempty"`
}

type mlHostBase struct {
	M     map[string]*mlMetricState `json:"m"`
	Dests []uint64                  `json:"dests,omitempty"`
}

type mlState struct {
	Version int                    `json:"version"`
	Method  string                 `json:"method"`
	Updated time.Time              `json:"updated"`
	Fleet   *mlLinScope            `json:"lineage_fleet"`
	Hosts   map[string]*mlLinScope `json:"lineage_hosts"`
	Hist    map[string]*mlHist     `json:"history"`
	Base    map[string]*mlHostBase `json:"baselines"`
	Cursor  map[string]string      `json:"cursor"`
	Learned map[string]int         `json:"learned"` // events learned per kind
}

func newMLState() *mlState {
	return &mlState{Version: 1, Method: mlMethod, Fleet: newLinScope(), Hosts: map[string]*mlLinScope{},
		Hist: map[string]*mlHist{}, Base: map[string]*mlHostBase{}, Cursor: map[string]string{}, Learned: map[string]int{}}
}

type mlEngine struct {
	op    sync.Mutex // serialises poll/replay/reset
	mu    sync.Mutex // guards st
	st    *mlState
	path  string
	store *Store
	dirty bool
	saved time.Time
}

func newMLEngine(store *Store) *mlEngine {
	e := &mlEngine{store: store, st: newMLState()}
	if store != nil {
		e.path = store.path + ".mlbehaviour.json"
		if b, err := os.ReadFile(e.path); err == nil {
			var s mlState
			if json.Unmarshal(b, &s) == nil && s.Version == 1 {
				n := newMLState()
				if s.Fleet != nil {
					n.Fleet = s.Fleet
				}
				for k, v := range s.Hosts {
					n.Hosts[k] = v
				}
				for k, v := range s.Hist {
					n.Hist[k] = v
				}
				for k, v := range s.Base {
					n.Base[k] = v
				}
				for k, v := range s.Cursor {
					n.Cursor[k] = v
				}
				for k, v := range s.Learned {
					n.Learned[k] = v
				}
				n.Updated = s.Updated
				e.st = n
			}
		}
	}
	return e
}

func (e *mlEngine) saveLocked() {
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

// ---------- helpers ----------

func mlBase(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	p = strings.ToLower(p)
	if len(p) > mlMaxName {
		p = strings.ToValidUTF8(p[:mlMaxName], "")
	}
	return p
}

func mlHash(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64() & 0xFFFFFFFFFFFF
}

// ---------- model (a): process lineage ----------

func (s *mlLinScope) add(parent, child string, maxEdges int) {
	row := s.P[parent]
	if row == nil {
		row = map[string]int{}
	}
	if _, ok := row[child]; !ok {
		if s.Edges >= maxEdges {
			s.Dropped++
			return
		}
		s.Edges++
	}
	row[child]++
	s.P[parent] = row
	s.PT[parent]++
	s.Total++
}

// mlSurprisal returns -log2 P(child|parent) with additive smoothing over vocabulary size v.
func mlSurprisal(s *mlLinScope, parent, child string, v int) (bits float64, count int, parentSeen bool) {
	if v < 1 {
		v = 1
	}
	count = s.P[parent][child]
	pt := s.PT[parent]
	p := (float64(count) + mlSmoothing) / (float64(pt) + mlSmoothing*float64(v+1)) // +1 slot for "unseen child"
	return -math.Log2(p), count, pt > 0
}

func mlVocab(s *mlLinScope) int {
	seen := map[string]struct{}{}
	for _, row := range s.P {
		for c := range row {
			seen[c] = struct{}{}
		}
	}
	return len(seen)
}

func (e *mlEngine) learnLineage(host, parent, child string) {
	if parent == "" || child == "" {
		return
	}
	e.st.Fleet.add(parent, child, mlMaxEdgesFleet)
	h := e.st.Hosts[host]
	if h == nil {
		if len(e.st.Hosts) >= mlMaxHosts {
			return
		}
		h = newLinScope()
		e.st.Hosts[host] = h
	}
	h.add(parent, child, mlMaxEdgesHost)
}

// ---------- model (b): command-line similarity ----------

func mlFeaturize(cmd string, keep int) mlVec {
	cmd = strings.ToLower(strings.Join(strings.Fields(cmd), " "))
	if len(cmd) > mlMaxQuery {
		cmd = strings.ToValidUTF8(cmd[:mlMaxQuery], "")
	}
	cnt := map[uint16]float64{}
	for n := 3; n <= 5; n++ {
		for i := 0; i+n <= len(cmd); i++ {
			h := fnv.New32a()
			h.Write([]byte(cmd[i : i+n]))
			cnt[uint16(h.Sum32()&(mlVecDim-1))]++
		}
	}
	type kv struct {
		i uint16
		w float64
	}
	all := make([]kv, 0, len(cnt))
	mx := 0.0
	for i, c := range cnt {
		w := math.Sqrt(c)
		all = append(all, kv{i, w})
		if w > mx {
			mx = w
		}
	}
	sort.Slice(all, func(a, b int) bool {
		if all[a].w != all[b].w {
			return all[a].w > all[b].w
		}
		return all[a].i < all[b].i
	})
	if keep > 0 && len(all) > keep {
		all = all[:keep]
	}
	sort.Slice(all, func(a, b int) bool { return all[a].i < all[b].i })
	v := mlVec{Idx: make([]uint16, len(all)), W: make([]uint8, len(all))}
	for k, x := range all {
		v.Idx[k] = x.i
		q := math.Round(x.w / mx * 255)
		if q < 1 {
			q = 1
		}
		v.W[k] = uint8(q)
	}
	return v
}

func (v mlVec) norm() float64 {
	s := 0.0
	for _, w := range v.W {
		s += float64(w) * float64(w)
	}
	return math.Sqrt(s)
}

func mlCosine(a, b mlVec) float64 {
	return mlCosineN(a, a.norm(), b, b.norm())
}

func mlCosineN(a mlVec, na float64, b mlVec, nb float64) float64 {
	if na == 0 || nb == 0 {
		return 0
	}
	dot, i, j := 0.0, 0, 0
	for i < len(a.Idx) && j < len(b.Idx) {
		switch {
		case a.Idx[i] == b.Idx[j]:
			dot += float64(a.W[i]) * float64(b.W[j])
			i++
			j++
		case a.Idx[i] < b.Idx[j]:
			i++
		default:
			j++
		}
	}
	return dot / (na * nb)
}

type mlExemplar struct {
	Rule      string
	Name      string
	Technique string
	Tactic    string
	Vec       mlVec
	Norm      float64
}

var mlExemplars []mlExemplar

// init builds the known-bad exemplar set from the positive samples of process-type content rules.
func init() {
	packs, err := embeddedContentPacks()
	if err != nil {
		return
	}
	reg, _ := buildContentRegistry(packs)
	if reg == nil {
		return
	}
	for _, r := range reg.rules {
		if r.EventType != "process" || r.Tests == nil {
			continue
		}
		for _, p := range r.Tests.Positive {
			if strings.TrimSpace(p.Command) == "" {
				continue
			}
			v := mlFeaturize(p.Command, 0)
			mlExemplars = append(mlExemplars, mlExemplar{Rule: r.ID, Name: r.Name, Technique: r.Technique, Tactic: r.Tactic, Vec: v, Norm: v.norm()})
		}
	}
}

type mlNeighbour struct {
	Similarity float64 `json:"similarity"`
	Rule       string  `json:"rule_id,omitempty"`
	Name       string  `json:"rule_name,omitempty"`
	Technique  string  `json:"technique,omitempty"`
	Tactic     string  `json:"tactic,omitempty"`
}

func mlNearestExemplars(q mlVec, k int) []mlNeighbour {
	best := map[string]mlNeighbour{}
	qn := q.norm()
	for i := range mlExemplars {
		x := &mlExemplars[i]
		s := mlCosineN(q, qn, x.Vec, x.Norm)
		if cur, ok := best[x.Rule]; !ok || s > cur.Similarity {
			best[x.Rule] = mlNeighbour{Similarity: math.Round(s*1000) / 1000, Rule: x.Rule, Name: x.Name, Technique: x.Technique, Tactic: x.Tactic}
		}
	}
	out := make([]mlNeighbour, 0, len(best))
	for _, n := range best {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Similarity != out[j].Similarity {
			return out[i].Similarity > out[j].Similarity
		}
		return out[i].Rule < out[j].Rule
	})
	if len(out) > k {
		out = out[:k]
	}
	return out
}

func (e *mlEngine) learnCommand(host, cmd string) {
	if strings.TrimSpace(cmd) == "" {
		return
	}
	h := e.st.Hist[host]
	if h == nil {
		if len(e.st.Hist) >= mlHistHosts {
			return
		}
		h = &mlHist{}
		e.st.Hist[host] = h
	}
	v := mlFeaturize(cmd, mlHistKeep)
	h.Seen++
	if len(h.Vecs) < mlHistCap {
		h.Vecs = append(h.Vecs, v)
		return
	}
	// Algorithm R with a deterministic pseudo-random index derived from (host, count).
	j := int(mlHash(host+"#"+strconv.Itoa(h.Seen)) % uint64(h.Seen))
	if j < mlHistCap {
		h.Vecs[j] = v
	}
}

// ---------- model (c): per-host hour-of-week baselines ----------

func mlSlotOf(hour int64) int {
	t := time.Unix(hour*3600, 0).UTC()
	return int(t.Weekday())*24 + t.Hour()
}

func mlSD(s mlSlot) float64 {
	return math.Max(math.Max(math.Sqrt(s.Var), 0.1*s.Mean), 1.0)
}

// mlZ scores x against the slot; ok=false means not enough history.
func mlZ(m *mlMetricState, slot int, x float64) (float64, bool) {
	s := m.Slots[slot]
	if s.N < mlMinSlotN || m.Closed < mlMinHostHours {
		return 0, false
	}
	return (x - s.Mean) / mlSD(s), true
}

func (m *mlMetricState) fold(hour int64, x float64) {
	slot := mlSlotOf(hour)
	z, ok := mlZ(m, slot, x)
	m.LastHour, m.LastCount, m.LastZ, m.LastZOK = hour, x, z, ok
	if ok && z >= mlZThreshold {
		m.Anomalies++
	}
	s := &m.Slots[slot]
	if s.N == 0 {
		s.Mean, s.Var = x, 0
	} else {
		d := x - s.Mean
		s.Mean += mlAlpha * d
		s.Var = (1 - mlAlpha) * (s.Var + mlAlpha*d*d)
	}
	s.N++
	m.Closed++
}

// add counts n units in the hour containing t; closed hours (and idle gap hours, as zeros) are folded.
func (m *mlMetricState) add(t time.Time, n float64) {
	hour := t.Unix() / 3600
	switch {
	case !m.OpenHas:
		m.OpenHas, m.OpenHour, m.OpenCount = true, hour, n
	case hour == m.OpenHour:
		m.OpenCount += n
	case hour > m.OpenHour:
		m.fold(m.OpenHour, m.OpenCount)
		start := m.OpenHour + 1
		if hour-start > mlSlots {
			start = hour - mlSlots
		}
		for h := start; h < hour; h++ {
			m.fold(h, 0)
		}
		m.OpenHour, m.OpenCount = hour, n
	default: // out-of-order older event: ignored
	}
}

func (e *mlEngine) metric(host, name string) *mlMetricState {
	hb := e.st.Base[host]
	if hb == nil {
		if len(e.st.Base) >= mlMaxHosts {
			return nil
		}
		hb = &mlHostBase{M: map[string]*mlMetricState{}}
		e.st.Base[host] = hb
	}
	m := hb.M[name]
	if m == nil {
		m = &mlMetricState{}
		hb.M[name] = m
	}
	return m
}

func (e *mlEngine) learnDest(host, dest string, t time.Time) {
	m := e.metric(host, "new_destination_count")
	if m == nil {
		return
	}
	b := e.st.Base[host]
	h := mlHash(dest)
	for _, x := range b.Dests {
		if x == h {
			m.add(t, 0)
			return
		}
	}
	if len(b.Dests) < mlMaxDests {
		b.Dests = append(b.Dests, h)
	}
	m.add(t, 1)
}

// ---------- learning (apply) ----------

func (e *mlEngine) applyProcess(ev Event) {
	if ev.Host == "" {
		return
	}
	e.learnLineage(ev.Host, mlBase(ev.ParentExe), mlBase(ev.Executable))
	e.learnCommand(ev.Host, ev.Command)
	if m := e.metric(ev.Host, "exec_count"); m != nil {
		m.add(ev.Time, 1)
	}
	e.st.Learned["process"]++
	e.dirty = true
}

func (e *mlEngine) applyNetwork(n NetworkEvent) {
	if n.Host == "" || n.Destination == "" {
		return
	}
	e.learnDest(n.Host, strings.ToLower(n.Destination), n.Time)
	e.st.Learned["network"]++
	e.dirty = true
}

func (e *mlEngine) applyFile(f FileEvent) {
	if f.Host == "" {
		return
	}
	if m := e.metric(f.Host, "file_event_burst"); m != nil {
		m.add(f.Time, 1)
	}
	e.st.Learned["file"]++
	e.dirty = true
}

// ---------- hook: incremental tail of the store ----------

func mlKeyP(e Event) string {
	return strconv.FormatInt(e.Time.UnixNano(), 10) + "|" + e.Host + "|" + strconv.Itoa(e.PID) + "|" + e.ProcessStart + "|" + e.ID + "|" + e.Executable
}
func mlKeyN(n NetworkEvent) string {
	return strconv.FormatInt(n.Time.UnixNano(), 10) + "|" + n.Host + "|" + strconv.Itoa(n.PID) + "|" + n.ID + "|" + n.Destination
}
func mlKeyF(f FileEvent) string {
	return strconv.FormatInt(f.Time.UnixNano(), 10) + "|" + f.Host + "|" + f.ID + "|" + f.Path + "|" + f.Operation
}

func mlTail[T any](s []T, key func(T) string, last string, max int) ([]T, string) {
	if len(s) == 0 {
		return nil, last
	}
	start := 0
	if last != "" {
		for i := len(s) - 1; i >= 0; i-- {
			if key(s[i]) == last {
				start = i + 1
				break
			}
		}
	}
	if len(s)-start > max {
		start = len(s) - max
	}
	return append([]T(nil), s[start:]...), key(s[len(s)-1])
}

// poll learns events appended to the store since the last poll. The store lock is held only to
// copy the new tail (proportional to new events); all model work happens outside it.
func (e *mlEngine) poll() {
	if e.store == nil {
		return
	}
	e.op.Lock()
	defer e.op.Unlock()
	e.mu.Lock()
	cp, cn, cf := e.st.Cursor["p"], e.st.Cursor["n"], e.st.Cursor["f"]
	e.mu.Unlock()
	e.store.mu.Lock()
	ps, np := mlTail(e.store.recentEvents, mlKeyP, cp, mlMaxBatch)
	ns, nn := mlTail(e.store.networkEvents, mlKeyN, cn, mlMaxBatch)
	fs, nf := mlTail(e.store.fileEvents, mlKeyF, cf, mlMaxBatch)
	e.store.mu.Unlock()
	if len(ps)+len(ns)+len(fs) == 0 {
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
	for _, x := range fs {
		e.applyFile(x)
	}
	e.st.Cursor["p"], e.st.Cursor["n"], e.st.Cursor["f"] = np, nn, nf
	e.dirty = true
	e.mu.Unlock()
	e.maybeSave()
}

func (e *mlEngine) maybeSave() {
	e.mu.Lock()
	if e.dirty && time.Since(e.saved) >= mlSaveEvery {
		e.saveLocked()
	}
	e.mu.Unlock()
}

func (e *mlEngine) run(stop <-chan struct{}) {
	t := time.NewTicker(mlPollEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			e.poll()
		}
	}
}

// reset discards all learned state; the cursor is moved to the store tail so retained events are not re-learned.
func (e *mlEngine) reset() {
	e.op.Lock()
	defer e.op.Unlock()
	e.resetLocked()
}

func (e *mlEngine) resetLocked() {
	st := newMLState()
	if e.store != nil {
		e.store.mu.Lock()
		if n := len(e.store.recentEvents); n > 0 {
			st.Cursor["p"] = mlKeyP(e.store.recentEvents[n-1])
		}
		if n := len(e.store.networkEvents); n > 0 {
			st.Cursor["n"] = mlKeyN(e.store.networkEvents[n-1])
		}
		if n := len(e.store.fileEvents); n > 0 {
			st.Cursor["f"] = mlKeyF(e.store.fileEvents[n-1])
		}
		e.store.mu.Unlock()
	}
	e.mu.Lock()
	e.st = st
	e.dirty = true
	e.saveLocked()
	e.mu.Unlock()
}

// replay rebuilds all models from the events retained in the store (time-ordered per type).
func (e *mlEngine) replay() map[string]int {
	e.op.Lock()
	defer e.op.Unlock()
	e.resetLocked()
	if e.store == nil {
		return nil
	}
	e.store.mu.Lock()
	ps := append([]Event(nil), e.store.recentEvents...)
	ns := append([]NetworkEvent(nil), e.store.networkEvents...)
	fs := append([]FileEvent(nil), e.store.fileEvents...)
	e.store.mu.Unlock()
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Time.Before(ps[j].Time) })
	sort.SliceStable(ns, func(i, j int) bool { return ns[i].Time.Before(ns[j].Time) })
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Time.Before(fs[j].Time) })
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, x := range ps {
		e.applyProcess(x)
	}
	for _, x := range ns {
		e.applyNetwork(x)
	}
	for _, x := range fs {
		e.applyFile(x)
	}
	e.saveLocked()
	return map[string]int{"process": len(ps), "network": len(ns), "file": len(fs)}
}
