// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"
)

// seqEvent is the normalized event kavach-seq evaluates. F holds string,
// int64 or bool values keyed by catalogue field name.
type seqEvent struct {
	Cat  string
	ID   string
	Time time.Time
	F    map[string]any
}

func (e *seqEvent) str(f string) string {
	s, _ := e.F[f].(string)
	if len(s) > seqValueCap {
		return s[:seqValueCap]
	}
	return s
}
func (e *seqEvent) num(f string) int64 { n, _ := e.F[f].(int64); return n }
func (e *seqEvent) boolean(f string) bool {
	b, _ := e.F[f].(bool)
	return b
}

// globMatch implements * (any run) and ? (one byte) with linear-ish
// backtracking over a single star; the pattern length is capped by the parser.
func globMatch(pat, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pat) && (pat[p] == '?' || pat[p] == s[i]) && pat[p] != '*':
			p++
			i++
		case p < len(pat) && pat[p] == '*':
			star = p
			mark = i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}

func compileLeaf(n *seqNode, typ seqFType) func(*seqEvent) bool {
	f := n.Field
	switch typ {
	case ftInt:
		ints := n.Ints
		switch n.Op {
		case "==":
			return func(e *seqEvent) bool { return e.num(f) == ints[0] }
		case "!=":
			return func(e *seqEvent) bool { return e.num(f) != ints[0] }
		case "<":
			return func(e *seqEvent) bool { return e.num(f) < ints[0] }
		case "<=":
			return func(e *seqEvent) bool { return e.num(f) <= ints[0] }
		case ">":
			return func(e *seqEvent) bool { return e.num(f) > ints[0] }
		case ">=":
			return func(e *seqEvent) bool { return e.num(f) >= ints[0] }
		case "in":
			return func(e *seqEvent) bool {
				v := e.num(f)
				for _, x := range ints {
					if x == v {
						return true
					}
				}
				return false
			}
		}
	case ftBool:
		want := n.Bools[0]
		if n.Op == "==" {
			return func(e *seqEvent) bool { return e.boolean(f) == want }
		}
		return func(e *seqEvent) bool { return e.boolean(f) != want }
	case ftString:
		strs := n.Strs
		switch n.Op {
		case "==":
			return func(e *seqEvent) bool { return e.str(f) == strs[0] }
		case "!=":
			return func(e *seqEvent) bool { return e.str(f) != strs[0] }
		case "in":
			return func(e *seqEvent) bool {
				v := e.str(f)
				for _, x := range strs {
					if x == v {
						return true
					}
				}
				return false
			}
		case ":": // case-insensitive wildcard match, any of the list
			low := make([]string, len(strs))
			for i, s := range strs {
				low[i] = strings.ToLower(s)
			}
			return func(e *seqEvent) bool {
				v := strings.ToLower(e.str(f))
				for _, x := range low {
					if globMatch(x, v) {
						return true
					}
				}
				return false
			}
		case "like": // case-sensitive wildcard
			return func(e *seqEvent) bool {
				v := e.str(f)
				for _, x := range strs {
					if globMatch(x, v) {
						return true
					}
				}
				return false
			}
		case "startswith":
			return func(e *seqEvent) bool { return strings.HasPrefix(e.str(f), strs[0]) }
		case "endswith":
			return func(e *seqEvent) bool { return strings.HasSuffix(e.str(f), strs[0]) }
		case "contains":
			return func(e *seqEvent) bool { return strings.Contains(e.str(f), strs[0]) }
		case "regex":
			re := n.Re
			return func(e *seqEvent) bool { return re.MatchString(e.str(f)) }
		}
	}
	return func(*seqEvent) bool { return false }
}

// ---- event collection ----

func hashID(prefix string, v any) string {
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return prefix + hex.EncodeToString(d[:8])
}

func processSeqEvent(e Event) seqEvent {
	id := e.ID
	if id == "" {
		id = hashID("p:", e)
	} else {
		id = "p:" + id
	}
	return seqEvent{Cat: "process", ID: id, Time: e.Time, F: map[string]any{
		"host": e.Host, "pid": int64(e.PID), "ppid": int64(e.PPID), "uid": int64(e.UID),
		"executable": e.Executable, "parent_exe": e.ParentExe, "command": e.Command, "process_start": e.ProcessStart}}
}

func networkSeqEvent(n NetworkEvent) seqEvent {
	id := n.ID
	if id == "" {
		id = hashID("n:", n)
	} else {
		id = "n:" + id
	}
	return seqEvent{Cat: "network", ID: id, Time: n.Time, F: map[string]any{
		"host": n.Host, "pid": int64(n.PID), "destination": n.Destination, "verdict": n.Verdict,
		"source": n.Source, "process_start": n.ProcessStart}}
}

func fileSeqEvent(e FileEvent) seqEvent {
	id := e.ID
	if id == "" {
		id = hashID("f:", e)
	} else {
		id = "f:" + id
	}
	return seqEvent{Cat: "file", ID: id, Time: e.Time, F: map[string]any{
		"host": e.Host, "pid": int64(e.PID), "path": e.Path, "operation": e.Operation, "size": e.Size}}
}

func telemetrySeqEvent(typ string, e TelemetryEvent) seqEvent {
	f := map[string]any{"host": e.Host, "pid": int64(e.PID), "user": e.User}
	switch typ {
	case "registry":
		f["key"], f["value_name"], f["value_data"], f["operation"] = e.Key, e.ValueName, e.ValueData, e.Operation
	case "dns":
		f["query"], f["qtype"], f["answers"], f["resolver"] = e.Query, e.QType, strings.Join(e.Answers, ","), e.Resolver
	case "auth":
		f["source_ip"], f["method"], f["outcome"] = e.SourceIP, e.Method, e.Outcome
	case "module":
		f["module_path"], f["hash"], f["signed"], f["signer"], f["kind"] = e.ModulePath, e.Hash, e.Signed, e.Signer, e.Kind
	}
	return seqEvent{Cat: typ, ID: hashID("t"+typ[:1]+":", e), Time: e.Time, F: f}
}

// sortSeqEvents orders by time, then id, then the original (stable) order.
func sortSeqEvents(ev []seqEvent) {
	sort.SliceStable(ev, func(i, j int) bool {
		if !ev[i].Time.Equal(ev[j].Time) {
			return ev[i].Time.Before(ev[j].Time)
		}
		return ev[i].ID < ev[j].ID
	})
}

// seqSource returns raw events for the requested categories.
type seqSource interface {
	Events(cats map[string]bool) []seqEvent
}

type storeSeqSource struct{ s *Store }

func (ss storeSeqSource) Events(cats map[string]bool) []seqEvent {
	var out []seqEvent
	if ss.s != nil {
		ss.s.mu.Lock()
		if cats["process"] {
			for _, e := range ss.s.recentEvents {
				out = append(out, processSeqEvent(e))
			}
		}
		if cats["network"] {
			for _, e := range ss.s.networkEvents {
				out = append(out, networkSeqEvent(e))
			}
		}
		if cats["file"] {
			for _, e := range ss.s.fileEvents {
				out = append(out, fileSeqEvent(e))
			}
		}
		ss.s.mu.Unlock()
	}
	defaultTelemetryMu.RLock()
	ts := DefaultTelemetry
	defaultTelemetryMu.RUnlock()
	if ts != nil {
		ts.mu.Lock()
		for _, typ := range TelemetryTypes {
			if cats[typ] {
				for _, e := range ts.ring[typ] {
					out = append(out, telemetrySeqEvent(typ, e))
				}
			}
		}
		ts.mu.Unlock()
	}
	return out
}

// ---- evaluation ----

type seqMatch struct {
	Key    string
	Events []*seqEvent
}

type seqResult struct {
	Matches    []seqMatch
	Truncated  bool
	TimedOut   bool
	StepCounts []int // events satisfying each step (index len(Steps) = until)
	Scanned    map[string]int
	Considered int
}

func (q *seqQuery) cats() map[string]bool {
	m := map[string]bool{}
	for _, s := range q.Steps {
		m[s.Cat] = true
	}
	if q.Until != nil {
		m[q.Until.Cat] = true
	}
	return m
}

func joinKey(keys []string, e *seqEvent) (string, bool) {
	if len(keys) == 0 {
		return "", true
	}
	var sb strings.Builder
	for _, k := range keys {
		switch k {
		case "host":
			h := e.str("host")
			if h == "" {
				return "", false
			}
			sb.WriteString("host=" + h + " ")
		case "pid":
			p := e.num("pid")
			if p <= 0 {
				return "", false
			}
			sb.WriteString("pid=" + strconv.FormatInt(p, 10) + " ")
		}
	}
	return strings.TrimSpace(sb.String()), true
}

// runSeq evaluates q over events, which must already be sorted
// (sortSeqEvents) and time-filtered. Semantics (skip-till-next-match):
//
//  1. Events are partitioned by the join key (host/pid); events lacking a key
//     value are ignored. Without `by`, all events form one partition.
//  2. In a partition, scanning in (time, id) order, a candidate start is any
//     event satisfying step 1. From it each later step is bound to the
//     EARLIEST later event satisfying it (non-matching events are skipped).
//  3. An event satisfying the `until` condition seen after the start and
//     before the final step completes aborts that attempt. (An event that
//     satisfies both until and a step counts as until.)
//  4. With maxspan, the last event must be <= first event time + maxspan.
//  5. Matches in a partition do not overlap: after a match the next start
//     must come after its last event. A failed start is retried with the
//     next candidate start.
func runSeq(ctx context.Context, q *seqQuery, events []seqEvent, limit int) seqResult {
	if limit <= 0 || limit > seqMaxMatches {
		limit = seqMaxMatches
	}
	res := seqResult{StepCounts: make([]int, len(q.Steps)+1), Scanned: map[string]int{}}
	n := len(events)
	mask := make([]uint8, n)
	steps := q.Steps
	untilBit := uint8(1 << 7)
	for i := range events {
		if i&1023 == 0 && ctx.Err() != nil {
			res.TimedOut = true
			return res
		}
		ev := &events[i]
		res.Scanned[ev.Cat]++
		for si, st := range steps {
			if st.Cat == ev.Cat && st.Cond.pred(ev) {
				mask[i] |= 1 << uint(si)
				res.StepCounts[si]++
			}
		}
		if q.Until != nil && q.Until.Cat == ev.Cat && q.Until.Cond.pred(ev) {
			mask[i] |= untilBit
			res.StepCounts[len(steps)]++
		}
	}
	res.Considered = n

	if q.Kind == "single" {
		for i := range events {
			if mask[i]&1 != 0 {
				if len(res.Matches) >= limit {
					res.Truncated = true
					break
				}
				res.Matches = append(res.Matches, seqMatch{Events: []*seqEvent{&events[i]}})
			}
		}
		return res
	}

	groups := map[string][]int{}
	var order []string
	for i := range events {
		if mask[i] == 0 {
			continue // matches no step and no until: irrelevant to every attempt
		}
		k, ok := joinKey(q.Keys, &events[i])
		if !ok {
			continue
		}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	sort.Strings(order)

	type foundMatch struct {
		key string
		idx []int
	}
	var all []foundMatch
	steps0 := uint8(1)
	budget := 0
	for _, k := range order {
		g := groups[k]
		for si := 0; si < len(g); si++ {
			if mask[g[si]]&steps0 == 0 {
				continue
			}
			budget++
			if budget&255 == 0 && ctx.Err() != nil {
				res.TimedOut = true
				goto done
			}
			t0 := events[g[si]].Time
			chain := []int{g[si]}
			cur := si
			var outcome int // 0 ok, 1 fail-span, 2 fail-until, 3 fail-end
			untilAt := 0
			for step := 1; step < len(steps) && outcome == 0; step++ {
				found := false
				for j := cur + 1; j < len(g); j++ {
					if j&1023 == 0 && ctx.Err() != nil {
						res.TimedOut = true
						goto done
					}
					m := mask[g[j]]
					if q.MaxSpan > 0 && events[g[j]].Time.Sub(t0) > q.MaxSpan {
						outcome = 1
						break
					}
					if m&untilBit != 0 {
						outcome = 2
						untilAt = j
						break
					}
					if m&(1<<uint(step)) != 0 {
						chain = append(chain, g[j])
						cur = j
						found = true
						break
					}
				}
				if outcome == 0 && !found {
					outcome = 3
				}
			}
			switch outcome {
			case 0:
				all = append(all, foundMatch{k, chain})
				si = cur
			case 2:
				si = untilAt - 1 // every earlier start dies at the same until event
			case 3:
				si = len(g) // chains are monotone: later starts cannot succeed either
			}
		}
	}
done:
	sort.SliceStable(all, func(a, b int) bool {
		la, lb := all[a].idx[len(all[a].idx)-1], all[b].idx[len(all[b].idx)-1]
		if la != lb {
			return la < lb
		}
		return all[a].idx[0] < all[b].idx[0]
	})
	for _, f := range all {
		if len(res.Matches) >= limit {
			res.Truncated = true
			break
		}
		m := seqMatch{Key: f.key}
		for _, ix := range f.idx {
			m.Events = append(m.Events, &events[ix])
		}
		res.Matches = append(res.Matches, m)
	}
	return res
}
