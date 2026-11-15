// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed hunt_eql_examples.json
var seqExamplesJSON []byte

// SeqExample is one ready-made kavach-seq query.
type SeqExample struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Technique   string   `json:"technique"`
	Description string   `json:"description"`
	Query       string   `json:"query"`
	Noisy       bool     `json:"noisy,omitempty"` // may legitimately fire on benign activity
	Tags        []string `json:"tags,omitempty"`
}

func seqExamples() []SeqExample {
	var ex []SeqExample
	_ = json.Unmarshal(seqExamplesJSON, &ex)
	return ex
}

const seqSemantics = "skip-till-next-match; events ordered by time then id; matches per join-key partition do not overlap; " +
	"events without a join-key value are ignored; until (before the last step) aborts an attempt; maxspan measured from the first event"

const seqTimeBudget = 5 * time.Second

func parseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if strings.HasSuffix(s, "d") {
		if n, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil && n >= 0 && n < 3650 {
			return now.Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return now.Add(-d), nil
	}
	return time.Parse(time.RFC3339, s)
}

// collectSeq gathers, filters, sorts and caps the events a query needs.
func collectSeq(src seqSource, q *seqQuery, since time.Time) (events []seqEvent, capped bool) {
	raw := src.Events(q.cats())
	for _, e := range raw {
		if !since.IsZero() && e.Time.Before(since) {
			continue
		}
		events = append(events, e)
	}
	sortSeqEvents(events)
	if len(events) > seqMaxScan {
		events = events[len(events)-seqMaxScan:]
		capped = true
	}
	return
}

func seqRenderEvent(step int, e *seqEvent) map[string]any {
	m := map[string]any{"step": step + 1, "category": e.Cat, "id": e.ID, "time": e.Time.UTC().Format(time.RFC3339Nano)}
	f := map[string]any{}
	for k, v := range e.F {
		switch x := v.(type) {
		case string:
			if x == "" {
				continue
			}
		case int64:
			if x == 0 && (k == "pid" || k == "size" || k == "ppid") {
				continue
			}
		}
		f[k] = v
	}
	m["fields"] = f
	return m
}

func (n *seqNode) tree() map[string]any {
	m := map[string]any{"op": n.Op, "pos": n.Pos}
	if n.Field != "" {
		m["field"] = n.Field
	}
	if n.Strs != nil {
		m["values"] = n.Strs
	}
	if n.Ints != nil {
		m["values"] = n.Ints
	}
	if n.Bools != nil {
		m["values"] = n.Bools
	}
	if len(n.Args) > 0 {
		a := []any{}
		for _, c := range n.Args {
			a = append(a, c.tree())
		}
		m["args"] = a
	}
	return m
}

func (q *seqQuery) tree() map[string]any {
	steps := []any{}
	for _, s := range q.Steps {
		steps = append(steps, map[string]any{"category": s.Cat, "where": s.Cond.tree()})
	}
	out := map[string]any{"kind": q.Kind, "steps": steps}
	if len(q.Keys) > 0 {
		out["by"] = q.Keys
	}
	if q.MaxSpan > 0 {
		out["maxspan"] = q.MaxSpan.String()
	}
	if q.Until != nil {
		out["until"] = map[string]any{"category": q.Until.Cat, "where": q.Until.Cond.tree()}
	}
	return out
}

func registerHuntSeq(mux *http.ServeMux, token string, store *Store) {
	registerHuntSeqWith(mux, token, storeSeqSource{store})
}

func registerHuntSeqWith(mux *http.ServeMux, token string, src seqSource) {
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	type reqBody struct {
		Query string `json:"query"`
		Since string `json:"since"`
		Limit int    `json:"limit"`
	}
	decode := func(w http.ResponseWriter, r *http.Request) (reqBody, *seqQuery, time.Time, bool) {
		var b reqBody
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		defer r.Body.Close()
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			reply(w, 400, map[string]any{"error": "invalid json body"})
			return b, nil, time.Time{}, false
		}
		since, err := parseSince(b.Since, time.Now().UTC())
		if err != nil {
			reply(w, 400, map[string]any{"error": "invalid since (use 24h, 7d or RFC3339)"})
			return b, nil, since, false
		}
		q, perr := parseSeq(b.Query)
		if perr != nil {
			reply(w, 400, map[string]any{"error": perr.Error(), "pos": perr.Pos, "line": perr.Line, "col": perr.Col})
			return b, nil, since, false
		}
		return b, q, since, true
	}
	auth := func(f http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if requireAuth(w, r, token) {
				f(w, r)
			}
		}
	}

	mux.HandleFunc("POST /v1/hunt/seq", auth(func(w http.ResponseWriter, r *http.Request) {
		b, q, since, ok := decode(w, r)
		if !ok {
			return
		}
		if len(q.Problems) > 0 {
			reply(w, 400, map[string]any{"error": "query uses unavailable fields", "problems": q.Problems})
			return
		}
		start := time.Now()
		events, capped := collectSeq(src, q, since)
		ctx, cancel := context.WithTimeout(r.Context(), seqTimeBudget)
		defer cancel()
		res := runSeq(ctx, q, events, b.Limit)
		matches := []any{}
		for _, m := range res.Matches {
			evs := []any{}
			for i, e := range m.Events {
				evs = append(evs, seqRenderEvent(i, e))
			}
			item := map[string]any{"events": evs}
			if m.Key != "" {
				item["key"] = m.Key
			}
			if len(m.Events) > 1 {
				item["span_ms"] = m.Events[len(m.Events)-1].Time.Sub(m.Events[0].Time).Milliseconds()
			}
			matches = append(matches, item)
		}
		AppendAudit(token, "hunt.seq", b.Query)
		reply(w, 200, map[string]any{
			"query": b.Query, "kind": q.Kind, "count": len(matches), "matches": matches,
			"truncated": res.Truncated, "timed_out": res.TimedOut, "scan_capped": capped,
			"scanned": res.Scanned, "scanned_total": res.Considered,
			"elapsed_ms": time.Since(start).Milliseconds(), "semantics": seqSemantics,
		})
	}))

	mux.HandleFunc("GET /v1/hunt/seq/fields", auth(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{
			"categories": seqCatalogue, "join_keys": []string{"host", "pid"},
			"operators": map[string]string{
				"string": "== != : like regex in startswith endswith contains (prefix with `not` for negation)",
				"int":    "== != < <= > >= in",
				"bool":   "== !=",
			},
			"notes": []string{
				": is a case-insensitive wildcard match (* and ?); like is the case-sensitive form; regex is RE2 (max 256 bytes, case-sensitive, use (?i))",
				"fields with optional=true may be empty/0; pid 0 means unknown and never joins in a `by pid` sequence",
				"strings longer than 4096 bytes are truncated before glob/regex matching",
			},
			"limits": map[string]any{"query_bytes": seqMaxQueryLen, "steps": seqMaxSteps, "matches": seqMaxMatches,
				"scanned_events": seqMaxScan, "time_budget_ms": seqTimeBudget.Milliseconds(), "max_maxspan": seqMaxSpan.String()},
		})
	}))

	mux.HandleFunc("GET /v1/hunt/seq/examples", auth(func(w http.ResponseWriter, r *http.Request) {
		ex := seqExamples()
		reply(w, 200, map[string]any{"count": len(ex), "examples": ex})
	}))

	mux.HandleFunc("POST /v1/hunt/seq/explain", auth(func(w http.ResponseWriter, r *http.Request) {
		var b reqBody
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		defer r.Body.Close()
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			reply(w, 400, map[string]any{"error": "invalid json body"})
			return
		}
		since, err := parseSince(b.Since, time.Now().UTC())
		if err != nil {
			reply(w, 400, map[string]any{"error": "invalid since (use 24h, 7d or RFC3339)"})
			return
		}
		q, perr := parseSeq(b.Query)
		if perr != nil {
			reply(w, 200, map[string]any{"ok": false, "error": perr.Error(), "pos": perr.Pos, "line": perr.Line, "col": perr.Col})
			return
		}
		out := map[string]any{"ok": len(q.Problems) == 0, "kind": q.Kind, "tree": q.tree(), "unavailable_fields": q.Problems,
			"semantics": seqSemantics}
		if q.Problems == nil {
			out["unavailable_fields"] = []SeqFieldProblem{}
		}
		if len(q.Problems) == 0 {
			events, capped := collectSeq(src, q, since)
			ctx, cancel := context.WithTimeout(r.Context(), seqTimeBudget)
			defer cancel()
			res := runSeq(ctx, q, events, 1)
			out["scanned"] = res.Scanned
			out["scanned_total"] = res.Considered
			out["scan_capped"] = capped
			out["timed_out"] = res.TimedOut
			out["step_match_counts"] = res.StepCounts
			out["has_match"] = len(res.Matches) > 0
		}
		reply(w, 200, out)
	}))
}
