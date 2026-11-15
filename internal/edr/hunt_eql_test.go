package edr

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

func matchIDs(r seqResult) []string {
	var out []string
	for _, m := range r.Matches {
		var ids []string
		for _, e := range m.Events {
			ids = append(ids, e.ID)
		}
		out = append(out, strings.Join(ids, ">"))
	}
	return out
}

func mkp(id string, sec int, host string, pid int, cmd string) seqEvent {
	e := processSeqEvent(Event{ID: id, Time: sq_fxT(sec), Host: host, PID: pid, Executable: "/bin/x", Command: cmd})
	e.ID = id
	return e
}

func TestSeqParseErrorsHavePositions(t *testing.T) {
	cases := []struct{ q, marker, want string }{
		{`process whre true`, "whre", `expected "where"`},
		{`foo where true`, "foo", "unknown category"},
		{`process where executable == `, "", "expected a literal"},
		{`process where executable == 5`, "5", "is a string"},
		{`process where pid == "x"`, `"x"`, "is an int"},
		{`process where pid : 5`, ":", "not valid for int"},
		{`process where executable regex "("`, `"("`, "invalid regex"},
		{`process where (executable == "a"`, "", "expected ')'"},
		{`process where executable == "abc`, `"abc`, "unterminated string"},
		{`process where executable @ "a"`, "@", "unexpected character"},
		{`sequence [process where true]`, "", "at least 2 steps"},
		{`sequence by user [process where true] [process where true]`, "user", "unsupported join key"},
		{`sequence by host, host [process where true] [process where true]`, "host [", "duplicate join key"},
		{`sequence with maxspan=5x [process where true] [process where true]`, "x [", "unknown duration unit"},
		{`sequence with maxspan=48h [process where true] [process where true]`, "48h", "duration too large"},
		{`sequence with maxspan 5m [process where true] [process where true]`, "5m", "expected '='"},
		{`sequence [process where true] [process where true] extra`, "extra", "unexpected 'extra'"},
		{`sequence [process where true] [process where true] until`, "", "expected '['"},
		{`process where executable like`, "", "expected a literal"},
		{`process where true and`, "", "expected a condition"},
		{`process where executable = "a"`, "=", "expected a comparison operator"},
		{`process where signed == true`, "", ""}, // field problem, not a syntax error (tested below)
		{"process where executable == \"a\\q\"", `\q`, "unknown escape"},
	}
	for _, c := range cases {
		q, err := parseSeq(c.q)
		if c.want == "" {
			if err != nil {
				t.Errorf("%q: unexpected error %v", c.q, err)
			} else if len(q.Problems) == 0 {
				t.Errorf("%q: expected field problem", c.q)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q: expected error %q", c.q, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: error %q lacks %q", c.q, err, c.want)
		}
		wantPos := len(c.q)
		if c.marker != "" {
			wantPos = strings.Index(c.q, c.marker)
		}
		if err.Pos != wantPos {
			t.Errorf("%q: pos=%d want %d (%v)", c.q, err.Pos, wantPos, err)
		}
		if !strings.Contains(err.Error(), "offset") || err.Line != 1 || err.Col != err.Pos+1 {
			t.Errorf("%q: bad position info %+v", c.q, err)
		}
	}
	// multi-line position
	_, err := parseSeq("process where\n  executable == 5")
	if err == nil || err.Line != 2 || err.Col != 17 {
		t.Errorf("multiline: %+v", err)
	}
}

func TestSeqUnavailableFields(t *testing.T) {
	q, err := parseSeq(`network where executable : "*curl*" and destination like "*:443"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Problems) != 1 || q.Problems[0].Field != "executable" || !strings.Contains(q.Problems[0].Reason, "no process image") {
		t.Fatalf("%+v", q.Problems)
	}
	q, _ = parseSeq(`file where hash == "x" or bogus == "y"`)
	if len(q.Problems) != 2 {
		t.Fatalf("%+v", q.Problems)
	}
}

func TestSeqOperators(t *testing.T) {
	e := processSeqEvent(Event{ID: "1", Time: sq_fxT(0), Host: "h", PID: 42, UID: 0, Executable: "/usr/bin/PowerShell", Command: "ps -ENC abc"})
	m := sq_module(true)
	tests := []struct {
		q    string
		want bool
	}{
		{`process where executable == "/usr/bin/PowerShell"`, true},
		{`process where executable == "/usr/bin/powershell"`, false},
		{`process where executable : "*powershell"`, true},
		{`process where executable like "*powershell"`, false},
		{`process where executable like "*Power?hell"`, true},
		{`process where command : "*-enc*"`, true},
		{`process where command : ("*zzz*","*-enc*")`, true},
		{`process where command regex "-ENC [a-z]+"`, true},
		{`process where command regex "(?i)-enc"`, true},
		{`process where command not regex "zzz"`, true},
		{`process where executable startswith "/usr"`, true},
		{`process where executable endswith "Shell"`, true},
		{`process where command contains "abc"`, true},
		{`process where pid in (1,42)`, true},
		{`process where pid not in (1,42)`, false},
		{`process where pid >= 42 and pid < 43`, true},
		{`process where uid == 0 and not (pid == 1 or pid == 2)`, true},
		{`process where executable not like "/bin/*"`, true},
		{`process where true`, true},
		{`process where false or pid == 42`, true},
		{`PROCESS WHERE PID == 42`, true},
		{`process where parent_exe == ""`, true},
	}
	for _, c := range tests {
		r := runText(t, c.q, []seqEvent{e})
		if (len(r.Matches) == 1) != c.want {
			t.Errorf("%q => %v want %v", c.q, len(r.Matches) == 1, c.want)
		}
	}
	if r := runText(t, `module where signed == true`, []seqEvent{m}); len(r.Matches) != 1 {
		t.Error("bool")
	}
	if r := runText(t, `module where signed != true`, []seqEvent{m}); len(r.Matches) != 0 {
		t.Error("bool ne")
	}
}

func sq_module(signed bool) seqEvent {
	return telemetrySeqEvent("module", TelemetryEvent{Time: sq_fxT(0), Host: "h", ModulePath: "/x", Signed: signed})
}

func TestSeqGlob(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true}, {"a*", "abc", true}, {"*c", "abc", true}, {"a*c", "abc", true}, {"a*d", "abc", false},
		{"a?c", "abc", true}, {"a?c", "ac", false}, {"**a**", "xay", true}, {"", "", true}, {"", "a", false},
		{"*a*b*c*", "xxaxxbxxcxx", true}, {"*a*b*c*", "xxaxxcxxbxx", false},
	}
	for _, c := range cases {
		if globMatch(c.p, c.s) != c.want {
			t.Errorf("glob(%q,%q)", c.p, c.s)
		}
	}
}

func TestSeqSemantics(t *testing.T) {
	A := func(id string, s int, host string, pid int) seqEvent { return mkp(id, s, host, pid, "A") }
	B := func(id string, s int, host string, pid int) seqEvent { return mkp(id, s, host, pid, "B") }
	U := func(id string, s int, host string, pid int) seqEvent { return mkp(id, s, host, pid, "U") }
	const base = `[process where command == "A"] [process where command == "B"]`

	t.Run("basic order", func(t *testing.T) {
		r := runText(t, "sequence by host "+base, []seqEvent{B("b0", 0, "h", 1), A("a1", 1, "h", 1), B("b1", 2, "h", 1)})
		if got := matchIDs(r); len(got) != 1 || got[0] != "a1>b1" {
			t.Fatal(got)
		}
	})
	t.Run("skip till next match picks earliest and does not overlap", func(t *testing.T) {
		r := runText(t, "sequence "+base, []seqEvent{A("a1", 1, "h", 1), A("a2", 2, "h", 1), B("b1", 3, "h", 1), B("b2", 4, "h", 1)})
		if got := matchIDs(r); len(got) != 1 || got[0] != "a1>b1" {
			t.Fatal(got)
		}
		r = runText(t, "sequence "+base, []seqEvent{A("a1", 1, "h", 1), B("b1", 2, "h", 1), A("a2", 3, "h", 1), B("b2", 4, "h", 1)})
		if got := matchIDs(r); len(got) != 2 || got[0] != "a1>b1" || got[1] != "a2>b2" {
			t.Fatal(got)
		}
	})
	t.Run("maxspan inclusive", func(t *testing.T) {
		r := runText(t, "sequence with maxspan=5m "+base, []seqEvent{A("a", 0, "h", 1), B("b", 300, "h", 1)})
		if len(r.Matches) != 1 {
			t.Fatal("exactly maxspan must match")
		}
		r = runText(t, "sequence with maxspan=5m "+base, []seqEvent{A("a", 0, "h", 1), B("b", 301, "h", 1)})
		if len(r.Matches) != 0 {
			t.Fatal("beyond maxspan must not match")
		}
		// failed start is retried with a later start inside the window
		r = runText(t, "sequence with maxspan=10s "+base, []seqEvent{A("a1", 0, "h", 1), A("a2", 50, "h", 1), B("b", 55, "h", 1)})
		if got := matchIDs(r); len(got) != 1 || got[0] != "a2>b" {
			t.Fatal(got)
		}
	})
	t.Run("until", func(t *testing.T) {
		u := base + ` until [process where command == "U"]`
		r := runText(t, "sequence "+u, []seqEvent{A("a", 0, "h", 1), U("u", 1, "h", 1), B("b", 2, "h", 1)})
		if len(r.Matches) != 0 {
			t.Fatal("until must abort")
		}
		r = runText(t, "sequence "+u, []seqEvent{A("a", 0, "h", 1), B("b", 1, "h", 1), U("u", 2, "h", 1)})
		if len(r.Matches) != 1 {
			t.Fatal("until after completion must not abort")
		}
		// a start after the until still works
		r = runText(t, "sequence "+u, []seqEvent{A("a", 0, "h", 1), U("u", 1, "h", 1), A("a2", 2, "h", 1), B("b", 3, "h", 1)})
		if got := matchIDs(r); len(got) != 1 || got[0] != "a2>b" {
			t.Fatal(got)
		}
		// until is per join key
		r = runText(t, "sequence by host "+u, []seqEvent{A("a", 0, "h1", 1), U("u", 1, "h2", 1), B("b", 2, "h1", 1)})
		if len(r.Matches) != 1 {
			t.Fatal("until on another host must not abort")
		}
	})
	t.Run("by keys", func(t *testing.T) {
		ev := []seqEvent{A("a1", 0, "h1", 1), B("b2", 1, "h2", 1), B("b1", 2, "h1", 2), B("b3", 3, "h1", 1)}
		if got := matchIDs(runText(t, "sequence by host "+base, ev)); len(got) != 1 || got[0] != "a1>b1" {
			t.Fatal(got)
		}
		if got := matchIDs(runText(t, "sequence by host, pid "+base, ev)); len(got) != 1 || got[0] != "a1>b3" {
			t.Fatal(got)
		}
		if got := matchIDs(runText(t, "sequence "+base, ev)); len(got) != 1 || got[0] != "a1>b2" {
			t.Fatal(got)
		}
	})
	t.Run("missing pid never joins by pid", func(t *testing.T) {
		ev := []seqEvent{mkp("a", 0, "h", 0, "A"), mkp("b", 1, "h", 0, "B")}
		if len(runText(t, "sequence by pid "+base, ev).Matches) != 0 {
			t.Fatal("pid 0 is unknown")
		}
		if len(runText(t, "sequence by host "+base, ev).Matches) != 1 {
			t.Fatal("host join ok")
		}
	})
	t.Run("ties ordered by id", func(t *testing.T) {
		// same timestamp: id decides, "a" sorts before "z"
		ev := []seqEvent{A("z", 5, "h", 1), B("a", 5, "h", 1)}
		if len(runText(t, "sequence "+base, ev).Matches) != 0 {
			t.Fatal("B(a) is ordered before A(z)")
		}
		ev = []seqEvent{A("a", 5, "h", 1), B("z", 5, "h", 1)}
		if len(runText(t, "sequence "+base, ev).Matches) != 1 {
			t.Fatal("A(a) before B(z)")
		}
		// an event cannot satisfy two steps of the same match
		r := runText(t, `sequence [process where true] [process where true]`, []seqEvent{A("a", 0, "h", 1)})
		if len(r.Matches) != 0 {
			t.Fatal("one event cannot be two steps")
		}
	})
	t.Run("input order does not matter", func(t *testing.T) {
		evs := []seqEvent{A("a1", 1, "h", 1), B("b1", 2, "h", 1), A("a2", 3, "h", 1), B("b2", 4, "h", 1)}
		want := matchIDs(runText(t, "sequence "+base, evs))
		rand.New(rand.NewSource(1)).Shuffle(len(evs), func(i, j int) { evs[i], evs[j] = evs[j], evs[i] })
		if got := matchIDs(runText(t, "sequence "+base, evs)); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatal(got, want)
		}
	})
	t.Run("single event query and limit", func(t *testing.T) {
		var ev []seqEvent
		for i := 0; i < 20; i++ {
			ev = append(ev, A(fmt.Sprintf("a%02d", i), i, "h", 1))
		}
		q, _ := parseSeq(`process where command == "A"`)
		sortSeqEvents(ev)
		r := runSeq(context.Background(), q, ev, 5)
		if len(r.Matches) != 5 || !r.Truncated {
			t.Fatalf("%d %v", len(r.Matches), r.Truncated)
		}
		r = runSeq(context.Background(), q, ev, 100000)
		if len(r.Matches) != 20 {
			t.Fatal("limit clamp")
		}
	})
	t.Run("context cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		q, _ := parseSeq("sequence " + base)
		var ev []seqEvent
		for i := 0; i < 5000; i++ {
			ev = append(ev, A(fmt.Sprintf("a%05d", i), i, "h", 1))
		}
		sortSeqEvents(ev)
		if r := runSeq(ctx, q, ev, 10); !r.TimedOut {
			t.Fatal("expected timeout flag")
		}
	})
}

func TestSeqLimits(t *testing.T) {
	step := `[process where true]`
	if _, err := parseSeq("sequence " + strings.Repeat(step+" ", 6)); err != nil {
		t.Fatalf("6 steps ok: %v", err)
	}
	if _, err := parseSeq("sequence " + strings.Repeat(step+" ", 7)); err == nil || !strings.Contains(err.Error(), "too many sequence steps") {
		t.Fatalf("7 steps: %v", err)
	}
	if _, err := parseSeq(`process where command == "` + strings.Repeat("a", 5000) + `"`); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("long query: %v", err)
	}
	if _, err := parseSeq(`process where command == "` + strings.Repeat("a", 600) + `"`); err == nil || !strings.Contains(err.Error(), "string literal too long") {
		t.Fatalf("long literal: %v", err)
	}
	if _, err := parseSeq(`process where command regex "` + strings.Repeat("a", 300) + `"`); err == nil {
		t.Fatal("regex cap")
	}
	if _, err := parseSeq(`process where ` + strings.Repeat("(", 40) + "true" + strings.Repeat(")", 40)); err == nil || !strings.Contains(err.Error(), "nested too deeply") {
		t.Fatalf("depth: %v", err)
	}
	if _, err := parseSeq(`process where ` + strings.Repeat("not ", 40) + "true"); err == nil || !strings.Contains(err.Error(), "nested too deeply") {
		t.Fatalf("not depth: %v", err)
	}
	if _, err := parseSeq(`process where ` + strings.Repeat("pid == 1 or ", 300) + "true"); err == nil || !strings.Contains(err.Error(), "too complex") {
		t.Fatalf("nodes: %v", err)
	}
	var items []string
	for i := 0; i < 70; i++ {
		items = append(items, "1")
	}
	if _, err := parseSeq(`process where pid in (` + strings.Join(items, ",") + `)`); err == nil || !strings.Contains(err.Error(), "list too long") {
		t.Fatalf("list: %v", err)
	}
	// catastrophic-backtracking regex stays linear (RE2)
	start := time.Now()
	r := runText(t, `process where command regex "(a+)+$"`, []seqEvent{mkp("x", 0, "h", 1, strings.Repeat("a", 3000)+"!")})
	if time.Since(start) > 2*time.Second || len(r.Matches) != 0 {
		t.Fatalf("regex slow or wrong: %v", time.Since(start))
	}
	// matches cap
	var ev []seqEvent
	for i := 0; i < 700; i++ {
		ev = append(ev, mkp(fmt.Sprintf("e%04d", i), i, "h", 1, "A"))
	}
	if r := runText(t, `process where true`, ev); len(r.Matches) != seqMaxMatches || !r.Truncated {
		t.Fatalf("cap: %d %v", len(r.Matches), r.Truncated)
	}
}

// ---- brute-force cross-check ----

type bfStep struct {
	cat  string
	vals []string
}

func (s bfStep) text() string {
	f := map[string]string{"process": "command", "file": "path"}[s.cat]
	q := make([]string, len(s.vals))
	for i, v := range s.vals {
		q[i] = `"` + v + `"`
	}
	return fmt.Sprintf(`[%s where %s in (%s)]`, s.cat, f, strings.Join(q, ","))
}

func (s bfStep) matches(e *seqEvent) bool {
	f := map[string]string{"process": "command", "file": "path"}[s.cat]
	if e.Cat != s.cat {
		return false
	}
	v := e.F[f].(string)
	for _, x := range s.vals {
		if x == v {
			return true
		}
	}
	return false
}

// bruteForce enumerates every position tuple and keeps those satisfying the
// documented semantics, then greedily removes overlaps. It shares no code with
// runSeq apart from the sorted event slice.
func bruteForce(ev []seqEvent, steps []bfStep, until *bfStep, keys []string, maxspan time.Duration) []string {
	groups := map[string][]int{}
	for i := range ev {
		k := ""
		ok := true
		for _, key := range keys {
			switch key {
			case "host":
				k += "h:" + ev[i].F["host"].(string) + "|"
			case "pid":
				if ev[i].F["pid"].(int64) == 0 {
					ok = false
				}
				k += fmt.Sprintf("p:%d|", ev[i].F["pid"].(int64))
			}
		}
		if ok {
			groups[k] = append(groups[k], i)
		}
	}
	type res struct {
		end, start int
		id         string
	}
	var all []res
	for _, g := range groups {
		var tuples [][]int
		var rec func(step int, chosen []int)
		rec = func(step int, chosen []int) {
			if step == len(steps) {
				tuples = append(tuples, append([]int(nil), chosen...))
				return
			}
			for _, pos := range g {
				if len(chosen) > 0 && pos <= chosen[len(chosen)-1] {
					continue
				}
				if !steps[step].matches(&ev[pos]) {
					continue
				}
				if len(chosen) > 0 {
					// must be the earliest matching event after the previous one
					earlier := false
					for _, p2 := range g {
						if p2 > chosen[len(chosen)-1] && p2 < pos && steps[step].matches(&ev[p2]) {
							earlier = true
						}
					}
					if earlier {
						continue
					}
				}
				rec(step+1, append(chosen, pos))
			}
		}
		rec(0, nil)
		var valid [][]int
		for _, tp := range tuples {
			first, last := tp[0], tp[len(tp)-1]
			if maxspan > 0 && ev[last].Time.Sub(ev[first].Time) > maxspan {
				continue
			}
			bad := false
			if until != nil {
				for _, p := range g {
					if p > first && p <= last && until.matches(&ev[p]) {
						bad = true
					}
				}
			}
			if !bad {
				valid = append(valid, tp)
			}
		}
		sort.Slice(valid, func(a, b int) bool { return valid[a][0] < valid[b][0] })
		lastEnd := -1
		for _, tp := range valid {
			if tp[0] <= lastEnd {
				continue
			}
			lastEnd = tp[len(tp)-1]
			var ids []string
			for _, p := range tp {
				ids = append(ids, ev[p].ID)
			}
			all = append(all, res{tp[len(tp)-1], tp[0], strings.Join(ids, ">")})
		}
	}
	var out []string
	for _, r := range all {
		out = append(out, r.id)
	}
	sort.Strings(out)
	return out
}

func TestSeqBruteForceCrossCheck(t *testing.T) {
	rng := rand.New(rand.NewSource(20260101))
	vals := []string{"a", "b", "c"}
	pick := func() []string {
		n := 1 + rng.Intn(2)
		var v []string
		for i := 0; i < n; i++ {
			v = append(v, vals[rng.Intn(3)])
		}
		return v
	}
	mk := func() bfStep { return bfStep{cat: []string{"process", "file"}[rng.Intn(2)], vals: pick()} }
	iters := 3000
	if testing.Short() {
		iters = 500
	}
	nonEmpty := 0
	for it := 0; it < iters; it++ {
		var ev []seqEvent
		n := 4 + rng.Intn(14)
		for i := 0; i < n; i++ {
			ts := rng.Intn(25) // many ties
			id := fmt.Sprintf("e%02d", rng.Intn(100)) + fmt.Sprintf("-%d", i)
			host := []string{"h1", "h2"}[rng.Intn(2)]
			pid := rng.Intn(3) // 0 = unknown
			v := vals[rng.Intn(3)]
			if rng.Intn(2) == 0 {
				ev = append(ev, processSeqEvent(Event{ID: id, Time: sq_fxT(ts), Host: host, PID: pid, Command: v}))
			} else {
				ev = append(ev, fileSeqEvent(FileEvent{ID: id, Time: sq_fxT(ts), Host: host, PID: pid, Path: v}))
			}
		}
		sortSeqEvents(ev)
		var steps []bfStep
		for i, k := 0, 2+rng.Intn(3); i < k; i++ {
			steps = append(steps, mk())
		}
		var until *bfStep
		if rng.Intn(2) == 0 {
			u := mk()
			until = &u
		}
		var keys []string
		switch rng.Intn(4) {
		case 1:
			keys = []string{"host"}
		case 2:
			keys = []string{"pid"}
		case 3:
			keys = []string{"host", "pid"}
		}
		var maxspan time.Duration
		text := "sequence"
		if len(keys) > 0 {
			text += " by " + strings.Join(keys, ", ")
		}
		if rng.Intn(2) == 0 {
			maxspan = time.Duration(1+rng.Intn(12)) * time.Second
			text += fmt.Sprintf(" with maxspan=%ds", int(maxspan/time.Second))
		}
		for _, s := range steps {
			text += " " + s.text()
		}
		if until != nil {
			text += " until " + until.text()
		}
		q, err := parseSeq(text)
		if err != nil || len(q.Problems) > 0 {
			t.Fatalf("generated query failed to parse: %s: %v %v", text, err, q)
		}
		got := matchIDs(runSeq(context.Background(), q, ev, 500))
		sort.Strings(got)
		want := bruteForce(ev, steps, until, keys, maxspan)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("iteration %d mismatch\nquery: %s\ngot:  %v\nwant: %v", it, text, got, want)
		}
		if len(want) > 0 {
			nonEmpty++
		}
	}
	if nonEmpty < iters/20 {
		t.Fatalf("generator too sparse: only %d/%d non-empty cases", nonEmpty, iters)
	}
}

// ---- fuzz ----

func FuzzParseSeq(f *testing.F) {
	for _, e := range seqExamples() {
		f.Add(e.Query)
	}
	for _, s := range []string{"", "sequence", "process where", `process where command regex "(`, "sequence [", "\x00", `until`} {
		f.Add(s)
	}
	ev := []seqEvent{mkp("a", 0, "h", 1, "x"), mkp("b", 1, "h", 1, "y")}
	f.Fuzz(func(t *testing.T, s string) {
		q, err := parseSeq(s)
		if err != nil {
			if err.Error() == "" || err.Pos < 0 || err.Pos > len(s) {
				t.Fatalf("bad error for %q: %+v", s, err)
			}
			return
		}
		if len(q.Problems) == 0 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			runSeq(ctx, q, ev, 10)
		}
		_ = q.tree()
	})
}

func TestSeqParserMutationSmoke(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var seeds []string
	for _, e := range seqExamples() {
		seeds = append(seeds, e.Query)
	}
	ev := []seqEvent{mkp("a", 0, "h", 1, "x")}
	for i := 0; i < 4000; i++ {
		b := []byte(seeds[rng.Intn(len(seeds))])
		for k := 0; k < 1+rng.Intn(4); k++ {
			if len(b) == 0 {
				break
			}
			p := rng.Intn(len(b))
			switch rng.Intn(3) {
			case 0:
				b[p] = byte(rng.Intn(128))
			case 1:
				b = append(b[:p], b[p+1:]...)
			case 2:
				b = append(b[:p], append([]byte{byte(32 + rng.Intn(90))}, b[p:]...)...)
			}
		}
		q, err := parseSeq(string(b))
		if err == nil && len(q.Problems) == 0 {
			runSeq(context.Background(), q, ev, 5)
		}
	}
}

// ---- HTTP ----

type fixedSource []seqEvent

func (f fixedSource) Events(cats map[string]bool) []seqEvent {
	var out []seqEvent
	for _, e := range f {
		if cats[e.Cat] {
			out = append(out, e)
		}
	}
	return out
}

func TestSeqHTTP(t *testing.T) {
	now := time.Now().UTC()
	old := sq_id(processSeqEvent(Event{ID: "old", Time: now.Add(-48 * time.Hour), Host: "h", PID: 1, Executable: "/usr/bin/curl", Command: "curl http://x"}), "old")
	a := sq_id(processSeqEvent(Event{ID: "a", Time: now.Add(-time.Hour), Host: "h", PID: 2, Executable: "/usr/bin/curl", Command: "curl http://x"}), "a")
	b := sq_id(processSeqEvent(Event{ID: "b", Time: now.Add(-50 * time.Minute), Host: "h", PID: 3, Executable: "/tmp/p", Command: "/tmp/p"}), "b")
	mux := http.NewServeMux()
	registerHuntSeqWith(mux, "tok", fixedSource{old, a, b})
	do := func(method, url, body, tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, strings.NewReader(body))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}
	for _, u := range [][2]string{{"POST", "/v1/hunt/seq"}, {"GET", "/v1/hunt/seq/fields"}, {"POST", "/v1/hunt/seq/explain"}, {"GET", "/v1/hunt/seq/examples"}} {
		if rr := do(u[0], u[1], `{"query":"process where true"}`, ""); rr.Code != 401 && rr.Code != 403 {
			t.Fatalf("%v unauthenticated => %d", u, rr.Code)
		}
	}
	q := `sequence by host with maxspan=1h [process where executable endswith "/curl"] [process where executable startswith "/tmp/"]`
	body, _ := json.Marshal(map[string]any{"query": q, "since": "24h"})
	rr := do("POST", "/v1/hunt/seq", string(body), "tok")
	var out struct {
		Count   int `json:"count"`
		Matches []struct {
			Events []struct {
				ID   string `json:"id"`
				Step int    `json:"step"`
			} `json:"events"`
		} `json:"matches"`
		ScannedTotal int `json:"scanned_total"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if out.Count != 1 || out.Matches[0].Events[0].ID != "a" || out.Matches[0].Events[1].ID != "b" || out.ScannedTotal != 2 {
		t.Fatalf("%s", rr.Body.String())
	}
	// no since: old curl is outside maxspan of b, so the attempt fails and a is retried as the start
	body, _ = json.Marshal(map[string]any{"query": q})
	rr = do("POST", "/v1/hunt/seq", string(body), "tok")
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Count != 1 || out.Matches[0].Events[0].ID != "a" || out.ScannedTotal != 3 {
		t.Fatalf("%s", rr.Body.String())
	}
	// syntax error carries position
	rr = do("POST", "/v1/hunt/seq", `{"query":"process whre true"}`, "tok")
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), `"pos":8`) {
		t.Fatal(rr.Code, rr.Body.String())
	}
	// unavailable field is refused with a reason
	rr = do("POST", "/v1/hunt/seq", `{"query":"network where executable == \"x\""}`, "tok")
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "no process image") {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr = do("POST", "/v1/hunt/seq", `{"query":"process where true","since":"bogus"}`, "tok"); rr.Code != 400 {
		t.Fatal("since")
	}
	if rr = do("POST", "/v1/hunt/seq", `not json`, "tok"); rr.Code != 400 {
		t.Fatal("json")
	}
	// fields
	rr = do("GET", "/v1/hunt/seq/fields", "", "tok")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"absent"`) || !strings.Contains(rr.Body.String(), "network events carry no process image") {
		t.Fatal(rr.Body.String())
	}
	// explain: ok
	rr = do("POST", "/v1/hunt/seq/explain", string(mustJSON(map[string]any{"query": q})), "tok")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"step_match_counts":[2,1,0]`) && !strings.Contains(rr.Body.String(), `"step_match_counts":[2,1`) {
		t.Fatal(rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"scanned":{"process":3}`) {
		t.Fatal(rr.Body.String())
	}
	// explain: unavailable fields are listed, not executed
	rr = do("POST", "/v1/hunt/seq/explain", `{"query":"file where executable : \"x\""}`, "tok")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"ok":false`) || !strings.Contains(rr.Body.String(), `"field":"executable"`) {
		t.Fatal(rr.Body.String())
	}
	// explain: syntax error
	rr = do("POST", "/v1/hunt/seq/explain", `{"query":"sequence [process where true]"}`, "tok")
	if !strings.Contains(rr.Body.String(), `"ok":false`) || !strings.Contains(rr.Body.String(), "at least 2 steps") {
		t.Fatal(rr.Body.String())
	}
	// examples
	rr = do("GET", "/v1/hunt/seq/examples", "", "tok")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "seq-download-exec") {
		t.Fatal(rr.Body.String())
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestSeqRegisteredOnAPI(t *testing.T) {
	store, err := testStore(t, t.TempDir()+"/e.jsonl", 100)
	if err != nil {
		t.Fatal(err)
	}
	store.recentEvents = []Event{{ID: "1", Time: time.Now().UTC(), Host: "h", PID: 1, Executable: "/bin/x", Command: "x"}}
	h := API("tok", store)
	req := httptest.NewRequest("POST", "/v1/hunt/seq", strings.NewReader(`{"query":"process where executable endswith \"/x\""}`))
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"count":1`) {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func sq_id(e seqEvent, id string) seqEvent { e.ID = id; return e }
