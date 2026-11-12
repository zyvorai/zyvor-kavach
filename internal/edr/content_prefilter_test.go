// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// compileTestRule builds a ready-to-evaluate rule (matcher + prefilter) from a match tree.
func compileTestRule(t testing.TB, id, eventType string, m ContentMatch) *ContentRule {
	t.Helper()
	r := &ContentRule{ID: id, EventType: eventType, Severity: "low", Tactic: "Execution", Technique: "T1059", Match: m}
	n, err := m.toLab("match")
	if err != nil {
		t.Fatal(err)
	}
	nodes := 0
	if err := n.validateFields("match", 0, &nodes, contentFieldsFor(eventType)); err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	r.node = &n
	r.pre = buildPrefilter(&n)
	return r
}

var preVocab = []string{
	"powershell", "-enc", "ld_preload", "/tmp/", "/dev/shm/", "curl", "wget", "base64", "chmod +x", "nc -e",
	"http://", "https://", "\\temp\\", "appdata", "mimikatz", "kelvin", "ssh", "assets", "passwd", "/etc/shadow",
	"rundll32", "cmd.exe /c", "whoami", "id", "tar czf", "authorized_keys", "xmrig", "stratum+tcp", "-w hidden",
	"Éclair", "ǅ", "σίσυφος", "ΣΑΣ", "日本語", "foo123baz", "bar9baz", "aab", "xxy", "abcabc",
}

// preRegexTemplates exercise literals, alternation, repetition, classes, anchors, fold flags and
// constructs with no extractable literal.
var preRegexTemplates = []string{
	`ld_preload=\S*(/tmp/|/dev/shm/)`, `(?i)powershell\s+.*-enc`, `(foo|bar)\d+baz`, `^/usr/bin/(curl|wget)`,
	`\bnc\b.*-e`, `a+b`, `x{2,}y`, `(?:abc){2}`, `[a-z]+\.exe`, `(?i)kelvin`, `(?i)ssh`, `(?i)assets?`,
	`\\temp\\`, `(?i)mimi(katz|lib)`, `(?s).*`, `^$`, `(?i)stratum\+tcp://`, `base64|b64`, `é|ǆ`, `(?i)σίσυφος`,
	`(?i)ΣΑΣ`, `chmod\s+\+x`, `\x{FFFD}`, `[[:alpha:]]{3}authorized_keys`, `(?i)(cmd|sh)\.exe\s+/c`, `https?://[^/]+/`,
	`(a|b)?c`, `z*q`, `(?i:abc)def`, `日本`, `^(?i)xmrig`, `(?m)^id$`, `/etc/(passwd|shadow)`,
}

func randLeaf(r *rand.Rand) ContentMatch {
	fields := []string{"command", "executable", "path", "destination"}
	ops := []string{"contains", "prefix", "suffix", "equals", "regex", "in", "regex"}
	f, op := fields[r.Intn(len(fields))], ops[r.Intn(len(ops))]
	m := ContentMatch{Field: f, Op: op, CaseSensitive: r.Intn(3) == 0}
	word := func() string { return preVocab[r.Intn(len(preVocab))] }
	switch op {
	case "regex":
		m.Pattern = preRegexTemplates[r.Intn(len(preRegexTemplates))]
	case "in":
		for i := 0; i < 1+r.Intn(4); i++ {
			m.Patterns = append(m.Patterns, word())
		}
	default:
		if r.Intn(3) == 0 {
			m.Patterns = []string{word(), word()}
		} else {
			m.Pattern = word()
		}
	}
	return m
}

func randTree(r *rand.Rand, depth int) ContentMatch {
	if depth >= 3 || r.Intn(3) == 0 {
		return randLeaf(r)
	}
	kids := make([]ContentMatch, 1+r.Intn(3))
	for i := range kids {
		kids[i] = randTree(r, depth+1)
	}
	switch r.Intn(4) {
	case 0:
		return ContentMatch{Any: kids}
	case 1:
		return ContentMatch{Not: &kids[0]}
	default:
		return ContentMatch{All: kids}
	}
}

func randField(r *rand.Rand) string {
	switch r.Intn(12) {
	case 0:
		return "" // absent field
	case 1:
		return "\xff\xfe" + preVocab[r.Intn(len(preVocab))] + "\x80" // invalid UTF-8
	case 2:
		return "Kelvin ſsh assets K" // Kelvin sign and long s: fold to k and s under (?i)
	case 3: // beyond the 4096-byte truncation point
		return strings.Repeat("x ", 2100) + preVocab[r.Intn(len(preVocab))]
	}
	n := 1 + r.Intn(6)
	parts := make([]string, n)
	for i := range parts {
		w := preVocab[r.Intn(len(preVocab))]
		switch r.Intn(4) {
		case 0:
			w = strings.ToUpper(w)
		case 1:
			w = strings.Title(w) //nolint:staticcheck
		}
		parts[i] = w
	}
	return strings.Join(parts, []string{" ", "", "/", "\\"}[r.Intn(4)])
}

// TestContentPrefilterEquivalence proves the prefilter never changes a result: the 10 seed rules,
// every shipped rule and 500 generated rules run over many events with and without it.
func TestContentPrefilterEquivalence(t *testing.T) {
	reg := loadTestRegistry(t)
	var rules []*ContentRule
	rules = append(rules, reg.rules...)
	rnd := rand.New(rand.NewSource(20260101))
	for i := 0; i < 500; i++ {
		rules = append(rules, compileTestRule(t, fmt.Sprintf("gen-%d", i), "process", randTree(rnd, 0)))
	}
	withPre := 0
	for _, r := range rules {
		if len(r.pre) > 0 {
			withPre++
		}
	}
	if withPre < len(rules)/2 {
		t.Fatalf("prefilter extracted literals for only %d of %d rules", withPre, len(rules))
	}
	var events []LabEvent
	for _, r := range reg.rules { // every sample event of every shipped rule
		events = append(events, r.Tests.Positive...)
		events = append(events, r.Tests.Negative...)
	}
	events = append(events, benignBaseline...)
	for i := 0; i < 1500; i++ {
		uid := 1000
		ev := LabEvent{Executable: randField(rnd), Command: randField(rnd), Path: randField(rnd), Destination: randField(rnd)}
		if i%2 == 0 {
			ev.UID = &uid
		}
		events = append(events, ev)
	}
	matches, checked := 0, 0
	for _, ev := range events {
		ctx := newEvalCtx(ev)
		for _, r := range rules {
			want := r.matchCtx(newEvalCtx(ev), false)
			got := r.matchCtx(ctx, true) // shared context, as on the live path
			if got != want {
				t.Fatalf("prefilter changed the result for rule %s (want %v, got %v) on event %+v", r.ID, want, got, ev)
			}
			if want {
				matches++
			}
			checked++
		}
	}
	if matches == 0 {
		t.Fatal("generated corpus never matched anything; the equivalence test is vacuous")
	}
	t.Logf("%d rules (%d with literal prefilter) x %d events = %d evaluations, %d matches, all identical", len(rules), withPre, len(events), checked, matches)
}

// TestContentPrefilterUnicodeFolding pins the cases where naive lowercasing would be unsound.
func TestContentPrefilterUnicodeFolding(t *testing.T) {
	r := compileTestRule(t, "fold", "process", ContentMatch{Field: "command", Op: "regex", Pattern: `kelvin ssh`})
	if len(r.pre) == 0 {
		t.Fatal("expected a prefilter for a literal regex")
	}
	// U+212A (Kelvin sign) and U+017F (long s) match (?i)k and (?i)s in RE2.
	ev := LabEvent{Command: "run Kelvin ſſh now"}
	if !r.matchCtx(newEvalCtx(ev), false) {
		t.Fatal("matcher itself should match Kelvin/long-s under case folding")
	}
	if !r.matchCtx(newEvalCtx(ev), true) {
		t.Fatal("prefilter must not skip a rule that matches through Unicode case folding")
	}
	// Absent field and literal missing: skipped without error.
	if r.Matches(LabEvent{Executable: "/bin/ls"}) {
		t.Fatal("absent field matched")
	}
}

// bulkRegexRules builds n realistic non-matching regex rules (the 58ms/1000 scenario).
func bulkRegexRules(t testing.TB, n int) []*ContentRule {
	rules := make([]*ContentRule, 0, n)
	for i := 0; i < n; i++ {
		var p string
		switch i % 4 {
		case 0:
			p = fmt.Sprintf(`implant%d\S*(/tmp/|/dev/shm/)`, i)
		case 1:
			p = fmt.Sprintf(`(?i)dropper%d\.exe\s+-[a-z]+\s+\d+`, i)
		case 2:
			p = fmt.Sprintf(`\b(beacon%d|stager%d)\b.*-(e|c)\s`, i, i)
		default:
			p = fmt.Sprintf(`^/opt/evil%d/(bin|sbin)/[a-z0-9_]+`, i)
		}
		rules = append(rules, compileTestRule(t, fmt.Sprintf("bulk-%d", i), "process", ContentMatch{Field: "command", Op: "regex", Pattern: p}))
	}
	return rules
}

func bulkEvent() LabEvent {
	words := []string{"ls", "-la", "/home/dev/project", "git", "status", "go", "build", "./...", "echo", "hello", "cat", "/etc/hostname", "tar", "czf", "backup.tgz"}
	var b strings.Builder
	for b.Len() < 3000 {
		b.WriteString(words[b.Len()%len(words)])
		b.WriteByte(' ')
	}
	return LabEvent{Executable: "/bin/bash", Command: b.String()}
}

func evalAll(rules []*ContentRule, ev LabEvent, usePre bool) int {
	c := newEvalCtx(ev)
	n := 0
	for _, r := range rules {
		if r.matchCtx(c, usePre) {
			n++
		}
	}
	return n
}

func BenchmarkContentEvaluate1000Regex3KB(b *testing.B) {
	rules := bulkRegexRules(b, 1000)
	ev := bulkEvent()
	for _, mode := range []struct {
		name string
		pre  bool
	}{{"no-prefilter", false}, {"prefilter", true}} {
		b.Run(mode.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if evalAll(rules, ev, mode.pre) != 0 {
					b.Fatal("unexpected match")
				}
			}
		})
	}
}

// TestContentPrefilterSpeedup checks the prefilter is a large win on the non-matching workload and
// logs the numbers (see the benchmark for stable figures).
func TestContentPrefilterSpeedup(t *testing.T) {
	rules := bulkRegexRules(t, 1000)
	ev := bulkEvent()
	if len(ev.Command) < 3000 {
		t.Fatal("event too small")
	}
	timeIt := func(pre bool) time.Duration {
		best := time.Duration(1 << 62)
		for i := 0; i < 5; i++ {
			s := time.Now()
			evalAll(rules, ev, pre)
			if d := time.Since(s); d < best {
				best = d
			}
		}
		return best
	}
	off, on := timeIt(false), timeIt(true)
	t.Logf("1000 non-matching regexes vs 3KB command: no-prefilter %v, prefilter %v (%.0fx)", off, on, float64(off)/float64(on+1))
	if on*5 > off {
		t.Fatalf("prefilter expected to be at least 5x faster: %v vs %v", on, off)
	}
}
