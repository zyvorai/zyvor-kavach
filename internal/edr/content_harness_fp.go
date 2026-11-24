// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Benign-corpus false-positive report. The operator supplies logs they believe are clean (or uses
// the small synthetic corpus built into this file); every file is replayed through the detectors
// and the hits are counted per rule. The result describes the supplied corpus only: it does not
// estimate the false-positive rate of any other environment. Samples are redacted with the same
// redaction rules as the data-governance policy plus the web query-secret rule.

const (
	fpMaxFiles     = 1000
	fpMaxFileBytes = 32 << 20
	fpMaxTotal     = 256 << 20
	fpChunkRecords = 40000
	fpDefaultRate  = 1.0
)

// FPOptions tunes ReplayBenign.
type FPOptions struct {
	Registry  *ContentRegistry
	Threshold float64       // noisy when hits per 1000 records of the rule's kind reach this
	Kind      string        // force one kind for every file ("" = detect)
	Builtin   bool          // add the synthetic benign corpus
	Budget    time.Duration // 0 = 5 minutes
}

// FPFile is one replayed input.
type FPFile struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Records  int    `json:"records"`
	Parsed   int    `json:"parsed"`
	Rejected int    `json:"rejected"`
	Hits     int    `json:"hits"`
	Note     string `json:"note,omitempty"`
}

// FPRule is the hit statistics of one rule over the corpus.
type FPRule struct {
	Rule        string   `json:"rule"`
	Family      string   `json:"family"`
	Severity    string   `json:"severity"`
	Kind        string   `json:"kind"`
	Hits        int      `json:"hits"`
	Files       int      `json:"files_hit"`
	Records     int      `json:"records_evaluated"`
	RatePer1000 float64  `json:"hits_per_1000_records"`
	Noisy       bool     `json:"noisy"`
	Samples     []string `json:"samples,omitempty"`
}

// FPReport is the false-positive report.
type FPReport struct {
	Mode      string         `json:"mode"`
	Threshold float64        `json:"noisy_threshold_per_1000"`
	Files     []FPFile       `json:"files"`
	Records   map[string]int `json:"records_by_kind"`
	Rules     []FPRule       `json:"rules"` // rules with at least one hit, noisiest first
	Noisy     []string       `json:"noisy_rules"`
	Skipped   []string       `json:"skipped,omitempty"`
	Truncated bool           `json:"truncated"`
	Note      string         `json:"note"`
}

func harnessFamilyKind(fam string) string {
	switch fam {
	case "web-content", "web-analytic":
		return "web"
	case "auth-analytic":
		return "auth"
	case "idp-analytic":
		return "idp"
	case "ransom-analytic":
		return "ransom"
	case "tripwire":
		return "tripwire"
	}
	return "event"
}

var fpExt = map[string]bool{".log": true, ".txt": true, ".json": true, ".jsonl": true, ".ndjson": true, ".access": true}

var fpKindHints = []struct{ sub, kind string }{
	{"web", "web"}, {"access", "web"}, {"nginx", "web"}, {"apache", "web"}, {"waf", "web"},
	{"okta", "idp"}, {"entra", "idp"}, {"idp", "idp"}, {"azuread", "idp"},
	{"auth", "auth"}, {"login", "auth"}, {"signin", "auth"},
	{"ransom", "ransom"}, {"backup", "ransom"}, {"fileact", "ransom"}, {"file_activity", "ransom"},
	{"event", "event"}, {"corpus", "event"},
}

// fpSniffKind picks a detection path from the file name, then from the first record's keys.
func fpSniffKind(name string, head []byte) string {
	low := strings.ToLower(filepath.Base(name))
	for _, h := range fpKindHints {
		if strings.Contains(low, h.sub) {
			return h.kind
		}
	}
	t := bytes.TrimSpace(head)
	if len(t) == 0 {
		return "web"
	}
	var first map[string]any
	switch t[0] {
	case '[':
		dec := json.NewDecoder(bytes.NewReader(t))
		if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
			return "web"
		}
		if dec.More() {
			_ = dec.Decode(&first)
		}
	case '{':
		line := t
		if i := bytes.IndexByte(t, '\n'); i >= 0 {
			line = t[:i]
		}
		_ = json.Unmarshal(line, &first)
	default:
		return "web"
	}
	if first == nil {
		return "web"
	}
	has := func(keys ...string) bool {
		for k := range first {
			lk := strings.ToLower(k)
			for _, w := range keys {
				if lk == w {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has("kind") && has("executable", "command", "destination", "query", "key", "module_path"):
		return "event"
	case has("eventtype", "activitydisplayname", "userprincipalname"):
		return "idp"
	case has("method", "request", "uri", "request_uri", "clientrequestmethod", "http_method", "verb", "clientrequesturi"):
		return "web"
	case has("new_path", "newpath", "job", "job_name", "entropy", "backup_size", "operation", "op", "file_path", "target_filename", "command_line", "retention"):
		return "ransom"
	case has("user", "username", "email", "principal", "account", "ip", "source_ip", "outcome"):
		return "auth"
	}
	return "web"
}

func fpChunks(kind, text string) []string {
	if kind == "event" || strings.HasPrefix(strings.TrimSpace(text), "[") {
		return []string{text}
	}
	lines := strings.Split(text, "\n")
	if len(lines) <= fpChunkRecords {
		return []string{text}
	}
	var out []string
	for i := 0; i < len(lines); i += fpChunkRecords {
		j := i + fpChunkRecords
		if j > len(lines) {
			j = len(lines)
		}
		out = append(out, strings.Join(lines[i:j], "\n"))
	}
	return out
}

type fpAgg struct {
	hits    int
	files   map[string]bool
	samples []string
}

// ReplayBenign replays the files and directories through the detectors.
func ReplayBenign(paths []string, o FPOptions) (*FPReport, error) {
	reg := o.Registry
	if reg == nil {
		var err error
		if reg, err = HarnessRegistry(); reg == nil {
			return nil, fmt.Errorf("content packs unavailable: %v", err)
		}
	}
	if o.Threshold <= 0 {
		o.Threshold = fpDefaultRate
	}
	if o.Kind != "" && (!harnessKinds[o.Kind] || o.Kind == "netcfg" || o.Kind == "zslog" || o.Kind == "zspolicy" || o.Kind == "zdx") {
		return nil, fmt.Errorf("kind must be one of web, auth, idp, ransom, event")
	}
	budget := o.Budget
	if budget <= 0 {
		budget = 5 * time.Minute
	}
	deadline := time.Now().Add(budget)
	rep := &FPReport{Mode: "observe-only", Threshold: o.Threshold, Files: []FPFile{}, Records: map[string]int{}, Rules: []FPRule{}, Noisy: []string{},
		Note: "this measures only the corpus you supplied: a rule with no hits here can still be noisy elsewhere, and a hit here is a false positive only if the corpus really is clean. Thresholds are fixed heuristics; analytic rules count findings (capped per rule per file), content rules count matching lines or events."}
	agg := map[string]*fpAgg{}
	var total int64

	type input struct{ name, kind, text string }
	var inputs []input
	if o.Builtin {
		for _, k := range []string{"web", "auth", "idp", "ransom"} {
			inputs = append(inputs, input{"builtin:synthetic-" + k, k, fpBenignCorpus(k)})
		}
	}
	var files []string
	for _, p := range paths {
		st, err := os.Lstat(p)
		if err != nil {
			return nil, fmt.Errorf("%s: not readable", filepath.Base(p))
		}
		if st.IsDir() {
			_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
				if err != nil || len(files) >= fpMaxFiles {
					return nil
				}
				if d.Type().IsRegular() && fpExt[strings.ToLower(filepath.Ext(path))] {
					files = append(files, path)
				}
				return nil
			})
			continue
		}
		if !st.Mode().IsRegular() {
			rep.Skipped = append(rep.Skipped, p+" (not a regular file)")
			continue
		}
		files = append(files, p)
	}
	sort.Strings(files)
	if len(files) > fpMaxFiles {
		files = files[:fpMaxFiles]
		rep.Truncated = true
	}
	if len(inputs) == 0 && len(files) == 0 {
		return nil, fmt.Errorf("no input: give --benign DIR_OR_FILE or --builtin")
	}
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			rep.Skipped = append(rep.Skipped, f+" (unreadable)")
			continue
		}
		b, err := io.ReadAll(io.LimitReader(fh, fpMaxFileBytes+1))
		fh.Close()
		if err != nil {
			rep.Skipped = append(rep.Skipped, f+" (read error)")
			continue
		}
		note := ""
		if len(b) > fpMaxFileBytes {
			b = b[:fpMaxFileBytes]
			if i := bytes.LastIndexByte(b, '\n'); i > 0 {
				b = b[:i]
			}
			note = fmt.Sprintf("truncated to the first %d MiB", fpMaxFileBytes>>20)
			rep.Truncated = true
		}
		total += int64(len(b))
		if total > fpMaxTotal {
			rep.Skipped = append(rep.Skipped, f+" (corpus byte limit reached)")
			rep.Truncated = true
			break
		}
		head := b
		if len(head) > 8192 {
			head = head[:8192]
		}
		kind := o.Kind
		if kind == "" {
			kind = fpSniffKind(f, head)
		}
		inputs = append(inputs, input{f, kind, string(b)})
		_ = note
	}
	for _, in := range inputs {
		ff := FPFile{Path: in.name, Kind: in.kind}
		if time.Now().After(deadline) {
			ff.Note = "skipped: time budget reached"
			rep.Truncated = true
			rep.Files = append(rep.Files, ff)
			continue
		}
		for _, chunk := range fpChunks(in.kind, in.text) {
			run := harnessRunKind(in.kind, chunk, "", "", 0, reg)
			ff.Records += run.total
			ff.Parsed += run.parsed
			ff.Rejected += run.rejected
			if run.err != "" && ff.Note == "" {
				ff.Note = run.err
			}
			for r, n := range run.fired {
				a := agg[r]
				if a == nil {
					a = &fpAgg{files: map[string]bool{}}
					agg[r] = a
				}
				a.hits += n
				ff.Hits += n
				a.files[in.name] = true
				for _, s := range run.samples[r] {
					if len(a.samples) < 3 {
						a.samples = append(a.samples, s)
					}
				}
			}
			rep.Records[in.kind] += run.parsed
		}
		rep.Files = append(rep.Files, ff)
	}
	for _, hr := range HarnessInventory(reg) {
		a := agg[hr.ID]
		if a == nil {
			continue
		}
		k := harnessFamilyKind(hr.Family)
		n := rep.Records[k]
		rate := 0.0
		if n > 0 {
			rate = float64(a.hits) * 1000 / float64(n)
		}
		rule := FPRule{Rule: hr.ID, Family: hr.Family, Severity: hr.Severity, Kind: k, Hits: a.hits, Files: len(a.files), Records: n,
			RatePer1000: float64(int(rate*100+0.5)) / 100, Noisy: rate >= o.Threshold, Samples: a.samples}
		rep.Rules = append(rep.Rules, rule)
	}
	sort.Slice(rep.Rules, func(i, j int) bool {
		if rep.Rules[i].RatePer1000 != rep.Rules[j].RatePer1000 {
			return rep.Rules[i].RatePer1000 > rep.Rules[j].RatePer1000
		}
		return rep.Rules[i].Rule < rep.Rules[j].Rule
	})
	for _, r := range rep.Rules {
		if r.Noisy {
			rep.Noisy = append(rep.Noisy, r.Rule)
		}
	}
	return rep, nil
}

// ---- synthetic benign corpus ----

func fpBenignCorpus(kind string) string {
	var b strings.Builder
	base := time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)
	switch kind {
	case "web":
		uas := []string{"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Version/17.2 Safari/605.1.15",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", "okhttp/4.12.0"}
		paths := []string{"/", "/index.html", "/static/app.js", "/static/site.css", "/img/logo.png", "/favicon.ico", "/about", "/pricing",
			"/blog/european-union-station-guide", "/blog/how-to-select-a-laptop", "/docs/script-tag-basics", "/search?q=union+station+hours",
			"/search?q=select+size+medium", "/search?q=drop+shipping+rates", "/api/v1/items?page=2&sort=name", "/api/v1/items/42", "/api/v1/users/me",
			"/products/shoes?color=blue&size=10", "/docs/intro#select", "/healthz"}
		for i := 0; i < 3000; i++ {
			t := base.Add(time.Duration(i) * 1200 * time.Millisecond)
			ip := fmt.Sprintf("198.51.100.%d", 1+i%40)
			status, method := 200, "GET"
			switch {
			case i%53 == 0:
				status = 404
			case i%29 == 0:
				status = 304
			case i%61 == 0:
				status = 301
			case i%97 == 0:
				method, status = "POST", 201
			}
			p := paths[(i*7+i/3)%len(paths)]
			fmt.Fprintf(&b, "%s - - [%s] \"%s %s HTTP/1.1\" %d %d \"-\" \"%s\"\n", ip, t.Format("02/Jan/2006:15:04:05 -0700"), method, p, status, 300+(i*37)%9000, uas[(i%40)%3])
		}
		for i := 0; i < 12; i++ { // a few ordinary login attempts
			t := base.Add(time.Duration(i) * 7 * time.Minute)
			st := 200
			if i%4 == 0 {
				st = 401
			}
			fmt.Fprintf(&b, "198.51.100.%d - - [%s] \"POST /login HTTP/1.1\" %d 512 \"-\" \"%s\"\n", 50+i%5, t.Format("02/Jan/2006:15:04:05 -0700"), st, uas[0])
		}
	case "auth":
		for i := 0; i < 600; i++ {
			t := base.Add(time.Duration(i) * 40 * time.Second)
			u := i % 40
			out := "success"
			if i%37 == 0 {
				out = "failure"
			}
			fmt.Fprintf(&b, `{"time":"%s","user":"user%02d","ip":"203.0.113.%d","outcome":"%s","country":"US","lat":40.7,"lon":-74.0}`+"\n", t.Format(time.RFC3339), u, 1+u%30, out)
		}
	case "idp":
		for i := 0; i < 300; i++ {
			t := base.Add(time.Duration(i) * 90 * time.Second)
			u := i % 25
			fmt.Fprintf(&b, `{"eventType":"user.session.start","published":"%s","actor":{"alternateId":"person%02d@example.org"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"203.0.113.%d","device":"Computer","geographicalContext":{"country":"United States","geolocation":{"lat":40.7,"lon":-74.0}}},"authenticationContext":{"externalSessionId":"sess%03d"}}`+"\n",
				t.Format(time.RFC3339), u, 1+u, i)
		}
		for i := 0; i < 3; i++ {
			t := base.Add(time.Duration(i) * time.Hour)
			fmt.Fprintf(&b, `{"eventType":"user.account.update_password","published":"%s","actor":{"alternateId":"person%02d@example.org"},"outcome":{"result":"SUCCESS"},"client":{"ipAddress":"203.0.113.%d"}}`+"\n", t.Format(time.RFC3339), i, 1+i)
		}
	case "ransom":
		for i := 0; i < 800; i++ {
			t := base.Add(time.Duration(i) * 3 * time.Second)
			switch {
			case i%40 == 0:
				fmt.Fprintf(&b, `{"time":"%s","host":"fs01","op":"rename","path":"C:\\Shares\\docs\\draft%d.docx","new_path":"C:\\Shares\\docs\\final%d.docx","process":"explorer.exe"}`+"\n", t.Format(time.RFC3339), i, i)
			case i%25 == 0:
				fmt.Fprintf(&b, `{"time":"%s","host":"fs01","op":"delete","path":"C:\\Temp\\tmp%d.tmp","process":"svchost.exe"}`+"\n", t.Format(time.RFC3339), i)
			default:
				fmt.Fprintf(&b, `{"time":"%s","host":"fs01","op":"write","path":"C:\\Shares\\docs\\file%d.docx","entropy":%.1f,"process":"winword.exe"}`+"\n", t.Format(time.RFC3339), i%60, 4.2+float64(i%20)/10)
			}
		}
		for i := 0; i < 6; i++ {
			t := base.Add(time.Duration(i) * 24 * time.Hour)
			fmt.Fprintf(&b, `{"time":"%s","host":"bk01","job":"nightly","event":"Job finished","message":"backup completed","backup_size":%d}`+"\n", t.Format(time.RFC3339), 100000+i*1500)
		}
	}
	return b.String()
}

// HarnessBenignCorpus returns the synthetic benign log text for one kind (web, auth, idp, ransom).
func HarnessBenignCorpus(kind string) string { return fpBenignCorpus(kind) }
