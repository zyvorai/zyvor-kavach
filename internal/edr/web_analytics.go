// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Analytics over the web access logs an operator sends (see web_access.go): API endpoint inventory,
// shadow endpoints and verb/parameter drift against an OpenAPI JSON document the operator also sends,
// HTTP flood summaries, login-endpoint credential abuse and enumeration. Windowed detections are
// built-in (the per-event content framework cannot count) and are registered in ruleMITRE the same
// way the failed-login burst detector is. Observation only: nothing here blocks, throttles or
// contacts a server; shadow-API output is a report, not a finding.

const (
	webBucketSecs      = 10  // flood bucket width
	webFloodSource     = 200 // requests from one client in one bucket
	webFloodDistTotal  = 1000
	webFloodDistIPs    = 50
	webLoginMinute     = 20 // login POSTs from one client in one minute
	webLoginRatio      = 0.8
	webStuffWindow     = 300 // seconds
	webStuffAttempts   = 100
	webStuffIPs        = 20
	webStuffPerIPMax   = 5
	webEnumRequests    = 60
	webEnumPaths       = 40
	webEnumRatio       = 0.8
	webUARotation      = 10
	webUARotationReqs  = 30
	webMaxEndpoints    = 5000
	webMaxClients      = 100000
	webAnalyticsFindMx = 25
	webSpecMax         = 4 << 20
	webSpecPathsMax    = 5000
)

var webAnalyticRules = []struct {
	ID, Tactic, Technique, TechID, Sev string
}{
	{"web-an-http-flood-source", "Impact", "Endpoint Denial of Service: Service Exhaustion Flood", "T1499.002", "medium"},
	{"web-an-http-flood-distributed", "Impact", "Endpoint Denial of Service: Service Exhaustion Flood", "T1499.002", "high"},
	{"web-an-login-bruteforce", "Credential Access", "Brute Force", "T1110", "medium"},
	{"web-an-credential-stuffing", "Credential Access", "Brute Force: Credential Stuffing", "T1110.004", "high"},
	{"web-an-path-enumeration", "Reconnaissance", "Active Scanning: Wordlist Scanning", "T1595.003", "medium"},
	{"web-an-ua-rotation", "Reconnaissance", "Active Scanning", "T1595", "low"},
}

func init() {
	for _, r := range webAnalyticRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

// ---- path templating ----

func webIsHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if webHexVal(s[i]) < 0 {
			return false
		}
	}
	return len(s) > 0
}

func webIsDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func webSegTemplate(seg string) string {
	switch {
	case webIsDigits(seg):
		return "{id}"
	case len(seg) == 36 && seg[8] == '-' && seg[13] == '-' && seg[18] == '-' && seg[23] == '-' && webIsHex(strings.ReplaceAll(seg, "-", "")):
		return "{uuid}"
	case len(seg) >= 16 && webIsHex(seg):
		return "{hash}"
	case len(seg) >= 24 && strings.ContainsAny(seg, "0123456789"):
		return "{token}"
	}
	return seg
}

// webTemplate replaces identifier-looking path segments with placeholders.
func webTemplate(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		segs[i] = webSegTemplate(s)
	}
	return "/" + strings.Join(segs, "/")
}

var webStaticExt = []string{".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".txt", ".html", ".htm"}

func webIsStatic(path string) bool {
	p := strings.ToLower(path)
	for _, e := range webStaticExt {
		if strings.HasSuffix(p, e) {
			return true
		}
	}
	return false
}

// ---- OpenAPI (JSON only, stdlib) ----

type webSpecPath struct {
	Template string
	segs     []string
	lits     int
	Methods  map[string]map[string]bool // method -> declared query parameter names
}

// WebSpec is the subset of an OpenAPI 3 / Swagger 2 JSON document the shadow-API check needs.
type WebSpec struct {
	BasePath string
	byLen    map[int][]*webSpecPath
	all      []*webSpecPath
	cache    map[string]*webSpecPath
	Ops      int
}

type specParam struct {
	Ref  string `json:"$ref"`
	Name string `json:"name"`
	In   string `json:"in"`
}

var webSpecMethods = map[string]bool{"get": true, "put": true, "post": true, "delete": true, "options": true, "head": true, "patch": true, "trace": true}

// ParseWebSpec parses an OpenAPI 3.x or Swagger 2.0 document in JSON. YAML is not supported (no
// third-party dependency); convert it first.
func ParseWebSpec(raw []byte) (*WebSpec, error) {
	if len(raw) > webSpecMax {
		return nil, fmt.Errorf("openapi document over %d bytes", webSpecMax)
	}
	var doc struct {
		Swagger  string `json:"swagger"`
		OpenAPI  string `json:"openapi"`
		BasePath string `json:"basePath"`
		Servers  []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Parameters map[string]specParam                  `json:"parameters"`
		Components struct {
			Parameters map[string]specParam `json:"parameters"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("openapi must be JSON: %v", err)
	}
	if doc.Swagger == "" && doc.OpenAPI == "" {
		return nil, errors.New("not an OpenAPI or Swagger document (no openapi/swagger field)")
	}
	if len(doc.Paths) == 0 {
		return nil, errors.New("openapi document has no paths")
	}
	if len(doc.Paths) > webSpecPathsMax {
		return nil, fmt.Errorf("openapi document has more than %d paths", webSpecPathsMax)
	}
	s := &WebSpec{byLen: map[int][]*webSpecPath{}, cache: map[string]*webSpecPath{}}
	base := doc.BasePath
	if base == "" && len(doc.Servers) > 0 {
		u := doc.Servers[0].URL
		if i := strings.Index(u, "://"); i >= 0 {
			u = u[i+3:]
			if j := strings.IndexByte(u, '/'); j >= 0 {
				u = u[j:]
			} else {
				u = ""
			}
		}
		if strings.HasPrefix(u, "/") {
			base = u
		}
	}
	s.BasePath = strings.TrimRight(base, "/")
	params := map[string]specParam{}
	for k, v := range doc.Parameters {
		params["#/parameters/"+k] = v
	}
	for k, v := range doc.Components.Parameters {
		params["#/components/parameters/"+k] = v
	}
	queryNames := func(raw json.RawMessage, into map[string]bool) {
		var list []specParam
		if json.Unmarshal(raw, &list) != nil {
			return
		}
		for _, p := range list {
			if p.Ref != "" {
				p = params[p.Ref]
			}
			if p.In == "query" && p.Name != "" {
				into[p.Name] = true
			}
		}
	}
	for tpl, item := range doc.Paths {
		if !strings.HasPrefix(tpl, "/") {
			continue
		}
		sp := &webSpecPath{Template: tpl, Methods: map[string]map[string]bool{}}
		common := map[string]bool{}
		if raw, ok := item["parameters"]; ok {
			queryNames(raw, common)
		}
		for m, op := range item {
			if !webSpecMethods[strings.ToLower(m)] {
				continue
			}
			q := map[string]bool{}
			for k := range common {
				q[k] = true
			}
			var body struct {
				Parameters json.RawMessage `json:"parameters"`
			}
			if json.Unmarshal(op, &body) == nil && len(body.Parameters) > 0 {
				queryNames(body.Parameters, q)
			}
			sp.Methods[strings.ToUpper(m)] = q
			s.Ops++
		}
		sp.segs = strings.Split(strings.Trim(tpl, "/"), "/")
		if tpl == "/" {
			sp.segs = nil
		}
		for _, g := range sp.segs {
			if !strings.Contains(g, "{") {
				sp.lits++
			}
		}
		s.byLen[len(sp.segs)] = append(s.byLen[len(sp.segs)], sp)
		s.all = append(s.all, sp)
	}
	for _, l := range s.byLen {
		sort.Slice(l, func(i, j int) bool {
			return l[i].lits > l[j].lits || (l[i].lits == l[j].lits && l[i].Template < l[j].Template)
		})
	}
	sort.Slice(s.all, func(i, j int) bool { return s.all[i].Template < s.all[j].Template })
	return s, nil
}

// Match returns the most specific spec path for a concrete request path, and whether the path is
// under the spec base path at all.
func (s *WebSpec) Match(path string) (sp *webSpecPath, inScope bool) {
	if s.BasePath != "" {
		if path != s.BasePath && !strings.HasPrefix(path, s.BasePath+"/") {
			return nil, false
		}
		path = strings.TrimPrefix(path, s.BasePath)
		if path == "" {
			path = "/"
		}
	}
	if v, ok := s.cache[path]; ok {
		return v, true
	}
	trim := strings.Trim(path, "/")
	var segs []string
	if trim != "" {
		segs = strings.Split(trim, "/")
	}
	for _, c := range s.byLen[len(segs)] {
		ok := true
		for i, g := range c.segs {
			if strings.Contains(g, "{") {
				if segs[i] == "" {
					ok = false
					break
				}
				continue
			}
			if g != segs[i] {
				ok = false
				break
			}
		}
		if ok {
			sp = c
			break
		}
	}
	if len(s.cache) < 20000 {
		s.cache[path] = sp
	}
	return sp, true
}

// ---- report types ----

type WebEndpoint struct {
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	Requests    int            `json:"requests"`
	Clients     int            `json:"clients"`
	Statuses    map[string]int `json:"statuses"`
	QueryParams []string       `json:"query_params,omitempty"`
	First       *time.Time     `json:"first_seen,omitempty"`
	Last        *time.Time     `json:"last_seen,omitempty"`
	Documented  *bool          `json:"documented,omitempty"`
}

type WebFloodWindow struct {
	Start        time.Time `json:"start"`
	Seconds      int       `json:"seconds"`
	Requests     int       `json:"requests"`
	Sources      int       `json:"sources"`
	TopSource    string    `json:"top_source"`
	TopSourcePct int       `json:"top_source_pct"`
	TopPath      string    `json:"top_path"`
	ServerErrors int       `json:"server_errors"`
}

type WebClient struct {
	IP            string `json:"ip"`
	Requests      int    `json:"requests"`
	ClientErrors  int    `json:"errors_4xx"`
	ServerErrors  int    `json:"errors_5xx"`
	DistinctPaths int    `json:"distinct_paths"`
}

type WebDrift struct {
	Method            string   `json:"method"`
	Path              string   `json:"path"`
	Requests          int      `json:"requests"`
	DocumentedMethods []string `json:"documented_methods,omitempty"`
	UndeclaredParams  []string `json:"undeclared_params,omitempty"`
}

type WebAPIReport struct {
	SpecLoaded         bool          `json:"spec_loaded"`
	SpecPaths          int           `json:"spec_paths,omitempty"`
	SpecOperations     int           `json:"spec_operations,omitempty"`
	BasePath           string        `json:"base_path,omitempty"`
	EndpointsTotal     int           `json:"endpoints_total"`
	EndpointsTruncated bool          `json:"endpoints_truncated,omitempty"`
	Endpoints          []WebEndpoint `json:"endpoints"`
	Shadow             []WebEndpoint `json:"shadow_endpoints,omitempty"`
	UndocProtected     []WebEndpoint `json:"undocumented_protected,omitempty"`
	VerbDrift          []WebDrift    `json:"verb_drift,omitempty"`
	ParamDrift         []WebDrift    `json:"param_drift,omitempty"`
	NotObserved        []string      `json:"spec_operations_not_observed,omitempty"`
	StaticSkipped      int           `json:"static_requests_skipped"`
}

type WebReport struct {
	Mode          string           `json:"mode"`
	Lines         int              `json:"lines"`
	Parsed        int              `json:"parsed"`
	Rejected      int              `json:"rejected"`
	Oversize      int              `json:"oversize_lines"`
	Untimed       int              `json:"untimed"`
	NotEvaluated  int              `json:"not_evaluated"`
	From          *time.Time       `json:"from,omitempty"`
	To            *time.Time       `json:"to,omitempty"`
	Statuses      map[string]int   `json:"status_classes"`
	Methods       map[string]int   `json:"methods"`
	TopClients    []WebClient      `json:"top_clients"`
	PeakPerSecond float64          `json:"peak_requests_per_second"`
	Flood         []WebFloodWindow `json:"flood_windows,omitempty"`
	ByRule        map[string]int   `json:"by_rule"`
	Findings      int              `json:"findings"`
	FindingsCap   bool             `json:"findings_truncated,omitempty"`
	IPsTruncated  bool             `json:"clients_truncated,omitempty"`
	API           WebAPIReport     `json:"api"`
	Errors        []string         `json:"errors,omitempty"`
	Note          string           `json:"note"`
}

type webLite struct {
	t      time.Time
	hasT   bool
	ip     string
	method string
	path   string
	status int
	ua     string
	login  bool
	static bool
}

type webClientAgg struct {
	req, e4, e5 int
	paths       map[string]struct{}
	paths4      map[string]struct{}
	uas         map[string]struct{}
}

type webEpAgg struct {
	method, path string
	req          int
	st           map[string]int
	clients      map[string]struct{}
	params       map[string]int
	first, last  time.Time
	hasT         bool
	sample       string
	documented   *bool
	denied       int
}

func webIsLogin(method, path string) bool {
	p := strings.ToLower(path)
	if strings.Contains(p, "xmlrpc.php") {
		return method == "POST"
	}
	if method != "POST" {
		return false
	}
	for _, k := range []string{"login", "signin", "sign-in", "sign_in", "logon", "authenticate", "/auth", "/session", "/token", "wp-login", "/oauth", "/sso", "/user/login"} {
		if strings.Contains(p, k) {
			return true
		}
	}
	return false
}

func webStatusClass(s int) string { return fmt.Sprintf("%dxx", s/100) }

func webLoginFailure(status int) bool {
	return status == 401 || status == 403 || status == 422 || status == 429 || status == 400
}

// AnalyzeWebLogs parses, evaluates and summarises one batch of log text.
func AnalyzeWebLogs(text, format, hostOverride string, spec *WebSpec, reg *ContentRegistry) (*WebReport, []Finding, error) {
	rep := &WebReport{Mode: "observe-only", Statuses: map[string]int{}, Methods: map[string]int{}, ByRule: map[string]int{},
		API: WebAPIReport{Endpoints: []WebEndpoint{}}, TopClients: []WebClient{},
		Note: "offline analysis of logs you sent; no request was made to any server. Thresholds are fixed heuristics, not tuned to your traffic."}
	lines := strings.Split(text, "\n")
	var findings []Finding
	var recs []webLite
	clients := map[string]*webClientAgg{}
	eps := map[string]*webEpAgg{}
	deadline := time.Now().Add(webEvalBudget)
	seen := map[string]bool{}
	note := func(msg string) {
		if len(rep.Errors) < webErrorsMax {
			rep.Errors = append(rep.Errors, msg)
		}
	}
	for ln, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rep.Lines++
		if len(line) > webLineMax {
			rep.Oversize++
			rep.Rejected++
			note(fmt.Sprintf("line %d: over %d bytes", ln+1, webLineMax))
			continue
		}
		rec, err := ParseWebLine(line, format)
		if err != nil {
			rep.Rejected++
			note(fmt.Sprintf("line %d: %v", ln+1, err))
			continue
		}
		rep.Parsed++
		ev := NormalizeWebRecord(rec, hostOverride)
		if !rec.HasTime {
			rep.Untimed++
		} else {
			if rep.From == nil || rec.Time.Before(*rep.From) {
				t := rec.Time
				rep.From = &t
			}
			if rep.To == nil || rec.Time.After(*rep.To) {
				t := rec.Time
				rep.To = &t
			}
		}
		rep.Statuses[webStatusClass(rec.Status)]++
		rep.Methods[rec.Method]++
		// rule evaluation (bounded)
		if rep.Parsed > 1 && time.Now().After(deadline) {
			rep.NotEvaluated++
		} else {
			for _, f := range WebEvaluate(reg, ev) {
				rep.ByRule[f.Rule]++
				if len(findings) >= webFindingsMx {
					rep.FindingsCap = true
					continue
				}
				// one finding per (rule, client, path) so a scanner replaying a probe is stored once
				key := f.Rule + "|" + rec.IP + "|" + ev.Path
				if seen[key] {
					continue
				}
				seen[key] = true
				f.ID = fmt.Sprintf("web:%s:%08x", f.Rule, fnv32(key+"|"+rec.Time.String()+"|"+fmt.Sprint(ln)))
				findings = append(findings, f)
			}
		}
		l := webLite{t: rec.Time, hasT: rec.HasTime, ip: rec.IP, method: rec.Method, path: webTruncate(ev.Path, 256),
			status: rec.Status, ua: webTruncate(ev.Lab.ParentExe, 80), static: webIsStatic(ev.Path)}
		l.login = webIsLogin(rec.Method, ev.Path)
		recs = append(recs, l)
		// client aggregate
		c := clients[rec.IP]
		if c == nil && len(clients) < webMaxClients {
			c = &webClientAgg{paths: map[string]struct{}{}, paths4: map[string]struct{}{}, uas: map[string]struct{}{}}
			clients[rec.IP] = c
		} else if c == nil {
			rep.IPsTruncated = true
		}
		if c != nil {
			c.req++
			switch rec.Status / 100 {
			case 4:
				c.e4++
				if len(c.paths4) < 200 {
					c.paths4[l.path] = struct{}{}
				}
			case 5:
				c.e5++
			}
			if len(c.paths) < 200 {
				c.paths[l.path] = struct{}{}
			}
			if len(c.uas) < 16 {
				c.uas[l.ua] = struct{}{}
			}
		}
		// API inventory
		if l.static {
			rep.API.StaticSkipped++
			continue
		}
		tpl := webTemplate(ev.Path)
		var documented *bool
		if spec != nil {
			sp, scope := spec.Match(ev.Path)
			if !scope {
				continue // outside the documented base path: not an API request
			}
			d := sp != nil && sp.Methods[rec.Method] != nil
			if sp != nil {
				tpl = sp.Template
			}
			documented = &d
		}
		key := rec.Method + " " + tpl
		e := eps[key]
		if e == nil {
			if len(eps) >= webMaxEndpoints {
				rep.API.EndpointsTruncated = true
				continue
			}
			e = &webEpAgg{method: rec.Method, path: tpl, st: map[string]int{}, clients: map[string]struct{}{}, params: map[string]int{}, sample: ev.Path, documented: documented}
			eps[key] = e
		}
		e.req++
		e.st[webStatusClass(rec.Status)]++
		if rec.Status == 401 || rec.Status == 403 {
			e.denied++
		}
		if len(e.clients) < 64 {
			e.clients[rec.IP] = struct{}{}
		}
		for _, p := range ev.Params {
			if len(e.params) < 40 || e.params[p] > 0 {
				e.params[p]++
			}
		}
		if rec.HasTime {
			if !e.hasT || rec.Time.Before(e.first) {
				e.first = rec.Time
			}
			if !e.hasT || rec.Time.After(e.last) {
				e.last = rec.Time
			}
			e.hasT = true
		}
	}
	fhost := hostOverride
	if fhost == "" {
		fhost = "web:logs"
	} else {
		fhost = "web:" + strings.ToLower(webTruncate(webSanitise(fhost), 120))
	}
	findings = append(findings, webWindowed(rep, recs, clients, fhost)...)
	webTopClients(rep, clients)
	webAPIReport(rep, eps, spec)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Time.Before(findings[j].Time) })
	rep.Findings = len(findings)
	return rep, findings, nil
}

func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func webTopClients(rep *WebReport, clients map[string]*webClientAgg) {
	for ip, c := range clients {
		rep.TopClients = append(rep.TopClients, WebClient{IP: ip, Requests: c.req, ClientErrors: c.e4, ServerErrors: c.e5, DistinctPaths: len(c.paths)})
	}
	sort.Slice(rep.TopClients, func(i, j int) bool {
		if rep.TopClients[i].Requests != rep.TopClients[j].Requests {
			return rep.TopClients[i].Requests > rep.TopClients[j].Requests
		}
		return rep.TopClients[i].IP < rep.TopClients[j].IP
	})
	if len(rep.TopClients) > 10 {
		rep.TopClients = rep.TopClients[:10]
	}
}

func webAnalyticFinding(rule, host, ip string, t time.Time, desc string) Finding {
	sev := "medium"
	for _, r := range webAnalyticRules {
		if r.ID == rule {
			sev = r.Sev
		}
	}
	m := ruleMITRE[rule]
	return Finding{ID: fmt.Sprintf("%s:%s:%s:%d", host, rule, ip, t.UnixNano()), Time: t, Host: host, Rule: rule, Severity: sev,
		Description: desc + " (heuristic over the logs you sent; investigate, not proof of malicious intent)",
		Destination: ip, Tags: []string{m.ID, "web-access", "analytics", "observe-only"},
		Evidence: Event{Time: t, Host: host, Executable: webExecutable, Command: webTruncate(desc, 300)}}
}

type webBucket struct {
	id      int64
	total   int
	e5      int
	ips     map[string]int
	paths   map[string]int
	started time.Time
}

// webWindowed runs the count-based detections: floods, login abuse, enumeration, UA rotation.
func webWindowed(rep *WebReport, recs []webLite, clients map[string]*webClientAgg, host string) []Finding {
	var out []Finding
	add := func(f Finding) {
		if len(out) < webAnalyticsFindMx*6 {
			out = append(out, f)
			rep.ByRule[f.Rule]++
		}
	}
	timed := make([]webLite, 0, len(recs))
	for _, r := range recs {
		if r.hasT {
			timed = append(timed, r)
		}
	}
	sort.SliceStable(timed, func(i, j int) bool { return timed[i].t.Before(timed[j].t) })

	// 10-second buckets: floods
	var cur *webBucket
	srcFlagged := map[string]bool{}
	var windows []WebFloodWindow
	var peak int
	closeB := func(b *webBucket) {
		if b == nil {
			return
		}
		if b.total > peak {
			peak = b.total
		}
		topIP, topN := "", 0
		for ip, n := range b.ips {
			if n > topN || (n == topN && ip < topIP) {
				topIP, topN = ip, n
			}
		}
		topPath, topP := "", 0
		for p, n := range b.paths {
			if n > topP || (n == topP && p < topPath) {
				topPath, topP = p, n
			}
		}
		for ip, n := range b.ips {
			if n >= webFloodSource && !srcFlagged[ip] && len(srcFlagged) < webAnalyticsFindMx {
				srcFlagged[ip] = true
				add(webAnalyticFinding("web-an-http-flood-source", host, ip, b.started,
					fmt.Sprintf("%s sent %d requests in %ds (%.0f req/s), top path %s", ip, n, webBucketSecs, float64(n)/webBucketSecs, topPath)))
			}
		}
		pct := 0
		if b.total > 0 {
			pct = topN * 100 / b.total
		}
		if b.total >= webFloodDistTotal {
			windows = append(windows, WebFloodWindow{Start: b.started, Seconds: webBucketSecs, Requests: b.total, Sources: len(b.ips),
				TopSource: topIP, TopSourcePct: pct, TopPath: topPath, ServerErrors: b.e5})
		}
	}
	for _, r := range timed {
		id := r.t.Unix() / webBucketSecs
		if cur == nil || cur.id != id {
			closeB(cur)
			cur = &webBucket{id: id, ips: map[string]int{}, paths: map[string]int{}, started: time.Unix(id*webBucketSecs, 0).UTC()}
		}
		cur.total++
		if r.status >= 500 {
			cur.e5++
		}
		if _, ok := cur.ips[r.ip]; ok || len(cur.ips) < 20000 {
			cur.ips[r.ip]++
		}
		if _, ok := cur.paths[r.path]; ok || len(cur.paths) < 5000 {
			cur.paths[r.path]++
		}
	}
	closeB(cur)
	sort.Slice(windows, func(i, j int) bool { return windows[i].Requests > windows[j].Requests })
	if len(windows) > 0 {
		w := windows[0]
		if w.Sources >= webFloodDistIPs && w.TopSourcePct < 50 {
			add(webAnalyticFinding("web-an-http-flood-distributed", host, "", w.Start,
				fmt.Sprintf("%d requests from %d sources in %ds (top source %d%%, top path %s, %d server errors)", w.Requests, w.Sources, w.Seconds, w.TopSourcePct, w.TopPath, w.ServerErrors)))
		}
	}
	if len(windows) > 20 {
		windows = windows[:20]
	}
	rep.Flood = windows
	rep.PeakPerSecond = float64(peak) / webBucketSecs

	// login endpoints
	type minKey struct {
		ip string
		m  int64
	}
	type minAgg struct{ n, fail int }
	per := map[minKey]*minAgg{}
	loginFlag := map[string]bool{}
	var sb *struct {
		id       int64
		n, fail  int
		perIP    map[string]int
		started  time.Time
		reported bool
	}
	stuffReports := 0
	closeS := func() {
		if sb == nil || sb.reported || stuffReports >= 5 {
			return
		}
		if sb.n >= webStuffAttempts && len(sb.perIP) >= webStuffIPs && float64(sb.fail)/float64(sb.n) >= webLoginRatio {
			counts := make([]int, 0, len(sb.perIP))
			for _, n := range sb.perIP {
				counts = append(counts, n)
			}
			sort.Ints(counts)
			if counts[len(counts)/2] <= webStuffPerIPMax {
				stuffReports++
				sb.reported = true
				add(webAnalyticFinding("web-an-credential-stuffing", host, "", sb.started,
					fmt.Sprintf("%d login attempts (%d%% failed) from %d sources in %ds, median %d per source (distributed, low-and-slow)", sb.n, sb.fail*100/sb.n, len(sb.perIP), webStuffWindow, counts[len(counts)/2])))
			}
		}
	}
	for _, r := range timed {
		if !r.login {
			continue
		}
		k := minKey{r.ip, r.t.Unix() / 60}
		a := per[k]
		if a == nil && len(per) < 200000 {
			a = &minAgg{}
			per[k] = a
		}
		fail := webLoginFailure(r.status)
		if a != nil {
			a.n++
			if fail {
				a.fail++
			}
			if a.n >= webLoginMinute && float64(a.fail)/float64(a.n) >= webLoginRatio && !loginFlag[r.ip] && len(loginFlag) < webAnalyticsFindMx {
				loginFlag[r.ip] = true
				add(webAnalyticFinding("web-an-login-bruteforce", host, r.ip, r.t,
					fmt.Sprintf("%s made %d login requests in one minute, %d%% failed (HTTP 400/401/403/422/429)", r.ip, a.n, a.fail*100/a.n)))
			}
		}
		id := r.t.Unix() / webStuffWindow
		if sb == nil || sb.id != id {
			closeS()
			sb = &struct {
				id       int64
				n, fail  int
				perIP    map[string]int
				started  time.Time
				reported bool
			}{id: id, perIP: map[string]int{}, started: time.Unix(id*webStuffWindow, 0).UTC()}
		}
		sb.n++
		if fail {
			sb.fail++
		}
		if _, ok := sb.perIP[r.ip]; ok || len(sb.perIP) < 20000 {
			sb.perIP[r.ip]++
		}
	}
	closeS()

	// per-client enumeration and UA rotation (works without timestamps)
	ips := make([]string, 0, len(clients))
	for ip := range clients {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	nEnum, nUA := 0, 0
	t0 := time.Now().UTC() // untimed logs: stamp enumeration findings with the receive time
	if rep.From != nil {
		t0 = *rep.From
	}
	for _, ip := range ips {
		c := clients[ip]
		if c.req >= webEnumRequests && len(c.paths4) >= webEnumPaths && float64(c.e4)/float64(c.req) >= webEnumRatio && nEnum < webAnalyticsFindMx {
			nEnum++
			add(webAnalyticFinding("web-an-path-enumeration", host, ip, t0,
				fmt.Sprintf("%s requested %d distinct missing or forbidden paths in %d requests (%d%% 4xx): wordlist-style enumeration", ip, len(c.paths4), c.req, c.e4*100/c.req)))
		}
		if c.req >= webUARotationReqs && len(c.uas) >= webUARotation && nUA < webAnalyticsFindMx {
			nUA++
			add(webAnalyticFinding("web-an-ua-rotation", host, ip, t0,
				fmt.Sprintf("%s used %d different User-Agent values over %d requests", ip, len(c.uas), c.req)))
		}
	}
	return out
}

func webAPIReport(rep *WebReport, eps map[string]*webEpAgg, spec *WebSpec) {
	api := &rep.API
	api.EndpointsTotal = len(eps)
	keys := make([]string, 0, len(eps))
	for k := range eps {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := eps[keys[i]], eps[keys[j]]
		if a.req != b.req {
			return a.req > b.req
		}
		return keys[i] < keys[j]
	})
	conv := func(e *webEpAgg) WebEndpoint {
		we := WebEndpoint{Method: e.method, Path: e.path, Requests: e.req, Clients: len(e.clients), Statuses: e.st, Documented: e.documented}
		names := make([]string, 0, len(e.params))
		for p := range e.params {
			names = append(names, p)
		}
		sort.Strings(names)
		we.QueryParams = names
		if e.hasT {
			f, l := e.first, e.last
			we.First, we.Last = &f, &l
		}
		return we
	}
	for i, k := range keys {
		if i < 200 {
			api.Endpoints = append(api.Endpoints, conv(eps[k]))
		}
	}
	if spec == nil {
		return
	}
	api.SpecLoaded, api.SpecPaths, api.SpecOperations, api.BasePath = true, len(spec.all), spec.Ops, spec.BasePath
	observed := map[string]bool{}
	for _, k := range keys {
		e := eps[k]
		observed[k] = true
		sp, _ := spec.Match(e.sample)
		ok2xx := e.st["2xx"]+e.st["3xx"] > 0
		protected := e.denied > 0 && !ok2xx // 401/403 only: exists but protected; 404-only is scanner noise
		switch {
		case sp == nil:
			we := conv(e)
			we.Path = e.sample
			if ok2xx {
				api.Shadow = append(api.Shadow, we)
			} else if protected {
				api.UndocProtected = append(api.UndocProtected, we)
			}
		case e.documented != nil && !*e.documented && e.method != "HEAD" && e.method != "OPTIONS" && ok2xx:
			var docs []string
			for m := range sp.Methods {
				docs = append(docs, m)
			}
			sort.Strings(docs)
			api.VerbDrift = append(api.VerbDrift, WebDrift{Method: e.method, Path: sp.Template, Requests: e.req, DocumentedMethods: docs})
		case e.documented != nil && *e.documented:
			declared := sp.Methods[e.method]
			var extra []string
			for p := range e.params {
				if !declared[p] {
					extra = append(extra, p)
				}
			}
			if len(extra) > 0 {
				sort.Strings(extra)
				api.ParamDrift = append(api.ParamDrift, WebDrift{Method: e.method, Path: sp.Template, Requests: e.req, UndeclaredParams: extra})
			}
		}
	}
	for _, sp := range spec.all {
		ms := make([]string, 0, len(sp.Methods))
		for m := range sp.Methods {
			ms = append(ms, m)
		}
		sort.Strings(ms)
		for _, m := range ms {
			if !observed[m+" "+sp.Template] && len(api.NotObserved) < 200 {
				api.NotObserved = append(api.NotObserved, m+" "+sp.Template)
			}
		}
	}
	capEP := func(l []WebEndpoint) []WebEndpoint {
		if len(l) > 200 {
			return l[:200]
		}
		return l
	}
	api.Shadow, api.UndocProtected = capEP(api.Shadow), capEP(api.UndocProtected)
	if len(api.VerbDrift) > 200 {
		api.VerbDrift = api.VerbDrift[:200]
	}
	if len(api.ParamDrift) > 200 {
		api.ParamDrift = api.ParamDrift[:200]
	}
}

// ---- HTTP ----

var webFormats = []string{"auto", "combined", "json", "logfmt"}

func webStoreFindings(store *Store, findings []Finding) (int, error) {
	if store == nil || len(findings) == 0 {
		return 0, nil
	}
	findings = FilterExcluded(findings)
	n := 0
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, f := range findings {
		if err := store.appendFindingLocked(f); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func webAdmin(w http.ResponseWriter, r *http.Request, token string) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !secureEqual(got, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func webReadBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, webBodyMax)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid body", http.StatusBadRequest)
		}
		return nil, false
	}
	return raw, true
}

func webRun(w http.ResponseWriter, store *Store, text, format, host string, spec *WebSpec) {
	switch format {
	case "", "auto", "combined", "common", "clf", "json", "logfmt", "f5":
	default:
		http.Error(w, "unknown format (auto|combined|json|logfmt)", http.StatusBadRequest)
		return
	}
	if strings.Count(text, "\n") > webLinesMax {
		http.Error(w, fmt.Sprintf("too many lines (max %d)", webLinesMax), http.StatusRequestEntityTooLarge)
		return
	}
	if strings.TrimSpace(text) == "" {
		http.Error(w, "empty log", http.StatusBadRequest)
		return
	}
	rep, findings, err := AnalyzeWebLogs(text, format, host, spec, contentReg.Load())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if rep.Parsed == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "no line could be parsed", "rejected": rep.Rejected, "errors": rep.Errors})
		return
	}
	stored, err := webStoreFindings(store, findings)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	rep.Findings = stored
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}

// RegisterWebLogs mounts the web access-log routes. Ingest needs the admin token; the sources
// listing needs any authenticated caller.
func RegisterWebLogs(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("POST /v1/web/logs", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		webRun(w, store, string(raw), strings.ToLower(r.URL.Query().Get("format")), r.URL.Query().Get("host"), nil)
	})
	mux.HandleFunc("POST /v1/web/analyze", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		var env struct {
			Log     string          `json:"log"`
			Format  string          `json:"format"`
			Host    string          `json:"host"`
			OpenAPI json.RawMessage `json:"openapi"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			http.Error(w, "body must be JSON {log, format?, host?, openapi?}", http.StatusBadRequest)
			return
		}
		var spec *WebSpec
		if len(env.OpenAPI) > 0 && string(env.OpenAPI) != "null" {
			var err error
			if spec, err = ParseWebSpec(env.OpenAPI); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		webRun(w, store, env.Log, strings.ToLower(env.Format), env.Host, spec)
	})
	mux.HandleFunc("GET /v1/web/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		rules := 0
		if reg := contentReg.Load(); reg != nil {
			rules = len(webRules(reg))
		}
		an := make([]map[string]string, 0, len(webAnalyticRules))
		for _, a := range webAnalyticRules {
			an = append(an, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"formats": webFormats, "rules": rules, "rule_prefix": "web-", "analytic_rules": an, "auth_analytic_rules": authAnalyticList(),
			"observation_only": true, "openapi": "JSON only (OpenAPI 3.x or Swagger 2.0)",
			"limits": map[string]int{"body_bytes": webBodyMax, "lines": webLinesMax, "line_bytes": webLineMax, "findings_per_request": webFindingsMx}})
	})
}
