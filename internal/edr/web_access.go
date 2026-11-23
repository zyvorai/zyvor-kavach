// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Offline web access-log detection (observation only). Access logs that the operator SENDS (NGINX,
// Apache, F5 BIG-IP / Advanced WAF key=value or JSON, Cloudflare Logpush JSON, any JSON or logfmt
// line with recognisable keys) are parsed with a linear, bounded scanner, normalised into the
// process-shaped event the content engine already evaluates, and matched against the `web-` rules
// (content/web_access.json, batch web-access-v1). Kavach never fetches logs, never contacts a web
// server and never blocks a request.
//
// Canonical mapping onto the rule event:
//
//	executable  = web:access
//	operation   = HTTP method (INVALID when the request line is not an HTTP request line)
//	parent_exe  = User-Agent (control characters removed, 200 chars)
//	path        = decoded request path without the query
//	destination = client IP as logged
//	host        = web:<virtual host or ?host= label>
//	command     = "status=<n> bytes=<n> len=<raw target length> dec=<decode passes 0-3> target=<decoded path and query>"
//
// The target keeps at most webTargetMax characters. Values of secret-looking query parameters are
// replaced with REDACTED in the stored evidence (matching runs on the unredacted text first).
const (
	webBodyMax    = 8 << 20
	webLinesMax   = 50000
	webLineMax    = 64 << 10
	webTargetMax  = 2048
	webUAMax      = 200
	webEvidenceMx = 300
	webErrorsMax  = 5
	webFindingsMx = 2000
	webEvalBudget = 3 * time.Second
	webBatchTag   = "web-access-v1"
	webExecutable = "web:access"
)

// WebRecord is one parsed access-log line.
type WebRecord struct {
	Time    time.Time
	HasTime bool
	IP      string
	User    string
	Host    string
	Method  string
	Target  string // raw request target as logged (path and query)
	Referer string
	UA      string
	Status  int
	Bytes   int64
}

// ---- line scanner ----

type webScan struct {
	s string
	i int
}

func (p *webScan) skipSpace() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func (p *webScan) token() string {
	p.skipSpace()
	st := p.i
	for p.i < len(p.s) && p.s[p.i] != ' ' && p.s[p.i] != '\t' {
		p.i++
	}
	return p.s[st:p.i]
}

func (p *webScan) bracket() (string, bool) {
	p.skipSpace()
	if p.i >= len(p.s) || p.s[p.i] != '[' {
		return "", false
	}
	j := strings.IndexByte(p.s[p.i:], ']')
	if j < 0 {
		return "", false
	}
	v := p.s[p.i+1 : p.i+j]
	p.i += j + 1
	return v, true
}

// quoted reads a double-quoted field. A backslash escapes the next byte (Apache writes \" and nginx
// writes \x22, which stays literal text).
func (p *webScan) quoted() (string, bool) {
	p.skipSpace()
	if p.i >= len(p.s) || p.s[p.i] != '"' {
		return "", false
	}
	var b strings.Builder
	k := p.i + 1
	for k < len(p.s) {
		c := p.s[k]
		if c == '\\' && k+1 < len(p.s) {
			b.WriteByte(p.s[k+1])
			k += 2
			continue
		}
		if c == '"' {
			p.i = k + 1
			return b.String(), true
		}
		b.WriteByte(c)
		k++
	}
	return "", false
}

func webMethodOK(m string) bool {
	if len(m) < 3 || len(m) > 16 {
		return false
	}
	for i := 0; i < len(m); i++ {
		if (m[i] < 'A' || m[i] > 'Z') && m[i] != '-' {
			return false
		}
	}
	return true
}

// splitRequestLine splits `METHOD target [HTTP/x]`. Anything that is not shaped like that (binary
// TLS probes, garbage) comes back as method INVALID with the whole text as the target.
func splitRequestLine(req string) (method, target string) {
	req = strings.TrimSpace(req)
	sp := strings.IndexByte(req, ' ')
	if sp <= 0 {
		return "INVALID", req
	}
	m := req[:sp]
	if !webMethodOK(m) {
		return "INVALID", req
	}
	rest := strings.TrimSpace(req[sp+1:])
	if k := strings.LastIndexByte(rest, ' '); k >= 0 && strings.HasPrefix(strings.ToUpper(rest[k+1:]), "HTTP/") {
		rest = strings.TrimSpace(rest[:k])
	}
	return m, rest
}

var webTimeLayouts = []string{"02/Jan/2006:15:04:05 -0700", time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05",
	"02/Jan/2006:15:04:05", "Jan 2 2006 15:04:05", "2006-01-02T15:04:05Z0700", "2006-01-02 15:04:05 -0700"}

// parseWebTime accepts the usual access-log layouts and numeric epochs (s, ms, us, ns).
func parseWebTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return time.Time{}, false
	}
	sane := func(t time.Time) (time.Time, bool) {
		if y := t.Year(); y < 2000 || y > 2100 {
			return time.Time{}, false
		}
		return t.UTC(), true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && f > 0 {
		switch {
		case f >= 1e17:
			f /= 1e9
		case f >= 1e14:
			f /= 1e6
		case f >= 1e11:
			f /= 1e3
		}
		if f > 4.2e9 {
			return time.Time{}, false
		}
		sec := math.Floor(f)
		return sane(time.Unix(int64(sec), int64((f-sec)*1e9)))
	}
	for _, l := range webTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return sane(t)
		}
	}
	return time.Time{}, false
}

func webAtoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return -1
	}
	return n
}

func parseWebCLF(line string) (WebRecord, error) {
	p := &webScan{s: line}
	var r WebRecord
	r.IP = p.token()
	if r.IP == "" {
		return r, fmt.Errorf("empty line")
	}
	_ = p.token() // ident
	if u := p.token(); u != "-" {
		r.User = u
	}
	ts, ok := p.bracket()
	if !ok {
		return r, fmt.Errorf("no [time] field")
	}
	r.Time, r.HasTime = parseWebTime(ts)
	req, ok := p.quoted()
	if !ok {
		return r, fmt.Errorf("no quoted request")
	}
	r.Method, r.Target = splitRequestLine(req)
	r.Status = webAtoi(p.token())
	if r.Status < 100 || r.Status > 599 {
		return r, fmt.Errorf("bad status")
	}
	if b := p.token(); b != "-" {
		if n, err := strconv.ParseInt(b, 10, 64); err == nil && n >= 0 {
			r.Bytes = n
		}
	}
	if ref, ok := p.quoted(); ok {
		if ref != "-" {
			r.Referer = ref
		}
		if ua, ok := p.quoted(); ok && ua != "-" {
			r.UA = ua
		}
	}
	return r, nil
}

// webFlatten flattens nested JSON objects (depth 3) into lower-case dotted keys with string values.
func webFlatten(m map[string]any, prefix string, depth int, out map[string]string) {
	for k, v := range m {
		key := strings.ToLower(prefix + k)
		switch x := v.(type) {
		case string:
			out[key] = x
		case float64:
			out[key] = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			out[key] = strconv.FormatBool(x)
		case map[string]any:
			if depth < 3 {
				webFlatten(x, key+".", depth+1, out)
			}
		}
	}
}

func webPick(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" && v != "-" {
			return v
		}
	}
	return ""
}

// webFromKV builds a record from a flat lower-case key/value map (JSON or logfmt).
func webFromKV(m map[string]string) (WebRecord, error) {
	var r WebRecord
	r.IP = webPick(m, "remote_addr", "client_ip", "clientip", "clientrequestip", "src_ip", "source.ip", "ip_client", "c-ip", "remote_ip", "client.ip", "src")
	r.Method = strings.ToUpper(webPick(m, "method", "request_method", "clientrequestmethod", "http.request.method", "cs-method", "verb"))
	uri := webPick(m, "request_uri", "uri", "url", "clientrequesturi", "url.original", "cs-uri-stem", "path", "url.path", "target")
	if q := webPick(m, "cs-uri-query", "url.query", "query_string", "query"); q != "" && !strings.Contains(uri, "?") && uri != "" {
		uri += "?" + q
	}
	if req := webPick(m, "request", "request_line", "http.request.line"); req != "" && (r.Method == "" || uri == "") {
		method, target := splitRequestLine(strings.SplitN(req, "\n", 2)[0])
		if r.Method == "" {
			r.Method = method
		}
		if uri == "" {
			uri = target
		}
	}
	r.Target = uri
	r.Status = webAtoi(webPick(m, "status", "response_code", "sc-status", "edgeresponsestatus", "http.response.status_code", "request_status", "code"))
	if n, err := strconv.ParseInt(webPick(m, "body_bytes_sent", "bytes_sent", "bytes", "size", "edgeresponsebytes", "http.response.body.bytes", "sc-bytes", "response_size"), 10, 64); err == nil && n >= 0 {
		r.Bytes = n
	}
	r.UA = webPick(m, "http_user_agent", "user_agent", "useragent", "ua", "clientrequestuseragent", "user_agent.original", "cs(user-agent)", "agent")
	r.Referer = webPick(m, "http_referer", "referer", "referrer", "clientrequestreferer", "cs(referer)")
	r.Host = webPick(m, "host", "server_name", "vhost", "http_host", "clientrequesthost", "url.domain", "virtual_server_name", "vs_name")
	r.User = webPick(m, "remote_user", "user", "user.name", "username")
	r.Time, r.HasTime = parseWebTime(webPick(m, "time_iso8601", "time_local", "@timestamp", "timestamp", "time", "edgestarttimestamp", "ts", "date_time", "datetime"))
	if r.IP == "" || r.Target == "" {
		return r, fmt.Errorf("missing client ip or request target")
	}
	if r.Method == "" {
		r.Method = "INVALID"
	}
	if r.Status < 100 || r.Status > 599 {
		return r, fmt.Errorf("missing or bad status")
	}
	return r, nil
}

func parseWebJSON(line string) (WebRecord, error) {
	var m map[string]any
	if err := json.NewDecoder(strings.NewReader(line)).Decode(&m); err != nil {
		return WebRecord{}, fmt.Errorf("bad JSON: %v", err)
	}
	flat := map[string]string{}
	webFlatten(m, "", 0, flat)
	return webFromKV(flat)
}

// parseWebLogfmt reads key=value pairs separated by spaces or commas; values may be double quoted
// (the F5 BIG-IP ASM / Advanced WAF request log uses key="value",key="value").
func parseWebLogfmt(line string) (WebRecord, error) {
	m := map[string]string{}
	i := 0
	for i < len(line) && len(m) < 200 {
		for i < len(line) && (line[i] == ' ' || line[i] == ',' || line[i] == '\t') {
			i++
		}
		st := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' && line[i] != ',' {
			i++
		}
		if i >= len(line) || line[i] != '=' {
			continue
		}
		key := strings.ToLower(line[st:i])
		i++
		var val string
		if i < len(line) && line[i] == '"' {
			p := &webScan{s: line, i: i}
			v, ok := p.quoted()
			if !ok {
				return WebRecord{}, fmt.Errorf("unterminated quote")
			}
			val, i = v, p.i
		} else {
			vs := i
			for i < len(line) && line[i] != ' ' && line[i] != ',' {
				i++
			}
			val = line[vs:i]
		}
		if key != "" {
			m[key] = val
		}
	}
	if len(m) == 0 {
		return WebRecord{}, fmt.Errorf("no key=value pairs")
	}
	return webFromKV(m)
}

// ParseWebLine parses one line. format is auto, combined (also common), json or logfmt.
func ParseWebLine(line, format string) (WebRecord, error) {
	line = strings.TrimSpace(strings.TrimRight(line, "\r\n"))
	if line == "" {
		return WebRecord{}, fmt.Errorf("empty line")
	}
	switch format {
	case "combined", "common", "clf":
		return parseWebCLF(line)
	case "json":
		return parseWebJSON(line)
	case "logfmt", "f5":
		return parseWebLogfmt(line)
	}
	switch {
	case line[0] == '{':
		return parseWebJSON(line)
	case strings.Contains(line, "] \""):
		return parseWebCLF(line)
	case strings.Contains(line, "="):
		return parseWebLogfmt(line)
	}
	return WebRecord{}, fmt.Errorf("unrecognised log format")
}

// ---- decoding and normalisation ----

func webHexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// webPctDecode decodes %XX sequences once; malformed sequences stay as they are.
func webPctDecode(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, false
	}
	b := make([]byte, 0, len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			h, l := webHexVal(s[i+1]), webHexVal(s[i+2])
			if h >= 0 && l >= 0 {
				b = append(b, byte(h<<4|l))
				i += 2
				changed = true
				continue
			}
		}
		b = append(b, s[i])
	}
	return string(b), changed
}

// webDecodeAll decodes up to three passes and reports how many passes changed the text.
func webDecodeAll(s string) (string, int) {
	passes := 0
	for passes < 3 {
		d, ch := webPctDecode(s)
		if !ch {
			break
		}
		s = d
		passes++
	}
	return s, passes
}

// webSanitise makes decoded text safe to embed in a one-line command: valid UTF-8, no control
// characters. NUL, CR and LF are kept visible as tokens because injection rules look for them.
func webSanitise(s string) string {
	s = strings.ToValidUTF8(s, "?")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0:
			b.WriteString("<nul>")
		case r == '\r':
			b.WriteString("<cr>")
		case r == '\n':
			b.WriteString("<lf>")
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func webTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// webSecretParam reports whether a query parameter name looks like it carries a credential.
func webSecretParam(name string) bool {
	n := strings.ToLower(name)
	for _, k := range []string{"pass", "pwd", "secret", "token", "key", "auth", "sess", "sid", "jwt", "cred", "signature", "sig", "code", "otp", "bearer"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// webRedactQuery replaces the value of secret-looking parameters in a raw (still encoded) target.
func webRedactQuery(raw string) string {
	q := strings.IndexByte(raw, '?')
	if q < 0 {
		return raw
	}
	parts := strings.Split(raw[q+1:], "&")
	for i, kv := range parts {
		if e := strings.IndexByte(kv, '='); e >= 0 {
			name, _ := webPctDecode(kv[:e])
			if webSecretParam(name) {
				parts[i] = kv[:e+1] + "REDACTED"
			}
		}
	}
	return raw[:q+1] + strings.Join(parts, "&")
}

// WebEvent is a normalised record ready for rule evaluation.
type WebEvent struct {
	Rec      WebRecord
	Lab      LabEvent
	Evidence string // command with secret query values redacted
	Path     string // decoded request path
	Template string // heuristic path template (see webTemplate)
	Params   []string
	RawLen   int
}

func webHostLabel(rec WebRecord, hostOverride string) string {
	h := hostOverride
	if h == "" {
		h = rec.Host
	}
	h = strings.ToLower(webTruncate(webSanitise(h), 120))
	h = strings.NewReplacer(" ", "_", ":", "_").Replace(h)
	if h == "" {
		h = "unknown"
	}
	return "web:" + h
}

// NormalizeWebRecord builds the rule event for one record.
func NormalizeWebRecord(rec WebRecord, hostOverride string) WebEvent {
	raw := rec.Target
	rawLen := len(raw)
	if len(raw) > 8192 {
		raw = raw[:8192] // bound decode work; the length is kept in len=
	}
	pathRaw, queryRaw := raw, ""
	if q := strings.IndexByte(raw, '?'); q >= 0 {
		pathRaw, queryRaw = raw[:q], raw[q+1:]
	}
	if h := strings.IndexByte(pathRaw, '#'); h >= 0 {
		pathRaw = pathRaw[:h]
	}
	dp, p1 := webDecodeAll(pathRaw)
	dq, p2 := webDecodeAll(strings.ReplaceAll(queryRaw, "+", " "))
	passes := p1
	if p2 > passes {
		passes = p2
	}
	path := webSanitise(dp)
	target := path
	if queryRaw != "" {
		target += "?" + webSanitise(dq)
	}
	redRaw := webRedactQuery(raw)
	_, redQ, _ := strings.Cut(redRaw, "?")
	redTarget := path
	if redQ != "" {
		d, _ := webDecodeAll(strings.ReplaceAll(redQ, "+", " "))
		redTarget += "?" + webSanitise(d)
	}
	ua := webTruncate(webSanitise(rec.UA), webUAMax)
	host := webHostLabel(rec, hostOverride)
	head := fmt.Sprintf("status=%d bytes=%d len=%d dec=%d target=", rec.Status, rec.Bytes, rawLen, passes)
	cmd := head + webTruncate(target, webTargetMax)
	ev := WebEvent{Rec: rec, Path: path, RawLen: rawLen, Evidence: head + webTruncate(redTarget, webEvidenceMx)}
	ev.Lab = LabEvent{Kind: "process", Time: rec.Time, Host: host, Executable: webExecutable, Operation: rec.Method,
		ParentExe: ua, Command: cmd, Path: webTruncate(path, webTargetMax), Destination: rec.IP}
	ev.Params = webParamNames(queryRaw)
	return ev
}

// webParamNames lists distinct query parameter names (never values), capped.
func webParamNames(q string) []string {
	if q == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, kv := range strings.Split(q, "&") {
		name, _, _ := strings.Cut(kv, "=")
		name, _ = webPctDecode(name)
		name = webTruncate(webSanitise(name), 40)
		if name == "" || seen[name] || len(out) >= 24 {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// ---- rule evaluation ----

var webRuleCache sync.Map // *ContentRegistry -> []*ContentRule

func webRules(reg *ContentRegistry) []*ContentRule {
	if reg == nil {
		return nil
	}
	if v, ok := webRuleCache.Load(reg); ok {
		return v.([]*ContentRule)
	}
	var out []*ContentRule
	for _, r := range reg.rules {
		if r.Batch == webBatchTag {
			out = append(out, r)
		}
	}
	webRuleCache.Store(reg, out)
	return out
}

// WebEvaluate runs only the web- rules (not the whole process rule set) over one event.
func WebEvaluate(reg *ContentRegistry, ev WebEvent) []Finding {
	rules := webRules(reg)
	if len(rules) == 0 {
		return nil
	}
	ctx := newEvalCtx(ev.Lab)
	var out []Finding
	for _, r := range rules {
		if !r.matchCtx(ctx, true) {
			continue
		}
		f := Finding{Time: ev.Rec.Time, Host: ev.Lab.Host, Destination: ev.Rec.IP,
			Evidence: Event{Time: ev.Rec.Time, Host: ev.Lab.Host, Executable: webExecutable, ParentExe: ev.Lab.ParentExe,
				Command: ev.Rec.Method + " " + ev.Evidence}}
		f.Rule, f.Severity, f.Description = r.ID, r.Severity, r.Name+": "+r.Description
		f.Tags = append([]string{"content", r.Technique, "web-access"}, r.Tags...)
		f.Tags = append(f.Tags, "batch:"+r.Batch)
		out = append(out, f)
		if len(out) >= contentMaxPerEvent {
			break
		}
	}
	return out
}
