package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Syslog parsers and normalisers (observation only, pure functions, no I/O).
// See docs/syslog-listener.md for the sources read and what is UNVERIFIED.

const (
	syslogMaxMsg = 8 << 10
	syslogMaxSD  = 32
)

// SyslogMsg is the parsed envelope of one syslog line.
type SyslogMsg struct {
	Format   string                       `json:"format"` // rfc5424, rfc3164, cef, leef, raw
	Facility int                          `json:"facility"`
	Severity int                          `json:"severity"`
	HasPRI   bool                         `json:"has_pri"`
	Time     time.Time                    `json:"time,omitempty"`
	Host     string                       `json:"host,omitempty"`
	App      string                       `json:"app,omitempty"`
	ProcID   string                       `json:"procid,omitempty"`
	MsgID    string                       `json:"msgid,omitempty"`
	SD       map[string]map[string]string `json:"structured_data,omitempty"`
	Body     string                       `json:"body"`
	CEF      *SyslogCEF                   `json:"cef,omitempty"`
	LEEF     *SyslogCEF                   `json:"leef,omitempty"`
}

// SyslogCEF holds a parsed CEF or LEEF record (LEEF reuses the shape).
type SyslogCEF struct {
	Version  string            `json:"version"`
	Vendor   string            `json:"vendor"`
	Product  string            `json:"product"`
	DevVer   string            `json:"device_version"`
	EventID  string            `json:"event_id"`
	Name     string            `json:"name,omitempty"`
	Severity string            `json:"severity,omitempty"`
	Ext      map[string]string `json:"ext"`
}

var (
	reRFC3164TS = regexp.MustCompile(`^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ 0-9]\d \d\d:\d\d:\d\d `)
	reTag       = regexp.MustCompile(`^([^\s:\[\]]{1,48})(?:\[([^\]\s]{1,32})\])?:?(?:\s+|$)(.*)$`)
)

// ParseSyslog parses one line. ok is false only when nothing recognisable was found
// (no PRI, and not CEF/LEEF/a known message shape) so the caller can count and sample it.
func ParseSyslog(line string, now time.Time) (SyslogMsg, bool) {
	line = strings.TrimRight(line, "\r\n\x00")
	m := SyslogMsg{Body: line}
	rest := line
	if strings.HasPrefix(rest, "<") {
		if end := strings.IndexByte(rest, '>'); end > 1 && end <= 4 {
			if p, err := strconv.Atoi(rest[1:end]); err == nil && p >= 0 && p <= 191 && (end == 2 || rest[1] != '0') {
				m.HasPRI, m.Facility, m.Severity = true, p/8, p%8
				rest = rest[end+1:]
			}
		}
	}
	if m.HasPRI {
		if strings.HasPrefix(rest, "1 ") {
			if parse5424(&m, rest[2:]) {
				m.Format = "rfc5424"
				finishEnvelope(&m)
				return m, true
			}
		}
		parse3164(&m, rest, now)
		m.Format = "rfc3164"
		finishEnvelope(&m)
		return m, true
	}
	// No PRI: CEF/LEEF/known shape anywhere in the line, otherwise unparsed.
	m.Body = rest
	finishEnvelope(&m)
	if m.CEF != nil || m.LEEF != nil {
		return m, true
	}
	m.Format = "raw"
	if len(normaliseShapes(m, "x")) > 0 || shapeKnown(m) {
		return m, true
	}
	return m, false
}

// finishEnvelope detects CEF/LEEF payloads in the body and sets the format accordingly.
func finishEnvelope(m *SyslogMsg) {
	if i := strings.Index(m.Body, "CEF:"); i >= 0 && i < 128 {
		if c := parseCEF(m.Body[i:]); c != nil {
			m.CEF, m.Format = c, "cef"
			return
		}
	}
	if i := strings.Index(m.Body, "LEEF:"); i >= 0 && i < 128 {
		if c := parseLEEF(m.Body[i:]); c != nil {
			m.LEEF, m.Format = c, "leef"
		}
	}
}

func parse3164(m *SyslogMsg, rest string, now time.Time) {
	if loc := reRFC3164TS.FindString(rest); loc != "" {
		ts, err := time.ParseInLocation("Jan _2 15:04:05", strings.TrimSpace(loc), time.UTC)
		if err == nil {
			t := time.Date(now.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, time.UTC)
			if t.After(now.Add(48 * time.Hour)) { // RFC 3164 timestamps carry no year
				t = t.AddDate(-1, 0, 0)
			}
			m.Time = t
		}
		rest = rest[len(loc):]
	} else if sp := strings.IndexByte(rest, ' '); sp > 10 { // rsyslog-style RFC 3339 timestamp (de-facto, UNVERIFIED in RFC 3164)
		if t, err := time.Parse(time.RFC3339Nano, rest[:sp]); err == nil {
			m.Time = t.UTC()
			rest = rest[sp+1:]
		}
	}
	// Optional hostname: first token unless it looks like a TAG (ends with ':' or has '[').
	if sp := strings.IndexByte(rest, ' '); sp > 0 {
		tok := rest[:sp]
		if !strings.HasSuffix(tok, ":") && !strings.Contains(tok, "[") && len(tok) <= 255 && !m.Time.IsZero() {
			m.Host = tok
			rest = rest[sp+1:]
		}
	}
	if g := reTag.FindStringSubmatch(rest); g != nil && !strings.ContainsAny(g[1], "=,") {
		m.App, m.ProcID, m.Body = g[1], g[2], g[3]
		return
	}
	m.Body = rest
}

func parse5424(m *SyslogMsg, rest string) bool {
	f := make([]string, 0, 5)
	for len(f) < 5 {
		sp := strings.IndexByte(rest, ' ')
		if sp <= 0 {
			return false
		}
		f = append(f, rest[:sp])
		rest = rest[sp+1:]
	}
	if f[0] != "-" {
		t, err := time.Parse(time.RFC3339Nano, f[0])
		if err != nil {
			return false
		}
		m.Time = t.UTC()
	}
	nv := func(s string) string {
		if s == "-" {
			return ""
		}
		return s
	}
	m.Host, m.App, m.ProcID, m.MsgID = nv(f[1]), nv(f[2]), nv(f[3]), nv(f[4])
	sd, tail, ok := parseSD(rest)
	if !ok {
		return false
	}
	m.SD = sd
	tail = strings.TrimPrefix(tail, " ")
	m.Body = strings.TrimPrefix(tail, "\xef\xbb\xbf")
	return true
}

// parseSD parses STRUCTURED-DATA; returns the remainder after it.
func parseSD(s string) (map[string]map[string]string, string, bool) {
	if strings.HasPrefix(s, "-") {
		return nil, s[1:], true
	}
	out := map[string]map[string]string{}
	i, n := 0, 0
	for i < len(s) && s[i] == '[' {
		if n++; n > syslogMaxSD {
			return nil, "", false
		}
		i++
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != ']' {
			j++
		}
		id := s[i:j]
		if id == "" {
			return nil, "", false
		}
		params := map[string]string{}
		i = j
		for i < len(s) && s[i] == ' ' {
			i++
			j = i
			for j < len(s) && s[j] != '=' {
				j++
			}
			if j+1 >= len(s) || s[j+1] != '"' {
				return nil, "", false
			}
			name := s[i:j]
			j += 2
			var val strings.Builder
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) && (s[j+1] == '"' || s[j+1] == '\\' || s[j+1] == ']') {
					j++
				}
				val.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, "", false
			}
			if len(params) < syslogMaxSD {
				params[name] = val.String()
			}
			i = j + 1
		}
		if i >= len(s) || s[i] != ']' {
			return nil, "", false
		}
		i++
		out[id] = params
	}
	if n == 0 {
		return nil, "", false
	}
	return out, s[i:], true
}

func splitUnescaped(s string, sep byte, max int) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
			continue
		}
		if c == sep && len(out) < max-1 {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	return append(out, cur.String())
}

func cefHdrUnesc(s string) string {
	return strings.NewReplacer(`\|`, `|`, `\\`, `\`).Replace(s)
}

var reCEFKey = regexp.MustCompile(`(^|\s)([A-Za-z][A-Za-z0-9_.\-\[\]]{0,63})=`)

// parseCEF parses "CEF:ver|vendor|product|devver|sigid|name|severity|extension".
func parseCEF(s string) *SyslogCEF {
	if !strings.HasPrefix(s, "CEF:") {
		return nil
	}
	p := splitUnescaped(s[4:], '|', 8)
	if len(p) != 8 {
		return nil
	}
	c := &SyslogCEF{Version: p[0], Vendor: cefHdrUnesc(p[1]), Product: cefHdrUnesc(p[2]), DevVer: cefHdrUnesc(p[3]),
		EventID: cefHdrUnesc(p[4]), Name: cefHdrUnesc(p[5]), Severity: cefHdrUnesc(p[6]), Ext: map[string]string{}}
	ext := p[7]
	idx := reCEFKey.FindAllStringSubmatchIndex(ext, 65)
	for n, loc := range idx {
		if n >= 64 {
			break
		}
		key := ext[loc[4]:loc[5]]
		end := len(ext)
		if n+1 < len(idx) {
			end = idx[n+1][0]
		}
		v := strings.TrimSpace(ext[loc[1]:end])
		v = strings.NewReplacer(`\=`, `=`, `\n`, "\n", `\r`, "\r", `\\`, `\`).Replace(v)
		c.Ext[key] = v
	}
	return c
}

// parseLEEF parses LEEF 1.0 (tab delimiter) and 2.0 (delimiter field). Delimiter semantics are
// from general knowledge of the format and are UNVERIFIED against IBM's spec (see docs).
func parseLEEF(s string) *SyslogCEF {
	if !strings.HasPrefix(s, "LEEF:") {
		return nil
	}
	p := strings.SplitN(s[5:], "|", 7)
	if len(p) < 6 {
		return nil
	}
	c := &SyslogCEF{Version: p[0], Vendor: p[1], Product: p[2], DevVer: p[3], EventID: p[4], Ext: map[string]string{}}
	delim, attrs := "\t", p[5]
	if strings.HasPrefix(p[0], "2") {
		if len(p) < 7 {
			return nil
		}
		attrs = p[6]
		if d := p[5]; len(d) == 1 {
			delim = d
		} else if len(d) == 3 && (d[0] == 'x' || d[0] == 'X') {
			if v, err := strconv.ParseUint(d[1:], 16, 8); err == nil {
				delim = string(rune(v))
			}
		} else if d != "" {
			return nil
		}
	} else if len(p) == 7 { // 1.0: attributes may contain '|'
		attrs = p[5] + "|" + p[6]
	}
	for n, kv := range strings.Split(attrs, delim) {
		if n >= 64 {
			break
		}
		if i := strings.IndexByte(kv, '='); i > 0 {
			c.Ext[kv[:i]] = kv[i+1:]
		}
	}
	return c
}

// ---- Normalisation ----

// SyslogEvent is one normalised event; exactly one of Tel / Net is set.
type SyslogEvent struct {
	Type  string          `json:"type"` // auth, dns, network
	Shape string          `json:"shape"`
	Tel   *TelemetryEvent `json:"telemetry,omitempty"`
	Net   *NetworkEvent   `json:"network,omitempty"`
}

var (
	reSSHAccepted = regexp.MustCompile(`^Accepted (password|publickey|keyboard-interactive/pam|hostbased|gssapi-with-mic) for (\S+) from (\S+) port (\d+)`)
	reSSHFailed   = regexp.MustCompile(`^Failed (password|publickey|keyboard-interactive/pam|hostbased|gssapi-with-mic) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	reSSHInvalid  = regexp.MustCompile(`^Invalid user (\S+) from (\S+)(?: port (\d+))?`)
	reSudoCmd     = regexp.MustCompile(`^\s*(\S+) : (?:TTY=\S+ ; )?PWD=\S+ ; USER=(\S+) ; COMMAND=`)
	reSudoFail    = regexp.MustCompile(`^\s*(\S+) : (\d+ incorrect password attempts?|authentication failure)`)
	rePAMFail     = regexp.MustCompile(`^pam_\w+\((\w[\w-]*):auth\): authentication failure;`)
	reAccessLine  = regexp.MustCompile(`^(\S+) \S+ (\S+) \[[^\]]+\] "[^"]*" (\d{3}) (\d+|-)`)
	reKV          = regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|\S*)`)
	reASA106100   = regexp.MustCompile(`access-list \S+ (permitted|denied|est-allowed) (\w+) [^/\s]+/(\S+?)\((\d+)\) ?(?:\([^)]*\))? ?-> ?[^/\s]+/(\S+?)\((\d+)\)`)
	reASA106023   = regexp.MustCompile(`^Deny (\w+) src \S+?:(\S+?)(?:/(\d+))? dst \S+?:(\S+?)(?:/(\d+))? `)
	reASABuilt    = regexp.MustCompile(`^Built (?:inbound|outbound) (TCP|UDP) connection \d+ for \S+?:(\S+?)/(\d+) \([^)]*\) to \S+?:(\S+?)/(\d+)`)
	reDnsmasq     = regexp.MustCompile(`^query\[(\w+)\] (\S+) from (\S+)`)
)

func isIP(s string) bool { return net.ParseIP(strings.Trim(s, "[]")) != nil }

func verdictOf(a string) string {
	switch strings.ToLower(a) {
	case "deny", "denied", "drop", "dropped", "block", "blocked", "reject", "reset", "reset-both", "reset-client", "reset-server", "drop-icmp", "blocked-by-policy", "failure":
		return "deny"
	case "allow", "allowed", "accept", "accepted", "permit", "permitted", "est-allowed", "pass", "success", "close", "start":
		return "allow"
	}
	return ""
}

func shapeKnown(m SyslogMsg) bool {
	b := m.Body
	return reAccessLine.MatchString(b) || reSudoCmd.MatchString(b) || reSudoFail.MatchString(b) || strings.HasPrefix(b, "pam_")
}

// syslogHostName builds the namespaced event host. Sender-supplied names can never collide with
// an enrolled agent host because every syslog host is prefixed "syslog:" and the name charset
// excludes ':'.
func syslogHostName(parsed, sender string) string {
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			return r
		}
		return -1
	}, parsed)
	if len(name) > 64 {
		name = name[:64]
	}
	if name == "" {
		name = sender
	}
	return "syslog:" + name
}

// NormaliseSyslog maps a parsed message to zero or more events. recv is the receive time.
func NormaliseSyslog(m SyslogMsg, sender string, recv time.Time) []SyslogEvent {
	evs := normaliseShapes(m, sender)
	if m.CEF != nil {
		evs = append(evs, normaliseCEF(m.CEF, "cef")...)
	}
	if m.LEEF != nil {
		evs = append(evs, normaliseCEF(leefAsCEF(m.LEEF), "leef")...)
	}
	t := recv.UTC()
	if !m.Time.IsZero() && m.Time.After(recv.Add(-48*time.Hour)) && m.Time.Before(recv.Add(48*time.Hour)) {
		t = m.Time.UTC()
	}
	host := syslogHostName(m.Host, sender)
	src := "syslog:" + sender
	for i := range evs {
		e := &evs[i]
		if e.Tel != nil {
			e.Tel.Time, e.Tel.Host = t, host
			e.Tel.Kind = src // no source field in TelemetryEvent; Kind carries the origin tag for auth/dns
		}
		if e.Net != nil {
			e.Net.Time, e.Net.Host, e.Net.Source = t, host, src
			h := sha256.Sum256([]byte(sender + "|" + m.Body + "|" + strconv.FormatInt(recv.UnixNano(), 10)))
			e.Net.ID = "syslog-" + hex.EncodeToString(h[:12])
		}
	}
	return evs
}

func leefAsCEF(l *SyslogCEF) *SyslogCEF {
	c := *l
	c.Ext = map[string]string{}
	for k, v := range l.Ext {
		c.Ext[k] = v
	}
	if v, ok := c.Ext["usrName"]; ok {
		c.Ext["suser"] = v
	}
	if v, ok := c.Ext["dstPort"]; ok {
		c.Ext["dpt"] = v
	}
	if v, ok := c.Ext["dstName"]; ok && c.Ext["dhost"] == "" {
		c.Ext["dhost"] = v
	}
	c.Name = l.EventID
	return &c
}

func authEv(method, outcome, user, ip, shape string) SyslogEvent {
	if len(user) > 128 {
		user = user[:128]
	}
	te := &TelemetryEvent{Method: method, Outcome: outcome, User: user}
	if isIP(ip) {
		te.SourceIP = strings.Trim(ip, "[]")
	}
	return SyslogEvent{Type: "auth", Shape: shape, Tel: te}
}

func netEv(dst, port, verdict, shape string) SyslogEvent {
	d := dst
	if port != "" && port != "0" {
		d = net.JoinHostPort(dst, port)
	}
	return SyslogEvent{Type: "network", Shape: shape, Net: &NetworkEvent{Destination: d, Verdict: verdict}}
}

func normaliseCEF(c *SyslogCEF, shape string) []SyslogEvent {
	x := c.Ext
	var out []SyslogEvent
	low := strings.ToLower(c.Name + " " + c.EventID + " " + x["cat"])
	verdict := verdictOf(firstNonEmpty(x["outcome"], x["act"]))
	if user := firstNonEmpty(x["suser"], x["duser"]); user != "" && (strings.Contains(low, "login") || strings.Contains(low, "logon") || strings.Contains(low, "authenticat")) {
		oc := "failure"
		if o := strings.ToLower(x["outcome"]); o == "success" || o == "allow" || o == "accept" || strings.Contains(low, "success") {
			oc = "success"
		}
		out = append(out, authEv("console", oc, user, x["src"], shape+"-auth"))
	}
	if dst := firstNonEmpty(x["dst"], x["dhost"]); dst != "" {
		out = append(out, netEv(dst, x["dpt"], verdict, shape+"-flow"))
	}
	if q := firstNonEmpty(x["requestdns"], x["dnsQuery"], x["qname"]); q != "" && len(q) <= 253 {
		out = append(out, SyslogEvent{Type: "dns", Shape: shape + "-dns", Tel: &TelemetryEvent{Query: q, SourceIP: ipOrEmpty(x["src"])}})
	}
	return out
}

func ipOrEmpty(s string) string {
	if isIP(s) {
		return s
	}
	return ""
}

// normaliseShapes recognises the documented well-known message shapes in m.Body.
func normaliseShapes(m SyslogMsg, sender string) []SyslogEvent {
	b := strings.TrimSpace(m.Body)
	var out []SyslogEvent
	if g := reSSHAccepted.FindStringSubmatch(b); g != nil {
		return append(out, authEv("ssh", "success", g[2], g[3], "ssh-accepted-"+g[1]))
	}
	if g := reSSHFailed.FindStringSubmatch(b); g != nil {
		return append(out, authEv("ssh", "failure", g[2], g[3], "ssh-failed-"+g[1]))
	}
	if g := reSSHInvalid.FindStringSubmatch(b); g != nil {
		return append(out, authEv("ssh", "failure", g[1], g[2], "ssh-invalid-user"))
	}
	if g := reSudoCmd.FindStringSubmatch(b); g != nil && (m.App == "sudo" || m.App == "") {
		return append(out, authEv("sudo", "success", g[1], "", "sudo-command"))
	}
	if g := reSudoFail.FindStringSubmatch(b); g != nil && (m.App == "sudo" || m.App == "") {
		return append(out, authEv("sudo", "failure", g[1], "", "sudo-failure"))
	}
	if g := rePAMFail.FindStringSubmatch(b); g != nil {
		kv := kvMap(b)
		method := "console"
		switch g[1] {
		case "sshd":
			method = "ssh"
		case "sudo":
			method = "sudo"
		}
		user := firstNonEmpty(kv["user"], kv["ruser"])
		if user == "" {
			return nil
		}
		return append(out, authEv(method, "failure", user, kv["rhost"], "pam-auth-failure"))
	}
	if reAccessLine.MatchString(b) {
		return nil // recognised (see shapeKnown); no Kavach telemetry type fits an HTTP access line
	}
	if g := reASA106100.FindStringSubmatch(b); g != nil {
		return append(out, netEv(g[5], g[6], verdictOf(g[1]), "cisco-asa-106100"))
	}
	if g := reASA106023.FindStringSubmatch(b); g != nil {
		return append(out, netEv(g[4], g[5], "deny", "cisco-asa-106023"))
	}
	if g := reASABuilt.FindStringSubmatch(b); g != nil {
		return append(out, netEv(g[4], g[5], "allow", "cisco-asa-built"))
	}
	if g := reDnsmasq.FindStringSubmatch(b); g != nil {
		return append(out, SyslogEvent{Type: "dns", Shape: "dnsmasq-query", Tel: &TelemetryEvent{Query: g[2], QType: g[1], SourceIP: ipOrEmpty(g[3])}})
	}
	if strings.Contains(b, "srcip=") || strings.Contains(b, "dstip=") || strings.Contains(b, "qname=") {
		kv := kvMap(b)
		if q := kv["qname"]; q != "" && len(q) <= 253 {
			out = append(out, SyslogEvent{Type: "dns", Shape: "fortinet-dns", Tel: &TelemetryEvent{Query: q, QType: kv["qtype"], SourceIP: ipOrEmpty(kv["srcip"])}})
		}
		if isIP(kv["dstip"]) && kv["action"] != "" {
			out = append(out, netEv(kv["dstip"], kv["dstport"], verdictOf(kv["action"]), "fortinet-traffic"))
		}
		return out
	}
	if strings.Count(b, ",") > 30 { // PAN-OS TRAFFIC CSV (field positions partly UNVERIFIED)
		f := strings.Split(b, ",")
		if len(f) > 30 && f[3] == "TRAFFIC" && isIP(f[8]) {
			return append(out, netEv(f[8], f[25], verdictOf(f[30]), "paloalto-traffic"))
		}
	}
	return nil
}

func kvMap(s string) map[string]string {
	out := map[string]string{}
	for _, g := range reKV.FindAllStringSubmatch(s, 64) {
		out[g[1]] = strings.Trim(g[2], `"`)
	}
	return out
}

// ---- redaction ----

var reSecret = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)(\s*[=:]\s*)("[^"]*"|\S+)`)
var reBearer = regexp.MustCompile(`(?i)\bbearer\s+\S+`)

// RedactSyslog masks obvious secrets (password=, token=, Bearer ...) and truncates.
func RedactSyslog(s string) string {
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	s = reBearer.ReplaceAllString(s, "Bearer [redacted]")
	return reSecret.ReplaceAllString(s, "$1=[redacted]")
}
