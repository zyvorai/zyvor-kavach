// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/csv"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// Evidence import parsers. Every parser treats its input as hostile text: it is never executed,
// never passed to a shell or template, length-capped per line, and a malformed line is counted as
// failed and skipped, never fatal. Parsers only normalise; detection happens in evidence_case.go.

const (
	evMaxLine  = 8192
	evMaxLines = 300000
)

// evItem is one normalised observation. Type is process | network | file | registry | auth.
type evItem struct {
	Type     string
	Artefact string
	Line     int
	Time     time.Time // zero means synthetic (assigned at replay)
	PID      int
	PPID     int
	UID      int
	User     string
	Exe      string
	Parent   string // resolved parent executable (snapshot formats only)
	Cmd      string
	Dest     string
	Path     string
	Op       string
	Size     int64
	Tel      TelemetryEvent
	Note     string
}

// evStat is the inventory row of one artefact.
type evStat struct {
	Name      string   `json:"name"`
	Format    string   `json:"format"`
	Bytes     int      `json:"bytes"`
	Lines     int      `json:"lines"`
	Parsed    int      `json:"parsed"`
	Skipped   int      `json:"skipped"`
	Failed    int      `json:"failed"`
	Truncated int      `json:"truncated_lines,omitempty"`
	Events    int      `json:"events"`
	Status    string   `json:"status"` // parsed | partial | failed
	Error     string   `json:"error,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

func (s *evStat) note(n string) {
	if len(s.Notes) < 20 {
		s.Notes = append(s.Notes, n)
	}
}

type evCtx struct {
	base time.Time // collection time (analyst supplied) or import time
}

type evParser func(lines []string, c *evCtx, st *evStat) []evItem

// evNormalizeText decodes UTF-16 (PowerShell redirection) and replaces control and bidi characters.
func evNormalizeText(b []byte) string {
	if len(b) >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF)) {
		le := b[0] == 0xFF
		b = b[2:]
		u := make([]uint16, 0, len(b)/2)
		for i := 0; i+1 < len(b); i += 2 {
			if le {
				u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
			} else {
				u = append(u, uint16(b[i+1])|uint16(b[i])<<8)
			}
		}
		b = []byte(string(utf16.Decode(u)))
	} else if len(b) >= 4 && b[1] == 0 && b[3] == 0 && b[0] != 0 && b[2] != 0 {
		u := make([]uint16, 0, len(b)/2)
		for i := 0; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		}
		b = []byte(string(utf16.Decode(u)))
	}
	s := strings.TrimPrefix(string(b), "\ufeff")
	s = strings.ToValidUTF8(s, "\ufffd")
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			sb.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			sb.WriteRune(' ')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func evSplitLines(text string, st *evStat) []string {
	raw := strings.Split(text, "\n")
	if len(raw) > evMaxLines {
		raw = raw[:evMaxLines]
		st.note("input truncated at 300000 lines")
	}
	out := make([]string, len(raw))
	for i, l := range raw {
		l = strings.TrimRight(l, "\r")
		if len(l) > evMaxLine {
			l = evClip(l, evMaxLine)
			st.Truncated++
		}
		out[i] = l
		if strings.TrimSpace(l) != "" {
			st.Lines++
		}
	}
	return out
}

func evClip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

var winExeRe = regexp.MustCompile(`(?i)^[a-z]:\\[^"|<>*?]*?\.(exe|bat|cmd|com|scr|ps1|vbs|js|msi|dll)\b`)

// evFirstToken returns the program part of a command line.
func evFirstToken(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	if cmd[0] == '"' {
		if j := strings.IndexByte(cmd[1:], '"'); j >= 0 {
			return cmd[1 : 1+j]
		}
		return strings.Trim(cmd, `"`)
	}
	if m := winExeRe.FindString(cmd); m != "" {
		return m
	}
	if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		cmd = cmd[:i]
	}
	if strings.HasPrefix(cmd, "-") && len(cmd) > 1 { // login shell: -bash
		cmd = cmd[1:]
	}
	return cmd
}

func evRestAfter(line string, n int) string {
	i := 0
	for k := 0; k < n; k++ {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
	}
	return strings.TrimSpace(line[i:])
}

func evUID(user string) int {
	u := strings.ToLower(strings.TrimSpace(user))
	if n, err := strconv.Atoi(u); err == nil && n >= 0 {
		return n
	}
	if u == "root" || u == "system" || strings.HasSuffix(u, `\system`) {
		return 0
	}
	return 1000
}

func evIdx(h []string, names ...string) int {
	for i, x := range h {
		for _, n := range names {
			if x == n {
				return i
			}
		}
	}
	return -1
}

func evResolveParents(items []evItem) {
	byPID := map[int]string{}
	for _, it := range items {
		if it.Type == "process" && it.PID > 0 {
			byPID[it.PID] = it.Exe
		}
	}
	for i := range items {
		if items[i].Type == "process" && items[i].PPID > 0 {
			items[i].Parent = byPID[items[i].PPID]
		}
	}
}

func evBlank(l string) bool { return strings.TrimSpace(l) == "" }

// ---- ps ----

func evParsePS(lines []string, _ *evCtx, st *evStat) []evItem {
	hi := -1
	var h []string
	for i := 0; i < len(lines) && i < 6; i++ {
		f := strings.Fields(strings.ToUpper(lines[i]))
		if evIdx(f, "PID") >= 0 && evIdx(f, "COMMAND", "CMD", "ARGS") >= 0 {
			hi, h = i, f
			break
		}
	}
	if hi < 0 {
		st.Error = "no ps header (PID ... COMMAND/CMD) found"
		return nil
	}
	ci, pi, ppi := evIdx(h, "COMMAND", "CMD", "ARGS"), evIdx(h, "PID"), evIdx(h, "PPID")
	ui := evIdx(h, "USER", "UID", "LOGNAME")
	var out []evItem
	for n := hi + 1; n < len(lines); n++ {
		l := lines[n]
		if evBlank(l) {
			continue
		}
		f := strings.Fields(l)
		if len(f) <= ci || len(f) <= pi {
			st.Failed++
			continue
		}
		pid, err := strconv.Atoi(f[pi])
		if err != nil || pid < 0 {
			st.Failed++
			continue
		}
		cmd := evRestAfter(l, ci)
		if cmd == "" || (strings.HasPrefix(cmd, "[") && strings.HasSuffix(cmd, "]")) || strings.HasSuffix(cmd, "<defunct>") {
			st.Skipped++ // kernel threads and zombies carry no command line
			continue
		}
		it := evItem{Type: "process", Line: n + 1, PID: pid, Exe: evFirstToken(cmd), Cmd: evClip(cmd, 4096), UID: 1000}
		if ppi >= 0 && ppi < len(f) {
			it.PPID, _ = strconv.Atoi(f[ppi])
		}
		if ui >= 0 && ui < len(f) {
			it.User = f[ui]
			it.UID = evUID(f[ui])
		}
		st.Parsed++
		out = append(out, it)
	}
	evResolveParents(out)
	return out
}

// ---- network: ss, netstat, lsof ----

var evProcRe = regexp.MustCompile(`\("([^"]{0,64})",pid=(\d+)`)

func evWildcard(a string) bool {
	return a == "" || a == "*" || strings.HasSuffix(a, ":*") || strings.HasSuffix(a, ".*") || a == "0.0.0.0:0" || a == "[::]:0" || a == ":::*"
}

func evAddr(a string) string {
	a = strings.TrimSpace(a)
	if a != "" && !strings.Contains(a, ":") { // macOS: 10.0.0.5.443
		if i := strings.LastIndexByte(a, '.'); i > 0 {
			a = a[:i] + ":" + a[i+1:]
		}
	}
	return evClip(a, 200)
}

func evParseSS(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	hdr := false
	noNetid := false
	for n, l := range lines {
		if evBlank(l) {
			continue
		}
		f := strings.Fields(l)
		if !hdr && (strings.EqualFold(f[0], "netid") || strings.EqualFold(f[0], "state")) {
			hdr = true
			noNetid = strings.EqualFold(f[0], "state")
			continue
		}
		off := 1
		if noNetid {
			off = 0
		}
		if len(f) < off+5 {
			st.Failed++
			continue
		}
		state, peer := f[off], f[off+4]
		if _, e1 := strconv.Atoi(f[off+1]); e1 != nil {
			st.Failed++
			continue
		}
		if strings.EqualFold(state, "LISTEN") || evWildcard(peer) {
			st.Skipped++
			continue
		}
		it := evItem{Type: "network", Line: n + 1, Dest: evAddr(peer)}
		if m := evProcRe.FindStringSubmatch(l); m != nil {
			it.PID, _ = strconv.Atoi(m[2])
			it.Exe = m[1]
		}
		st.Parsed++
		out = append(out, it)
	}
	if !hdr && len(out) == 0 {
		st.Error = "no ss header or connection rows"
	}
	return out
}

func evParseNetstat(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	for n, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 {
			if len(f) > 0 {
				st.Skipped++
			}
			continue
		}
		p := strings.ToLower(f[0])
		if !(strings.HasPrefix(p, "tcp") || strings.HasPrefix(p, "udp")) {
			st.Skipped++ // banners, headers, unix sockets
			continue
		}
		var foreign, state, pidTok string
		if _, e1 := strconv.Atoi(f[1]); e1 == nil && len(f) >= 5 { // Linux/macOS: proto recvq sendq local foreign [state] [pid/prog]
			foreign = f[4]
			rest := f[5:]
			if len(rest) > 0 && strings.ToUpper(rest[0]) == rest[0] && !strings.ContainsAny(rest[0], "/0123456789") {
				state = rest[0]
				rest = rest[1:]
			}
			if len(rest) > 0 {
				pidTok = rest[len(rest)-1]
			}
		} else { // Windows: proto local foreign [state] pid
			foreign = f[2]
			rest := f[3:]
			if len(rest) > 0 {
				pidTok = rest[len(rest)-1]
			}
			if len(rest) > 1 {
				state = rest[0]
			}
		}
		if strings.EqualFold(state, "LISTEN") || strings.EqualFold(state, "LISTENING") || evWildcard(foreign) {
			st.Skipped++
			continue
		}
		it := evItem{Type: "network", Line: n + 1, Dest: evAddr(foreign)}
		if i := strings.IndexByte(pidTok, '/'); i > 0 {
			it.PID, _ = strconv.Atoi(pidTok[:i])
			it.Exe = evClip(pidTok[i+1:], 64)
		} else if v, err := strconv.Atoi(pidTok); err == nil {
			it.PID = v
		}
		if it.Dest == "" {
			st.Failed++
			continue
		}
		st.Parsed++
		out = append(out, it)
	}
	return out
}

func evParseLsof(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	for n, l := range lines {
		f := strings.Fields(l)
		if len(f) < 9 {
			if len(f) > 0 && f[0] != "COMMAND" {
				st.Failed++
			}
			continue
		}
		if f[0] == "COMMAND" {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		name := strings.Join(f[8:], " ")
		if err != nil || (f[4] != "IPv4" && f[4] != "IPv6") {
			st.Skipped++
			continue
		}
		i := strings.Index(name, "->")
		if i < 0 {
			st.Skipped++ // listening or unconnected
			continue
		}
		dest := name[i+2:]
		if j := strings.IndexByte(dest, ' '); j >= 0 {
			dest = dest[:j]
		}
		st.Parsed++
		out = append(out, evItem{Type: "network", Line: n + 1, PID: pid, User: f[2], Exe: evClip(strings.ReplaceAll(f[0], `\x20`, " "), 64), Dest: evClip(dest, 200)})
	}
	return out
}

// ---- scheduled: crontab, ls -l / path list ----

var evCronSchedRe = regexp.MustCompile(`^(@[a-z]+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$`)
var evEnvLineRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

func evParseCron(system bool) evParser {
	return func(lines []string, _ *evCtx, st *evStat) []evItem {
		var out []evItem
		for n, l := range lines {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") || evEnvLineRe.MatchString(t) {
				if t != "" {
					st.Skipped++
				}
				continue
			}
			m := evCronSchedRe.FindStringSubmatch(t)
			if m == nil {
				st.Failed++
				continue
			}
			cmd, user := strings.TrimSpace(m[2]), ""
			if system {
				f := strings.Fields(cmd)
				if len(f) < 2 {
					st.Failed++
					continue
				}
				user, cmd = f[0], evRestAfter(cmd, 1)
			}
			st.Parsed++
			out = append(out, evItem{Type: "process", Line: n + 1, Exe: evFirstToken(cmd), Cmd: evClip(cmd, 4096), User: user, UID: evUID(user), Note: "cron"})
		}
		return out
	}
}

var evLsPermRe = regexp.MustCompile(`^[-dlbcps][rwxsStT-]{9}[.+@]?$`)

func evParseLs(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	dir := ""
	for n, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "total ") {
			continue
		}
		if strings.HasSuffix(t, ":") && !strings.ContainsAny(t, " \t") {
			dir = strings.TrimSuffix(t, ":")
			continue
		}
		f := strings.Fields(t)
		if len(f) < 9 || !evLsPermRe.MatchString(f[0]) {
			st.Failed++
			continue
		}
		name := evRestAfter(t, 8)
		if i := strings.Index(name, " -> "); i >= 0 {
			name = name[:i]
		}
		if name == "." || name == ".." || name == "" {
			st.Skipped++
			continue
		}
		p := name
		if dir != "" && !strings.HasPrefix(name, "/") {
			p = strings.TrimRight(dir, "/") + "/" + name
		}
		size, _ := strconv.ParseInt(f[4], 10, 64)
		st.Parsed++
		out = append(out, evItem{Type: "file", Line: n + 1, Path: evClip(p, 1024), Op: "listed", Size: size})
	}
	return out
}

var winPathRe = regexp.MustCompile(`^[A-Za-z]:\\`)

func evParsePathList(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	for n, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if !(strings.HasPrefix(t, "/") || winPathRe.MatchString(t)) {
			st.Failed++
			continue
		}
		st.Parsed++
		out = append(out, evItem{Type: "file", Line: n + 1, Path: evClip(t, 1024), Op: "listed"})
	}
	return out
}

// ---- services ----

var evUnitRe = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]{1,256}\.(service|socket|timer|path|target|mount|automount|swap|slice|scope)$`)

func evParseUnitFiles(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	for n, l := range lines {
		f := strings.Fields(strings.TrimLeft(l, " \u25cf*"))
		if len(f) == 0 {
			continue
		}
		if !evUnitRe.MatchString(f[0]) {
			st.Skipped++ // header and footer
			continue
		}
		state := ""
		if len(f) > 1 {
			state = f[1]
		}
		st.Parsed++
		out = append(out, evItem{Type: "file", Line: n + 1, Path: "systemd:" + f[0], Op: "listed", Note: state})
	}
	return out
}

func evParseLaunchctl(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	for n, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 {
			if len(f) > 0 {
				st.Failed++
			}
			continue
		}
		if f[0] == "PID" {
			continue
		}
		if _, err := strconv.Atoi(f[1]); err != nil {
			st.Failed++
			continue
		}
		st.Parsed++
		out = append(out, evItem{Type: "file", Line: n + 1, Path: "launchd:" + evClip(f[2], 200), Op: "listed"})
	}
	return out
}

// ---- shell history ----

var evZshRe = regexp.MustCompile(`^: (\d{9,11}):\d+;(.*)$`)

func evParseHistory(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	var pending time.Time
	now := time.Now()
	for n, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "#") && len(t) > 1 && len(t) <= 12 {
			if v, err := strconv.ParseInt(t[1:], 10, 64); err == nil {
				ts := time.Unix(v, 0).UTC()
				if ts.Year() >= 2000 && ts.Before(now.Add(48*time.Hour)) {
					pending = ts
				}
				st.Skipped++
				continue
			}
		}
		var when time.Time
		if m := evZshRe.FindStringSubmatch(t); m != nil {
			v, _ := strconv.ParseInt(m[1], 10, 64)
			when = time.Unix(v, 0).UTC()
			t = strings.TrimSpace(m[2])
		} else {
			when, pending = pending, time.Time{}
		}
		if t == "" {
			st.Skipped++
			continue
		}
		if !when.IsZero() && (when.Year() < 2000 || when.After(now.Add(48*time.Hour))) {
			when = time.Time{}
		}
		st.Parsed++
		out = append(out, evItem{Type: "process", Line: n + 1, Time: when, Exe: evFirstToken(t), Cmd: evClip(t, 4096), UID: 1000, Note: "history"})
	}
	return out
}

// ---- Windows: CSV processes, tasklist table, schtasks ----

func evReadCSV(text string, st *evStat) [][]string {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	var out [][]string
	errs := 0
	for len(out) < evMaxLines {
		rec, err := r.Read()
		if err != nil {
			if _, ok := err.(*csv.ParseError); ok {
				st.Failed++
				if errs++; errs > 1000 {
					break
				}
				continue
			}
			break
		}
		out = append(out, rec)
	}
	return out
}

func evLowerHdr(h []string) []string {
	o := make([]string, len(h))
	for i, x := range h {
		o[i] = strings.ToLower(strings.TrimSpace(x))
	}
	return o
}

func evParseProcessCSV(lines []string, _ *evCtx, st *evStat) []evItem {
	recs := evReadCSV(strings.Join(lines, "\n"), st)
	hi := -1
	for i, r := range recs {
		if i > 6 {
			break
		}
		h := evLowerHdr(r)
		if evIdx(h, "pid", "processid", "id") >= 0 && evIdx(h, "name", "image name", "processname", "commandline", "path") >= 0 {
			hi = i
			break
		}
	}
	if hi < 0 {
		st.Error = "no CSV header with a PID/ProcessId/Id column"
		return nil
	}
	h := evLowerHdr(recs[hi])
	pi := evIdx(h, "pid", "processid", "id")
	ni := evIdx(h, "name", "image name", "processname")
	ci := evIdx(h, "commandline", "command line")
	pathi := evIdx(h, "path", "executablepath")
	ppi := evIdx(h, "parentprocessid")
	ui := evIdx(h, "user name", "username", "user")
	var out []evItem
	for k := hi + 1; k < len(recs); k++ {
		rec := recs[k]
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue
		}
		if len(rec) > len(h) && ci >= 0 && ci+len(rec)-len(h) < len(rec) { // WMIC does not quote: commas inside CommandLine shift later columns
			extra := len(rec) - len(h)
			merged := strings.Join(rec[ci:ci+extra+1], ",")
			rec = append(append(append([]string{}, rec[:ci]...), merged), rec[ci+extra+1:]...)
			st.note("rows with unquoted commas in CommandLine were re-joined heuristically (unverified)")
		}
		if len(rec) <= pi {
			st.Failed++
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[pi]))
		if err != nil || pid < 0 {
			if strings.EqualFold(strings.TrimSpace(rec[pi]), h[pi]) {
				continue // repeated header
			}
			st.Failed++
			continue
		}
		get := func(i int) string {
			if i >= 0 && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		exe := get(pathi)
		if exe == "" {
			exe = get(ni)
		}
		cmd := get(ci)
		if cmd == "" {
			cmd = exe
		}
		if cmd == "" {
			st.Skipped++
			continue
		}
		if exe == "" {
			exe = evFirstToken(cmd)
		}
		it := evItem{Type: "process", Line: k + 1, PID: pid, Exe: evClip(exe, 1024), Cmd: evClip(cmd, 4096), UID: 1000}
		it.PPID, _ = strconv.Atoi(get(ppi))
		if u := get(ui); u != "" && u != "N/A" {
			it.User, it.UID = u, evUID(u)
		}
		st.Parsed++
		out = append(out, it)
	}
	evResolveParents(out)
	return out
}

var evTasklistRowRe = regexp.MustCompile(`^(.+?)\s+(\d+)\s+(\S+)\s+\d+\s+[\d,. ]+\s*K`)

func evParseTasklist(lines []string, c *evCtx, st *evStat) []evItem {
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			if strings.HasPrefix(strings.TrimSpace(l), `"`) {
				return evParseProcessCSV(lines, c, st)
			}
			break
		}
	}
	var out []evItem
	for n, l := range lines {
		if evBlank(l) || strings.HasPrefix(l, "Image Name") || strings.HasPrefix(l, "====") {
			continue
		}
		m := evTasklistRowRe.FindStringSubmatch(l)
		if m == nil {
			st.Failed++
			continue
		}
		pid, _ := strconv.Atoi(m[2])
		st.Parsed++
		out = append(out, evItem{Type: "process", Line: n + 1, PID: pid, Exe: evClip(m[1], 256), Cmd: evClip(m[1], 256), UID: 1000})
	}
	return out
}

func evParseSchtasks(lines []string, _ *evCtx, st *evStat) []evItem {
	recs := evReadCSV(strings.Join(lines, "\n"), st)
	var h []string
	var out []evItem
	for k, rec := range recs {
		low := evLowerHdr(rec)
		if evIdx(low, "taskname") >= 0 && evIdx(low, "task to run") >= 0 {
			h = low
			continue
		}
		if h == nil {
			if strings.TrimSpace(strings.Join(rec, "")) != "" {
				st.Skipped++
			}
			continue
		}
		ti, ri, ui := evIdx(h, "taskname"), evIdx(h, "task to run"), evIdx(h, "run as user")
		if len(rec) <= ri || len(rec) <= ti {
			st.Failed++
			continue
		}
		run := strings.TrimSpace(rec[ri])
		if run == "" || strings.EqualFold(run, "N/A") || strings.EqualFold(run, "COM handler") {
			st.Skipped++
			continue
		}
		it := evItem{Type: "process", Line: k + 1, Exe: evFirstToken(run), Cmd: evClip(run, 4096), UID: 1000, Note: "scheduled task " + evClip(rec[ti], 200)}
		if ui >= 0 && ui < len(rec) {
			it.User, it.UID = strings.TrimSpace(rec[ui]), evUID(rec[ui])
		}
		st.Parsed++
		out = append(out, it)
	}
	if h == nil {
		st.Error = `no schtasks CSV header ("TaskName" ... "Task To Run"); needs /v`
	}
	return out
}

// ---- registry (reg export .reg text and reg query output) ----

var evRegValRe = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"=(.*)$`)
var evRegQueryRe = regexp.MustCompile(`^\s{2,}(\S.*?)\s{2,}(REG_[A-Z_]+)\s{2,}(.*)$`)

func evRegUnescape(s string) string {
	s = strings.ReplaceAll(s, `\\`, "\x00")
	s = strings.ReplaceAll(s, `\"`, `"`)
	return strings.ReplaceAll(s, "\x00", `\`)
}

func evParseReg(lines []string, _ *evCtx, st *evStat) []evItem {
	var out []evItem
	key := ""
	cont := false
	for n, l := range lines {
		t := strings.TrimSpace(l)
		if cont { // hex continuation lines
			cont = strings.HasSuffix(t, `\`)
			continue
		}
		ut := strings.ToUpper(t)
		switch {
		case t == "" || strings.HasPrefix(ut, "WINDOWS REGISTRY EDITOR") || ut == "REGEDIT4" || strings.HasPrefix(t, ";"):
			continue
		case strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
			key = evClip(t[1:len(t)-1], 1024)
			continue
		case strings.HasPrefix(ut, "HKEY_") || strings.HasPrefix(ut, "HKLM\\") || strings.HasPrefix(ut, "HKCU\\"):
			key = evClip(t, 1024)
			continue
		}
		if key == "" {
			st.Failed++
			continue
		}
		name, data := "", ""
		if m := evRegValRe.FindStringSubmatch(t); m != nil {
			name = evRegUnescape(m[1])
			v := strings.TrimSpace(m[2])
			if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
				data = evRegUnescape(v[1 : len(v)-1])
			} else {
				cont = strings.HasPrefix(v, "hex") && strings.HasSuffix(v, `\`)
				st.Skipped++ // dword / hex values are not decoded
				continue
			}
		} else if strings.HasPrefix(t, `@="`) && strings.HasSuffix(t, `"`) && len(t) >= 4 {
			data = evRegUnescape(t[3 : len(t)-1])
		} else if m := evRegQueryRe.FindStringSubmatch(l); m != nil && (m[2] == "REG_SZ" || m[2] == "REG_EXPAND_SZ") {
			name, data = m[1], m[3]
		} else {
			st.Skipped++
			continue
		}
		st.Parsed++
		out = append(out, evItem{Type: "registry", Line: n + 1, Tel: TelemetryEvent{Key: key, ValueName: evClip(name, 255), ValueData: evClip(data, 4096), Operation: "set"}})
	}
	return out
}

// ---- auth log ----

var evAuthRe = regexp.MustCompile(`^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+\S+\s+sshd(?:\[\d+\])?:\s+(Failed|Accepted)\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+\d+`)

func evParseAuthLog(lines []string, c *evCtx, st *evStat) []evItem {
	var out []evItem
	for n, l := range lines {
		if evBlank(l) {
			continue
		}
		m := evAuthRe.FindStringSubmatch(l)
		if m == nil {
			st.Skipped++
			continue
		}
		ts, err := time.Parse("2006 Jan 2 15:04:05", strconv.Itoa(c.base.Year())+" "+m[1]+" "+m[2]+" "+m[3])
		if err != nil {
			st.Failed++
			continue
		}
		if ts.After(c.base.Add(24 * time.Hour)) {
			ts = ts.AddDate(-1, 0, 0) // syslog omits the year
		}
		outcome := "success"
		if m[4] == "Failed" {
			outcome = "failure"
		}
		st.Parsed++
		out = append(out, evItem{Type: "auth", Line: n + 1, Time: ts, Tel: TelemetryEvent{User: evClip(m[6], 128), Method: "ssh", Outcome: outcome, SourceIP: evClip(m[7], 64)}})
	}
	return out
}

// ---- informational: passwd, dpkg, rpm (inventory only, no events) ----

func evParsePasswd(lines []string, _ *evCtx, st *evStat) []evItem {
	var uid0 []string
	for _, l := range lines {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			if !evBlank(l) {
				st.Failed++
			}
			continue
		}
		st.Parsed++
		if f[2] == "0" && f[0] != "root" {
			uid0 = append(uid0, evClip(f[0], 32))
		}
	}
	if len(uid0) > 0 {
		st.note("observation: non-root accounts with uid 0: " + strings.Join(uid0, ", "))
	}
	return nil
}

func evParseDpkg(lines []string, _ *evCtx, st *evStat) []evItem {
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) >= 3 && len(f[0]) <= 3 && strings.Contains(" ii rc hi un iU ", " "+f[0]+" ") {
			st.Parsed++
		} else if !evBlank(l) {
			st.Skipped++
		}
	}
	return nil
}

var evRPMRe = regexp.MustCompile(`^[A-Za-z0-9_.+-]+-[0-9][^\s]*\.[A-Za-z0-9_]+$`)

func evParseRPM(lines []string, _ *evCtx, st *evStat) []evItem {
	for _, l := range lines {
		if evRPMRe.MatchString(strings.TrimSpace(l)) {
			st.Parsed++
		} else if !evBlank(l) {
			st.Failed++
		}
	}
	return nil
}

// ---- registry of formats, name aliases and content sniffing ----

var evParsers map[string]evParser

func init() {
	evParsers = map[string]evParser{
		"ps": evParsePS, "ss": evParseSS, "netstat": evParseNetstat, "lsof": evParseLsof,
		"crontab": evParseCron(false), "crontab_system": evParseCron(true), "ls": evParseLs, "filelist": evParsePathList,
		"systemd_unit_files": evParseUnitFiles, "systemd_units": evParseUnitFiles, "launchctl": evParseLaunchctl,
		"history": evParseHistory, "tasklist": evParseTasklist, "process_csv": evParseProcessCSV, "schtasks": evParseSchtasks,
		"reg": evParseReg, "authlog": evParseAuthLog, "passwd": evParsePasswd, "dpkg": evParseDpkg, "rpm": evParseRPM,
	}
}

// EvidenceFormats lists the supported format ids.
func EvidenceFormats() []string {
	return []string{"ps", "ss", "netstat", "lsof", "crontab", "crontab_system", "ls", "filelist", "systemd_unit_files",
		"systemd_units", "launchctl", "history", "tasklist", "process_csv", "schtasks", "reg", "authlog", "passwd", "dpkg", "rpm"}
}

var evContainsAlias = []struct{ needle, format string }{
	{"list-unit-files", "systemd_unit_files"}, {"unit-files", "systemd_unit_files"}, {"unit_files", "systemd_unit_files"},
	{"list-units", "systemd_units"}, {"launchctl", "launchctl"}, {"netstat", "netstat"}, {"lsof", "lsof"},
	{"tasklist", "tasklist"}, {"schtasks", "schtasks"}, {"wmic", "process_csv"}, {"get-process", "process_csv"},
	{"process_csv", "process_csv"}, {"history", "history"}, {"crontab_system", "crontab_system"}, {"cron.d", "crontab_system"},
	{"/etc/crontab", "crontab_system"}, {"crontab", "crontab"}, {"auth.log", "authlog"}, {"authlog", "authlog"},
	{"run key", "reg"}, {"runkey", "reg"}, {"run-key", "reg"}, {"autorun", "reg"}, {".reg", "reg"}, {"passwd", "passwd"},
	{"dpkg", "dpkg"}, {"rpm", "rpm"}, {"filelist", "filelist"}, {"recent files", "ls"}, {"cron listing", "ls"}, {"ls -", "ls"},
}
var evTokenAlias = map[string]string{"ps": "ps", "ss": "ss", "ls": "ls", "reg": "reg", "cron": "crontab", "secure": "authlog", "auth": "authlog"}

func evFormatFromName(name string) string {
	l := strings.ToLower(strings.TrimSpace(name))
	if l == "" {
		return ""
	}
	if _, ok := evParsers[l]; ok {
		return l
	}
	for _, a := range evContainsAlias {
		if strings.Contains(l, a.needle) {
			return a.format
		}
	}
	tok := strings.FieldsFunc(l, func(r rune) bool { return !(r >= 'a' && r <= 'z') })
	if len(tok) > 0 {
		if f, ok := evTokenAlias[tok[0]]; ok {
			return f
		}
	}
	return ""
}

var (
	evSniffPerm = regexp.MustCompile(`^[-dlbcps][rwxsStT-]{9}[.+@]?\s`)
	evSniffPass = regexp.MustCompile(`^[^:\s]+:[^:]*:\d+:\d+:`)
	evSniffNet  = regexp.MustCompile(`(?i)^\s*(tcp|udp)[46]?\s`)
	evSniffCron = regexp.MustCompile(`^(@[a-z]+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+\S`)
	evSniffRPM  = regexp.MustCompile(`^[A-Za-z0-9_.+-]+-[0-9][^\s]*\.[A-Za-z0-9_]+$`)
	evSniffAuth = regexp.MustCompile(`^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+\S+\s+\S+`)
	evSniffUnit = regexp.MustCompile(`^[\s\x{25cf}*]*[A-Za-z0-9:_.@\\-]+\.(service|socket|timer)\s`)
)

// evSniff guesses a format from content. Returns "" when nothing matches with confidence.
func evSniff(lines []string) string {
	var s []string
	for _, l := range lines {
		if !evBlank(l) {
			s = append(s, l)
		}
		if len(s) >= 25 {
			break
		}
	}
	if len(s) == 0 {
		return ""
	}
	frac := func(re *regexp.Regexp) bool {
		n := 0
		for _, l := range s {
			if re.MatchString(l) {
				n++
			}
		}
		return n*10 >= len(s)*6
	}
	for i, l := range s {
		if i > 4 {
			break
		}
		u := strings.ToUpper(l)
		f := strings.Fields(u)
		switch {
		case strings.HasPrefix(u, "COMMAND") && strings.Contains(u, " FD ") && strings.Contains(u, "NAME"):
			return "lsof"
		case evIdx(f, "PID") >= 0 && evIdx(f, "COMMAND", "CMD") >= 0 && !strings.Contains(u, ","):
			return "ps"
		case strings.HasPrefix(u, "NETID") || (strings.HasPrefix(u, "STATE") && strings.Contains(u, "LOCAL ADDRESS")):
			return "ss"
		case strings.Contains(u, "PROTO") && strings.Contains(u, "LOCAL ADDRESS"):
			return "netstat"
		case strings.Contains(u, "UNIT FILE") && strings.Contains(u, "STATE"):
			return "systemd_unit_files"
		case strings.HasPrefix(u, "UNIT ") && strings.Contains(u, "ACTIVE") && strings.Contains(u, "LOAD"):
			return "systemd_units"
		case strings.HasPrefix(u, "PID") && strings.Contains(u, "STATUS") && strings.Contains(u, "LABEL"):
			return "launchctl"
		case strings.Contains(u, `"TASKNAME"`) && strings.Contains(u, "TASK TO RUN"):
			return "schtasks"
		case strings.HasPrefix(u, `"IMAGE NAME"`) || strings.HasPrefix(u, "IMAGE NAME "):
			return "tasklist"
		case strings.Contains(u, "PROCESSID") && strings.Contains(u, ","), strings.HasPrefix(u, `"NAME","ID"`), strings.HasPrefix(u, `"PROCESSNAME"`):
			return "process_csv"
		case strings.HasPrefix(u, "WINDOWS REGISTRY EDITOR") || u == "REGEDIT4" || strings.HasPrefix(u, "HKEY_") || strings.HasPrefix(u, "HKLM\\") || strings.HasPrefix(u, "HKCU\\"):
			return "reg"
		case strings.HasPrefix(u, "DESIRED=UNKNOWN") || strings.HasPrefix(u, "||/ NAME"):
			return "dpkg"
		}
	}
	switch {
	case frac(evSniffNet):
		return "netstat"
	case frac(evSniffPass):
		return "passwd"
	case frac(evSniffPerm):
		return "ls"
	case frac(evSniffUnit):
		return "systemd_unit_files"
	case frac(evSniffRPM):
		return "rpm"
	case frac(evSniffAuth) && strings.Contains(strings.Join(s, "\n"), "sshd"):
		return "authlog"
	case frac(evSniffCron):
		return "crontab"
	}
	return ""
}

// evParseArtefact normalises and parses one artefact into items and an inventory row.
func evParseArtefact(name, hint string, raw []byte, c *evCtx) (items []evItem, st evStat) {
	st = evStat{Name: evClip(name, 128), Bytes: len(raw), Status: "failed"}
	text := evNormalizeText(raw)
	lines := evSplitLines(text, &st)
	format := evFormatFromName(hint)
	if format == "" {
		format = evFormatFromName(name)
	}
	if format == "" {
		format = evSniff(lines)
	}
	if format == "" {
		st.Format = "unknown"
		st.Error = "unrecognised artefact: supply a format (name) or a standard command output"
		return nil, st
	}
	st.Format = format
	if st.Lines == 0 {
		st.Error = "empty artefact"
		return nil, st
	}
	items = evParsers[format](lines, c, &st)
	for i := range items {
		items[i].Artefact = st.Name
	}
	st.Events = len(items)
	switch {
	case st.Error != "":
		st.Status = "failed"
	case st.Parsed == 0:
		st.Status = "failed"
		st.Error = "no lines could be parsed"
	case st.Failed > 0:
		st.Status = "partial"
	default:
		st.Status = "parsed"
	}
	return items, st
}
