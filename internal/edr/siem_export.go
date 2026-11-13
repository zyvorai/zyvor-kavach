// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// SIEM and standards export (pull-based, read-only). A SIEM or collector polls
// these endpoints; Kavach opens no new outbound connection.
//
//	GET /v1/export/findings?format=ocsf|ecs|cef|leef|splunk-hec  (hooked from exportFindings)
//	GET /v1/export/iocs?format=stix
//	GET /v1/export/attack-layer
//
// Field mappings are documented in docs/siem-export.md.

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	siemVendor         = "Zyvor AI Labs"
	siemProduct        = "Kavach"
	siemProductVersion = "1.0"
	siemDefaultLimit   = 1000
	siemMaxLimit       = 10000
)

var siemFormats = map[string]string{
	"ocsf": "application/x-ndjson", "ecs": "application/x-ndjson", "splunk-hec": "application/x-ndjson",
	"cef": "text/plain; charset=utf-8", "leef": "text/plain; charset=utf-8",
}

// siemRec is one exportable record: a finding or a raw process event.
type siemRec struct {
	Time time.Time
	ID   string
	F    *Finding
	E    *Event
}

func eventRecID(e Event) string {
	if e.ID != "" {
		return e.ID
	}
	return fmt.Sprintf("%s:%d:%s", e.Host, e.PID, e.ProcessStart)
}

func siemSort(rs []siemRec) {
	sort.SliceStable(rs, func(i, j int) bool {
		if !rs[i].Time.Equal(rs[j].Time) {
			return rs[i].Time.Before(rs[j].Time)
		}
		return rs[i].ID < rs[j].ID
	})
}

// --- cursor: opaque, resumes strictly after (time,id) ---

func encodeSIEMCursor(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte("v1|" + strconv.FormatInt(t.UnixNano(), 10) + "|" + id))
}

func decodeSIEMCursor(c string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	p := strings.SplitN(string(b), "|", 3)
	if len(p) != 3 || p[0] != "v1" {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	n, err := strconv.ParseInt(p[1], 10, 64)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	return time.Unix(0, n).UTC(), p[2], nil
}

func siemAfter(r siemRec, t time.Time, id string) bool {
	if r.Time.After(t) {
		return true
	}
	return r.Time.Equal(t) && r.ID > id
}

// siemExport serves the SIEM formats of /v1/export/findings. It returns false
// when the request is not for one of them (legacy csv/json/ndjson path).
func siemExport(w http.ResponseWriter, r *http.Request, store *Store) bool {
	q := r.URL.Query()
	format := strings.ToLower(q.Get("format"))
	ct, ok := siemFormats[format]
	if !ok {
		return false
	}
	kind := q.Get("kind")
	if kind == "" {
		kind = "findings"
	}
	if kind != "findings" && kind != "events" {
		http.Error(w, "kind must be findings or events", 400)
		return true
	}
	limit := siemDefaultLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > siemMaxLimit {
			http.Error(w, "limit must be 1.."+strconv.Itoa(siemMaxLimit), 400)
			return true
		}
		limit = n
	}
	var since time.Time
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "since must be RFC3339", 400)
			return true
		}
		since = t
	}
	cur := q.Get("cursor")
	var curT time.Time
	var curID string
	if cur != "" {
		var err error
		if curT, curID, err = decodeSIEMCursor(cur); err != nil {
			http.Error(w, err.Error(), 400)
			return true
		}
	}
	sev, host, rule := strings.ToLower(q.Get("severity")), q.Get("host"), q.Get("rule")

	var recs []siemRec
	if kind == "findings" {
		fs := govMaybeRedact(store, store.List())
		for i := range fs {
			f := fs[i]
			if (sev != "" && strings.ToLower(f.Severity) != sev) || (host != "" && f.Host != host) || (rule != "" && f.Rule != rule) {
				continue
			}
			recs = append(recs, siemRec{Time: f.Time.UTC(), ID: f.ID, F: &f})
		}
	} else {
		store.mu.Lock()
		evs := append([]Event(nil), store.recentEvents...)
		store.mu.Unlock()
		for i := range evs {
			e := evs[i]
			if host != "" && e.Host != host {
				continue
			}
			recs = append(recs, siemRec{Time: e.Time.UTC(), ID: eventRecID(e), E: &e})
		}
	}
	siemSort(recs)
	out := recs[:0:0]
	for _, rc := range recs {
		if cur != "" {
			if !siemAfter(rc, curT, curID) {
				continue
			}
		} else if !since.IsZero() && rc.Time.Before(since) {
			continue
		}
		out = append(out, rc)
		if len(out) >= limit {
			break
		}
	}
	next := cur
	if n := len(out); n > 0 {
		next = encodeSIEMCursor(out[n-1].Time, out[n-1].ID)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Kavach-Count", strconv.Itoa(len(out)))
	if next != "" {
		w.Header().Set("X-Kavach-Next-Cursor", next)
	}
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	for _, rc := range out {
		bw.WriteString(renderSIEMLine(format, rc))
		bw.WriteString("\n")
	}
	return true
}

func renderSIEMLine(format string, rc siemRec) string {
	switch format {
	case "cef":
		return cefLine(rc)
	case "leef":
		return leefLine(rc)
	}
	var v any
	switch format {
	case "ocsf":
		v = ocsfRecord(rc)
	case "ecs":
		v = ecsRecord(rc)
	default:
		v = hecRecord(rc)
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimSuffix(sb.String(), "\n")
}

// --- shared helpers ---

func sevRank(s string) int { // 1 info .. 5 critical (OCSF severity_id)
	switch strings.ToLower(s) {
	case "info", "informational":
		return 1
	case "low":
		return 2
	case "medium", "med":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	}
	return 0
}

func ecsSeverity(s string) int {
	return []int{0, 1, 21, 47, 73, 99}[sevRank(s)]
}

func cefSeverity(s string) int {
	return []int{0, 1, 3, 5, 8, 10}[sevRank(s)]
}

func ruleMitre(rule string) (tactic, technique, id string, ok bool) {
	m, ok := contentMITREAll()[rule]
	if !ok {
		m, ok = ruleMITRE[rule]
	}
	return m.Tactic, m.Technique, m.ID, ok
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func procObj(e Event) map[string]any {
	p := map[string]any{"pid": e.PID, "cmd_line": e.Command,
		"file": map[string]any{"path": e.Executable, "name": baseName(e.Executable)},
		"user": map[string]any{"uid": strconv.Itoa(e.UID)}}
	if e.ParentExe != "" || e.PPID != 0 {
		p["parent_process"] = map[string]any{"pid": e.PPID, "file": map[string]any{"path": e.ParentExe, "name": baseName(e.ParentExe)}}
	}
	return p
}

// --- OCSF 1.3: Detection Finding (2004) for findings, Process Activity (1007) for events ---

func ocsfRecord(rc siemRec) map[string]any {
	meta := map[string]any{"version": "1.3.0", "product": map[string]any{"name": siemProduct, "vendor_name": siemVendor}}
	if rc.E != nil {
		e := rc.E
		meta["uid"] = rc.ID
		return map[string]any{
			"class_uid": 1007, "class_name": "Process Activity", "category_uid": 1, "category_name": "System Activity",
			"activity_id": 1, "activity_name": "Launch", "type_uid": 100701, "type_name": "Process Activity: Launch",
			"severity_id": 1, "severity": "Informational", "time": e.Time.UnixMilli(), "metadata": meta,
			"device":  map[string]any{"hostname": e.Host, "name": e.Host},
			"process": procObj(*e),
			"actor":   map[string]any{"process": procObj(*e)},
		}
	}
	f := rc.F
	meta["uid"] = f.ID
	sid := sevRank(f.Severity)
	sname := []string{"Unknown", "Informational", "Low", "Medium", "High", "Critical"}[sid]
	fi := map[string]any{"uid": f.ID, "title": f.Rule, "desc": f.Description, "types": []string{"Kavach detection rule"}}
	if len(f.Tags) > 0 {
		fi["tags"] = f.Tags
	}
	if tac, tech, id, ok := ruleMitre(f.Rule); ok {
		fi["attacks"] = []any{map[string]any{"tactic": map[string]any{"name": tac}, "technique": map[string]any{"uid": id, "name": tech}}}
	}
	ev := map[string]any{"process": procObj(f.Evidence)}
	if f.Destination != "" {
		ev["dst_endpoint"] = map[string]any{"name": f.Destination}
	}
	return map[string]any{
		"class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "category_name": "Findings",
		"activity_id": 1, "activity_name": "Create", "type_uid": 200401, "type_name": "Detection Finding: Create",
		"severity_id": sid, "severity": sname, "time": f.Time.UnixMilli(), "message": f.Description,
		"status_id": 1, "status": "New", "action_id": 1, "action": "Allowed", "disposition_id": 15, "disposition": "Detected",
		"metadata": meta, "finding_info": fi,
		"device":    map[string]any{"hostname": f.Host, "name": f.Host},
		"evidences": []any{ev},
	}
}

// --- ECS 8.x ---

func ecsRecord(rc siemRec) map[string]any {
	base := map[string]any{
		"ecs":      map[string]any{"version": "8.11.0"},
		"observer": map[string]any{"vendor": siemVendor, "product": siemProduct, "type": "edr"},
	}
	if rc.E != nil {
		e := rc.E
		base["@timestamp"] = e.Time.UTC().Format("2006-01-02T15:04:05.000Z")
		base["event"] = map[string]any{"kind": "event", "category": []string{"process"}, "type": []string{"start"},
			"id": rc.ID, "dataset": "kavach.events", "module": "kavach"}
		base["host"] = map[string]any{"name": e.Host}
		base["process"] = ecsProc(*e)
		return base
	}
	f := rc.F
	base["@timestamp"] = f.Time.UTC().Format("2006-01-02T15:04:05.000Z")
	base["event"] = map[string]any{"kind": "alert", "category": []string{"intrusion_detection"}, "type": []string{"info"},
		"id": f.ID, "severity": ecsSeverity(f.Severity), "action": f.Rule, "dataset": "kavach.findings", "module": "kavach"}
	base["message"] = f.Description
	base["rule"] = map[string]any{"name": f.Rule, "description": f.Description}
	base["host"] = map[string]any{"name": f.Host}
	base["process"] = ecsProc(f.Evidence)
	base["labels"] = map[string]any{"kavach_severity": f.Severity}
	if len(f.Tags) > 0 {
		base["tags"] = f.Tags
	}
	if f.Destination != "" {
		base["destination"] = map[string]any{"address": f.Destination}
	}
	if tac, tech, id, ok := ruleMitre(f.Rule); ok {
		base["threat"] = map[string]any{"framework": "MITRE ATT&CK",
			"tactic":    map[string]any{"name": []string{tac}},
			"technique": map[string]any{"id": []string{id}, "name": []string{tech}}}
	}
	return base
}

func ecsProc(e Event) map[string]any {
	p := map[string]any{"pid": e.PID, "executable": e.Executable, "name": baseName(e.Executable),
		"command_line": e.Command, "user": map[string]any{"id": strconv.Itoa(e.UID)}}
	if e.ParentExe != "" || e.PPID != 0 {
		p["parent"] = map[string]any{"pid": e.PPID, "executable": e.ParentExe}
	}
	return p
}

// --- Splunk HTTP Event Collector envelope (NDJSON; the collector forwards it) ---

func hecRecord(rc siemRec) map[string]any {
	t := rc.Time
	rec := map[string]any{"time": json.Number(fmt.Sprintf("%d.%03d", t.Unix(), t.Nanosecond()/1e6)), "source": "kavach"}
	if rc.E != nil {
		rec["host"], rec["sourcetype"], rec["event"] = rc.E.Host, "kavach:event", rc.E
		return rec
	}
	rec["host"], rec["sourcetype"], rec["event"] = rc.F.Host, "kavach:finding", rc.F
	rec["fields"] = map[string]any{"severity": rc.F.Severity, "rule": rc.F.Rule}
	return rec
}

// --- shared key/value builder for CEF and LEEF ---

type siemKV struct{ k, v string }

type kvList []siemKV

// add appends k=v, skipping empty values.
func (l *kvList) add(k, v string) {
	if v != "" {
		*l = append(*l, siemKV{k, v})
	}
}

// addLabeled appends csN/csNLabel only when the value is non-empty.
func (l *kvList) addLabeled(n int, label, v string) {
	if v != "" {
		*l = append(*l, siemKV{"cs" + strconv.Itoa(n) + "Label", label}, siemKV{"cs" + strconv.Itoa(n), v})
	}
}

func isIPish(s string) bool {
	if s == "" || !strings.ContainsAny(s, ".:") {
		return false
	}
	for _, c := range s {
		if !(c == '.' || c == ':' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// --- CEF:0 ---

func cefHeaderEsc(s string) string {
	s = strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(s)
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func cefExtEsc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r\n", `\n`, "\n", `\n`, "\r", `\n`).Replace(s)
}

func cefLine(rc siemRec) string {
	var name, sig string
	var sev int
	var x kvList
	if rc.E != nil {
		e := rc.E
		sig, name, sev = "process-start", "Process started", 1
		x.add("rt", strconv.FormatInt(e.Time.UnixMilli(), 10))
		x.add("cat", "process")
		x.add("externalId", rc.ID)
		x.add("dvchost", e.Host)
		x.add("dvcpid", strconv.Itoa(e.PID))
		x.add("sproc", e.Executable)
		x.add("suid", strconv.Itoa(e.UID))
		x.addLabeled(1, "command", e.Command)
		x.addLabeled(2, "parentExecutable", e.ParentExe)
	} else {
		f := rc.F
		sig, name, sev = f.Rule, f.Rule, cefSeverity(f.Severity)
		x.add("rt", strconv.FormatInt(f.Time.UnixMilli(), 10))
		x.add("cat", "detection")
		x.add("externalId", f.ID)
		x.add("dvchost", f.Host)
		x.add("dvcpid", strconv.Itoa(f.PID))
		x.add("msg", f.Description)
		x.add("sproc", f.Evidence.Executable)
		x.add("suid", strconv.Itoa(f.Evidence.UID))
		x.addLabeled(1, "command", f.Evidence.Command)
		x.addLabeled(2, "tags", strings.Join(f.Tags, ","))
		if _, _, id, ok := ruleMitre(f.Rule); ok {
			x.addLabeled(3, "mitreTechnique", id)
		}
		if isIPish(f.Destination) {
			x.add("dst", f.Destination)
		} else {
			x.add("dhost", f.Destination)
		}
	}
	parts := make([]string, 0, len(x))
	for _, p := range x {
		parts = append(parts, p.k+"="+cefExtEsc(p.v))
	}
	return "CEF:0|" + cefHeaderEsc(siemVendor) + "|" + siemProduct + "|" + siemProductVersion + "|" +
		cefHeaderEsc(sig) + "|" + cefHeaderEsc(name) + "|" + strconv.Itoa(sev) + "|" + strings.Join(parts, " ")
}

// --- LEEF 2.0 (explicit caret delimiter) ---

func leefVal(s string) string {
	return strings.NewReplacer("^", " ", "\r", " ", "\n", " ", "\t", " ").Replace(s)
}

func leefHdr(s string) string { return strings.NewReplacer("|", "/", "\n", " ", "\r", " ").Replace(s) }

func leefLine(rc siemRec) string {
	var id string
	var x kvList
	if rc.E != nil {
		e := rc.E
		id = "process-start"
		x.add("cat", "process")
		x.add("sev", "1")
		x.add("devTime", e.Time.UTC().Format("2006-01-02T15:04:05.000Z"))
		x.add("devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
		x.add("identHostName", e.Host)
		x.add("eventId", rc.ID)
		x.add("pid", strconv.Itoa(e.PID))
		x.add("exe", e.Executable)
		x.add("usrName", strconv.Itoa(e.UID))
		x.add("cmd", e.Command)
	} else {
		f := rc.F
		id = f.Rule
		x.add("cat", "detection")
		x.add("sev", strconv.Itoa(cefSeverity(f.Severity)))
		x.add("devTime", f.Time.UTC().Format("2006-01-02T15:04:05.000Z"))
		x.add("devTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
		x.add("identHostName", f.Host)
		x.add("eventId", f.ID)
		x.add("pid", strconv.Itoa(f.PID))
		x.add("msg", f.Description)
		x.add("exe", f.Evidence.Executable)
		x.add("usrName", strconv.Itoa(f.Evidence.UID))
		x.add("cmd", f.Evidence.Command)
		if isIPish(f.Destination) {
			x.add("dst", f.Destination)
		} else {
			x.add("dstName", f.Destination)
		}
		if _, _, tid, ok := ruleMitre(f.Rule); ok {
			x.add("mitre", tid)
		}
	}
	parts := make([]string, 0, len(x))
	for _, p := range x {
		parts = append(parts, p.k+"="+leefVal(p.v))
	}
	return "LEEF:2.0|" + leefHdr(siemVendor) + "|" + siemProduct + "|" + siemProductVersion + "|" + leefHdr(id) + "|^|" + strings.Join(parts, "^")
}

// --- STIX 2.1 bundle of the IOC store ---

var stixNS = [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8} // RFC 4122 DNS namespace, reused as a fixed namespace

// uuid5 returns an RFC 4122 version-5 UUID string for name under the fixed namespace.
func uuid5(name string) string {
	h := sha1.New()
	h.Write(stixNS[:])
	h.Write([]byte(name))
	s := h.Sum(nil)[:16]
	s[6] = (s[6] & 0x0f) | 0x50
	s[8] = (s[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

func stixTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func stixQuote(s string) string { return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) }

// stixPatternFor returns the STIX pattern for an IOC, or "" when the type is unsupported.
func stixPatternFor(typ, val string) string {
	v := stixQuote(val)
	switch strings.ToLower(typ) {
	case "sha256":
		return "[file:hashes.'SHA-256' = '" + v + "']"
	case "sha1":
		return "[file:hashes.'SHA-1' = '" + v + "']"
	case "md5":
		return "[file:hashes.MD5 = '" + v + "']"
	case "domain":
		return "[domain-name:value = '" + v + "']"
	case "ipv4":
		return "[ipv4-addr:value = '" + v + "']"
	case "ipv6":
		return "[ipv6-addr:value = '" + v + "']"
	case "url":
		return "[url:value = '" + v + "']"
	}
	return ""
}

func buildSTIXBundle(list []IOC, now time.Time) map[string]any {
	idID := "identity--" + uuid5("identity:kavach")
	ts := stixTime(now)
	objs := []any{map[string]any{"type": "identity", "spec_version": "2.1", "id": idID, "created": ts, "modified": ts,
		"name": siemProduct, "identity_class": "system", "description": "Kavach observation-only EDR (" + siemVendor + ")"}}
	sorted := append([]IOC(nil), list...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, i := range sorted {
		if !i.Enabled {
			continue
		}
		pat := stixPatternFor(i.Type, i.Value)
		if pat == "" {
			continue
		}
		created := i.CreatedAt
		if created.IsZero() {
			created = now
		}
		name := i.Description
		if name == "" {
			name = i.Type + " " + i.Value
		}
		o := map[string]any{"type": "indicator", "spec_version": "2.1", "id": "indicator--" + uuid5("indicator:"+strings.ToLower(i.Type)+":"+i.Value),
			"created_by_ref": idID, "created": stixTime(created), "modified": stixTime(created),
			"name": name, "pattern": pat, "pattern_type": "stix", "pattern_version": "2.1",
			"valid_from": stixTime(created), "indicator_types": []string{"malicious-activity"},
			"labels": []string{"kavach", "severity:" + strings.ToLower(i.Severity)}}
		if i.Description != "" {
			o["description"] = i.Description + " (source: " + i.Source + ")"
		}
		objs = append(objs, o)
	}
	return map[string]any{"type": "bundle", "id": "bundle--" + uuid5("bundle:"+ts+":"+strconv.Itoa(len(objs))), "objects": objs}
}

// --- ATT&CK Navigator layer (v4.5) ---

func navTactic(name string) string { return strings.ToLower(strings.ReplaceAll(name, " ", "-")) }

func buildNavigatorLayer(findings []Finding) map[string]any {
	m := BuildATTACKMatrix(findings)
	tacs, _ := m["tactics"].([]*ATTACKTactic)
	techs := []any{}
	maxHits := 0
	for _, t := range tacs {
		for _, x := range t.Techniques {
			color, comment := "#a1d99b", "Covered by: "+strings.Join(x.Rules, ", ")
			if x.Hits > 0 {
				color = "#fb6a4a"
				comment += fmt.Sprintf("; observed %d finding(s)", x.Hits)
			}
			if x.Hits > maxHits {
				maxHits = x.Hits
			}
			techs = append(techs, map[string]any{"techniqueID": x.ID, "tactic": navTactic(t.Tactic), "score": x.Hits,
				"color": color, "comment": comment, "enabled": true, "showSubtechniques": false})
		}
	}
	if maxHits < 1 {
		maxHits = 1
	}
	return map[string]any{
		"name": "Kavach coverage and observed hits", "domain": "enterprise-attack",
		"versions":    map[string]any{"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
		"description": "Techniques covered by Kavach detections (green) and techniques with observed findings (red). Observation only.",
		"sorting":     3, "hideDisabled": false,
		"layout":      map[string]any{"layout": "side", "showName": true, "showID": true},
		"gradient":    map[string]any{"colors": []string{"#ffffff", "#fb6a4a"}, "minValue": 0, "maxValue": maxHits},
		"legendItems": []any{map[string]any{"label": "Covered, no hits", "color": "#a1d99b"}, map[string]any{"label": "Observed hits", "color": "#fb6a4a"}},
		"techniques":  techs,
		"metadata":    []any{map[string]any{"name": "generator", "value": "kavach"}},
	}
}

// RegisterSIEMExport wires /v1/export/iocs and /v1/export/attack-layer. Read-only.
func RegisterSIEMExport(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/export/iocs", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		if f := r.URL.Query().Get("format"); f != "" && f != "stix" {
			http.Error(w, "format must be stix", 400)
			return
		}
		iocMu.Lock()
		list := append([]IOC(nil), iocs...)
		iocMu.Unlock()
		w.Header().Set("Content-Type", "application/stix+json;version=2.1")
		_ = json.NewEncoder(w).Encode(buildSTIXBundle(list, time.Now().UTC()))
	})
	mux.HandleFunc("GET /v1/export/attack-layer", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(buildNavigatorLayer(store.List()))
	})
}
