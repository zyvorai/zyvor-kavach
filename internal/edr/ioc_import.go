// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Offline threat-intel import and IOC lifecycle (docs/ioc-import.md).
//
// POST /v1/ioc/import (admin token) accepts a STIX 2.1 bundle, a MISP event/attribute JSON export or a
// plain CSV/TXT list from the request body. Nothing is fetched from the network. Dry run is the default.
// Imported indicators carry TLP, valid_from/valid_until and a per-source expiry; expired indicators
// stop matching but are kept for audit. A match only increments a counter. Observation only.

const (
	iocImportMaxBytes = 5 << 20
	iocImportMaxItems = 5000
	iocImportMaxShown = 1000
	iocImportIDPrefix = "imp-"
	iocMaxTTLDays     = 3650
)

var (
	iocPath      string // set by RegisterIOC; empty means no persistence
	iocFileMu    sync.Mutex
	iocDirty     bool // guarded by iocMu
	iocLastSave  time.Time
	iocSaveEvery = 30 * time.Second
)

// iocActive reports whether the indicator is inside its validity window (no window means always).
func iocActive(i IOC, now time.Time) bool {
	if i.ValidUntil != nil && !now.Before(*i.ValidUntil) {
		return false
	}
	if i.ValidFrom != nil && now.Before(*i.ValidFrom) {
		return false
	}
	return true
}

func iocExpired(i IOC, now time.Time) bool {
	return i.ValidUntil != nil && !now.Before(*i.ValidUntil)
}

// iocTTL returns the default expiry in days for a source: KAVACH_IOC_SOURCE_TTL_DAYS="misp=30,corp=0"
// overrides KAVACH_IOC_DEFAULT_TTL_DAYS (default 90). Zero means never expire.
func iocTTL(source string) (days int, perSource bool) {
	for _, kv := range strings.Split(os.Getenv("KAVACH_IOC_SOURCE_TTL_DAYS"), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), source) {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 && n <= iocMaxTTLDays {
				return n, true
			}
		}
	}
	days = 90
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("KAVACH_IOC_DEFAULT_TTL_DAYS"))); err == nil && n >= 0 && n <= iocMaxTTLDays {
		days = n
	}
	return days, false
}

func iocFlushSoonLocked(now time.Time) {
	if iocPath == "" || now.Sub(iocLastSave) < iocSaveEvery {
		return
	}
	iocLastSave = now
	lcGo(iocSave)
}

type iocDisk struct {
	Version int   `json:"version"`
	IOCs    []IOC `json:"iocs"`
}

// iocSave writes the imported indicators (including expired ones and sighting counters) atomically.
func iocSave() {
	iocFileMu.Lock()
	defer iocFileMu.Unlock()
	iocMu.Lock()
	path := iocPath
	d := iocDisk{Version: 1, IOCs: []IOC{}}
	for _, i := range iocs {
		if strings.HasPrefix(i.ID, iocImportIDPrefix) {
			d.IOCs = append(d.IOCs, i)
		}
	}
	iocDirty = false
	iocMu.Unlock()
	if path == "" {
		return
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err == nil {
		tmp := path + ".tmp"
		if err = os.WriteFile(tmp, b, 0600); err == nil {
			err = os.Rename(tmp, path)
		}
	}
	if err != nil {
		log.Printf("ioc import: save %s: %v", path, err)
	}
}

func iocLoad(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("ioc import: read %s: %v (starting empty)", path, err)
		}
		return
	}
	var d iocDisk
	if err := json.Unmarshal(b, &d); err != nil {
		log.Printf("ioc import: corrupt %s: %v (starting empty)", path, err)
		return
	}
	iocMu.Lock()
	defer iocMu.Unlock()
	have := map[string]bool{}
	for _, i := range iocs {
		have[i.ID] = true
	}
	for _, i := range d.IOCs {
		if !strings.HasPrefix(i.ID, iocImportIDPrefix) || have[i.ID] || len(iocs) >= iocMaxEntries {
			continue
		}
		i.Action = "detect_only"
		iocs = append(iocs, i)
	}
}

func iocImportInit(store *Store) {
	if store == nil || store.path == "" {
		return
	}
	iocMu.Lock()
	iocPath = store.path + ".iocimport.json"
	p := iocPath
	iocMu.Unlock()
	iocLoad(p)
	RegisterStopper("ioc-import", func(context.Context) error { iocSave(); return nil })
}

// ---- candidates ----

type iocCand struct {
	Ref      string
	Type     string
	Value    string
	TLP      string
	From     *time.Time
	Until    *time.Time
	Severity string
	Desc     string
	Err      string
}

var tlpRank = map[string]int{"": 0, "clear": 1, "green": 2, "amber": 3, "amber+strict": 4, "red": 5}

func normTLP(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "tlp:")
	switch s {
	case "":
		return "", true
	case "white":
		return "clear", true
	}
	_, ok := tlpRank[s]
	return s, ok
}

// tlpMax returns the more restrictive of two normalised markings.
func tlpMax(a, b string) string {
	if tlpRank[b] > tlpRank[a] {
		return b
	}
	return a
}

func parseWhen(s string) (*time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not an RFC 3339 timestamp: %q", iocTrunc(s, 40))
	}
	t = t.UTC()
	return &t, nil
}

func iocTrunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func iocClean(s string, n int) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, iocTrunc(s, n))
}

var stixTLPIDs = map[string]string{
	"marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",
	"marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
	"marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
	"marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}

func parseSTIXBundle(b []byte) ([]iocCand, int, error) {
	var bundle struct {
		Type    string            `json:"type"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, 0, fmt.Errorf("invalid STIX JSON: %v", err)
	}
	if bundle.Type != "bundle" {
		return nil, 0, fmt.Errorf("not a STIX bundle (type must be \"bundle\")")
	}
	if len(bundle.Objects) > iocImportMaxItems {
		return nil, 0, fmt.Errorf("bundle has %d objects, limit is %d", len(bundle.Objects), iocImportMaxItems)
	}
	type obj struct {
		Type        string          `json:"type"`
		ID          string          `json:"id"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Pattern     string          `json:"pattern"`
		PatternType string          `json:"pattern_type"`
		ValidFrom   string          `json:"valid_from"`
		ValidUntil  string          `json:"valid_until"`
		Revoked     bool            `json:"revoked"`
		Confidence  *int            `json:"confidence"`
		Markings    []string        `json:"object_marking_refs"`
		DefType     string          `json:"definition_type"`
		Definition  json.RawMessage `json:"definition"`
	}
	objs := make([]obj, len(bundle.Objects))
	marks := map[string]string{}
	for k, v := range stixTLPIDs {
		marks[k] = v
	}
	for i, raw := range bundle.Objects {
		if json.Unmarshal(raw, &objs[i]) != nil {
			objs[i] = obj{Type: "?"}
			continue
		}
		o := objs[i]
		if o.Type == "marking-definition" && o.DefType == "tlp" {
			var d struct {
				TLP string `json:"tlp"`
			}
			if json.Unmarshal(o.Definition, &d) == nil {
				if t, ok := normTLP(d.TLP); ok && t != "" && o.ID != "" {
					marks[o.ID] = t
				}
			}
		}
	}
	var out []iocCand
	ignored := 0
	for _, o := range objs {
		if o.Type != "indicator" {
			ignored++
			continue
		}
		base := iocCand{Ref: o.ID, Desc: iocClean(iocFirst(o.Description, o.Name), 200), Severity: "medium"}
		if o.Confidence != nil {
			switch {
			case *o.Confidence >= 80:
				base.Severity = "high"
			case *o.Confidence < 40:
				base.Severity = "low"
			}
		}
		fail := func(msg string) { c := base; c.Err = msg; out = append(out, c) }
		if o.Revoked {
			fail("indicator is revoked")
			continue
		}
		if o.PatternType != "stix" {
			fail(fmt.Sprintf("unsupported pattern_type %q (only stix)", iocTrunc(o.PatternType, 20)))
			continue
		}
		var err error
		if base.From, err = parseWhen(o.ValidFrom); err != nil {
			fail("valid_from: " + err.Error())
			continue
		}
		if base.Until, err = parseWhen(o.ValidUntil); err != nil {
			fail("valid_until: " + err.Error())
			continue
		}
		for _, m := range o.Markings {
			if t, ok := marks[m]; ok {
				base.TLP = tlpMax(base.TLP, t)
			}
		}
		vals, err := ParseSTIXPattern(o.Pattern)
		if err != nil {
			fail("pattern: " + err.Error())
			continue
		}
		for _, v := range vals {
			c := base
			c.Type, c.Value = v.Type, v.Value
			out = append(out, c)
		}
	}
	return out, ignored, nil
}

func iocFirst(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}

type mispTag struct {
	Name string `json:"name"`
}

type mispAttr struct {
	Type    string          `json:"type"`
	Value   string          `json:"value"`
	ToIDS   json.RawMessage `json:"to_ids"`
	Deleted json.RawMessage `json:"deleted"`
	Comment string          `json:"comment"`
	UUID    string          `json:"uuid"`
	Tag     []mispTag       `json:"Tag"`
}

type mispEvent struct {
	Info      string     `json:"info"`
	UUID      string     `json:"uuid"`
	Attribute []mispAttr `json:"Attribute"`
	Object    []struct {
		Attribute []mispAttr `json:"Attribute"`
	} `json:"Object"`
	Tag []mispTag `json:"Tag"`
}

func jsonTruthy(r json.RawMessage) bool {
	s := strings.Trim(strings.TrimSpace(string(r)), `"`)
	return s == "true" || s == "1"
}

func parseMISP(b []byte) ([]iocCand, error) {
	var root struct {
		Event    *mispEvent `json:"Event"`
		Response []struct {
			Event *mispEvent `json:"Event"`
		} `json:"response"`
		mispEvent
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("invalid MISP JSON: %v", err)
	}
	var events []*mispEvent
	if root.Event != nil {
		events = append(events, root.Event)
	}
	for _, r := range root.Response {
		if r.Event != nil {
			events = append(events, r.Event)
		}
	}
	if len(root.Attribute) > 0 || len(root.Object) > 0 {
		e := root.mispEvent
		events = append(events, &e)
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("no MISP Event or Attribute found")
	}
	var out []iocCand
	total := 0
	for _, ev := range events {
		var attrs []mispAttr
		attrs = append(attrs, ev.Attribute...)
		for _, o := range ev.Object {
			attrs = append(attrs, o.Attribute...)
		}
		total += len(attrs)
		if total > iocImportMaxItems {
			return nil, fmt.Errorf("more than %d attributes, limit is %d", iocImportMaxItems, iocImportMaxItems)
		}
		evTLP, evBad := "", ""
		for _, t := range ev.Tag {
			evTLP, evBad = mispTLP(t, evTLP, evBad)
		}
		for _, a := range attrs {
			c := iocCand{Ref: iocFirst(a.UUID, ev.UUID), Severity: "medium", Desc: iocClean(iocFirst(a.Comment, ev.Info), 200), TLP: evTLP}
			bad := evBad
			for _, t := range a.Tag {
				c.TLP, bad = mispTLP(t, c.TLP, bad)
			}
			switch {
			case jsonTruthy(a.Deleted):
				c.Err = "attribute is deleted"
			case bad != "":
				c.Err = "unknown TLP marking " + bad
			case !jsonTruthy(a.ToIDS):
				c.Err = "to_ids is not set (not flagged as a detection indicator)"
			default:
				c.Type, c.Value, c.Err = mispMap(a.Type, a.Value)
			}
			out = append(out, c)
		}
	}
	return out, nil
}

func mispTLP(t mispTag, cur, bad string) (string, string) {
	n := strings.ToLower(strings.TrimSpace(t.Name))
	if !strings.HasPrefix(n, "tlp:") {
		return cur, bad
	}
	v, ok := normTLP(n)
	if !ok || v == "" {
		return cur, iocTrunc(iocClean(t.Name, 30), 30)
	}
	return tlpMax(cur, v), bad
}

func mispMap(typ, val string) (t, v, errMsg string) {
	typ = strings.ToLower(typ)
	if strings.HasPrefix(typ, "filename|") {
		parts := strings.SplitN(val, "|", 2)
		if len(parts) != 2 {
			return "", "", "composite attribute value is not name|hash"
		}
		val, typ = parts[1], strings.TrimPrefix(typ, "filename|")
	}
	switch typ {
	case "md5", "sha1", "sha256", "url":
		t = typ
	case "domain", "hostname":
		t = "domain"
	case "ip-src", "ip-dst":
		t = DetectIOCType(val)
		if t != "ipv4" && t != "ipv6" {
			return "", "", "value is not an IP address"
		}
	case "email", "email-src", "email-dst":
		t = "email"
	default:
		return "", "", fmt.Sprintf("unsupported MISP attribute type %q", iocTrunc(iocClean(typ, 30), 30))
	}
	n, err := NormalizeIOCValue(t, val)
	if err != nil {
		return "", "", err.Error()
	}
	return t, n, ""
}

var csvTypes = map[string]string{"sha256": "sha256", "sha1": "sha1", "md5": "md5", "domain": "domain", "ipv4": "ipv4", "ipv6": "ipv6", "url": "url", "email": "email"}

func parseList(b []byte, format string) ([]iocCand, error) {
	var recs [][]string
	if format == "txt" {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			recs = append(recs, []string{ln})
			if len(recs) > iocImportMaxItems+1 {
				break
			}
		}
	} else {
		r := csv.NewReader(bytes.NewReader(b))
		r.FieldsPerRecord = -1
		r.LazyQuotes = true
		r.Comment = '#'
		r.TrimLeadingSpace = true
		for {
			rec, err := r.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("invalid CSV: %v", err)
			}
			recs = append(recs, rec)
			if len(recs) > iocImportMaxItems+1 {
				break
			}
		}
	}
	col := map[string]int{}
	if len(recs) > 0 && format != "txt" {
		for i, h := range recs[0] {
			col[strings.ToLower(strings.TrimSpace(h))] = i
		}
		vi := -1
		for _, k := range []string{"value", "indicator", "ioc"} {
			if i, ok := col[k]; ok {
				vi = i
				break
			}
		}
		if vi >= 0 {
			col["value"] = vi
			if u, ok := col["expires"]; ok {
				if _, has := col["valid_until"]; !has {
					col["valid_until"] = u
				}
			}
			recs = recs[1:]
		} else {
			col = map[string]int{}
		}
	}
	if len(recs) > iocImportMaxItems {
		return nil, fmt.Errorf("more than %d entries, limit is %d", iocImportMaxItems, iocImportMaxItems)
	}
	get := func(rec []string, k string) string {
		if i, ok := col[k]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	var out []iocCand
	for n, rec := range recs {
		c := iocCand{Ref: "line-" + strconv.Itoa(n+1), Severity: "medium"}
		var val string
		if len(col) > 0 {
			val, c.Type = get(rec, "value"), strings.ToLower(get(rec, "type"))
			c.Desc = iocClean(get(rec, "description"), 200)
			if s := strings.ToLower(get(rec, "severity")); s == "low" || s == "medium" || s == "high" || s == "critical" {
				c.Severity = s
			}
			var err error
			var ok bool
			if c.TLP, ok = normTLP(get(rec, "tlp")); !ok {
				c.Err = "unknown TLP marking"
			}
			if c.From, err = parseWhen(get(rec, "valid_from")); err != nil && c.Err == "" {
				c.Err = "valid_from: " + err.Error()
			}
			if c.Until, err = parseWhen(get(rec, "valid_until")); err != nil && c.Err == "" {
				c.Err = "valid_until: " + err.Error()
			}
		} else if len(rec) >= 2 && csvTypes[strings.ToLower(strings.TrimSpace(rec[0]))] != "" {
			c.Type, val = strings.ToLower(strings.TrimSpace(rec[0])), strings.TrimSpace(rec[1])
		} else {
			val = strings.TrimSpace(rec[0])
		}
		if c.Err != "" {
			out = append(out, c)
			continue
		}
		if c.Type == "" {
			c.Type = DetectIOCType(val)
		} else if csvTypes[c.Type] == "" {
			c.Err = fmt.Sprintf("unsupported type %q", iocTrunc(iocClean(c.Type, 30), 30))
			out = append(out, c)
			continue
		}
		nv, err := NormalizeIOCValue(c.Type, val)
		if err != nil {
			c.Err = err.Error()
		}
		c.Value = nv
		out = append(out, c)
	}
	return out, nil
}

func detectIOCFormat(b []byte) string {
	t := bytes.TrimSpace(b)
	if len(t) > 0 && (t[0] == '{' || t[0] == '[') {
		var probe map[string]json.RawMessage
		if json.Unmarshal(t, &probe) == nil {
			if _, ok := probe["objects"]; ok {
				return "stix"
			}
			if string(probe["type"]) == `"bundle"` {
				return "stix"
			}
			return "misp"
		}
		return "stix" // looks like JSON but does not parse: let the STIX parser report the error
	}
	ln, _, _ := strings.Cut(string(t), "\n")
	if strings.Contains(ln, ",") {
		return "csv"
	}
	return "txt"
}

// ---- report ----

type iocImportItem struct {
	N      int    `json:"n"`
	Ref    string `json:"ref,omitempty"`
	Type   string `json:"type,omitempty"`
	Value  string `json:"value,omitempty"`
	Status string `json:"status"` // valid (dry run) | imported | updated | duplicate | rejected
	Reason string `json:"reason,omitempty"`
	TLP    string `json:"tlp,omitempty"`
	Until  string `json:"valid_until,omitempty"`
}

func iocID(typ, val string) string {
	h := sha256.Sum256([]byte(typ + "\x00" + val))
	return iocImportIDPrefix + hex.EncodeToString(h[:8])
}

func validSourceName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// iocImportRun stages (and, when apply is true, stores) the candidates. now is injected for tests.
func iocImportRun(cands []iocCand, source string, apply bool, now time.Time) (items []iocImportItem, sum map[string]int, ttlDays int) {
	ttlDays, _ = iocTTL(source)
	sum = map[string]int{"candidates": len(cands), "valid": 0, "imported": 0, "updated": 0, "duplicate": 0, "rejected": 0}
	iocMu.Lock()
	defer iocMu.Unlock()
	idx := map[string]int{}
	for k, i := range iocs {
		idx[i.Type+"\x00"+strings.ToLower(i.Value)] = k
	}
	seen := map[string]bool{}
	for n, c := range cands {
		it := iocImportItem{N: n + 1, Ref: iocTrunc(iocClean(c.Ref, 80), 80), Type: c.Type, Value: iocTrunc(c.Value, 200), TLP: c.TLP}
		reject := func(msg string) { it.Status, it.Reason = "rejected", msg; sum["rejected"]++ }
		switch {
		case c.Err != "":
			reject(c.Err)
		case c.Until != nil && !now.Before(*c.Until):
			reject("already expired (valid_until is in the past)")
		case c.From != nil && c.Until != nil && !c.From.Before(*c.Until):
			reject("valid_from is not before valid_until")
		default:
			until, from := c.Until, c.From
			if until == nil && ttlDays > 0 {
				t := now.AddDate(0, 0, ttlDays)
				until = &t
			}
			if until != nil {
				it.Until = until.Format(time.RFC3339)
			}
			key := c.Type + "\x00" + strings.ToLower(c.Value)
			k, exists := idx[key]
			switch {
			case seen[key]:
				it.Status = "duplicate"
				it.Reason = "repeated within this import"
				sum["duplicate"]++
			case exists && !strings.HasPrefix(iocs[k].ID, iocImportIDPrefix):
				it.Status = "duplicate"
				it.Reason = "already present from another source; left unchanged"
				sum["duplicate"]++
			case exists:
				it.Status = "updated"
				sum["updated"]++
				if !apply {
					it.Status = "valid"
					it.Reason = "would refresh validity of the existing indicator"
					sum["updated"]--
					sum["valid"]++
				} else {
					e := &iocs[k]
					e.ValidFrom, e.ValidUntil, e.TLP, e.Enabled = from, until, c.TLP, true
				}
			case apply && len(iocs) >= iocMaxEntries:
				reject("ioc limit reached")
			case apply:
				iocs = append(iocs, IOC{ID: iocID(c.Type, c.Value), Type: c.Type, Value: c.Value, Action: "detect_only",
					Severity: c.Severity, Description: c.Desc, Source: source, CreatedAt: now, Enabled: true,
					TLP: c.TLP, ValidFrom: from, ValidUntil: until})
				idx[key] = len(iocs) - 1
				it.Status = "imported"
				sum["imported"]++
			default:
				it.Status = "valid"
				sum["valid"]++
			}
			seen[key] = true
		}
		if len(items) < iocImportMaxShown {
			items = append(items, it)
		}
	}
	if apply {
		iocDirty = true
	}
	return
}

func iocParseFormat(body []byte, format string) (cands []iocCand, ignored int, used string, err error) {
	if format == "" || format == "auto" {
		format = detectIOCFormat(body)
	}
	used = format
	switch format {
	case "stix":
		cands, ignored, err = parseSTIXBundle(body)
	case "misp":
		cands, err = parseMISP(body)
	case "csv", "txt":
		cands, err = parseList(body, format)
	default:
		err = fmt.Errorf("format must be auto, stix, misp, csv or txt")
	}
	return
}

type iocSourceStat struct {
	Total       int `json:"total"`
	Active      int `json:"active"`
	Expired     int `json:"expired"`
	NotYetValid int `json:"not_yet_valid"`
	Sightings   int `json:"sightings"`
}

func iocStats(now time.Time) map[string]any {
	iocMu.Lock()
	defer iocMu.Unlock()
	byType, byTLP := map[string]int{}, map[string]int{}
	bySource := map[string]*iocSourceStat{}
	var active, expired, notYet, disabled, sightings int
	for _, i := range iocs {
		s := bySource[i.Source]
		if s == nil {
			s = &iocSourceStat{}
			bySource[i.Source] = s
		}
		byType[i.Type]++
		tlp := i.TLP
		if tlp == "" {
			tlp = "unmarked"
		}
		byTLP[tlp]++
		s.Total++
		s.Sightings += i.Sightings
		sightings += i.Sightings
		switch {
		case iocExpired(i, now):
			expired++
			s.Expired++
		case i.ValidFrom != nil && now.Before(*i.ValidFrom):
			notYet++
			s.NotYetValid++
		default:
			active++
			s.Active++
		}
		if !i.Enabled {
			disabled++
		}
	}
	def, _ := iocTTL("")
	return map[string]any{
		"mode": "observe-only", "generated_at": now.Format(time.RFC3339), "total": len(iocs),
		"active": active, "expired": expired, "not_yet_valid": notYet, "disabled": disabled,
		"sightings_total": sightings, "by_type": byType, "by_source": bySource, "by_tlp": byTLP,
		"config": map[string]any{"default_ttl_days": def, "source_ttl_env": "KAVACH_IOC_SOURCE_TTL_DAYS", "default_ttl_env": "KAVACH_IOC_DEFAULT_TTL_DAYS"},
		"note":   "Expired indicators no longer match but are retained for audit. Sightings are match counters only.",
	}
}

func registerIOCImport(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/ioc/stats", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		customJSON(w, 200, iocStats(time.Now().UTC()))
	})
	mux.HandleFunc("POST /v1/ioc/import", func(w http.ResponseWriter, r *http.Request) {
		isAdmin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		if !isAdmin {
			customJSON(w, http.StatusForbidden, map[string]any{"error": "admin token required"})
			return
		}
		limits := map[string]any{"max_bytes": iocImportMaxBytes, "max_items": iocImportMaxItems, "max_items_shown": iocImportMaxShown}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, iocImportMaxBytes))
		if err != nil {
			customJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body too large or unreadable", "limits": limits})
			return
		}
		q := r.URL.Query()
		dry := true
		switch q.Get("dry_run") {
		case "false", "0":
			dry = false
		case "", "true", "1":
		default:
			customJSON(w, 400, map[string]any{"error": "dry_run must be true or false"})
			return
		}
		cands, ignored, format, err := iocParseFormat(body, strings.ToLower(q.Get("format")))
		if err != nil {
			customJSON(w, 400, map[string]any{"error": err.Error(), "limits": limits})
			return
		}
		source := q.Get("source")
		if source == "" {
			source = "import-" + format
		} else if !validSourceName(source) {
			customJSON(w, 400, map[string]any{"error": "source must be 1-64 characters of letters, digits, '.', '_' or '-'"})
			return
		}
		items, sum, ttl := iocImportRun(cands, source, !dry, time.Now().UTC())
		if !dry {
			AppendAudit(token, "ioc.import", fmt.Sprintf("%s source=%s imported=%d updated=%d rejected=%d", format, source, sum["imported"], sum["updated"], sum["rejected"]))
			iocSave()
		}
		customJSON(w, 200, map[string]any{"mode": "observe-only", "dry_run": dry, "format": format, "source": source,
			"default_ttl_days": ttl, "ignored_objects": ignored, "summary": sum, "items_truncated": len(cands) > len(items),
			"limits": limits, "items": items,
			"caveats": "Offline import only; nothing is fetched. Unsupported or invalid items are rejected with a reason, never guessed. TLP is stored as a label and does not change handling."})
	})
}
