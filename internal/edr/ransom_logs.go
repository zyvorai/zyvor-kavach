// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Offline ransomware-indicator analytics over file-activity and backup-job logs you send
// (observation only). Kavach reads a small allow-list of fields, never file content: an "entropy"
// field or flag is whatever your tool wrote. It does not stop a process, restore a file, lock a
// share or change a backup job. Findings are stored per host with the usual rule guidance.
const (
	rwMaxRecords    = 50000
	rwRenameWindow  = 60 * time.Second
	rwRenameMin     = 50
	rwChurnWindow   = 5 * time.Minute
	rwChurnMin      = 30
	rwChurnShare    = 80 // percent of recent extension-changing renames sharing one new extension
	rwEntropyWindow = 5 * time.Minute
	rwEntropyMin    = 30
	rwEntropyLevel  = 7.5 // bits per byte, scale 0..8
	rwDeleteWindow  = 60 * time.Second
	rwDeleteMin     = 100
	rwNoteDirs      = 5
	rwNoteWindow    = 10 * time.Minute
	rwBackupDelWin  = 10 * time.Minute
	rwBackupDelMin  = 3
	rwCorrWindow    = time.Hour
	rwSpikeRatio    = 3.0
	rwSpikeBaseline = 3
	rwCmdMax        = 2048
	rwDequeCap      = 4096
	rwHostCap       = 20000
	rwFindCap       = 25
)

var rwRules = []struct {
	ID, Tactic, Technique, TechID, Sev string
}{
	{"rwlog-an-mass-rename", "Impact", "Data Encrypted for Impact", "T1486", "high"},
	{"rwlog-an-extension-churn", "Impact", "Data Encrypted for Impact", "T1486", "high"},
	{"rwlog-an-high-entropy-writes", "Impact", "Data Encrypted for Impact", "T1486", "high"},
	{"rwlog-an-ransom-note-spread", "Impact", "Data Encrypted for Impact", "T1486", "high"},
	{"rwlog-an-mass-delete", "Impact", "Data Destruction", "T1485", "high"},
	{"rwlog-an-recovery-inhibit-command", "Impact", "Inhibit System Recovery", "T1490", "high"},
	{"rwlog-an-backup-deletion", "Impact", "Inhibit System Recovery", "T1490", "high"},
	{"rwlog-an-backup-config-weakened", "Impact", "Inhibit System Recovery", "T1490", "medium"},
	{"rwlog-an-backup-malware-flag", "Impact", "Data Encrypted for Impact", "T1486", "high"},
	{"rwlog-an-backup-change-spike", "Impact", "Data Encrypted for Impact", "T1486", "medium"},
	{"rwlog-an-backup-tamper-near-encryption", "Impact", "Inhibit System Recovery", "T1490", "critical"},
}

func init() {
	for _, r := range rwRules {
		ruleMITRE[r.ID] = struct{ Tactic, Technique, ID string }{r.Tactic, r.Technique, r.TechID}
	}
}

func rwRuleList() []map[string]string {
	out := make([]map[string]string, 0, len(rwRules))
	for _, a := range rwRules {
		out = append(out, map[string]string{"id": a.ID, "technique": a.TechID, "severity": a.Sev})
	}
	return out
}

// Recovery-inhibiting commands, written from public descriptions of the commands themselves.
// Go regexps run in linear time; inputs are also capped at rwCmdMax bytes.
var rwCmdRe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bvssadmin(\.exe)?\b.{0,40}\bdelete\s+shadows`),
	regexp.MustCompile(`(?i)\bvssadmin(\.exe)?\b.{0,40}\bresize\s+shadowstorage`),
	regexp.MustCompile(`(?i)\bwmic(\.exe)?\b.{0,60}\bshadowcopy\b.{0,20}\bdelete`),
	regexp.MustCompile(`(?i)\bdiskshadow(\.exe)?\b.{0,80}\bdelete\s+shadows`),
	regexp.MustCompile(`(?i)\bwbadmin(\.exe)?\b.{0,20}\bdelete\s+(catalog|backup|systemstatebackup)`),
	regexp.MustCompile(`(?i)\bbcdedit(\.exe)?\b.{0,60}\brecoveryenabled\s+(no|off)\b`),
	regexp.MustCompile(`(?i)\bbcdedit(\.exe)?\b.{0,60}\bbootstatuspolicy\s+ignoreallfailures`),
	regexp.MustCompile(`(?i)\bwin32_shadowcopy\b.{0,80}\b(delete|remove)`),
	regexp.MustCompile(`(?i)\btmutil(\.exe)?\b.{0,20}\bdeletelocalsnapshots`),
	regexp.MustCompile(`(?i)\bzfs\s+destroy\b.{0,80}@`),
}

var rwNoteWords = []string{"decrypt", "restore_files", "restore-files", "how_to_recover", "recover_files", "recover-files", "readme_to", "ransom", "your_files", "files_encrypted", "encrypted_files"}

type rwEvent struct {
	T                          time.Time
	Host, User, Proc           string
	Op                         string // rename|create|write|delete|backup|""
	Path, NewPath              string
	Cmd, Text, Job             string
	Entropy                    float64
	HasEntropy, EntropyFlag    bool
	Size                       float64
	HasSize                    bool
	RetentionOld, RetentionNew float64
	HasRetention               bool
}

// RansomLogReport is the JSON response.
type RansomLogReport struct {
	Mode         string         `json:"mode"`
	Received     int            `json:"received"`
	Parsed       int            `json:"parsed"`
	Rejected     int            `json:"rejected"`
	Hosts        int            `json:"distinct_hosts"`
	Ops          map[string]int `json:"by_operation"`
	From         *time.Time     `json:"from,omitempty"`
	To           *time.Time     `json:"to,omitempty"`
	ByRule       map[string]int `json:"by_rule"`
	Findings     int            `json:"findings"`
	TripwireHits int            `json:"tripwire_hits,omitempty"`
	Errors       []string       `json:"errors,omitempty"`
	Note         string         `json:"note"`
}

func rwNum(s string) (float64, bool) {
	f, ok := authFloat(s)
	return f, ok
}

func rwTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1", "y", "high", "encrypted", "flagged":
		return true
	}
	return false
}

func rwOp(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.Contains(s, "renam") || strings.HasPrefix(s, "move") || s == "mv":
		return "rename"
	case strings.Contains(s, "delet") || strings.Contains(s, "unlink") || s == "remove" || s == "removed":
		return "delete"
	case strings.Contains(s, "creat") || s == "new" || s == "added":
		return "create"
	case strings.Contains(s, "writ") || strings.Contains(s, "modif") || strings.Contains(s, "chang") || strings.Contains(s, "updat") || s == "overwrite":
		return "write"
	}
	return ""
}

// rwNormalize reads the allow-listed fields of one record.
func rwNormalize(m map[string]any) (rwEvent, string) {
	var e rwEvent
	flat := map[string]string{}
	webFlatten(m, "", 0, flat)
	t, ok := parseWebTime(webPick(flat, "time", "timestamp", "@timestamp", "eventtime", "creationtime", "createdat", "date", "_time", "timecreated", "published"))
	if !ok {
		return e, "no parseable timestamp"
	}
	e.T = t
	e.Host = strings.ToLower(webTruncate(webSanitise(webPick(flat, "host", "hostname", "computer", "computername", "device", "host.name", "machine", "server")), 120))
	e.User = strings.ToLower(webTruncate(webSanitise(webPick(flat, "user", "username", "user.name", "account")), 100))
	e.Proc = strings.ToLower(webTruncate(webSanitise(webPick(flat, "process", "process_name", "image", "process.name", "process.executable")), 120))
	e.Path = webTruncate(webSanitise(webPick(flat, "path", "file", "file_path", "filepath", "target_filename", "targetfilename", "filename", "file.path", "object")), 400)
	e.NewPath = webTruncate(webSanitise(webPick(flat, "new_path", "newpath", "new_name", "newname", "destination", "dest", "dst", "to", "file.new_path")), 400)
	if old := webPick(flat, "old_path", "oldpath", "previous_path", "old_name", "oldname", "src", "source_path", "from"); old != "" && e.NewPath == "" && e.Path != "" {
		e.NewPath = e.Path
		e.Path = webTruncate(webSanitise(old), 400)
	} else if old != "" && e.Path == "" {
		e.Path = webTruncate(webSanitise(old), 400)
	}
	e.Cmd = webTruncate(webSanitise(webPick(flat, "command", "command_line", "commandline", "cmdline", "process.command_line", "commandlinearguments")), rwCmdMax)
	e.Job = webTruncate(webSanitise(webPick(flat, "job", "job_name", "jobname", "backup_job", "policy")), 120)
	opRaw := webPick(flat, "operation", "op", "action", "event_type", "eventtype", "event", "activity", "activity_type", "activitytype", "event_name", "eventname", "kind")
	e.Op = rwOp(opRaw)
	var tb strings.Builder
	for _, k := range []string{"operation", "op", "action", "event_type", "eventtype", "event", "activity", "activity_type", "activitytype", "event_name", "eventname", "message", "msg", "description", "status", "detail", "details", "result"} {
		if v := flat[k]; v != "" {
			tb.WriteString(strings.ToLower(v))
			tb.WriteByte(' ')
		}
		if tb.Len() > 600 {
			break
		}
	}
	e.Text = webTruncate(webSanitise(tb.String()), 600)
	if v, ok := rwNum(webPick(flat, "entropy", "shannon_entropy", "entropy_score", "file_entropy", "write_entropy")); ok && v >= 0 && v <= 8 {
		e.Entropy, e.HasEntropy = v, true
	}
	e.EntropyFlag = rwTruthy(webPick(flat, "high_entropy", "entropy_flag", "encrypted", "is_encrypted", "encryption_detected", "suspicious_encryption"))
	if v, ok := rwNum(webPick(flat, "data_size", "datasize", "backup_size", "size", "changed_bytes", "change_rate", "changerate", "transferred")); ok && v >= 0 {
		e.Size, e.HasSize = v, true
	}
	ro, ok1 := rwNum(webPick(flat, "retention_old", "old_retention", "retention_days_old", "previous_retention"))
	rn, ok2 := rwNum(webPick(flat, "retention_new", "new_retention", "retention_days_new", "retention_days", "retention"))
	if ok1 && ok2 {
		e.RetentionOld, e.RetentionNew, e.HasRetention = ro, rn, true
	}
	if e.Path == "" && e.NewPath == "" && e.Cmd == "" && e.Text == "" && e.Job == "" {
		return e, "no file, command, job or event text"
	}
	return e, ""
}

func rwExt(p string) string {
	b := path.Base(strings.ReplaceAll(p, `\`, "/"))
	i := strings.LastIndex(b, ".")
	if i <= 0 || i == len(b)-1 || len(b)-i > 16 {
		return ""
	}
	return strings.ToLower(b[i:])
}

func rwBase(p string) (dir, base string) {
	p = strings.ReplaceAll(p, `\`, "/")
	return path.Dir(p), strings.ToLower(path.Base(p))
}

type rwWin struct {
	ts   []time.Time
	cool time.Time
}

// hit records t and returns the count inside the window; it is bounded by rwDequeCap.
func (w *rwWin) hit(t time.Time, win time.Duration) int {
	cut := t.Add(-win)
	i := 0
	for i < len(w.ts) && !w.ts[i].After(cut) {
		i++
	}
	w.ts = append(w.ts[i:], t)
	if len(w.ts) > rwDequeCap {
		w.ts = w.ts[len(w.ts)-rwDequeCap:]
	}
	return len(w.ts)
}

// ready reports whether a rule may fire again (one finding per window per host).
func (w *rwWin) ready(t time.Time, win time.Duration) bool {
	if t.Before(w.cool) {
		return false
	}
	w.cool = t.Add(win)
	return true
}

type rwChurn struct {
	ts   []time.Time
	exts []string
	cnt  map[string]int
	cool time.Time
}

// AnalyzeRansomLogs runs the windowed detections over file-activity and backup-job records.
func AnalyzeRansomLogs(recs []map[string]any, hostLabel string) (*RansomLogReport, []Finding) {
	rep := &RansomLogReport{Mode: "observe-only", Received: len(recs), Ops: map[string]int{}, ByRule: map[string]int{},
		Note: "offline analysis of file-activity and backup-job logs you sent; no file content is read, so entropy values and flags are whatever your tool wrote. Nothing is stopped, restored or changed. Thresholds are fixed heuristics; bulk renames by installers, archivers and sync clients cause false positives."}
	if hostLabel == "" {
		hostLabel = "ransom:logs"
	}
	var evs []rwEvent
	for i, m := range recs {
		if m == nil {
			rep.Rejected++
			if len(rep.Errors) < 5 {
				rep.Errors = append(rep.Errors, fmt.Sprintf("record %d: not a JSON object", i))
			}
			continue
		}
		e, why := rwNormalize(m)
		if why != "" {
			rep.Rejected++
			if len(rep.Errors) < 5 {
				rep.Errors = append(rep.Errors, fmt.Sprintf("record %d: %s", i, why))
			}
			continue
		}
		evs = append(evs, e)
		op := e.Op
		if op == "" {
			op = "other"
		}
		rep.Ops[op]++
	}
	rep.Parsed = len(evs)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].T.Before(evs[j].T) })
	if len(evs) > 0 {
		f, l := evs[0].T, evs[len(evs)-1].T
		rep.From, rep.To = &f, &l
	}
	var out []Finding
	perRule := map[string]int{}
	add := func(rule string, t time.Time, host, desc string) {
		if perRule[rule] >= rwFindCap {
			return
		}
		perRule[rule]++
		rep.ByRule[rule]++
		sev := "medium"
		for _, a := range rwRules {
			if a.ID == rule {
				sev = a.Sev
			}
		}
		if host == "" {
			host = hostLabel
		}
		m := ruleMITRE[rule]
		out = append(out, Finding{ID: fmt.Sprintf("%s:%s:%d:%d", host, rule, t.UnixNano(), perRule[rule]), Time: t, Host: host, Rule: rule, Severity: sev,
			Description: desc + " (heuristic over the logs you sent; investigate, not proof of ransomware)",
			Tags:        []string{m.ID, "ransomware", "analytics", "observe-only"},
			Evidence:    Event{Time: t, Host: host, Executable: "ransom:log", Command: webTruncate(desc, 300)}})
	}
	hosts := map[string]bool{}
	renames, dels, ent := map[string]*rwWin{}, map[string]*rwWin{}, map[string]*rwWin{}
	churn := map[string]*rwChurn{}
	notes := map[string]*struct {
		first time.Time
		dirs  map[string]bool
		done  bool
	}{}
	bdel := map[string]*rwWin{}
	type jobHist struct{ sizes []float64 }
	jobs := map[string]*jobHist{}
	var lastEnc, lastBackup time.Time
	var lastEncHost, lastBackupHost string
	corrN := 0
	win := func(m map[string]*rwWin, k string) *rwWin {
		w := m[k]
		if w == nil && len(m) < rwHostCap {
			w = &rwWin{}
			m[k] = w
		}
		return w
	}
	correlate := func(t time.Time, host string) {
		if corrN >= 5 || lastEnc.IsZero() || lastBackup.IsZero() {
			return
		}
		d := lastEnc.Sub(lastBackup)
		if d < 0 {
			d = -d
		}
		if d <= rwCorrWindow {
			corrN++
			add("rwlog-an-backup-tamper-near-encryption", t, host, fmt.Sprintf("backup tampering on %s and encryption indicators on %s occurred within %s of each other", orDash(lastBackupHost), orDash(lastEncHost), d.Round(time.Second)))
			lastEnc, lastBackup = time.Time{}, time.Time{}
		}
	}
	enc := func(t time.Time, host string) {
		lastEnc, lastEncHost = t, host
		correlate(t, host)
	}
	bk := func(t time.Time, host string) {
		lastBackup, lastBackupHost = t, host
		correlate(t, host)
	}
	for _, e := range evs {
		h := e.Host
		hosts[h] = true
		if len(hosts) > 200000 {
			delete(hosts, h)
		}
		// recovery-inhibiting commands
		if e.Cmd != "" {
			for _, re := range rwCmdRe {
				if re.MatchString(e.Cmd) {
					add("rwlog-an-recovery-inhibit-command", e.T, h, fmt.Sprintf("command that removes or disables recovery data on %s: %s", orDash(h), webTruncate(e.Cmd, 160)))
					bk(e.T, h)
					break
				}
			}
		}
		switch e.Op {
		case "rename":
			if w := win(renames, h); w != nil && w.hit(e.T, rwRenameWindow) >= rwRenameMin && w.ready(e.T, rwRenameWindow) {
				add("rwlog-an-mass-rename", e.T, h, fmt.Sprintf("%d file renames within %s on %s (process %s)", len(w.ts), rwRenameWindow, orDash(h), orDash(e.Proc)))
				enc(e.T, h)
			}
			old, nw := rwExt(e.Path), rwExt(e.NewPath)
			if e.NewPath != "" && nw != "" && nw != old && len(churn) < rwHostCap+1 {
				c := churn[h]
				if c == nil {
					c = &rwChurn{cnt: map[string]int{}}
					churn[h] = c
				}
				cut := e.T.Add(-rwChurnWindow)
				i := 0
				for i < len(c.ts) && !c.ts[i].After(cut) {
					c.cnt[c.exts[i]]--
					i++
				}
				c.ts, c.exts = c.ts[i:], c.exts[i:]
				c.ts, c.exts = append(c.ts, e.T), append(c.exts, nw)
				c.cnt[nw]++
				if len(c.ts) > rwDequeCap {
					c.cnt[c.exts[0]]--
					c.ts, c.exts = c.ts[1:], c.exts[1:]
				}
				if c.cnt[nw] >= rwChurnMin && c.cnt[nw]*100/len(c.ts) >= rwChurnShare && !e.T.Before(c.cool) {
					c.cool = e.T.Add(rwChurnWindow)
					add("rwlog-an-extension-churn", e.T, h, fmt.Sprintf("%d files on %s were renamed to the same new extension %s within %s", c.cnt[nw], orDash(h), nw, rwChurnWindow))
					enc(e.T, h)
				}
			}
		case "delete":
			if w := win(dels, h); w != nil && w.hit(e.T, rwDeleteWindow) >= rwDeleteMin && w.ready(e.T, rwDeleteWindow) {
				add("rwlog-an-mass-delete", e.T, h, fmt.Sprintf("%d file deletions within %s on %s (process %s)", len(w.ts), rwDeleteWindow, orDash(h), orDash(e.Proc)))
			}
		}
		// ransom-note style files created in many directories
		if (e.Op == "create" || e.Op == "write" || e.Op == "") && e.Path != "" {
			dir, base := rwBase(e.Path)
			for _, k := range rwNoteWords {
				if strings.Contains(base, k) {
					key := h + "|" + base
					n := notes[key]
					if n == nil && len(notes) < 50000 {
						n = &struct {
							first time.Time
							dirs  map[string]bool
							done  bool
						}{first: e.T, dirs: map[string]bool{}}
						notes[key] = n
					}
					if n != nil {
						if e.T.Sub(n.first) > rwNoteWindow {
							n.first, n.dirs, n.done = e.T, map[string]bool{}, false
						}
						if len(n.dirs) < 64 {
							n.dirs[dir] = true
						}
						if len(n.dirs) >= rwNoteDirs && !n.done {
							n.done = true
							add("rwlog-an-ransom-note-spread", e.T, h, fmt.Sprintf("a file named %s was created in %d directories on %s within %s", base, len(n.dirs), orDash(h), rwNoteWindow))
							enc(e.T, h)
						}
					}
					break
				}
			}
		}
		// entropy indications (values or flags come from the log, never computed here)
		if (e.HasEntropy && e.Entropy >= rwEntropyLevel) || e.EntropyFlag {
			if w := win(ent, h); w != nil && w.hit(e.T, rwEntropyWindow) >= rwEntropyMin && w.ready(e.T, rwEntropyWindow) {
				add("rwlog-an-high-entropy-writes", e.T, h, fmt.Sprintf("%d writes flagged as high entropy or encrypted within %s on %s", len(w.ts), rwEntropyWindow, orDash(h)))
				enc(e.T, h)
			}
		}
		// backup-job events
		tx := e.Text
		isBackup := e.Job != "" || strings.Contains(tx, "backup") || strings.Contains(tx, "restore point") || strings.Contains(tx, "repository") || strings.Contains(tx, "snapshot") || strings.Contains(tx, "retention") || strings.Contains(tx, "immutab")
		if isBackup {
			delWord := strings.Contains(tx, "delet") || strings.Contains(tx, "remov") || strings.Contains(tx, "purg") || strings.Contains(tx, "expir") && strings.Contains(tx, "forc")
			objWord := strings.Contains(tx, "restore point") || strings.Contains(tx, "backup") || strings.Contains(tx, "snapshot") || strings.Contains(tx, "recovery point") || strings.Contains(tx, "repository")
			switch {
			case delWord && objWord && !strings.Contains(tx, "job") && !strings.Contains(tx, "retention"):
				if w := win(bdel, h); w != nil && w.hit(e.T, rwBackupDelWin) >= rwBackupDelMin && w.ready(e.T, rwBackupDelWin) {
					add("rwlog-an-backup-deletion", e.T, h, fmt.Sprintf("%d backup, snapshot or restore-point deletions within %s on %s", len(w.ts), rwBackupDelWin, orDash(h)))
					bk(e.T, h)
				}
			}
			weak := false
			switch {
			case strings.Contains(tx, "immutab") && (strings.Contains(tx, "disabl") || strings.Contains(tx, "remov") || strings.Contains(tx, " off")):
				weak = true
			case strings.Contains(tx, "job") && (strings.Contains(tx, "disabl") || strings.Contains(tx, "deleted") || strings.Contains(tx, "removed")):
				weak = true
			case strings.Contains(tx, "retention") && (strings.Contains(tx, "reduc") || strings.Contains(tx, "shorten") || strings.Contains(tx, "decreas") || strings.Contains(tx, "lower")):
				weak = true
			case e.HasRetention && e.RetentionNew < e.RetentionOld:
				weak = true
			case strings.Contains(tx, "repository") && (strings.Contains(tx, "removed") || strings.Contains(tx, "deleted")):
				weak = true
			}
			if weak {
				add("rwlog-an-backup-config-weakened", e.T, h, fmt.Sprintf("backup configuration weakened on %s (job %s): %s", orDash(h), orDash(e.Job), webTruncate(strings.TrimSpace(tx), 120)))
				bk(e.T, h)
			}
			if strings.Contains(tx, "malware activity detected") || strings.Contains(tx, "encrypteddata") || strings.Contains(tx, "ransomware") || strings.Contains(tx, "encryption detected") {
				add("rwlog-an-backup-malware-flag", e.T, h, fmt.Sprintf("the backup product flagged suspicious activity on %s (job %s): %s", orDash(h), orDash(e.Job), webTruncate(strings.TrimSpace(tx), 120)))
				enc(e.T, h)
			}
			if e.Job != "" && e.HasSize && e.Size > 0 {
				k := h + "|" + strings.ToLower(e.Job)
				jh := jobs[k]
				if jh == nil && len(jobs) < rwHostCap {
					jh = &jobHist{}
					jobs[k] = jh
				}
				if jh != nil {
					if len(jh.sizes) >= rwSpikeBaseline {
						s := append([]float64(nil), jh.sizes...)
						sort.Float64s(s)
						med := s[len(s)/2]
						if med > 0 && e.Size >= rwSpikeRatio*med {
							add("rwlog-an-backup-change-spike", e.T, h, fmt.Sprintf("job %s on %s reported %.0f, %.1fx its median of %.0f over %d earlier runs in this file", orDash(e.Job), orDash(h), e.Size, e.Size/med, med, len(jh.sizes)))
						}
					}
					if len(jh.sizes) < 256 {
						jh.sizes = append(jh.sizes, e.Size)
					}
				}
			}
		}
	}
	rep.Hosts = len(hosts)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	rep.Findings = len(out)
	return rep, out
}

// RegisterRansomLogs mounts POST /v1/ransom/logs (admin token) and GET /v1/ransom/logs/sources.
func RegisterRansomLogs(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ransom/logs/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": "observe-only", "rules": rwRuleList(), "max_records": rwMaxRecords,
			"thresholds": map[string]any{"renames_per_minute": rwRenameMin, "same_new_extension": rwChurnMin, "high_entropy_writes_per_5min": rwEntropyMin, "entropy_level": rwEntropyLevel, "deletes_per_minute": rwDeleteMin, "backup_deletions_per_10min": rwBackupDelMin, "backup_size_spike_ratio": rwSpikeRatio}})
	})
	mux.HandleFunc("POST /v1/ransom/logs", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		recs, err := authUnwrap(raw)
		if err != nil || len(recs) == 0 {
			http.Error(w, "invalid file or backup log payload", http.StatusBadRequest)
			return
		}
		if len(recs) > rwMaxRecords {
			http.Error(w, "too many records (max "+strconv.Itoa(rwMaxRecords)+")", http.StatusRequestEntityTooLarge)
			return
		}
		label := ""
		if h := r.URL.Query().Get("host"); h != "" {
			label = "ransom:" + strings.ToLower(webTruncate(webSanitise(h), 120))
		}
		rep, findings := AnalyzeRansomLogs(recs, label)
		twf, twn := twMerge(recs, "ransom")
		findings = append(findings, twf...)
		rep.TripwireHits = twn
		if rep.Parsed == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "no record could be parsed", "rejected": rep.Rejected, "errors": rep.Errors})
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
	})
}
