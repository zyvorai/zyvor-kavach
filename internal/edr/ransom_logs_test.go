// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

var rwBase0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func rwRec(t time.Time, host, op, p string, extra map[string]any) map[string]any {
	m := map[string]any{"time": t.Format(time.RFC3339Nano), "host": host, "op": op, "path": p}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func rwGen(n int, step time.Duration, f func(i int, t time.Time) map[string]any) []map[string]any {
	out := make([]map[string]any, n)
	for i := range out {
		out[i] = f(i, rwBase0.Add(time.Duration(i)*step))
	}
	return out
}

func TestRansomLogDetections(t *testing.T) {
	renameTo := func(ext string) func(i int, tt time.Time) map[string]any {
		return func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "rename", fmt.Sprintf("/data/d%d/f%d.docx", i%7, i), map[string]any{"new_path": fmt.Sprintf("/data/d%d/f%d.docx%s", i%7, i, ext)})
		}
	}
	cases := []struct {
		name string
		recs []map[string]any
		want []string
		not  []string
	}{
		{"mass rename and churn", rwGen(60, time.Second, renameTo(".locked")), []string{"rwlog-an-mass-rename", "rwlog-an-extension-churn"}, nil},
		{"rename slow is quiet", rwGen(60, 10*time.Second, renameTo(".locked")), []string{"rwlog-an-extension-churn"}, []string{"rwlog-an-mass-rename"}},
		{"rename varied extensions: no churn", rwGen(80, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "rename", fmt.Sprintf("/d/f%d.txt", i), map[string]any{"new_path": fmt.Sprintf("/d/f%d.e%d", i, i)})
		}), []string{"rwlog-an-mass-rename"}, []string{"rwlog-an-extension-churn"}},
		{"rename same extension is quiet", rwGen(40, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "rename", fmt.Sprintf("/d/f%d.txt", i), map[string]any{"new_path": fmt.Sprintf("/d/g%d.txt", i)})
		}), nil, []string{"rwlog-an-extension-churn", "rwlog-an-mass-rename"}},
		{"old_path style rename", rwGen(40, time.Second, func(i int, tt time.Time) map[string]any {
			return map[string]any{"time": tt.Format(time.RFC3339), "host": "h", "action": "renamed", "old_path": fmt.Sprintf("/d/f%d.txt", i), "path": fmt.Sprintf("/d/f%d.txt.enc", i)}
		}), []string{"rwlog-an-extension-churn"}, nil},
		{"entropy values", rwGen(35, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "write", fmt.Sprintf("/d/f%d", i), map[string]any{"entropy": float64(7.9)})
		}), []string{"rwlog-an-high-entropy-writes"}, nil},
		{"entropy flags", rwGen(35, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "write", fmt.Sprintf("/d/f%d", i), map[string]any{"encrypted": "true"})
		}), []string{"rwlog-an-high-entropy-writes"}, nil},
		{"low entropy quiet", rwGen(100, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "write", fmt.Sprintf("/d/f%d", i), map[string]any{"entropy": float64(4.2)})
		}), nil, []string{"rwlog-an-high-entropy-writes"}},
		{"entropy out of range ignored", rwGen(100, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "write", fmt.Sprintf("/d/f%d", i), map[string]any{"entropy": float64(99)})
		}), nil, []string{"rwlog-an-high-entropy-writes"}},
		{"mass delete", rwGen(110, 100*time.Millisecond, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "delete", fmt.Sprintf("/d/f%d", i), nil)
		}), []string{"rwlog-an-mass-delete"}, nil},
		{"ransom notes", rwGen(6, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "create", fmt.Sprintf("/data/dir%d/HOW_TO_DECRYPT.txt", i), nil)
		}), []string{"rwlog-an-ransom-note-spread"}, nil},
		{"one note is quiet", rwGen(1, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, "fs01", "create", "/data/README_decrypt.txt", nil)
		}), nil, []string{"rwlog-an-ransom-note-spread"}},
		{"recovery inhibit commands", []map[string]any{
			{"time": rwBase0.Format(time.RFC3339), "host": "h", "command": "vssadmin delete shadows /all /quiet"},
			{"time": rwBase0.Add(time.Second).Format(time.RFC3339), "host": "h", "command": `wmic shadowcopy delete`},
			{"time": rwBase0.Add(2 * time.Second).Format(time.RFC3339), "host": "h", "command": `bcdedit /set {default} recoveryenabled No`},
			{"time": rwBase0.Add(3 * time.Second).Format(time.RFC3339), "host": "h", "command": `wbadmin delete catalog -quiet`},
			{"time": rwBase0.Add(4 * time.Second).Format(time.RFC3339), "host": "h", "command": `zfs destroy tank/data@snap1`},
			{"time": rwBase0.Add(5 * time.Second).Format(time.RFC3339), "host": "h", "command": `Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() } Remove-WmiObject`},
		}, []string{"rwlog-an-recovery-inhibit-command"}, nil},
		{"benign commands quiet", []map[string]any{
			{"time": rwBase0.Format(time.RFC3339), "host": "h", "command": "vssadmin list shadows"},
			{"time": rwBase0.Format(time.RFC3339), "host": "h", "command": "wbadmin get versions"},
			{"time": rwBase0.Format(time.RFC3339), "host": "h", "command": "bcdedit /enum"},
			{"time": rwBase0.Format(time.RFC3339), "host": "h", "command": "zfs list -t snapshot"},
		}, nil, []string{"rwlog-an-recovery-inhibit-command"}},
		{"backup deletions", rwGen(4, time.Minute, func(i int, tt time.Time) map[string]any {
			return map[string]any{"time": tt.Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "Restore point deleted"}
		}), []string{"rwlog-an-backup-deletion"}, nil},
		{"single deletion quiet", rwGen(1, time.Minute, func(i int, tt time.Time) map[string]any {
			return map[string]any{"time": tt.Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "Restore point deleted"}
		}), nil, []string{"rwlog-an-backup-deletion"}},
		{"retention reduced", []map[string]any{{"time": rwBase0.Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "Job settings changed", "retention_old": float64(30), "retention_new": float64(1)}}, []string{"rwlog-an-backup-config-weakened"}, nil},
		{"retention raised quiet", []map[string]any{{"time": rwBase0.Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "Job settings changed", "retention_old": float64(7), "retention_new": float64(30)}}, nil, []string{"rwlog-an-backup-config-weakened"}},
		{"immutability disabled", []map[string]any{{"time": rwBase0.Format(time.RFC3339), "host": "bk", "message": "Repository immutability disabled"}}, []string{"rwlog-an-backup-config-weakened"}, nil},
		{"job disabled", []map[string]any{{"time": rwBase0.Format(time.RFC3339), "host": "bk", "job": "nightly", "message": "backup job disabled by user"}}, []string{"rwlog-an-backup-config-weakened"}, nil},
		{"vendor malware flag", []map[string]any{{"time": rwBase0.Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "Malware Activity Detected", "activity_type": "EncryptedData"}}, []string{"rwlog-an-backup-malware-flag"}, nil},
		{"backup size spike", []map[string]any{
			{"time": rwBase0.Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "backup job success", "data_size": float64(100)},
			{"time": rwBase0.Add(time.Hour).Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "backup job success", "data_size": float64(105)},
			{"time": rwBase0.Add(2 * time.Hour).Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "backup job success", "data_size": float64(98)},
			{"time": rwBase0.Add(3 * time.Hour).Format(time.RFC3339), "host": "bk", "job": "nightly", "event": "backup job success", "data_size": float64(450)},
		}, []string{"rwlog-an-backup-change-spike"}, nil},
		{"backup steady quiet", []map[string]any{
			{"time": rwBase0.Format(time.RFC3339), "host": "bk", "job": "n", "event": "backup job success", "data_size": float64(100)},
			{"time": rwBase0.Add(time.Hour).Format(time.RFC3339), "host": "bk", "job": "n", "event": "backup job success", "data_size": float64(105)},
			{"time": rwBase0.Add(2 * time.Hour).Format(time.RFC3339), "host": "bk", "job": "n", "event": "backup job success", "data_size": float64(98)},
			{"time": rwBase0.Add(3 * time.Hour).Format(time.RFC3339), "host": "bk", "job": "n", "event": "backup job success", "data_size": float64(130)},
		}, nil, []string{"rwlog-an-backup-change-spike"}},
		{"tamper near encryption", append(rwGen(60, time.Second, renameTo(".locked")), map[string]any{"time": rwBase0.Add(20 * time.Minute).Format(time.RFC3339), "host": "bk", "command": "wbadmin delete catalog -quiet"}),
			[]string{"rwlog-an-backup-tamper-near-encryption", "rwlog-an-recovery-inhibit-command"}, nil},
		{"tamper far from encryption", append(rwGen(60, time.Second, renameTo(".locked")), map[string]any{"time": rwBase0.Add(6 * time.Hour).Format(time.RFC3339), "host": "bk", "command": "wbadmin delete catalog -quiet"}),
			[]string{"rwlog-an-recovery-inhibit-command"}, []string{"rwlog-an-backup-tamper-near-encryption"}},
		{"hosts are separate", rwGen(60, time.Second, func(i int, tt time.Time) map[string]any {
			return rwRec(tt, fmt.Sprintf("h%d", i%3), "rename", fmt.Sprintf("/d/f%d.txt", i), map[string]any{"new_path": fmt.Sprintf("/d/f%d.txt.x", i)})
		}), nil, []string{"rwlog-an-mass-rename"}},
	}
	for _, c := range cases {
		rep, fs := AnalyzeRansomLogs(c.recs, "")
		for _, w := range c.want {
			if rep.ByRule[w] == 0 {
				t.Errorf("%s: missing %s (got %v, errors %v)", c.name, w, rep.ByRule, rep.Errors)
			}
		}
		for _, n := range c.not {
			if rep.ByRule[n] != 0 {
				t.Errorf("%s: unexpected %s", c.name, n)
			}
		}
		for _, f := range fs {
			if f.Host == "" || !strings.HasPrefix(f.Rule, "rwlog-an-") || len(f.Tags) == 0 || f.Severity == "" {
				t.Errorf("%s: bad finding %+v", c.name, f)
			}
		}
	}
}

func TestRansomLogRulesRegistered(t *testing.T) {
	for _, a := range rwRules {
		if m, ok := ruleMITRE[a.ID]; !ok || m.ID != a.TechID {
			t.Errorf("%s not registered", a.ID)
		}
		if _, ok := ResolveGuidance(a.ID); !ok {
			t.Errorf("no guidance for %s", a.ID)
		}
	}
}

func TestRansomLogHostileInput(t *testing.T) {
	recs := []map[string]any{nil, {}, {"time": "garbage", "path": "/x"}, {"time": rwBase0.Format(time.RFC3339)},
		{"time": rwBase0.Format(time.RFC3339), "host": strings.Repeat("H", 100000) + "\x00\n", "command": strings.Repeat("vssadmin ", 50000) + "delete shadows", "path": strings.Repeat("/a", 100000), "entropy": "NaN", "retention": "1e999"},
		{"time": rwBase0.Format(time.RFC3339), "command": strings.Repeat("wmic ", 10000) + strings.Repeat("shadowcopy ", 10000)},
		{"time": rwBase0.Format(time.RFC3339), "op": []any{1}, "path": map[string]any{"a": "b"}, "message": "x"},
	}
	nested := map[string]any{}
	cur := nested
	for i := 0; i < 5000; i++ {
		n := map[string]any{}
		cur["a"] = n
		cur = n
	}
	recs = append(recs, map[string]any{"time": rwBase0.Format(time.RFC3339), "path": "/p", "deep": nested})
	for i := 0; i < 40000; i++ {
		recs = append(recs, rwRec(rwBase0.Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("h%d", i%5000), "rename", fmt.Sprintf("/d/f%d.a", i), map[string]any{"new_path": fmt.Sprintf("/d/f%d.b%d", i, i%50), "process": fmt.Sprintf("p%d", i)}))
	}
	start := time.Now()
	rep, fs := AnalyzeRansomLogs(recs, "")
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %s", d)
	}
	if rep.Rejected < 4 || rep.Parsed < 40000 {
		t.Errorf("rejected=%d parsed=%d", rep.Rejected, rep.Parsed)
	}
	per := map[string]int{}
	for _, f := range fs {
		per[f.Rule]++
		if strings.ContainsAny(f.Description, "\x00\n") || len(f.Description) > 1500 {
			t.Errorf("unsanitised description")
		}
	}
	for r, n := range per {
		if n > rwFindCap {
			t.Errorf("%s over cap %d", r, n)
		}
	}
}

func TestRansomLogSampleFile(t *testing.T) {
	raw, err := os.ReadFile("testdata/ransom/file_backup_sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	recs, err := authUnwrap(raw)
	if err != nil || len(recs) != 4 {
		t.Fatalf("%v %d", err, len(recs))
	}
	rep, _ := AnalyzeRansomLogs(recs, "")
	if rep.Parsed != 4 || rep.ByRule["rwlog-an-recovery-inhibit-command"] != 1 || rep.ByRule["rwlog-an-backup-malware-flag"] != 1 {
		t.Errorf("%+v", rep)
	}
}

func TestRansomLogsHTTP(t *testing.T) {
	h := telHandler(t)
	var lines []string
	for i := 0; i < 3; i++ {
		b, _ := json.Marshal(map[string]any{"time": rwBase0.Add(time.Duration(i) * time.Second).Format(time.RFC3339), "host": "fs01", "command": "vssadmin delete shadows /all"})
		lines = append(lines, string(b))
	}
	body := strings.Join(lines, "\n")
	if w := telDo(h, "POST", "/v1/ransom/logs", body, ""); w.Code != 401 {
		t.Fatalf("unauth %d", w.Code)
	}
	w := telDo(h, "POST", "/v1/ransom/logs", body, "tok")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var rep RansomLogReport
	_ = json.Unmarshal(w.Body.Bytes(), &rep)
	if rep.ByRule["rwlog-an-recovery-inhibit-command"] != 3 || rep.Findings != 3 {
		t.Fatalf("%+v", rep)
	}
	if g := telDo(h, "GET", "/v1/findings", "", "tok"); !strings.Contains(g.Body.String(), "rwlog-an-recovery-inhibit-command") || !strings.Contains(g.Body.String(), "fs01") {
		t.Errorf("not stored")
	}
	if g := telDo(h, "GET", "/v1/ransom/logs/sources", "", "tok"); g.Code != 200 || !strings.Contains(g.Body.String(), "rwlog-an-mass-rename") {
		t.Errorf("sources %d", g.Code)
	}
	if g := telDo(h, "GET", "/v1/ransom/logs/sources", "", ""); g.Code != 401 {
		t.Errorf("sources unauth %d", g.Code)
	}
	for _, c := range []struct {
		body string
		code int
	}{{"", 400}, {"[]", 400}, {`[{"x":1}]`, 400}, {strings.Repeat("a", webBodyMax+1), 413}} {
		if w := telDo(h, "POST", "/v1/ransom/logs", c.body, "tok"); w.Code != c.code {
			t.Errorf("%.20q -> %d want %d", c.body, w.Code, c.code)
		}
	}
}
