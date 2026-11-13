// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

type provScenario struct {
	events   []Event
	network  []NetworkEvent
	files    []FileEvent
	findings []Finding
	attack   map[string]bool // finding IDs that belong to the attack chain
}

type provGen struct {
	r    *rand.Rand
	host string
	t0   time.Time
	pid  int
	ev   []Event
	nw   []NetworkEvent
	fl   []FileEvent
	fi   []Finding
	n    int
}

func (g *provGen) proc(ppid int, pexe, exe string, dt time.Duration) Event {
	g.pid++
	e := Event{ID: fmt.Sprintf("e%d", g.pid), ProcessStart: fmt.Sprintf("st%d", g.pid), Time: g.t0.Add(dt), Host: g.host,
		PID: g.pid, PPID: ppid, Executable: exe, ParentExe: pexe, Command: exe + " --x"}
	g.ev = append(g.ev, e)
	return e
}

func (g *provGen) hit(e Event, rule, sev string, dt time.Duration) string {
	g.n++
	id := fmt.Sprintf("f%d", g.n)
	g.fi = append(g.fi, Finding{ID: id, Time: e.Time.Add(dt), Host: g.host, PID: e.PID, Rule: rule, Severity: sev, Evidence: e})
	return id
}

var provNoiseRules = []string{"mass-file-activity", "netra-denied-process", "ioc-ip-match", "identity-impossible-travel", "ioa-credential-dump"}
var provChain = []struct{ rule, exe string }{
	{"download-execute", "/usr/bin/curl"},
	{"download-chmod-execute", "/tmp/.x/stage2"},
	{"ioa-credential-dump", "/tmp/.x/dumper"},
	{"ioa-lateral-smb", "/usr/bin/smbclient"},
	{"shell-network-redirection", "/bin/nc"},
	{"ransomware-burst", "/tmp/.x/enc"},
}

// genProvScenario builds a benign background (a hub init, sessions, noisy findings, a hard
// negative cluster) plus one multi-stage attack chain with random severity, length and a
// chance that a finding cannot be attached to a process.
func genProvScenario(seed int64, hostN int) provScenario {
	r := rand.New(rand.NewSource(seed))
	g := &provGen{r: r, host: fmt.Sprintf("h%d", hostN), t0: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), pid: 1}
	init := Event{ID: "init", ProcessStart: "st1", Time: g.t0, Host: g.host, PID: 1, PPID: 0, Executable: "/sbin/init"}
	g.ev = append(g.ev, init)
	sshd := g.proc(1, "/sbin/init", "/usr/sbin/sshd", time.Second)
	for i := 0; i < 40; i++ { // hub fan-out
		g.proc(1, "/sbin/init", fmt.Sprintf("/usr/sbin/svc%d", i%8), time.Duration(2+i)*time.Second)
	}
	// benign sessions
	var benign []Event
	for s := 0; s < 8; s++ {
		sh := g.proc(sshd.PID, "/usr/sbin/sshd", "/bin/bash", time.Duration(100+s*30)*time.Second)
		benign = append(benign, sh)
		for k := 0; k < 4; k++ {
			c := g.proc(sh.PID, "/bin/bash", []string{"/bin/ls", "/usr/bin/git", "/usr/bin/curl", "/usr/bin/vim"}[r.Intn(4)], time.Duration(101+s*30+k)*time.Second)
			benign = append(benign, c)
			if r.Intn(2) == 0 {
				g.nw = append(g.nw, NetworkEvent{ID: fmt.Sprintf("n%d", c.PID), Time: c.Time.Add(time.Second), Host: g.host, PID: c.PID,
					ProcessStart: c.ProcessStart, Destination: fmt.Sprintf("repo%d.example.com:443", r.Intn(2))})
			}
		}
	}
	// noisy isolated hits, some high severity
	for i := 0; i < 6; i++ {
		e := benign[r.Intn(len(benign))]
		g.hit(e, provNoiseRules[r.Intn(len(provNoiseRules))], []string{"low", "medium", "high", "critical"}[r.Intn(4)], time.Second)
	}
	// hard negative: 2-3 diverse hits in one benign session subtree
	hn := benign[r.Intn(len(benign))]
	hnA := g.proc(hn.PID, hn.Executable, "/usr/bin/python3", 500*time.Second)
	hnB := g.proc(hnA.PID, hnA.Executable, "/usr/bin/gcc", 502*time.Second)
	g.hit(hnA, "ioa-credential-dump", "medium", time.Second)
	g.hit(hnB, "mass-file-activity", "medium", time.Second)
	if r.Intn(2) == 0 {
		g.hit(hnB, "netra-denied-process", "low", 2*time.Second)
	}
	// attack chain: sshd -> bash -> stage1 -> stage2 ...
	attack := map[string]bool{}
	nst := 2 + r.Intn(5)
	if nst > len(provChain) {
		nst = len(provChain)
	}
	sh := g.proc(sshd.PID, "/usr/sbin/sshd", "/bin/bash", 700*time.Second)
	parent := sh
	for i := 0; i < nst; i++ {
		st := g.proc(parent.PID, parent.Executable, provChain[i].exe, time.Duration(710+i*20)*time.Second)
		sev := []string{"medium", "high", "critical"}[r.Intn(3)]
		id := g.hit(st, provChain[i].rule, sev, time.Second)
		if r.Intn(7) == 0 { // finding with an unknown pid: cannot attach
			g.fi[len(g.fi)-1].PID = 99999
			g.fi[len(g.fi)-1].Evidence.PID = 99999
			g.fi[len(g.fi)-1].Evidence.ProcessStart = ""
		}
		attack[id] = true
		if i == 1 {
			g.nw = append(g.nw, NetworkEvent{ID: "nx", Time: st.Time.Add(time.Second), Host: g.host, PID: st.PID, ProcessStart: st.ProcessStart, Destination: "203.0.113.9:4444"})
		}
		parent = st
	}
	return provScenario{events: g.ev, network: g.nw, files: g.fl, findings: g.fi, attack: attack}
}

func provTop1(s provScenario, host string) (ProvStory, bool) {
	g := BuildProvGraph(host, s.events, s.network, s.files, s.findings, 0)
	rar := NewProvRarity([]*ProvGraph{g})
	st := g.Stories(rar, 0)
	if len(st) == 0 {
		return ProvStory{}, false
	}
	return st[0], true
}

func TestProvStoriesRankAttackAboveNoise(t *testing.T) {
	s := genProvScenario(1, 1)
	st, ok := provTop1(s, "h1")
	if !ok {
		t.Fatal("no stories")
	}
	attackHits := 0
	for _, h := range st.Hits {
		if s.attack[h.FindingID] {
			attackHits++
		}
	}
	if attackHits < 2 || attackHits != len(st.Hits) {
		t.Fatalf("top story not the attack chain: %+v", st)
	}
	if len(st.Tactics) < 2 || st.OrderedRun < 2 {
		t.Fatalf("expected tactic diversity and order: %+v", st)
	}
}

func TestProvEvaluationSynthetic(t *testing.T) {
	const N = 300
	var correct, baseCorrect int
	var precSum, recSum float64
	strata := map[int][2]int{} // attached attack hits -> {correct, total}
	for i := 0; i < N; i++ {
		s := genProvScenario(int64(1000+i), 1)
		attached := 0
		g := BuildProvGraph("h1", s.events, s.network, s.files, s.findings, 0)
		for _, h := range g.hits {
			if s.attack[h.finding] {
				attached++
			}
		}
		st, ok := provTop1(s, "h1")
		v := strata[attached]
		v[1]++
		if ok {
			in := 0
			for _, h := range st.Hits {
				if s.attack[h.FindingID] {
					in++
				}
			}
			if in*2 > len(st.Hits) {
				correct++
				v[0]++
			}
			precSum += float64(in) / float64(len(st.Hits))
			if attached > 0 {
				recSum += float64(in) / float64(attached)
			}
		}
		strata[attached] = v
		// baseline: highest-severity single finding (first on ties), no graph
		best := -1.0
		bi := ""
		for _, f := range s.findings {
			if w := provSevWeight[f.Severity]; w > best {
				best, bi = w, f.ID
			}
		}
		if s.attack[bi] {
			baseCorrect++
		}
	}
	t.Logf("EVAL N=%d top1_correct=%.3f precision=%.3f recall=%.3f baseline_max_severity_top1=%.3f",
		N, float64(correct)/N, precSum/N, recSum/N, float64(baseCorrect)/N)
	t.Logf("EVAL strata (attached attack hits -> [top1 correct, scenarios]): %v", strata)
	if float64(correct)/N < 0.7 {
		t.Fatalf("top-1 accuracy too low: %d/%d", correct, N)
	}
}

func TestProvDeterministic(t *testing.T) {
	s := genProvScenario(7, 1)
	a, _ := json.Marshal(BuildProvGraph("h1", s.events, s.network, s.files, s.findings, 0).Stories(nil, 0))
	b, _ := json.Marshal(BuildProvGraph("h1", s.events, s.network, s.files, s.findings, 0).Stories(nil, 0))
	if string(a) != string(b) {
		t.Fatal("non-deterministic")
	}
}

func TestProvMissingAndFileEdges(t *testing.T) {
	t0 := time.Now()
	ev := []Event{{ID: "a", Time: t0, Host: "h", PID: 10, PPID: 999, Executable: "/bin/a", ProcessStart: "s"}}
	nw := []NetworkEvent{{ID: "n1", Time: t0, Host: "h", PID: 10, Destination: "x:1"}, {ID: "n2", Time: t0, Host: "h", Destination: "y:1"}, {ID: "n3", Time: t0, Host: "h", PID: 77, Destination: "z:1"}}
	fl := []FileEvent{{ID: "f1", Time: t0, Host: "h", Path: "/a"}, {ID: "f2", Time: t0, Host: "h", Path: "/b", PID: 10}}
	g := BuildProvGraph("h", ev, nw, fl, nil, 0)
	m := g.Missing
	if m.UnresolvedParents != 1 || m.NetworkNoPID != 1 || m.NetworkNoProcess != 1 || m.FileEventsNoWriter != 1 || m.FileEventsTotal != 2 {
		t.Fatalf("missing accounting wrong: %+v", m)
	}
	kinds := map[string]int{}
	for _, e := range g.Edges {
		kinds[e.Kind]++
	}
	if kinds[provEdgeConn] != 1 || kinds[provEdgeFile] != 1 {
		t.Fatalf("edges: %v", kinds)
	}
}

func TestProvNodeCapAndTrace(t *testing.T) {
	s := genProvScenario(3, 1)
	g := BuildProvGraph("h1", s.events, s.network, s.files, s.findings, 30)
	if len(g.Nodes) > 40 || !g.Truncated {
		// priority nodes may exceed the cap slightly but not by much
		t.Fatalf("cap not applied: %d nodes truncated=%v", len(g.Nodes), g.Truncated)
	}
	g = BuildProvGraph("h1", s.events, s.network, s.files, s.findings, 0)
	var fid, start string
	for id := range s.attack {
		for _, n := range g.Nodes {
			for _, f := range n.Findings {
				if f == id && fid == "" {
					fid, start = id, n.ID
				}
			}
		}
	}
	if start == "" {
		t.Skip("no attached attack finding for this seed")
	}
	back := g.Trace(start, "back", 2, 50)
	fwd := g.Trace(start, "fwd", 2, 50)
	if len(back.Nodes) < 2 {
		t.Fatalf("back trace empty: %+v", back)
	}
	capped := g.Trace(start, "both", 8, 3)
	if len(capped.Nodes) > 3 {
		t.Fatalf("node cap ignored: %d", len(capped.Nodes))
	}
	_ = fwd
}

func TestProvLineageSourceOverride(t *testing.T) {
	s := genProvScenario(5, 1)
	g := BuildProvGraph("h1", s.events, s.network, s.files, s.findings, 0)
	rar := NewProvRarity([]*ProvGraph{g})
	provLineageSource = func(host, p, c string) (int, int, bool) { return 100000, 100000, true }
	defer func() { provLineageSource = nil }()
	paths := g.Stories(rar, 0)
	if len(paths) == 0 || rar.Source != "behaviour-model" {
		t.Fatalf("lineage source not used: %v", rar.Source)
	}
}

func TestProvHTTP(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 100000)
	if err != nil {
		t.Fatal(err)
	}
	s := genProvScenario(11, 1)
	for _, e := range s.events {
		if _, err := st.Ingest(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range s.network {
		st.IngestNetwork(n)
	}
	for _, f := range s.findings {
		st.Append(f)
	}
	mux := http.NewServeMux()
	RegisterProvenance(mux, "tok", st)
	get := func(u string, auth bool) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest("GET", u, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer tok")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w, m
	}
	if w, _ := get("/v1/prov/status", false); w.Code != 401 {
		t.Fatalf("unauth got %d", w.Code)
	}
	for _, u := range []string{"/v1/prov/status", "/v1/prov/graph?host=h1&limit=50", "/v1/prov/stories?host=h1"} {
		w, m := get(u, true)
		if w.Code != 200 || m["method"] == nil || m["limitations"] == nil {
			t.Fatalf("%s: %d %v", u, w.Code, m)
		}
	}
	_, m := get("/v1/prov/stories?host=h1", true)
	stories, _ := m["stories"].([]any)
	if len(stories) == 0 {
		t.Fatal("no stories over http")
	}
	var fid string
	for id := range s.attack {
		fid = id
		break
	}
	w, m := get("/v1/prov/trace?finding_id="+fid+"&dir=both&hops=3", true)
	if w.Code != 200 || m["method"] == nil {
		t.Fatalf("trace: %d %v", w.Code, m)
	}
	if w, _ := get("/v1/prov/trace?finding_id=nope", true); w.Code != 404 {
		t.Fatalf("missing finding got %d", w.Code)
	}
	if w, _ := get("/v1/prov/trace?finding_id="+fid+"&dir=sideways", true); w.Code != 400 {
		t.Fatalf("bad dir got %d", w.Code)
	}
}
