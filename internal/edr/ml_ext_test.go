package edr

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var extT0 = time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC) // a Monday

func extEng() *mlExtEngine { return newMLExtEngine(nil) }

func (e *mlExtEngine) feedDNS(host, name string, t time.Time) {
	e.mu.Lock()
	e.learnDNS(host, name, t)
	e.mu.Unlock()
}

func extJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// ---------------- DNS fixtures ----------------

var extBenignNames = []string{"www.google.com", "mail.google.com", "api.github.com", "github.com", "www.wikipedia.org", "login.microsoftonline.com",
	"cdn.cloudflare.com", "slack.com", "files.slack.com", "www.amazon.com", "s3.amazonaws.com", "registry.npmjs.org", "pypi.org",
	"updates.example.org", "www.bbc.co.uk", "news.ycombinator.com", "teams.microsoft.com", "outlook.office365.com", "www.nytimes.com",
	"docs.python.org", "stackoverflow.com", "www.reddit.com", "play.google.com", "static.licdn.com", "www.linkedin.com"}

const extAlpha = "abcdefghijklmnopqrstuvwxyz0123456789"

func extRand(r *rand.Rand, n int, alphabet string) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// warm gives a host enough ordinary lookups to clear the cold-start guard, over several windows.
func extWarm(e *mlExtEngine, r *rand.Rand, host string) time.Time {
	t := extT0
	for i := 0; i < 80; i++ {
		e.feedDNS(host, extBenignNames[r.Intn(len(extBenignNames))], t)
		t = t.Add(20 * time.Second)
	}
	return t.Add(10 * time.Minute) // next window start is well after the warm-up
}

// one window of activity ending at start+4m; closed by a later benign lookup.
func extCloseWindow(e *mlExtEngine, host string, start time.Time) {
	e.feedDNS(host, "www.google.com", start.Add(20*time.Minute))
}

func extTunnelWindow(e *mlExtEngine, r *rand.Rand, host string, start time.Time) {
	n := 40 + r.Intn(80)
	dom := extRand(r, 8, "abcdefghij") + "-c2.net"
	for i := 0; i < n; i++ {
		e.feedDNS(host, extRand(r, 40+r.Intn(20), "abcdefghijklmnopqrstuvwxyz234567")+"."+dom, start.Add(time.Duration(i)*2*time.Second))
	}
}

func extDGAWindow(e *mlExtEngine, r *rand.Rand, host string, start time.Time) {
	n := 8 + r.Intn(15)
	for i := 0; i < n; i++ {
		e.feedDNS(host, extRand(r, 10+r.Intn(6), "bcdfghjklmnpqrstvwxz0123456789aeiou")+".com", start.Add(time.Duration(i)*5*time.Second))
	}
}

// benign hard cases: CDN-like many short, low-entropy subdomains; bursts of everyday names.
func extBenignWindow(e *mlExtEngine, r *rand.Rand, host string, start time.Time) {
	switch r.Intn(3) {
	case 0: // CDN shards
		for i := 0; i < 25+r.Intn(30); i++ {
			e.feedDNS(host, fmt.Sprintf("img%d.cdn.example.com", i), start.Add(time.Duration(i)*time.Second))
		}
	case 1: // page load fan-out to many everyday sites
		for i, n := range extBenignNames {
			e.feedDNS(host, n, start.Add(time.Duration(i)*time.Second))
		}
	default: // hashed-looking but short version strings
		for i := 0; i < 30; i++ {
			e.feedDNS(host, fmt.Sprintf("v%d.update.vendor-example.com", 100+i), start.Add(time.Duration(i)*time.Second))
		}
	}
}

func extFlagged(e *mlExtEngine, host, kind string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.st.DNS[host]
	for _, f := range h.Flags {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func TestMLDNSEvaluation(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	const trials = 150
	tunHit, dgaHit, benFP := 0, 0, 0
	for i := 0; i < trials; i++ {
		e := extEng()
		host := fmt.Sprintf("h%d", i)
		start := extWarm(e, r, host)
		extTunnelWindow(e, r, host, start)
		extCloseWindow(e, host, start)
		if extFlagged(e, host, "tunneling") {
			tunHit++
		}
		e2 := extEng()
		start = extWarm(e2, r, host)
		extDGAWindow(e2, r, host, start)
		extCloseWindow(e2, host, start)
		if extFlagged(e2, host, "dga_burst") {
			dgaHit++
		}
		e3 := extEng()
		start = extWarm(e3, r, host)
		for w := 0; w < 4; w++ {
			extBenignWindow(e3, r, host, start.Add(time.Duration(w)*10*time.Minute))
		}
		extCloseWindow(e3, host, start.Add(60*time.Minute))
		e3.mu.Lock()
		if len(e3.st.DNS[host].Flags) > 0 {
			benFP++
		}
		e3.mu.Unlock()
	}
	t.Logf("tunneling detection %d/%d, dga-burst detection %d/%d, benign host false positives %d/%d (4 benign windows each)", tunHit, trials, dgaHit, trials, benFP, trials)
	if tunHit < trials*95/100 {
		t.Fatalf("tunnel detection %d/%d", tunHit, trials)
	}
	if dgaHit < trials*80/100 {
		t.Fatalf("dga detection %d/%d", dgaHit, trials)
	}
	if benFP > trials*5/100 {
		t.Fatalf("benign false positives %d/%d", benFP, trials)
	}
}

func TestMLDNSColdStartAndLate(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	e := extEng()
	extTunnelWindow(e, r, "cold", extT0) // a tunnel-like window but only ~100 lookups total, below nothing? ensure guard path
	extCloseWindow(e, "cold", extT0)
	v := e.dnsView("cold", 10)
	if v["sample_count"].(int) >= mlDNSMinLookups {
		// the tunnel window itself exceeds the guard; use a smaller one
		e = extEng()
		for i := 0; i < 30; i++ {
			e.feedDNS("cold", extRand(r, 50, "abcdefghijklmnopqrstuvwxyz234567")+".x-c2.net", extT0.Add(time.Duration(i)*time.Second))
		}
		extCloseWindow(e, "cold", extT0)
		v = e.dnsView("cold", 10)
	}
	if v["status"] != "not_enough_data" || len(v["flags"].([]mlDNSFlag)) != 0 {
		t.Fatalf("cold start must not flag: %v", extJSON(v))
	}
	// late (older than open window) events are ignored, not folded in
	e.feedDNS("cold", "www.google.com", extT0.Add(time.Hour))
	e.feedDNS("cold", "www.google.com", extT0)
	if e.st.DNS["cold"].Late != 1 {
		t.Fatalf("late=%d", e.st.DNS["cold"].Late)
	}
}

func TestMLDNSDeterministic(t *testing.T) {
	build := func() string {
		r := rand.New(rand.NewSource(99))
		e := extEng()
		start := extWarm(e, r, "a")
		extTunnelWindow(e, r, "a", start)
		extDGAWindow(e, r, "a", start.Add(10*time.Minute))
		extCloseWindow(e, "a", start.Add(10*time.Minute))
		return extJSON(e.dnsView("a", 10)) + extJSON(e.dnsView("", 10))
	}
	if a, b := build(), build(); a != b {
		t.Fatal("dns view not deterministic")
	}
}

// ---------------- user baseline ----------------

func (e *mlExtEngine) feedAuth(user, host, outcome string, t time.Time) {
	e.mu.Lock()
	e.learnUserAuth(TelemetryEvent{User: user, Host: host, Outcome: outcome, Time: t})
	e.mu.Unlock()
}

func (e *mlExtEngine) feedProc(uid int, host, exe string, t time.Time) {
	e.mu.Lock()
	e.learnUserProc(Event{UID: uid, Host: host, Executable: exe, Time: t})
	e.mu.Unlock()
}

var extProcs = []string{"/bin/bash", "/usr/bin/git", "/usr/bin/vim", "/usr/bin/python3", "/usr/bin/make", "/usr/bin/ssh", "/usr/bin/ls",
	"/usr/bin/grep", "/usr/bin/curl", "/usr/bin/gcc", "/usr/bin/less", "/usr/bin/docker"}

func (e *mlExtEngine) anomTotal(keys ...string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, k := range keys {
		if u := e.st.Users[k]; u != nil {
			for _, v := range u.Anom {
				n += v
			}
		}
	}
	return n
}

func TestMLUserEvaluation(t *testing.T) {
	r := rand.New(rand.NewSource(11))
	e := extEng()
	const users = 60
	benignChecks, benignFlags := 0, 0
	injected, caught := 0, 0
	for u := 0; u < users; u++ {
		name := fmt.Sprintf("user%d", u)
		hosts := []string{fmt.Sprintf("ws%d", u), "build1", "git1"}
		day := func(d int, h int) time.Time { return extT0.AddDate(0, 0, d).Add(time.Duration(h)*time.Hour + time.Duration(r.Intn(3000))*time.Second) }
		logonHour := func() int { // working hours, with 3% shoulder hours
			if r.Float64() < 0.03 {
				return []int{6, 19, 20}[r.Intn(3)]
			}
			return 8 + r.Intn(10)
		}
		for i := 0; i < 120; i++ { // training
			e.feedAuth(name, hosts[r.Intn(3)], "success", day(i/4, logonHour()))
		}
		for i := 0; i < 300; i++ {
			e.feedProc(1000+u, "ws", extProcs[int(float64(len(extProcs))*r.Float64()*r.Float64())], day(i/10, 9))
		}
		uid := fmt.Sprintf("uid:%d", 1000+u)
		before := e.anomTotal(name, uid)
		for i := 0; i < 200; i++ {
			e.feedAuth(name, hosts[r.Intn(3)], "success", day(40+i/4, logonHour()))
			benignChecks++
		}
		for i := 0; i < 400; i++ {
			// everyday procs plus a rare-but-legitimate tail of 40 other tools, each 0.05%
			exe := extProcs[int(float64(len(extProcs))*r.Float64()*r.Float64())]
			if r.Float64() < 0.02 {
				exe = fmt.Sprintf("/usr/bin/tool%d", r.Intn(40))
			}
			e.feedProc(1000+u, "ws", exe, day(50+i/10, 10))
			benignChecks++
		}
		after := e.anomTotal(name, uid)
		benignFlags += after - before
		// injected: 3am logon from a never-seen host (two deviations) and a never-seen offensive tool
		injected += 3
		an0 := e.anomTotal(name, uid)
		e.feedAuth(name, "dc-unseen", "success", extT0.AddDate(0, 0, 100).Add(3*time.Hour))
		e.feedProc(1000+u, "ws", "/tmp/mimikatz.exe", extT0.AddDate(0, 0, 100).Add(3*time.Hour))
		caught += e.anomTotal(name, uid) - an0
	}
	rate := float64(benignFlags) / float64(benignChecks)
	t.Logf("benign deviation rate %.2f%% (%d/%d checks); injected deviations caught %d/%d", 100*rate, benignFlags, benignChecks, caught, injected)
	if caught < injected {
		t.Fatalf("caught %d/%d", caught, injected)
	}
	if rate > 0.02 {
		t.Fatalf("benign deviation rate %.4f", rate)
	}
}

func TestMLUserColdStart(t *testing.T) {
	e := extEng()
	for i := 0; i < 10; i++ {
		e.feedAuth("newbie", "h"+fmt.Sprint(i), "success", extT0.Add(time.Duration(i)*24*time.Hour+3*time.Hour))
	}
	for i := 0; i < 50; i++ {
		e.feedProc(7, "h", fmt.Sprintf("/bin/p%d", i), extT0)
	}
	v := e.userView("newbie", 5)
	if v["status"] != "not_enough_data" || len(v["recent_anomalies"].([]mlUserAnom)) != 0 {
		t.Fatalf("cold start flagged: %s", extJSON(v))
	}
	v2 := e.userView("uid:7", 5)
	if v2["status"] != "not_enough_data" {
		t.Fatalf("uid:7 should be cold: %s", extJSON(v2))
	}
	if v3 := e.userView("nobody", 5); v3["status"] != "not_enough_data" || v3["sample_count"].(int) != 0 {
		t.Fatalf("unknown user: %v", v3)
	}
}

func TestMLUserCapsAndFailures(t *testing.T) {
	e := extEng()
	for i := 0; i < mlExtMaxUsers+10; i++ {
		e.feedAuth(fmt.Sprintf("u%d", i), "h", "failure", extT0)
	}
	if len(e.st.Users) != mlExtMaxUsers || e.st.Dropped["users"] != 10 {
		t.Fatalf("users=%d dropped=%d", len(e.st.Users), e.st.Dropped["users"])
	}
	if e.st.Users["u0"].Fails != 1 || e.st.Users["u0"].Logons != 0 {
		t.Fatal("failures must not count as logons")
	}
}

func TestMLUserDeterministic(t *testing.T) {
	build := func() string {
		r := rand.New(rand.NewSource(5))
		e := extEng()
		for i := 0; i < 100; i++ {
			e.feedAuth("a", fmt.Sprintf("h%d", r.Intn(3)), "success", extT0.Add(time.Duration(i)*time.Hour*7))
			e.feedProc(1, "h", extProcs[r.Intn(5)], extT0)
		}
		e.feedProc(1, "h", "/x/new", extT0.Add(time.Hour))
		return extJSON(e.userView("a", 5)) + extJSON(e.userView("", 5)) + extJSON(e.st.Users)
	}
	if build() != build() {
		t.Fatal("user view not deterministic")
	}
}

// ---------------- peer group ----------------

func (e *mlExtEngine) feedPeer(host, exe, dest string) {
	e.mu.Lock()
	if exe != "" {
		e.learnPeerProc(Event{Host: host, Executable: exe})
	}
	if dest != "" {
		e.learnPeerDest(NetworkEvent{Host: host, Destination: dest})
	}
	e.mu.Unlock()
}

func extPeerFleet(r *rand.Rand, e *mlExtEngine, web, db int, outliers bool) {
	webP := []string{"nginx", "bash", "cron", "sshd", "python3", "logrotate", "node"}
	dbP := []string{"postgres", "bash", "cron", "sshd", "pg_dump", "logrotate", "python3"}
	webD := []string{"10.0.0.5:443", "10.0.0.6:5432", "repo.example.com:443", "10.0.0.9:9100"}
	dbD := []string{"10.0.0.7:5432", "10.0.0.8:5432", "backup.example.com:22", "10.0.0.9:9100"}
	draw := func(l []string) string { return l[int(float64(len(l))*r.Float64()*r.Float64())] }
	for i := 0; i < web; i++ {
		h := fmt.Sprintf("web%d", i)
		for j := 0; j < 300; j++ {
			e.feedPeer(h, draw(webP), "")
		}
		for j := 0; j < 80; j++ {
			e.feedPeer(h, "", draw(webD))
		}
	}
	for i := 0; i < db; i++ {
		h := fmt.Sprintf("db%d", i)
		for j := 0; j < 300; j++ {
			e.feedPeer(h, draw(dbP), "")
		}
		for j := 0; j < 80; j++ {
			e.feedPeer(h, "", draw(dbD))
		}
	}
	if outliers {
		for j := 0; j < 300; j++ { // miner-like host: unusual processes
			e.feedPeer("web-miner", []string{"xmrig", "kworker-fake", "bash", "nginx"}[r.Intn(4)], "")
		}
		for j := 0; j < 80; j++ {
			e.feedPeer("web-miner", "", "pool.minexample.net:3333")
		}
		for j := 0; j < 300; j++ { // exfil-like host: normal procs, odd destinations
			e.feedPeer("web-exfil", draw(webP), "")
		}
		for j := 0; j < 80; j++ {
			e.feedPeer("web-exfil", "", fmt.Sprintf("198.51.100.%d:8443", r.Intn(60)))
		}
	}
}

func TestMLPeerEvaluation(t *testing.T) {
	r := rand.New(rand.NewSource(21))
	const runs = 40
	minerHit, exfilHit, benignFlagged, benignTotal, dbFlagged, dbTotal := 0, 0, 0, 0, 0, 0
	for i := 0; i < runs; i++ {
		e := extEng()
		extPeerFleet(r, e, 20, 6, true)
		e.mu.Lock()
		all, _ := e.peerCompute()
		e.mu.Unlock()
		if all["web-miner"].MaxZ >= mlPeerZ {
			minerHit++
		}
		if all["web-exfil"].MaxZ >= mlPeerZ {
			exfilHit++
		}
		for h, res := range all {
			if h == "web-miner" || h == "web-exfil" {
				continue
			}
			benignTotal++
			if strings.HasPrefix(h, "db") {
				dbTotal++
				if res.MaxZ >= mlPeerZ {
					dbFlagged++
				}
			}
			if res.MaxZ >= mlPeerZ {
				benignFlagged++
			}
		}
	}
	t.Logf("miner-like host flagged %d/%d, exfil-like host flagged %d/%d, benign hosts flagged %d/%d, of which the db minority (6 hosts among 20 web) %d/%d", minerHit, runs, exfilHit, runs, benignFlagged, benignTotal, dbFlagged, dbTotal)
	if minerHit < runs*9/10 || exfilHit < runs*9/10 {
		t.Fatalf("detection miner=%d exfil=%d of %d", minerHit, exfilHit, runs)
	}
	if benignFlagged-dbFlagged > 0 {
		t.Fatalf("majority-role hosts flagged: %d", benignFlagged-dbFlagged)
	}
}

func TestMLPeerColdStartAndDeterminism(t *testing.T) {
	e := extEng()
	for i := 0; i < 3; i++ { // too few hosts
		for j := 0; j < 100; j++ {
			e.feedPeer(fmt.Sprintf("h%d", i), "bash", "")
		}
	}
	v := e.peerView("h0", 5)
	if v["status"] != "not_enough_data" {
		t.Fatalf("expected not_enough_data: %s", extJSON(v))
	}
	build := func() string {
		r := rand.New(rand.NewSource(3))
		e := extEng()
		extPeerFleet(r, e, 8, 3, true)
		return extJSON(e.peerView("", 50)) + extJSON(e.peerView("web-miner", 5))
	}
	if build() != build() {
		t.Fatal("peer view not deterministic")
	}
	r := rand.New(rand.NewSource(3))
	e2 := extEng()
	extPeerFleet(r, e2, 8, 3, true)
	pv := e2.peerView("web-miner", 5)
	if pv["outlier"] != true || len(pv["views"].([]mlPeerView)[0].Distinct) == 0 {
		t.Fatalf("miner should explain itself: %s", extJSON(pv))
	}
}

// ---------------- alert fatigue ----------------

func extFatigueFindings(now time.Time) ([]Finding, map[string]RulePrecision) {
	var fs []Finding
	add := func(rule string, n, hosts int, ageDays float64) {
		for i := 0; i < n; i++ {
			fs = append(fs, Finding{ID: fmt.Sprintf("%s-%d", rule, i), Rule: rule, Severity: "medium", Host: fmt.Sprintf("h%d", i%hosts),
				Time: now.Add(-time.Duration(ageDays*24*float64(time.Hour)) + time.Duration(i)*time.Minute)})
		}
	}
	add("noisy-rule", 300, 2, 2)      // huge, concentrated, recent
	add("noisy-unlabelled", 250, 3, 3) // same shape, no verdicts
	add("healthy-rule", 14, 10, 12)   // modest, spread
	add("rare-rule", 3, 3, 5)         // below the guard
	for i := 0; i < 40; i++ {         // background so shares are meaningful
		fs = append(fs, Finding{ID: fmt.Sprintf("bg%d", i), Rule: fmt.Sprintf("bg-rule-%d", i%20), Severity: "low", Host: "h9", Time: now.Add(-time.Duration(i) * time.Hour)})
	}
	pos, neg := 1, 25
	lo, hi := 0.0, 0.2
	sh1 := shrunkPrecision(neg*0, 26)
	_ = pos
	_ = neg
	fb := map[string]RulePrecision{
		"noisy-rule": {Rule: "noisy-rule", Decided: 26, Status: feedbackStatusOK, Shrunk: &sh1, WilsonLo: &lo, WilsonHi: &hi},
	}
	return fs, fb
}

func TestMLFatigueEvaluation(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	fs, fb := extFatigueFindings(now)
	rows := buildFatigue(fs, now, fb)
	by := map[string]FatigueResult{}
	for _, r := range rows {
		by[r.Rule] = r
	}
	if by["rare-rule"].Status != "not_enough_data" || by["rare-rule"].Retune {
		t.Fatalf("rare rule must not be judged: %+v", by["rare-rule"])
	}
	n := by["noisy-rule"]
	if !n.Retune || len(n.Suggestion) == 0 || !strings.Contains(strings.Join(n.Suggestion, " "), "rejected") {
		t.Fatalf("noisy rule with verdicts: %+v", n)
	}
	u := by["noisy-unlabelled"]
	if !u.Retune || !strings.Contains(strings.Join(u.Suggestion, " "), "too few analyst verdicts") || len(u.Omitted) == 0 {
		t.Fatalf("unlabelled noisy rule must ask for verdicts, not assert noise: %+v", u)
	}
	if h := by["healthy-rule"]; h.Retune {
		t.Fatalf("healthy rule flagged: %+v", h)
	}
	t.Logf("fatigue: noisy-rule score %.1f, noisy-unlabelled %.1f (coverage %.2f), healthy-rule %.1f, rare-rule %s", n.Score, u.Score, u.Coverage, by["healthy-rule"].Score, by["rare-rule"].Status)
	if extJSON(buildFatigue(fs, now, fb)) != extJSON(rows) {
		t.Fatal("fatigue not deterministic")
	}
}

// ---------------- priority, persistence, reset, HTTP ----------------

func TestMLExtPriorityFactors(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	e := extEng()
	start := extWarm(e, r, "hostA")
	extTunnelWindow(e, r, "hostA", start)
	extCloseWindow(e, "hostA", start)
	for i := 0; i < 150; i++ {
		e.feedProc(5, "hostA", extProcs[r.Intn(4)], start.Add(-time.Hour))
	}
	e.feedProc(5, "hostA", "/tmp/evil", start.Add(time.Minute))
	f := Finding{ID: "f1", Host: "hostA", Rule: "r", Severity: "high", Time: start.Add(2 * time.Minute), Evidence: Event{UID: 5}}
	c := &priorityCtx{health: map[string]RuleHealth{}, beacons: map[string]BeaconSeries{}, assets: map[string]PostureAsset{}, fb: map[string]RulePrecision{}}
	fs, om := e.factors(f, c)
	got := map[string]PriorityFactor{}
	for _, x := range fs {
		got[x.Name] = x
	}
	if got["dns_anomaly"].Value < 0.5 || got["dns_anomaly"].Note == "" {
		t.Fatalf("dns factor: %+v", got["dns_anomaly"])
	}
	if got["user_behaviour"].Value < 0.5 {
		t.Fatalf("user factor: %+v (omitted %v)", got["user_behaviour"], om)
	}
	joined := strings.Join(om, "|")
	if !strings.Contains(joined, "peer_outlier") || !strings.Contains(joined, "rule_fatigue") {
		t.Fatalf("expected peer/fatigue omitted with reasons: %v", om)
	}
	// unknown host: everything omitted, never invented
	fs, _ = e.factors(Finding{Host: "ghost", Rule: "r"}, c)
	if len(fs) != 0 {
		t.Fatalf("no data must give no factors: %+v", fs)
	}
}

func TestMLExtPersistenceResetCaps(t *testing.T) {
	st, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	e := newMLExtEngine(st)
	r := rand.New(rand.NewSource(4))
	start := extWarm(e, r, "h")
	extTunnelWindow(e, r, "h", start)
	extCloseWindow(e, "h", start)
	e.feedAuth("bob", "h1", "success", extT0)
	e.mu.Lock()
	e.saveLocked()
	e.mu.Unlock()
	e2 := newMLExtEngine(st)
	if extJSON(e.dnsView("h", 5)) != extJSON(e2.dnsView("h", 5)) || len(e2.st.Users) != 1 {
		t.Fatal("state not restored")
	}
	e2.reset()
	if len(e2.st.DNS) != 0 || len(e2.st.Users) != 0 {
		t.Fatal("reset must clear")
	}
	b, _ := json.Marshal(e.st)
	if len(b) > 1<<20 {
		t.Fatalf("state unexpectedly large: %d", len(b))
	}
	// vocab cap
	for i := 0; i < mlExtMaxItems+50; i++ {
		e.feedPeer("cap", fmt.Sprintf("p%d", i), "")
	}
	if len(e.st.Peers["cap"].Proc) != mlExtMaxItems || e.st.Peers["cap"].POther != 50 {
		t.Fatalf("cap: %d other %d", len(e.st.Peers["cap"].Proc), e.st.Peers["cap"].POther)
	}
}

func TestMLExtHTTPAndPriorityIntegration(t *testing.T) {
	st, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterMLBehaviour(mux, "tok", st)
	RegisterMLNet(mux, "tok", st)
	RegisterMLExt(mux, "tok", st)
	for _, p := range []string{"/v1/ml/dns", "/v1/ml/users", "/v1/ml/peers", "/v1/ml/fatigue"} {
		if w := mlDo(mux, "GET", p, false); w.Code != 401 {
			t.Fatalf("%s unauth: %d", p, w.Code)
		}
		w := mlDo(mux, "GET", p, true)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		if m["method"] != mlMethod {
			t.Fatalf("%s missing method", p)
		}
	}
	// events flow through the poller into the models
	for i := 0; i < 5; i++ {
		_, _ = st.Ingest(Event{Host: "hx", Executable: "/bin/bash", Command: "bash", Time: time.Now(), PID: 100 + i, UID: 3})
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/ml/reset", nil)
	req.Header.Set("Authorization", "Bearer tok")
	mux.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("reset: %d", w.Code)
	}
	if w := mlDo(mux, "GET", "/v1/ml/priority", true); w.Code != 200 {
		t.Fatalf("priority: %d", w.Code)
	}
	if w := mlDo(mux, "GET", "/v1/ml/fatigue?rule=nope", true); w.Code != 404 {
		t.Fatalf("fatigue 404: %d", w.Code)
	}
	for _, name := range []string{"dns_anomaly", "user_behaviour", "peer_outlier", "rule_fatigue"} {
		if mlExtWeight(name) == 0 {
			t.Fatalf("weight %s", name)
		}
	}
}
