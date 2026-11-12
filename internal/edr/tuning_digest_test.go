// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func tuneReq(t *testing.T, method, url, tok, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func tuneSeed(t *testing.T, s *Store, prefix, rule, sev string, hosts map[string]int, now time.Time) {
	t.Helper()
	i := 0
	for h, n := range hosts {
		for k := 0; k < n; k++ {
			i++
			f := Finding{ID: prefix + "-" + h + "-" + string(rune('a'+k)), Time: now.Add(-time.Duration(i) * time.Minute),
				Host: h, PID: i, Rule: rule, Severity: sev, Description: "d",
				Evidence: Event{Executable: "/usr/bin/curl", Command: "curl http://x/SECRETCMD --token=abc"}}
			if err := s.Append(f); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestTuningSuggestionMath(t *testing.T) {
	s, _ := NewStore(t.TempDir()+"/f.jsonl", 500)
	now := time.Now().UTC()
	tuneSeed(t, s, "n", "noisy-r", "medium", map[string]int{"h1": 8, "h2": 4}, now)
	tuneSeed(t, s, "q", "quiet-r", "medium", map[string]int{"h1": 2}, now)
	tr := map[string][]Transition{}
	for _, id := range []string{"n-h1-a", "n-h1-b", "n-h2-a"} {
		tr[id] = []Transition{{FindingID: id, Status: "false_positive", Time: now}}
	}
	got := BuildTuningSuggestions(s.List(), tr, now, 14)
	if len(got) != 1 {
		t.Fatalf("want 1 suggestion, got %d", len(got))
	}
	g := got[0]
	if g.Hits != 12 || g.FalsePositives != 3 || g.FalsePositiveRate != 25 {
		t.Fatalf("stats %+v", g)
	}
	if g.Action != "propose_exclusion" || g.Proposal == nil || g.Proposal.Pattern != "noisy-r h1" {
		t.Fatalf("proposal %+v", g)
	}
	if g.RemovesHits != 8 || g.RemovesPercent != 66.7 || g.CollateralHits != 0 || g.Risk != "medium" {
		t.Fatalf("math %+v", g)
	}
	if g.TopHosts[0].Name != "h1" || g.TopExecutables[0].Name != "curl" || g.TopCommands[0].Name != "curl" {
		t.Fatalf("top %+v", g)
	}
	// Window excludes old findings.
	if len(BuildTuningSuggestions(s.List(), tr, now.Add(30*24*time.Hour), 14)) != 0 {
		t.Fatal("window not applied")
	}
}

func TestTuningNeverSuppressCritical(t *testing.T) {
	srv, s, tok := obsServer(t)
	now := time.Now().UTC()
	tuneSeed(t, s, "c", "crit-r", "critical", map[string]int{"h1": 15}, now)
	g := BuildTuningSuggestions(s.List(), nil, now, 14)
	if len(g) != 1 || g[0].Proposal != nil || g[0].Risk != "blocked" || g[0].Action != "review_rule" {
		t.Fatalf("%+v", g)
	}
	code, _ := tuneReq(t, "POST", srv.URL+"/v1/tuning/apply", tok, `{"rule":"crit-r","pattern":"crit-r h1"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("apply critical: %d", code)
	}
	// Broad / wildcard patterns refused.
	for _, p := range []string{`"*"`, `"crit*r h1"`, `"nospacepattern"`, `""`} {
		if c, _ := tuneReq(t, "POST", srv.URL+"/v1/tuning/apply", tok, `{"rule":"other-r","pattern":`+p+`}`); c != 400 {
			t.Fatalf("pattern %s: %d", p, c)
		}
	}
}

func TestTuningCollateralCritical(t *testing.T) {
	s, _ := NewStore(t.TempDir()+"/f.jsonl", 500)
	now := time.Now().UTC()
	tuneSeed(t, s, "m", "scan", "medium", map[string]int{"h1": 12}, now)
	tuneSeed(t, s, "c", "xscan", "critical", map[string]int{"h1": 1}, now) // "scan h1" matches "xscan h1"
	for _, g := range BuildTuningSuggestions(s.List(), nil, now, 14) {
		if g.Rule == "scan" && (g.Proposal != nil || g.Risk != "blocked") {
			t.Fatalf("collateral critical not blocked: %+v", g)
		}
	}
}

func TestTuningApplyRevert(t *testing.T) {
	srv, s, tok := obsServer(t)
	now := time.Now().UTC()
	tuneSeed(t, s, "n", "noisy-r", "low", map[string]int{"h1": 11}, now)
	if c, _ := tuneReq(t, "POST", srv.URL+"/v1/tuning/apply", "", `{}`); c != 401 {
		t.Fatalf("unauth apply %d", c)
	}
	code, body := tuneReq(t, "POST", srv.URL+"/v1/tuning/apply", tok, `{"rule":"noisy-r","pattern":"noisy-r h1","reason":"fleet scanner"}`)
	if code != 201 {
		t.Fatalf("apply %d %s", code, body)
	}
	var rec TuningRecord
	_ = json.Unmarshal([]byte(body), &rec)
	if rec.AppliedBy != "admin-token" || rec.Status != "active" || rec.AppliedAt.IsZero() {
		t.Fatalf("%+v", rec)
	}
	t.Cleanup(func() { tuneReq(t, "POST", srv.URL+"/v1/tuning/revert?id="+rec.ID, tok, "") })
	if n := len(FilterExcluded(s.List())); n != 0 {
		t.Fatalf("exclusion not active, %d visible", n)
	}
	_, hist := tuneReq(t, "GET", srv.URL+"/v1/tuning/history", tok, "")
	if !strings.Contains(hist, rec.ID) {
		t.Fatal("history missing")
	}
	if c, _ := tuneReq(t, "GET", srv.URL+"/v1/tuning/history", "", ""); c != 401 {
		t.Fatal("history unauth")
	}
	if c, _ := tuneReq(t, "POST", srv.URL+"/v1/tuning/revert?id="+rec.ID, tok, ""); c != 200 {
		t.Fatalf("revert %d", c)
	}
	if n := len(FilterExcluded(s.List())); n != 11 {
		t.Fatalf("revert did not restore, %d visible", n)
	}
	if c, _ := tuneReq(t, "POST", srv.URL+"/v1/tuning/revert?id="+rec.ID, tok, ""); c != 409 {
		t.Fatalf("double revert %d", c)
	}
	if c, _ := tuneReq(t, "POST", srv.URL+"/v1/tuning/revert?id=nope", tok, ""); c != 404 {
		t.Fatalf("missing revert %d", c)
	}
}

type tuneSink struct {
	mu   sync.Mutex
	got  [][]byte
	sigs []string
}

func (k *tuneSink) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	k.mu.Lock()
	k.got = append(k.got, b)
	k.sigs = append(k.sigs, r.Header.Get(signatureHeader))
	k.mu.Unlock()
}

func (k *tuneSink) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.got)
}

func tuneService_(t *testing.T, s *Store, now *time.Time) *tuneService {
	d := NewDispatcher(s)
	d.Backoff = time.Millisecond
	d.secret = func() string { return "s3cret" }
	svc := newTuneService(s, d)
	svc.now = func() time.Time { return *now }
	return svc
}

func TestDigestSchedulerAndRestart(t *testing.T) {
	sink := &tuneSink{}
	ts := httptest.NewServer(http.HandlerFunc(sink.handler))
	defer ts.Close()
	s, _ := NewStore(t.TempDir()+"/f.jsonl", 100)
	now := time.Date(2026, 11, 12, 8, 59, 0, 0, time.UTC) // Thursday
	svc := tuneService_(t, s, &now)
	svc.st.Digests = []Digest{
		{ID: "dg-d", Name: "daily", Schedule: "daily", Hour: 9, Content: "top-risks", Type: "webhook", URL: ts.URL},
		{ID: "dg-w", Name: "weekly", Schedule: "weekly", Hour: 9, Content: "soc-metrics", Type: "webhook", URL: ts.URL},
	}
	ctx := context.Background()
	svc.tick(ctx)
	if sink.count() != 0 {
		t.Fatal("fired before hour")
	}
	now = now.Add(2 * time.Minute) // 09:01 Thursday: daily only
	svc.tick(ctx)
	svc.tick(ctx)
	if sink.count() != 1 {
		t.Fatalf("daily should fire once, got %d", sink.count())
	}
	// Restart: new service reloads persisted last-run; must not resend.
	svc2 := tuneService_(t, s, &now)
	svc2.tick(ctx)
	if sink.count() != 1 || len(svc2.st.Digests) != 2 {
		t.Fatalf("restart double-send: %d", sink.count())
	}
	now = now.Add(24 * time.Hour) // Friday: daily again
	svc2.tick(ctx)
	if sink.count() != 2 {
		t.Fatalf("next day: %d", sink.count())
	}
	now = time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC) // Monday: daily + weekly
	svc2.tick(ctx)
	svc2.tick(ctx)
	if sink.count() != 4 {
		t.Fatalf("monday: %d", sink.count())
	}
	if d := svc2.deliveries; d[len(d)-1].Status != "delivered" || d[len(d)-1].Trigger != "schedule" {
		t.Fatalf("%+v", d)
	}
}

func TestDigestPayloadSignedAndClean(t *testing.T) {
	sink := &tuneSink{}
	ts := httptest.NewServer(http.HandlerFunc(sink.handler))
	defer ts.Close()
	s, _ := NewStore(t.TempDir()+"/f.jsonl", 100)
	now := time.Now().UTC()
	tuneSeed(t, s, "k", "r1", "critical", map[string]int{"h1": 2}, now)
	svc := tuneService_(t, s, &now)
	for _, kind := range []string{"shift-report", "soc-metrics", "top-risks"} {
		d := Digest{ID: "dg-" + kind, Name: kind, Schedule: "daily", Content: kind, Type: "webhook", URL: ts.URL}
		if rec := svc.send(context.Background(), d, "p", "manual"); rec.Status != "delivered" {
			t.Fatalf("%s: %+v", kind, rec)
		}
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for i, b := range sink.got {
		for _, bad := range []string{"SECRETCMD", "token", "abc", "/usr/bin"} {
			if strings.Contains(string(b), bad) {
				t.Fatalf("payload %d leaks %q: %s", i, bad, b)
			}
		}
		m := hmac.New(sha256.New, []byte("s3cret"))
		m.Write(b)
		if sink.sigs[i] != "sha256="+hex.EncodeToString(m.Sum(nil)) {
			t.Fatalf("bad signature %q", sink.sigs[i])
		}
	}
	if len(sink.got) != 3 || !strings.Contains(string(sink.got[0]), "k-h1-a") {
		t.Fatalf("expected ids in shift report: %s", sink.got[0])
	}
}

func TestDigestAPIAuthSSRFAndSendNow(t *testing.T) {
	sink := &tuneSink{}
	ts := httptest.NewServer(http.HandlerFunc(sink.handler))
	defer ts.Close()
	srv, _, tok := obsServer(t)
	for _, m := range []string{"GET /v1/digests", "POST /v1/digests", "DELETE /v1/digests?id=x", "POST /v1/digests/send-now?id=x", "GET /v1/digests/deliveries", "GET /v1/tuning/suggestions"} {
		p := strings.SplitN(m, " ", 2)
		if c, _ := tuneReq(t, p[0], srv.URL+p[1], "", "{}"); c != 401 {
			t.Fatalf("%s unauth: %d", m, c)
		}
	}
	mk := func(url string) (int, string) {
		return tuneReq(t, "POST", srv.URL+"/v1/digests", tok,
			`{"name":"n","schedule":"daily","hour_utc":23,"content":"top-risks","type":"webhook","url":"`+url+`"}`)
	}
	for _, u := range []string{"https://127.0.0.1/x", "https://10.0.0.5/x", "http://example.com/x", "https://169.254.169.254/"} {
		if c, _ := mk(u); c != 400 {
			t.Fatalf("ssrf %s: %d", u, c)
		}
	}
	if c, _ := tuneReq(t, "POST", srv.URL+"/v1/digests", tok, `{"name":"n","schedule":"hourly","content":"top-risks","type":"webhook","url":"`+ts.URL+`"}`); c != 400 {
		t.Fatal("bad schedule accepted")
	}
	code, body := mk(ts.URL + "/hook?key=SECRETPATH")
	if code != 201 || strings.Contains(body, "SECRETPATH") {
		t.Fatalf("create %d %s", code, body)
	}
	var d Digest
	_ = json.Unmarshal([]byte(body), &d)
	if _, list := tuneReq(t, "GET", srv.URL+"/v1/digests", tok, ""); strings.Contains(list, "SECRETPATH") || !strings.Contains(list, d.ID) {
		t.Fatalf("list %s", list)
	}
	code, body = tuneReq(t, "POST", srv.URL+"/v1/digests/send-now?id="+d.ID, tok, "")
	if code != 200 || !strings.Contains(body, "delivered") || sink.count() != 1 {
		t.Fatalf("send-now %d %s", code, body)
	}
	if _, dl := tuneReq(t, "GET", srv.URL+"/v1/digests/deliveries", tok, ""); !strings.Contains(dl, "manual") {
		t.Fatalf("deliveries %s", dl)
	}
	if c, _ := tuneReq(t, "DELETE", srv.URL+"/v1/digests?id="+d.ID, tok, ""); c != 204 {
		t.Fatal("delete")
	}
	if c, _ := tuneReq(t, "POST", srv.URL+"/v1/digests/send-now?id="+d.ID, tok, ""); c != 404 {
		t.Fatal("send-now after delete")
	}
}
