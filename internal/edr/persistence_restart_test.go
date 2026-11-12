// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func dropFeedIOCs(id string) {
	iocMu.Lock()
	kept := iocs[:0]
	for _, i := range iocs {
		if !strings.HasPrefix(i.ID, feedIOCPrefix(id)) {
			kept = append(kept, i)
		}
	}
	iocs = kept
	iocMu.Unlock()
}

func TestIntelFeedsRestartRoundTrip(t *testing.T) {
	st, err := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 50)
	if err != nil {
		t.Fatal(err)
	}
	f := NewIntelFeeds(st)
	fd := IntelFeed{ID: "rt1", Name: "rt", URL: "http://x", Format: "plain", Interval: 60, Enabled: true}
	f.mu.Lock()
	f.feeds = append(f.feeds, fd)
	s := f.stateLocked(fd)
	s.status.Status, s.etag = "ok", "etag1"
	f.addIndicatorsLocked(fd, s, []indicator{{"domain", "rt-persist.example"}}, f.now().Add(time.Hour))
	err = f.saveLocked()
	f.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	defer dropFeedIOCs("rt1")
	dropFeedIOCs("rt1") // simulate process restart
	if hasIOC("rt-persist.example") != nil {
		t.Fatal("ioc should be gone")
	}
	f2 := NewIntelFeeds(st)
	if hasIOC("rt-persist.example") == nil {
		t.Fatal("indicator not restored")
	}
	if got := f2.statuses(); len(got) != 1 || got[0].Status != "ok" || got[0].Active != 1 {
		t.Fatalf("status not restored: %+v", got)
	}
	if f2.state["rt1"].etag != "etag1" {
		t.Fatal("etag lost")
	}
}

func TestIntelFeedsCorruptFile(t *testing.T) {
	st, _ := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 50)
	if err := os.WriteFile(st.path+".intel.json", []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if f := NewIntelFeeds(st); len(f.feeds) != 0 {
		t.Fatal("expected empty")
	}
}

func TestAlertRulesRestartAndJournal(t *testing.T) {
	srv, st, d, tok := alertSetup(t)
	d.ws = NewWorkspace(st)
	resp, _ := send(t, "POST", srv.URL+"/v1/alerts/rules", tok, `{"url":"https://example.com/hook","min_severity":"high"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	if d2 := NewDispatcher(st); len(d2.rules) != 1 {
		t.Fatalf("rules not restored: %d", len(d2.rules))
	}
	w2 := NewWorkspace(st)
	if n := len(w2.data.Journal); n != 1 || w2.data.Journal[0].Action != "alert_rule.create" {
		t.Fatalf("journal: %+v", w2.data.Journal)
	}
}

func TestAlertRulesCorruptFile(t *testing.T) {
	st, _ := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 50)
	_ = os.WriteFile(st.path+".alerts.json", []byte("garbage"), 0600)
	if d := NewDispatcher(st); len(d.rules) != 0 {
		t.Fatal("expected empty")
	}
}

func TestTuningRestartAndCorruptFiles(t *testing.T) {
	st, _ := NewStore(filepath.Join(t.TempDir(), "f.jsonl"), 50)
	s := newTuneService(st, nil)
	s.st.History = append(s.st.History,
		TuningRecord{ID: "tun-rt", ExclusionID: "ex-rt", Pattern: "p", Status: "active"},
		TuningRecord{ID: "tun-rv", ExclusionID: "ex-rv", Pattern: "q", Status: "reverted"})
	if err := s.saveLocked(); err != nil {
		t.Fatal(err)
	}
	newTuneService(st, nil)
	worldMu.Lock()
	a, b := tuneHasExclusion("ex-rt"), tuneHasExclusion("ex-rv")
	worldMu.Unlock()
	if !a || b {
		t.Fatalf("active=%v reverted=%v", a, b)
	}
	_ = os.WriteFile(st.path+".tuning.json", []byte("x"), 0600)
	newTuneService(st, nil)
	_ = os.WriteFile(st.path+".deception.json", []byte("x"), 0600)
	deceptNewStore(st)
}
