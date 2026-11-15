// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func snapOf(t *testing.T, raw string) ContentSnapshot {
	t.Helper()
	p, err := hashPack("detection/content/x.json", "detection", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return combineSnapshot([]ContentPackSnap{p})
}

func TestHashOrderIndependence(t *testing.T) {
	a := snapOf(t, `{"pack":"x","rules":[{"id":"a","severity":"high","match":{"field":"f","op":"equals"}},{"id":"b","severity":"low"}]}`)
	b := snapOf(t, `{"rules":[{"severity":"low","id":"b"},{"match":{"op":"equals","field":"f"},"severity":"high","id":"a"}],"pack":"x"}`)
	if a.Hash != b.Hash || a.Packs[0].Hash != b.Packs[0].Hash {
		t.Fatalf("hash depends on ordering: %s vs %s", a.Hash, b.Hash)
	}
	if a.Packs[0].Count != 2 {
		t.Fatalf("count=%d", a.Packs[0].Count)
	}
	c := snapOf(t, `{"pack":"x","rules":[{"id":"a","severity":"critical","match":{"field":"f","op":"equals"}},{"id":"b","severity":"low"}]}`)
	if c.Hash == a.Hash {
		t.Fatal("changed content must change hash")
	}
}

func TestEmbeddedSnapshotStable(t *testing.T) {
	a, errs := buildContentSnapshot()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	b, _ := buildContentSnapshot()
	if a.Hash != b.Hash || a.Total == 0 {
		t.Fatalf("unstable or empty: %s %s total=%d", a.Hash, b.Hash, a.Total)
	}
	for _, k := range []string{"detection", "bytes", "adversary", "scenario", "hunt", "compliance"} {
		if a.ByKind[k] == 0 {
			t.Errorf("no items for kind %s", k)
		}
	}
}

func TestDiffCases(t *testing.T) {
	base := snapOf(t, `{"rules":[{"id":"a","severity":"high","name":"A"},{"id":"b","severity":"low"},{"id":"c","severity":"low"}]}`)
	if d := diffSnapshots(base, base); !d.Identical || len(d.Added)+len(d.Removed)+len(d.Modified) != 0 {
		t.Fatalf("identical: %+v", d)
	}
	next := snapOf(t, `{"rules":[{"id":"a","severity":"critical","name":"A2"},{"id":"b","severity":"low"},{"id":"d","severity":"low"}]}`)
	d := diffSnapshots(base, next)
	if d.Identical || len(d.Added) != 1 || d.Added[0].ID != "d" || len(d.Removed) != 1 || d.Removed[0].ID != "c" || len(d.Modified) != 1 {
		t.Fatalf("diff: %+v", d)
	}
	m := d.Modified[0]
	if m.ID != "a" || len(m.Fields) != 2 || len(m.Highlight) != 1 || m.Highlight[0] != "severity" {
		t.Fatalf("modified: %+v", m)
	}
}

func TestHistoryCapAndRecord(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.contentversions.json")
	vs := newContentVersionStore(p, 3)
	now := time.Now()
	for i := 0; i < 5; i++ {
		s := snapOf(t, `{"rules":[{"id":"a","n":`+string(rune('0'+i))+`}]}`)
		if _, added := vs.Record(s, now, "b"); !added {
			t.Fatal("expected add")
		}
		if _, added := vs.Record(s, now, "b"); added {
			t.Fatal("identical snapshot must not be re-recorded")
		}
	}
	l := vs.list()
	if len(l) != 3 || l[0].Seq != 3 || l[2].Seq != 5 {
		t.Fatalf("cap: %+v", len(l))
	}
	re := newContentVersionStore(p, 3) // reload from disk
	if len(re.list()) != 3 || re.NextSeq != 6 {
		t.Fatalf("reload: %d next=%d", len(re.list()), re.NextSeq)
	}
}

func TestContentVersionEndpoints(t *testing.T) {
	st, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterContentVersionsAndBlindspots(mux, "tok", st)
	get := func(u string) (int, map[string]any) {
		r := httptest.NewRequest("GET", u, nil)
		r.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	if c, m := get("/v1/content/versions"); c != 200 || m["count"].(float64) != 1 {
		t.Fatalf("versions %d %v", c, m["count"])
	}
	if c, m := get("/v1/content/changes"); c != 200 || m["message"] != "no earlier snapshot" {
		t.Fatalf("changes %d %v", c, m)
	}
	if c, m := get("/v1/content/changelog"); c != 200 || m["message"] != "no earlier snapshot" {
		t.Fatalf("changelog %d %v", c, m)
	}
	if c, _ := get("/v1/coverage/telemetry"); c != 200 {
		t.Fatalf("telemetry %d", c)
	}
	if c, m := get("/v1/coverage/blindspots?validation=0"); c != 200 || m["collection_gaps"] == nil {
		t.Fatalf("blindspots %d", c)
	}
	r := httptest.NewRequest("GET", "/v1/content/versions", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatal("expected auth required")
	}
}
