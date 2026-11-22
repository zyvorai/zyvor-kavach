// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestContentManifestSnapshotsDiffSign(t *testing.T) {
	st, err := testStore(t, filepath.Join(t.TempDir(), "f.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterContentManifest(mux, "tok", st)
	do := func(method, u, auth, body string) (int, map[string]any) {
		r := httptest.NewRequest(method, u, strings.NewReader(body))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	if c, _ := do("GET", "/v1/content/manifest", "", ""); c != 401 {
		t.Fatalf("unauth manifest %d", c)
	}
	t.Setenv(contentSignKeyEnv, "k1")
	c, m := do("GET", "/v1/content/manifest", "tok", "")
	if c != 200 || m["signed"] != true {
		t.Fatalf("manifest %d %v", c, m["signed"])
	}
	mf := m["manifest"].(map[string]any)
	if int(mf["rule_count"].(float64)) < 1000 || len(mf["packs"].([]any)) < 10 {
		t.Fatalf("manifest too small")
	}
	mac := hmac.New(sha256.New, []byte("k1"))
	mac.Write([]byte(m["manifest_sha256"].(string)))
	if m["signature"].(map[string]any)["value"] != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("bad signature")
	}
	if c, _ := do("POST", "/v1/content/snapshots", "other", "{}"); c != 401 && c != 403 {
		t.Fatalf("non-admin snapshot %d", c)
	}
	if c, _ := do("POST", "/v1/content/snapshots", "tok", strings.Repeat("x", 5000)); c != 400 {
		t.Fatalf("oversize body %d", c)
	}
	if c, s := do("POST", "/v1/content/snapshots", "tok", `{"label":"a"}`); c != 201 || s["seq"].(float64) != 1 {
		t.Fatalf("snapshot %d %v", c, s)
	}
	if _, d := do("GET", "/v1/content/diff?from=1", "tok", ""); d["diff"].(map[string]any)["identical"] != true {
		t.Fatalf("expected identical: %v", d)
	}
	if c, _ := do("GET", "/v1/content/diff?from=99", "tok", ""); c != 404 {
		t.Fatalf("unknown from %d", c)
	}
}

func TestDiffManifestRulesFields(t *testing.T) {
	a := []ManifestRule{{ID: "a", Hash: "1", Sev: "s1", Match: "m", Attack: "t", Enabled: "e"}, {ID: "gone", Hash: "x"}}
	b := []ManifestRule{{ID: "a", Hash: "2", Sev: "s2", Match: "m2", Attack: "t", Enabled: "e2"}, {ID: "new", Hash: "y"}}
	d := diffManifestRules(a, b)
	if len(d.Added) != 1 || len(d.Removed) != 1 || len(d.Changed) != 1 || strings.Join(d.Changed[0].Changed, ",") != "severity,patterns,enabled_state" {
		t.Fatalf("%+v", d)
	}
}
