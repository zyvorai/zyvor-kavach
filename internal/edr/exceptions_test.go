// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func (e *schedEnv) exp(t *testing.T, body string) string {
	t.Helper()
	c, m := e.call("POST", "/v1/exceptions", body, "tok")
	if c != 201 {
		t.Fatalf("create exception %d %v", c, m)
	}
	return m["id"].(string)
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func TestExceptionAuthAndValidation(t *testing.T) {
	e := newSchedEnv(t)
	ok := `{"rule":"seed-*","reason":"r","owner":"o","expires":"` + rfc(e.clk.Now().Add(time.Hour)) + `"}`
	if c, _ := e.call("POST", "/v1/exceptions", ok, ""); c != 401 {
		t.Fatal(c)
	}
	if c, _ := e.call("GET", "/v1/exceptions", "", ""); c != 401 {
		t.Fatal(c)
	}
	if c, _ := e.call("GET", "/v1/exceptions/suppressed", "", ""); c != 401 {
		t.Fatal(c)
	}
	for _, bad := range []string{
		`{"rule":"x","reason":"r","owner":"o"}`, // no expiry
		`{"rule":"x","reason":"r","owner":"o","expires":"` + rfc(e.clk.Now().Add(366*24*time.Hour)) + `"}`, // > 365d
		`{"rule":"x","reason":"r","owner":"o","expires":"` + rfc(e.clk.Now().Add(-time.Hour)) + `"}`,       // past
		`{"rule":"*","reason":"r","owner":"o","expires":"` + rfc(e.clk.Now().Add(time.Hour)) + `"}`,        // blanket
		`{"rule":"x","owner":"o","expires":"` + rfc(e.clk.Now().Add(time.Hour)) + `"}`,                     // no reason
		`{"rule":"x","reason":"r","expires":"` + rfc(e.clk.Now().Add(time.Hour)) + `"}`,                    // no owner
	} {
		if c, _ := e.call("POST", "/v1/exceptions", bad, "tok"); c != 400 {
			t.Fatalf("want 400 for %s got %d", bad, c)
		}
	}
	e.exp(t, ok)
	e.exp(t, `{"rule":"x","reason":"r","owner":"o","expires":"`+rfc(e.clk.Now().Add(365*24*time.Hour-time.Minute))+`"}`)
}

func TestExceptionSuppressesAndExpires(t *testing.T) {
	e := newSchedEnv(t)
	id := e.exp(t, `{"rule":"seed-rule","host":"web-*","path":"*/needle","reason":"known","owner":"soc","expires":"`+rfc(e.clk.Now().Add(time.Hour))+`"}`)
	e.seed(t, "s1", "seed-rule", "web-1", "/usr/bin/needle") // suppressed
	e.seed(t, "s2", "seed-rule", "db-1", "/usr/bin/needle")  // host differs
	e.seed(t, "s3", "seed-rule", "web-2", "/usr/bin/other")  // path differs
	e.seed(t, "s4", "other-rule", "web-1", "/usr/bin/needle")
	if n := len(e.st.List()); n != 3 {
		t.Fatalf("main list has %d findings, want 3", n)
	}
	_, sup := e.call("GET", "/v1/exceptions/suppressed", "", "tok")
	list := sup["suppressed"].([]any)
	if len(list) != 1 || sup["total_suppressed"].(float64) != 1 || sup["counts"].(map[string]any)[id].(float64) != 1 {
		t.Fatalf("suppressed %v", sup)
	}
	// persisted: the finding is also not in the on-disk findings ledger as reported
	e.clk.Add(2 * time.Hour)
	e.seed(t, "s5", "seed-rule", "web-1", "/usr/bin/needle")
	if n := len(e.st.List()); n != 4 {
		t.Fatalf("expired exception still suppressing: %d", n)
	}
	_, l := e.call("GET", "/v1/exceptions", "", "tok")
	ex := l["exceptions"].([]any)[0].(map[string]any)
	if ex["status"] != "expired" || l["chain"].(map[string]any)["ok"] != true {
		t.Fatalf("%v", l)
	}
	_, h := e.call("GET", "/v1/exceptions/history", "", "tok")
	acts := ""
	for _, x := range h["history"].([]any) {
		acts += x.(map[string]any)["action"].(string) + ","
	}
	if acts != "create,expire," {
		t.Fatalf("history actions %q", acts)
	}
	if _, l2 := e.call("GET", "/v1/exceptions?status=active", "", "tok"); l2["count"].(float64) != 0 {
		t.Fatal("status filter")
	}
}

func TestExceptionUpdateExpireDeleteChain(t *testing.T) {
	e := newSchedEnv(t)
	id := e.exp(t, `{"rule":"seed-rule","reason":"r","owner":"o","expires":"`+rfc(e.clk.Now().Add(time.Hour))+`"}`)
	if c, _ := e.call("PUT", "/v1/exceptions/"+id, `{"reason":"changed","expires":"`+rfc(e.clk.Now().Add(2*time.Hour))+`"}`, "tok"); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.call("PUT", "/v1/exceptions/"+id, `{"expires":"`+rfc(e.clk.Now().Add(400*24*time.Hour))+`"}`, "tok"); c != 400 {
		t.Fatal("update must keep the 365 day cap", c)
	}
	if c, _ := e.call("PUT", "/v1/exceptions/"+id, `{"reason":"x"}`, ""); c != 401 {
		t.Fatal(c)
	}
	if c, _ := e.call("PUT", "/v1/exceptions/"+id, `{"expire_now":true}`, "tok"); c != 200 {
		t.Fatal(c)
	}
	e.seed(t, "s1", "seed-rule", "h", "/x")
	if len(e.st.List()) != 1 {
		t.Fatal("manually expired exception still suppressing")
	}
	if c, _ := e.call("DELETE", "/v1/exceptions/"+id, "", "tok"); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.call("DELETE", "/v1/exceptions/"+id, "", "tok"); c != 404 {
		t.Fatal(c)
	}
	_, h := e.call("GET", "/v1/exceptions/history", "", "tok")
	if len(h["history"].([]any)) != 4 || h["chain_ok"] != true { // create, update, expire, delete
		t.Fatalf("%v", h)
	}
}

func TestExceptionHashChainTamperDetected(t *testing.T) {
	e := newSchedEnv(t)
	for i := 0; i < 3; i++ {
		e.exp(t, `{"rule":"r`+string(rune('a'+i))+`","reason":"r","owner":"o","expires":"`+rfc(e.clk.Now().Add(time.Hour))+`"}`)
	}
	// edit the middle entry on disk, reload, verify
	b, err := os.ReadFile(e.exc.path)
	if err != nil {
		t.Fatal(err)
	}
	var f exceptionFile
	if json.Unmarshal(b, &f) != nil {
		t.Fatal("bad file")
	}
	f.History[1].Detail = "rule=\"innocent\""
	nb, _ := json.Marshal(f)
	if os.WriteFile(e.exc.path, nb, 0600) != nil {
		t.Fatal("write")
	}
	exc2 := newExceptionService(e.exc.path, e.clk.Now)
	if ok, at := exc2.verifyLocked(); ok || at != 2 {
		t.Fatalf("tamper not detected: ok=%v at=%d", ok, at)
	}
	// a rewritten entry with a recomputed hash still breaks the next link
	f.History[1].Hash = excEntryHash(f.History[1])
	nb, _ = json.Marshal(f)
	_ = os.WriteFile(e.exc.path, nb, 0600)
	exc3 := newExceptionService(e.exc.path, e.clk.Now)
	if ok, at := exc3.verifyLocked(); ok || at != 3 {
		t.Fatalf("relink tamper not detected: ok=%v at=%d", ok, at)
	}
}

func TestExceptionsComposeWithScheduledDetections(t *testing.T) {
	e := newSchedEnv(t)
	e.addSearch("needle")
	e.seed(t, "a1", "seed-rule", "h1", "/bin/needle")
	id := e.create(t, "")
	e.exp(t, `{"rule":"hunt-`+id+`","reason":"r","owner":"o","expires":"`+rfc(e.clk.Now().Add(time.Hour))+`"}`)
	_, m := e.call("POST", "/v1/detections/scheduled/"+id+"/run", "", "tok")
	run := m["run"].(map[string]any)
	if run["suppressed"].(float64) != 1 || run["recorded"].(float64) != 0 || e.mainRules("hunt-"+id) != 0 {
		t.Fatalf("%v", m)
	}
}

func TestNoExceptionServiceIsNoop(t *testing.T) {
	excSvc.Store(nil)
	if exceptionSuppress(Finding{Rule: "x"}) {
		t.Fatal("hook must be a no-op by default")
	}
}
