// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestFinancePlatformRoutes(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFinancePlatform(mux, "test-token-finance1", store, nil)

	paths := []string{
		"/v1/finance/modules", "/v1/finance/summary", "/v1/finance/institutions",
		"/v1/finance/exchanges", "/v1/finance/markets", "/v1/finance/trading-desks",
		"/v1/finance/workstations", "/v1/finance/algo", "/v1/finance/market-data",
		"/v1/finance/payment-rails", "/v1/finance/upi", "/v1/finance/cards",
		"/v1/finance/swift", "/v1/finance/treasury", "/v1/finance/core-banking",
		"/v1/finance/branches", "/v1/finance/atms", "/v1/finance/fraud",
		"/v1/finance/insider", "/v1/finance/sanctions", "/v1/finance/kyc",
		"/v1/finance/pci", "/v1/finance/rbi", "/v1/finance/sebi",
		"/v1/finance/nbfc", "/v1/finance/insurance", "/v1/finance/insurance-lines",
		"/v1/finance/insurance-tpa", "/v1/finance/reinsurance", "/v1/finance/irdai",
		"/v1/finance/motor-insurance", "/v1/finance/mutual-funds",
		"/v1/finance/events",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer test-token-finance1")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s -> %d %s", p, rec.Code, rec.Body.String())
		}
	}

	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "card_velocity", "place": "Connaught Place", "severity": "high"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/finance/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token-finance1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ingest -> %d %s", rec.Code, rec.Body.String())
	}

	sum := financeSummary(store, nil)
	if sum["enforce"] != false {
		t.Fatal("finance must remain observe-only")
	}
	if len(FinanceModules()) < 25 {
		t.Fatalf("modules=%d", len(FinanceModules()))
	}
	if len(financeInsuranceLines()) < 4 {
		t.Fatalf("insurance-lines=%d", len(financeInsuranceLines()))
	}
}

func TestFinanceInsuranceSurface(t *testing.T) {
	if len(financeInsurance()) < 5 {
		t.Fatalf("insurance=%d", len(financeInsurance()))
	}
	if len(financeInsuranceLines()) < 4 {
		t.Fatalf("insurance-lines=%d", len(financeInsuranceLines()))
	}
	if len(financeInsuranceTPA()) < 3 {
		t.Fatalf("insurance-tpa=%d", len(financeInsuranceTPA()))
	}
	if len(financeReinsurance()) < 2 {
		t.Fatalf("reinsurance=%d", len(financeReinsurance()))
	}
	if len(financeIRDAI()) < 3 {
		t.Fatalf("irdai=%d", len(financeIRDAI()))
	}
	if len(financeMotorInsurance()) < 3 {
		t.Fatalf("motor-insurance=%d", len(financeMotorInsurance()))
	}

	store, err := NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	sum := financeSummary(store, nil)
	if sum["enforce"] != false {
		t.Fatal("insurance surface must stay observe-only")
	}
	if sum["insurance"] == nil || sum["insurance_lines"] == nil {
		t.Fatalf("summary missing insurance tallies: %#v", sum)
	}

	mods := FinanceModules()
	wantIDs := map[string]bool{
		"insurance": false, "insurance-lines": false, "insurance-tpa": false,
		"reinsurance": false, "irdai": false, "motor-insurance": false,
	}
	for _, m := range mods {
		if _, ok := wantIDs[m.ID]; ok {
			wantIDs[m.ID] = true
		}
	}
	for id, ok := range wantIDs {
		if !ok {
			t.Fatalf("missing finance module %s", id)
		}
	}

	claims := listFinanceEvents("claims_burst")
	if len(claims) < 1 {
		t.Fatal("expected claims_burst seed event")
	}
	motor := listFinanceEvents("motor_fnol_anomaly")
	if len(motor) < 1 {
		t.Fatal("expected motor_fnol_anomaly seed event")
	}

	mux := http.NewServeMux()
	RegisterFinancePlatform(mux, "test-token-finance1", store, nil)
	for _, p := range []string{
		"/v1/finance/insurance", "/v1/finance/insurance-lines", "/v1/finance/insurance-tpa",
		"/v1/finance/reinsurance", "/v1/finance/irdai", "/v1/finance/motor-insurance",
	} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer test-token-finance1")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s -> %d", p, rec.Code)
		}
		var rows []map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
			t.Fatalf("%s decode: %v", p, err)
		}
		if len(rows) < 2 {
			t.Fatalf("%s empty inventory", p)
		}
	}
}
