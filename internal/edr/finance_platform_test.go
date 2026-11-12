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
		"/v1/finance/nbfc", "/v1/finance/insurance", "/v1/finance/mutual-funds",
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
	if len(FinanceModules()) < 20 {
		t.Fatalf("modules=%d", len(FinanceModules()))
	}
}
