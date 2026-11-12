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

func TestSectorsPlatformRoutes(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterSectorsPlatform(mux, "test-token-sectors1", store, nil)

	paths := []string{
		"/v1/sectors/modules", "/v1/sectors/summary",
		"/v1/sectors/railways", "/v1/sectors/rail-signaling", "/v1/sectors/stations",
		"/v1/sectors/passenger-apps", "/v1/sectors/freight", "/v1/sectors/metro",
		"/v1/sectors/gov-portals", "/v1/sectors/ministries", "/v1/sectors/e-office",
		"/v1/sectors/digital-id", "/v1/sectors/tax", "/v1/sectors/customs",
		"/v1/sectors/elections", "/v1/sectors/courts", "/v1/sectors/postal",
		"/v1/sectors/cert-in", "/v1/sectors/power", "/v1/sectors/scada",
		"/v1/sectors/oil-gas", "/v1/sectors/telecom", "/v1/sectors/spectrum",
		"/v1/sectors/aviation", "/v1/sectors/airports", "/v1/sectors/flights",
		"/v1/sectors/airlines", "/v1/sectors/atc-it", "/v1/sectors/baggage",
		"/v1/sectors/air-cargo", "/v1/sectors/airport-security", "/v1/sectors/fids",
		"/v1/sectors/ground-handling", "/v1/sectors/dgca",
		"/v1/sectors/ports", "/v1/sectors/highways",
		"/v1/sectors/transport-reg", "/v1/sectors/health", "/v1/sectors/pharma",
		"/v1/sectors/education", "/v1/sectors/smart-city", "/v1/sectors/water",
		"/v1/sectors/space", "/v1/sectors/defence-civil", "/v1/sectors/defence",
		"/v1/sectors/defence-portals", "/v1/sectors/border", "/v1/sectors/coast-guard",
		"/v1/sectors/paramilitary", "/v1/sectors/drdo-labs", "/v1/sectors/cantonment",
		"/v1/sectors/critical-sites", "/v1/sectors/citizen-services", "/v1/sectors/events",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer test-token-sectors1")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s -> %d %s", p, rec.Code, rec.Body.String())
		}
	}

	body, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "portal_anomaly", "sector": "government", "severity": "high"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/sectors/events", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token-sectors1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("ingest -> %d %s", rec.Code, rec.Body.String())
	}

	sum := sectorSummary(store, nil)
	if sum["enforce"] != false {
		t.Fatal("sectors must remain observe-only")
	}
	if len(SectorModules()) < 40 {
		t.Fatalf("modules=%d", len(SectorModules()))
	}
	if len(sectorAirports()) < 5 {
		t.Fatalf("airports=%d", len(sectorAirports()))
	}
}
