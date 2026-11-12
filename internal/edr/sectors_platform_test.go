// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
		"/v1/sectors/transport-reg", "/v1/sectors/gov-vehicles", "/v1/sectors/public-vehicles",
		"/v1/sectors/city-buses", "/v1/sectors/brts", "/v1/sectors/taxis-cabs",
		"/v1/sectors/autos-rickshaw", "/v1/sectors/school-buses", "/v1/sectors/municipal-fleet",
		"/v1/sectors/intercity-coaches", "/v1/sectors/ferries",
		"/v1/sectors/automotive",
		"/v1/sectors/ev-charging", "/v1/sectors/vehicle-oem", "/v1/sectors/dealers",
		"/v1/sectors/manufacturing", "/v1/sectors/industrial-parks", "/v1/sectors/steel-cement",
		"/v1/sectors/electronics-mfg", "/v1/sectors/textiles",
		"/v1/sectors/health", "/v1/sectors/pharma",
		"/v1/sectors/education", "/v1/sectors/smart-city", "/v1/sectors/water",
		"/v1/sectors/space", "/v1/sectors/isro-centers", "/v1/sectors/launch-range",
		"/v1/sectors/ground-stations", "/v1/sectors/space-research", "/v1/sectors/nsil-antrix",
		"/v1/sectors/defence-civil", "/v1/sectors/defence",
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
	if len(SectorModules()) < 60 {
		t.Fatalf("modules=%d", len(SectorModules()))
	}
	if len(sectorAirports()) < 5 {
		t.Fatalf("airports=%d", len(sectorAirports()))
	}
	if len(sectorISROCenters()) < 5 {
		t.Fatalf("isro=%d", len(sectorISROCenters()))
	}
	if len(sectorGovVehicles()) < 4 {
		t.Fatalf("gov-vehicles=%d", len(sectorGovVehicles()))
	}
	if len(sectorCityBuses()) < 5 {
		t.Fatalf("city-buses=%d", len(sectorCityBuses()))
	}
	if len(sectorPublicVehicles()) < 8 {
		t.Fatalf("public-vehicles=%d", len(sectorPublicVehicles()))
	}
}

func TestSectorsPublicVehiclesInventory(t *testing.T) {
	checks := []struct {
		name string
		fn   func() []map[string]any
		min  int
		key  string
	}{
		{"gov-vehicles", sectorGovVehicles, 6, "fleet"},
		{"public-vehicles", sectorPublicVehicles, 8, "domain"},
		{"city-buses", sectorCityBuses, 6, "fleet"},
		{"brts", sectorBRTS, 4, "corridor"},
		{"taxis-cabs", sectorTaxisCabs, 4, "fleet"},
		{"autos-rickshaw", sectorAutosRickshaw, 3, "fleet"},
		{"school-buses", sectorSchoolBuses, 3, "fleet"},
		{"municipal-fleet", sectorMunicipalFleet, 4, "fleet"},
		{"intercity-coaches", sectorIntercityCoaches, 4, "fleet"},
		{"ferries", sectorFerries, 4, "fleet"},
	}
	for _, c := range checks {
		rows := c.fn()
		if len(rows) < c.min {
			t.Fatalf("%s rows=%d want>=%d", c.name, len(rows), c.min)
		}
		foundKey, foundNote := false, false
		for _, row := range rows {
			if _, ok := row[c.key]; ok {
				foundKey = true
			}
			if n, ok := row["note"].(string); ok && strings.Contains(strings.ToLower(n), "never") {
				foundNote = true
			}
		}
		if !foundKey {
			t.Fatalf("%s missing key %q", c.name, c.key)
		}
		if !foundNote {
			t.Fatalf("%s missing observe-only note", c.name)
		}
	}

	sum := sectorSummary(nil, nil)
	for _, k := range []string{"public_vehicles", "city_buses", "gov_vehicles", "enforce"} {
		if _, ok := sum[k]; !ok {
			t.Fatalf("summary missing %s", k)
		}
	}
	if sum["enforce"] != false {
		t.Fatal("public vehicles surface must stay observe-only")
	}

	ev := listSectorEvents("city-buses")
	if len(ev) < 1 {
		t.Fatal("expected city-buses seed event")
	}
	ev = listSectorEvents("taxis-cabs")
	if len(ev) < 1 {
		t.Fatal("expected taxis-cabs seed event")
	}
	ev = listSectorEvents("ferries")
	if len(ev) < 1 {
		t.Fatal("expected ferries seed event")
	}
}

func TestSectorsIndustryAndSpaceInventory(t *testing.T) {
	if len(sectorAutomotive()) < 4 {
		t.Fatalf("automotive=%d", len(sectorAutomotive()))
	}
	if len(sectorEVCharging()) < 3 {
		t.Fatalf("ev-charging=%d", len(sectorEVCharging()))
	}
	if len(sectorVehicleOEM()) < 4 {
		t.Fatalf("vehicle-oem=%d", len(sectorVehicleOEM()))
	}
	if len(sectorDealers()) < 3 {
		t.Fatalf("dealers=%d", len(sectorDealers()))
	}
	if len(sectorIndustrialParks()) < 3 {
		t.Fatalf("industrial-parks=%d", len(sectorIndustrialParks()))
	}
	if len(sectorSteelCement()) < 2 {
		t.Fatalf("steel-cement=%d", len(sectorSteelCement()))
	}
	if len(sectorElectronicsMfg()) < 2 {
		t.Fatalf("electronics-mfg=%d", len(sectorElectronicsMfg()))
	}
	if len(sectorTextiles()) < 2 {
		t.Fatalf("textiles=%d", len(sectorTextiles()))
	}
	if len(sectorISROCenters()) < 6 {
		t.Fatalf("isro=%d", len(sectorISROCenters()))
	}
	if len(sectorLaunchRange()) < 3 {
		t.Fatalf("launch-range=%d", len(sectorLaunchRange()))
	}
	if len(sectorGroundStations()) < 3 {
		t.Fatalf("ground-stations=%d", len(sectorGroundStations()))
	}
	if len(sectorSpaceResearch()) < 2 {
		t.Fatalf("space-research=%d", len(sectorSpaceResearch()))
	}
	if len(sectorNSILAntrix()) < 2 {
		t.Fatalf("nsil-antrix=%d", len(sectorNSILAntrix()))
	}
	space := sectorSpace()
	if len(space) < 3 {
		t.Fatalf("space=%d", len(space))
	}

	sum := sectorSummary(nil, nil)
	if sum["oem_plants"] == nil || sum["isro_centers"] == nil || sum["manufacturing"] == nil {
		t.Fatalf("summary missing industry/space tallies: %#v", sum)
	}
}

func TestSectorsUnauthorized(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "findings.jsonl"), 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterSectorsPlatform(mux, "test-token-sectors1", store, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/sectors/public-vehicles", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatal("expected auth failure for public-vehicles")
	}
}
