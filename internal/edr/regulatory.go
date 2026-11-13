// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Regional incident-reporting clocks (observation only).
//
//   - The catalog (regulatory_regimes.json, embedded) lists breach/incident notification regimes.
//     Entries whose rules could not be confirmed against an official source carry verified=false.
//   - The customer chooses applicable regimes via PUT /v1/regulatory/profile, persisted in
//     <store>.regulatory.json.
//   - Clocks are computed the same way as the CERT-In clock: open high/critical findings measured
//     from first detection. Real regimes often start at awareness, classification or a materiality
//     determination, so first detection is a proxy only.
//   - Kavach never files or notifies anything. Output is informational, not legal advice.

//go:embed regulatory_regimes.json
var regulatoryCatalogJSON []byte

const regulatoryDisclaimer = "Informational, not legal advice; Kavach does not file reports. Verify every rule with the regulator or counsel."

// RegStage is one reporting step of a regime.
type RegStage struct {
	Name         string `json:"name"`
	Hours        int    `json:"hours"`
	BusinessDays int    `json:"business_days"`
	FromStart    bool   `json:"from_start"`
	Description  string `json:"description"`
}

// RegRegime is one catalog entry.
type RegRegime struct {
	ID             string     `json:"id"`
	Jurisdiction   string     `json:"jurisdiction"`
	Regulator      string     `json:"regulator"`
	Name           string     `json:"name"`
	Trigger        string     `json:"trigger"`
	StartEvent     string     `json:"start_event"`
	AppliesTo      string     `json:"applies_to"`
	Stages         []RegStage `json:"stages"`
	SourceURL      string     `json:"source_url"`
	SourceKind     string     `json:"source_kind"`
	LastVerified   string     `json:"last_verified"`
	LastResearched string     `json:"last_researched"`
	Verified       bool       `json:"verified"`
	Notes          string     `json:"notes"`
}

type regCatalog struct {
	Disclaimer string      `json:"disclaimer"`
	Regimes    []RegRegime `json:"regimes"`
}

var regStartEvents = map[string]bool{"awareness": true, "discovery": true, "classification": true, "materiality_determination": true, "reasonable_belief": true, "assessment": true}
var regSourceKinds = map[string]bool{"official_fetched": true, "official_unfetched": true, "secondary": true}

// LoadRegulatoryCatalog parses and validates catalog JSON.
func LoadRegulatoryCatalog(raw []byte) ([]RegRegime, error) {
	var c regCatalog
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i, r := range c.Regimes {
		p := fmt.Sprintf("regime %d (%q)", i, r.ID)
		switch {
		case r.ID == "" || seen[r.ID]:
			return nil, fmt.Errorf("%s: id empty or duplicate", p)
		case r.Jurisdiction == "" || r.Regulator == "" || r.Name == "" || r.Trigger == "" || r.AppliesTo == "":
			return nil, fmt.Errorf("%s: missing jurisdiction, regulator, name, trigger or applies_to", p)
		case !regStartEvents[r.StartEvent]:
			return nil, fmt.Errorf("%s: bad start_event %q", p, r.StartEvent)
		case !strings.HasPrefix(r.SourceURL, "https://"):
			return nil, fmt.Errorf("%s: source_url must be https", p)
		case !regSourceKinds[r.SourceKind]:
			return nil, fmt.Errorf("%s: bad source_kind %q", p, r.SourceKind)
		case len(r.Stages) == 0:
			return nil, fmt.Errorf("%s: no stages", p)
		}
		if _, err := time.Parse("2006-01-02", r.LastResearched); err != nil {
			return nil, fmt.Errorf("%s: last_researched: %v", p, err)
		}
		if r.Verified {
			if _, err := time.Parse("2006-01-02", r.LastVerified); err != nil {
				return nil, fmt.Errorf("%s: verified entries need a last_verified date", p)
			}
			if r.SourceKind != "official_fetched" {
				return nil, fmt.Errorf("%s: verified entries need source_kind official_fetched", p)
			}
		} else if r.LastVerified != "" {
			return nil, fmt.Errorf("%s: unverified entries must not carry last_verified", p)
		} else if !strings.Contains(r.Notes, "UNVERIFIED") {
			return nil, fmt.Errorf("%s: unverified entries must say UNVERIFIED in notes", p)
		}
		for j, s := range r.Stages {
			if s.Name == "" || s.Description == "" || s.Hours < 0 || s.BusinessDays < 0 || (s.Hours > 0 && s.BusinessDays > 0) {
				return nil, fmt.Errorf("%s stage %d: invalid", p, j)
			}
		}
		seen[r.ID] = true
	}
	return c.Regimes, nil
}

var (
	regCatOnce sync.Once
	regCat     []RegRegime
	regCatErr  error
)

// RegulatoryRegimes returns the embedded catalog.
func RegulatoryRegimes() ([]RegRegime, error) {
	regCatOnce.Do(func() { regCat, regCatErr = LoadRegulatoryCatalog(regulatoryCatalogJSON) })
	return regCat, regCatErr
}

// addBusinessDays skips Saturdays and Sundays (no holiday calendar).
func addBusinessDays(t time.Time, n int) time.Time {
	for n > 0 {
		t = t.Add(24 * time.Hour)
		if wd := t.Weekday(); wd != time.Saturday && wd != time.Sunday {
			n--
		}
	}
	return t
}

// stageDeadline returns the deadline from a start time and whether it is computable.
func stageDeadline(s RegStage, start time.Time) (time.Time, bool) {
	if !s.FromStart {
		return time.Time{}, false
	}
	switch {
	case s.Hours > 0:
		return start.Add(time.Duration(s.Hours) * time.Hour), true
	case s.BusinessDays > 0:
		return addBusinessDays(start, s.BusinessDays), true
	}
	return time.Time{}, false
}

// RegProfile is the persisted regime selection.
type RegProfile struct {
	Regimes   []string  `json:"regimes"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

type regService struct {
	mu      sync.Mutex
	path    string
	profile RegProfile
}

func (s *regService) load() {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var p RegProfile
	if json.Unmarshal(b, &p) == nil {
		s.profile = p
	}
}

func (s *regService) saveLocked() error {
	b, err := json.MarshalIndent(s.profile, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// BuildRegulatoryClocks computes per-regime stage clocks for open high/critical findings.
func BuildRegulatoryClocks(regimes []RegRegime, ids []string, store *Store, inc *IncidentStore, now time.Time) []map[string]any {
	entries := certInClock(store, inc, now)
	byID := map[string]RegRegime{}
	for _, r := range regimes {
		byID[r.ID] = r
	}
	out := []map[string]any{}
	for _, id := range ids {
		r, ok := byID[id]
		if !ok {
			continue
		}
		stages := []map[string]any{}
		for _, st := range r.Stages {
			row := map[string]any{"name": st.Name, "hours": st.Hours, "business_days": st.BusinessDays, "description": st.Description}
			_, computable := stageDeadline(st, now)
			row["computable"] = computable
			list := []map[string]any{}
			if computable {
				for _, e := range entries {
					dl, _ := stageDeadline(st, e.FirstDetected)
					rem := int64(dl.Sub(now).Seconds())
					list = append(list, map[string]any{"finding_id": e.FindingID, "rule": e.Rule, "host": e.Host, "severity": e.Severity,
						"status": e.Status, "first_detected": e.FirstDetected, "deadline": dl.UTC(), "remaining_seconds": rem, "overdue": rem < 0})
				}
				sort.Slice(list, func(i, j int) bool { return list[i]["remaining_seconds"].(int64) < list[j]["remaining_seconds"].(int64) })
			}
			row["incidents"] = list
			stages = append(stages, row)
		}
		out = append(out, map[string]any{"regime": r.ID, "name": r.Name, "jurisdiction": r.Jurisdiction, "verified": r.Verified,
			"start_event": r.StartEvent, "start_proxy": "first detection of the finding (conservative proxy; the legal start event is " + r.StartEvent + ")",
			"stages": stages, "notes": r.Notes, "source_url": r.SourceURL})
	}
	return out
}

// RegisterRegulatory wires the regional reporting-clock endpoints.
func RegisterRegulatory(mux *http.ServeMux, token string, store *Store, inc *IncidentStore) {
	svc := &regService{path: store.path + ".regulatory.json"}
	svc.load()
	known := func() (map[string]bool, []RegRegime, error) {
		rs, err := RegulatoryRegimes()
		m := map[string]bool{}
		for _, r := range rs {
			m[r.ID] = true
		}
		return m, rs, err
	}
	mux.HandleFunc("GET /v1/regulatory/regimes", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		_, rs, err := known()
		if err != nil {
			customJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		q := r.URL.Query()
		out := []RegRegime{}
		for _, x := range rs {
			if j := q.Get("jurisdiction"); j != "" && !strings.EqualFold(x.Jurisdiction, j) {
				continue
			}
			if (q.Get("verified") == "true" && !x.Verified) || (q.Get("verified") == "false" && x.Verified) {
				continue
			}
			out = append(out, x)
		}
		customJSON(w, 200, map[string]any{"count": len(out), "regimes": out, "informational": true, "disclaimer": regulatoryDisclaimer})
	})
	mux.HandleFunc("GET /v1/regulatory/profile", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		svc.mu.Lock()
		p := svc.profile
		svc.mu.Unlock()
		if p.Regimes == nil {
			p.Regimes = []string{}
		}
		customJSON(w, 200, map[string]any{"profile": p, "informational": true, "disclaimer": regulatoryDisclaimer})
	})
	mux.HandleFunc("PUT /v1/regulatory/profile", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
		var in struct {
			Regimes []string `json:"regimes"`
		}
		if err != nil || json.Unmarshal(b, &in) != nil || in.Regimes == nil {
			customJSON(w, 400, map[string]any{"error": "invalid JSON body {regimes: [id...]}"})
			return
		}
		m, _, cerr := known()
		if cerr != nil {
			customJSON(w, 500, map[string]any{"error": cerr.Error()})
			return
		}
		seen := map[string]bool{}
		clean := []string{}
		for _, id := range in.Regimes {
			if !m[id] {
				customJSON(w, 400, map[string]any{"error": "unknown regime id " + id})
				return
			}
			if !seen[id] {
				seen[id] = true
				clean = append(clean, id)
			}
		}
		by := "session"
		if admin {
			by = "admin"
		}
		svc.mu.Lock()
		svc.profile = RegProfile{Regimes: clean, UpdatedAt: time.Now().UTC(), UpdatedBy: by}
		err = svc.saveLocked()
		p := svc.profile
		svc.mu.Unlock()
		if err != nil {
			customJSON(w, 500, map[string]any{"error": "could not persist profile"})
			return
		}
		customJSON(w, 200, map[string]any{"status": "saved", "profile": p, "informational": true, "disclaimer": regulatoryDisclaimer})
	})
	mux.HandleFunc("GET /v1/regulatory/clocks", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		m, rs, err := known()
		if err != nil {
			customJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		var ids []string
		if q := r.URL.Query().Get("regime"); q != "" {
			for _, id := range strings.Split(q, ",") {
				id = strings.TrimSpace(id)
				if !m[id] {
					customJSON(w, 400, map[string]any{"error": "unknown regime id " + id})
					return
				}
				ids = append(ids, id)
			}
		} else {
			svc.mu.Lock()
			ids = append(ids, svc.profile.Regimes...)
			svc.mu.Unlock()
		}
		t := time.Now().UTC()
		customJSON(w, 200, map[string]any{"generated_at": t, "regimes": BuildRegulatoryClocks(rs, ids, store, inc, t),
			"informational": true, "disclaimer": regulatoryDisclaimer, "note": "Kavach does not file reports; clocks run from first detection as a proxy."})
	})
}
