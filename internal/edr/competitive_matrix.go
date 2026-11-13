// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

//go:embed competitive_matrix.json
var competitiveMatrixRaw []byte

// CompetitiveMatrix is the competitor capability matrix and backlog. It is
// research data from public documentation and may be out of date.
type CompetitiveMatrix struct {
	LastResearched string                           `json:"last_researched"`
	Note           string                           `json:"note"`
	StatusValues   []string                         `json:"status_values"`
	Products       []map[string]string              `json:"products"`
	Areas          []map[string]string              `json:"areas"`
	Matrix         map[string]map[string]MatrixCell `json:"matrix"`
	Backlog        []BacklogItem                    `json:"backlog"`
	Sources        []MatrixSource                   `json:"sources"`
}

// MatrixCell is one honest capability cell.
type MatrixCell struct {
	Status   string   `json:"status"`
	Verified bool     `json:"verified"`
	Note     string   `json:"note"`
	Sources  []string `json:"sources"`
}

// BacklogItem is one candidate observation-only feature.
type BacklogItem struct {
	ID                  int    `json:"id"`
	Title               string `json:"title"`
	What                string `json:"what"`
	Competitors         string `json:"competitors"`
	Why                 string `json:"why"`
	DataNeeded          string `json:"data_needed"`
	TelemetrySufficient string `json:"telemetry_sufficient"`
	Effort              string `json:"effort"`
	Risk                string `json:"risk"`
	Conflicts           string `json:"conflicts_with_observation_only"`
}

// MatrixSource records where a competitor claim came from.
type MatrixSource struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	URL      string `json:"url"`
	Accessed string `json:"accessed"`
}

var (
	competitiveOnce sync.Once
	competitiveVal  *CompetitiveMatrix
	competitiveErr  error
)

// LoadCompetitiveMatrix parses and validates the embedded matrix.
func LoadCompetitiveMatrix() (*CompetitiveMatrix, error) {
	competitiveOnce.Do(func() {
		var m CompetitiveMatrix
		if err := json.Unmarshal(competitiveMatrixRaw, &m); err != nil {
			competitiveErr = err
			return
		}
		if err := m.validate(); err != nil {
			competitiveErr = err
			return
		}
		competitiveVal = &m
	})
	return competitiveVal, competitiveErr
}

func (m *CompetitiveMatrix) validate() error {
	if m.LastResearched == "" || m.Note == "" {
		return fmt.Errorf("last_researched and note required")
	}
	allowed := map[string]bool{}
	for _, s := range m.StatusValues {
		allowed[s] = true
	}
	srcs := map[string]bool{}
	for _, s := range m.Sources {
		if s.ID == "" || s.URL == "" || s.Accessed == "" {
			return fmt.Errorf("source %q needs id, url, accessed", s.ID)
		}
		srcs[s.ID] = true
	}
	for _, a := range m.Areas {
		row, ok := m.Matrix[a["id"]]
		if !ok {
			return fmt.Errorf("missing row %s", a["id"])
		}
		for _, p := range m.Products {
			c, ok := row[p["id"]]
			if !ok {
				return fmt.Errorf("missing cell %s/%s", a["id"], p["id"])
			}
			if !allowed[c.Status] {
				return fmt.Errorf("cell %s/%s: invalid status %q", a["id"], p["id"], c.Status)
			}
			if p["id"] != "kavach" && c.Verified && len(c.Sources) == 0 {
				return fmt.Errorf("cell %s/%s: verified without source", a["id"], p["id"])
			}
			for _, s := range c.Sources {
				if !srcs[s] {
					return fmt.Errorf("cell %s/%s: unknown source %s", a["id"], p["id"], s)
				}
			}
		}
	}
	if k := m.Matrix["response"]["kavach"]; k.Status != "Out of scope by design" {
		return fmt.Errorf("kavach response must be out of scope by design")
	}
	if len(m.Backlog) < 25 {
		return fmt.Errorf("backlog needs at least 25 items, have %d", len(m.Backlog))
	}
	for _, b := range m.Backlog {
		if b.Title == "" || b.What == "" || b.DataNeeded == "" || b.Conflicts == "" {
			return fmt.Errorf("backlog item %d incomplete", b.ID)
		}
		if b.Effort != "S" && b.Effort != "M" && b.Effort != "L" {
			return fmt.Errorf("backlog item %d: bad effort %q", b.ID, b.Effort)
		}
	}
	return nil
}

// RegisterCompetitive serves the competitive matrix (read-only research data).
func RegisterCompetitive(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/world/competitive", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		m, err := LoadCompetitiveMatrix()
		if err != nil {
			http.Error(w, "competitive matrix unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
	})
}
