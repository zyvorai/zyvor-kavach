// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
)

// RiskScore is a heuristic (not ML-trained) score for analyst assist.
type RiskScore struct {
	Score      int      `json:"score"`
	Level      string   `json:"level"`
	Factors    []string `json:"factors"`
	Assistive  bool     `json:"assistive"`
	LLMNote    string   `json:"llm_note,omitempty"`
	ComputedAt time.Time `json:"computed_at"`
}

func ScoreFinding(f Finding) RiskScore {
	score := 20
	factors := []string{}
	switch f.Severity {
	case "high":
		score += 40
		factors = append(factors, "severity:high")
	case "medium":
		score += 20
		factors = append(factors, "severity:medium")
	case "low":
		score += 5
	}
	switch f.Rule {
	case "shell-network-redirection", "download-execute", "lolbin-netcat-shell", "download-chmod-execute", "ransomware-burst":
		score += 25
		factors = append(factors, "rule:"+f.Rule)
	case "mass-file-activity", "ransomware-extension-burst", "netra-denied-process":
		score += 15
		factors = append(factors, "rule:"+f.Rule)
	default:
		factors = append(factors, "rule:"+f.Rule)
	}
	if f.Evidence.UID == 0 {
		score += 10
		factors = append(factors, "uid:root")
	}
	if score > 100 {
		score = 100
	}
	level := "low"
	if score >= 70 {
		level = "critical"
	} else if score >= 50 {
		level = "high"
	} else if score >= 30 {
		level = "medium"
	}
	rs := RiskScore{Score: score, Level: level, Factors: factors, Assistive: true, ComputedAt: time.Now().UTC()}
	if os.Getenv("KAVACH_LLM_URL") != "" {
		rs.LLMNote = triageStub(f)
	}
	return rs
}

func triageStub(f Finding) string {
	// Optional LLM call; fails soft to a local note so demos never hang.
	url := os.Getenv("KAVACH_LLM_URL")
	if url == "" {
		return ""
	}
	body, _ := json.Marshal(map[string]string{
		"prompt": "Summarize this Kavach finding for an analyst in one sentence: " + f.Description + " rule=" + f.Rule,
	})
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "LLM unreachable; use heuristic score only."
	}
	req.Header.Set("Content-Type", "application/json")
	if key := os.Getenv("KAVACH_LLM_API_KEY"); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "LLM unreachable; use heuristic score only."
	}
	defer resp.Body.Close()
	var out struct {
		Text string `json:"text"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || out.Text == "" {
		return "Assistive triage: review process tree and Netra correlation for " + f.Rule + "."
	}
	return out.Text
}

func RegisterAIRoutes(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ai/score", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 && !validSession(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		id := r.URL.Query().Get("id")
		var found *Finding
		for _, f := range store.List() {
			if f.ID == id {
				x := f
				found = &x
				break
			}
		}
		if found == nil {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ScoreFinding(*found))
	})
	mux.HandleFunc("GET /v1/ai/scores", func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 && !validSession(r, token) {
			http.Error(w, "unauthorized", 401)
			return
		}
		out := []map[string]any{}
		for _, f := range store.List() {
			s := ScoreFinding(f)
			out = append(out, map[string]any{"finding_id": f.ID, "score": s})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
}
