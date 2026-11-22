// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// SARIF 2.1.0 export of one stored inspector report, for CI use. Pull-only: a
// client fetches it with GET; nothing is pushed anywhere. The export carries
// the findings, scoring factors and hashes already in the report (no input
// bytes). The artifact location is the client-supplied label reduced to a
// base name, or "sha256:<hash>" when there is none; it is never a local path.

import (
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strings"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
)

type sarifMsg struct {
	Text string `json:"text"`
}

// InspectSARIF builds a SARIF 2.1.0 log (as a generic map so the shape is exactly the spec's).
func InspectSARIF(r *InspectReport) map[string]any {
	uri := path.Base(strings.ReplaceAll(r.Name, "\\", "/"))
	if uri == "" || uri == "." || uri == "/" || strings.ContainsAny(uri, "\x00\r\n") {
		uri = "sha256:" + r.SHA256
	}
	ruleIdx := map[string]int{}
	var rules []map[string]any
	var results []map[string]any
	level := func(sev string) string {
		switch sev {
		case "critical", "high":
			return "error"
		case "medium":
			return "warning"
		}
		return "note"
	}
	for _, f := range r.Findings {
		idx, ok := ruleIdx[f.ID]
		if !ok {
			idx = len(rules)
			ruleIdx[f.ID] = idx
			rule := map[string]any{
				"id": f.ID, "name": f.ID, "shortDescription": sarifMsg{Text: f.Title},
				"defaultConfiguration": map[string]any{"level": level(f.Severity)},
				"properties":           map[string]any{"analyzer": f.Analyzer},
			}
			if f.Technique != "" {
				rule["properties"] = map[string]any{"analyzer": f.Analyzer, "tags": []string{f.Technique}}
				rule["helpUri"] = "https://attack.mitre.org/techniques/" + strings.ReplaceAll(f.Technique, ".", "/") + "/"
			}
			rules = append(rules, rule)
		}
		msg := f.Title
		if f.Evidence != "" {
			msg += ": " + f.Evidence
		}
		results = append(results, map[string]any{
			"ruleId": f.ID, "ruleIndex": idx, "level": level(f.Severity), "kind": "fail",
			"message": sarifMsg{Text: msg}, "rank": float64(f.Weight),
			"locations":           []map[string]any{{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": uri}}}},
			"partialFingerprints": map[string]string{"kavachFinding/v1": r.SHA256 + ":" + f.ID},
			"properties":          map[string]any{"severity": f.Severity, "weight": f.Weight, "analyzer": f.Analyzer, "technique": f.Technique},
		})
	}
	var notes []map[string]any
	errs := append([]string(nil), r.Errors...)
	sort.Strings(errs)
	for _, e := range errs {
		notes = append(notes, map[string]any{"level": "warning", "message": sarifMsg{Text: e}})
	}
	for _, l := range r.LimitsHit {
		notes = append(notes, map[string]any{"level": "note", "message": sarifMsg{Text: "limit reached: " + l}})
	}
	inv := map[string]any{"executionSuccessful": len(r.Errors) == 0}
	if len(notes) > 0 {
		inv["toolExecutionNotifications"] = notes
	}
	run := map[string]any{
		"tool": map[string]any{"driver": map[string]any{
			"name": "kavach-inspector", "semanticVersion": "1.0.0", "rules": rules,
			"informationUri": "https://zyvor.dev",
		}},
		"artifacts": []map[string]any{{
			"location": map[string]any{"uri": uri}, "length": r.Size,
			"hashes": map[string]string{"sha-256": r.SHA256},
		}},
		"results":     results,
		"invocations": []map[string]any{inv},
		"properties": map[string]any{
			"reportId": r.ID, "kind": r.Kind, "format": r.Format, "score": r.Score, "level": r.Level,
			"factors": r.Factors, "analyzers": r.Analyzers, "mode": r.Mode, "note": r.Note, "knownIocs": r.KnownIOCs,
		},
	}
	if results == nil {
		run["results"] = []map[string]any{}
	}
	return map[string]any{"$schema": sarifSchema, "version": sarifVersion, "runs": []map[string]any{run}}
}

// RegisterInspectSARIF serves the pull-only export:
//
//	GET /v1/inspect/sarif?id=<report id|latest>   or   ?sha256=<hash>
func RegisterInspectSARIF(mux *http.ServeMux, token string) {
	mux.HandleFunc("GET /v1/inspect/sarif", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		id, sha := strings.TrimSpace(q.Get("id")), strings.ToLower(strings.TrimSpace(q.Get("sha256")))
		if id == "" && sha == "" {
			http.Error(w, "give id= (a report id or \"latest\") or sha256=", http.StatusBadRequest)
			return
		}
		var found *InspectReport
		for _, rep := range RecentInspectReports(0) { // newest first
			if (id == "latest" && found == nil) || (id != "" && rep.ID == id) || (sha != "" && rep.SHA256 == sha) {
				found = rep
				break
			}
		}
		if found == nil {
			http.Error(w, "report not found (only reports still in the in-memory ring can be exported)", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/sarif+json")
		w.Header().Set("Content-Disposition", `attachment; filename="kavach-inspect.sarif"`)
		_ = json.NewEncoder(w).Encode(InspectSARIF(found))
	})
}
