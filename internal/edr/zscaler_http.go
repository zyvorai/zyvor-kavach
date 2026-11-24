// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type zscalerEnvelope struct {
	Log        string `json:"log"`
	Policy     any    `json:"policy"`
	Probes     string `json:"probes"`
	Format     string `json:"format"`
	Host       string `json:"host"`
	Sanctioned any    `json:"sanctioned_apps"`
	WorkStart  *int   `json:"work_start_hour"`
	WorkEnd    *int   `json:"work_end_hour"`
	Now        string `json:"now"`
}

func zsHostLabel(h string) string {
	if h == "" {
		return ""
	}
	return "zscaler:" + strings.ToLower(webTruncate(webSanitise(h), 120))
}

func zsOptions(env zscalerEnvelope) (ZsOptions, error) {
	opt := ZsOptions{Host: zsHostLabel(env.Host), Sanctioned: map[string]bool{}}
	for _, l := range strings.Split(netListText(env.Sanctioned), "\n") {
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" && len(opt.Sanctioned) < zsListMax {
			opt.Sanctioned[webTruncate(l, 80)] = true
		}
	}
	if env.WorkStart != nil || env.WorkEnd != nil {
		s, e := 6, 22
		if env.WorkStart != nil {
			s = *env.WorkStart
		}
		if env.WorkEnd != nil {
			e = *env.WorkEnd
		}
		if s < 0 || s > 23 || e < 1 || e > 24 || s >= e {
			return opt, fmt.Errorf("work_start_hour must be 0..23, work_end_hour 1..24 and start before end")
		}
		opt.WorkStart, opt.WorkEnd = s, e
	}
	return opt, nil
}

func zsRespond(w http.ResponseWriter, store *Store, rep any, findings []Finding, set func(int)) {
	if len(findings) > webFindingsMx {
		findings = findings[:webFindingsMx]
	}
	stored, err := webStoreFindings(store, findings)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	set(stored)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}

func zsFail(w http.ResponseWriter, err error) {
	if err == errNetTooMany {
		http.Error(w, fmt.Sprintf("too many records (max %d)", zsRecordsMax), http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "invalid input: "+webTruncate(webSanitise(err.Error()), 200), http.StatusBadRequest)
}

// RegisterZscaler mounts the Zscaler export-analysis routes. POST routes need the admin token;
// nothing contacts Zscaler and nothing is fetched.
func RegisterZscaler(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/zscaler/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": "observe-only", "log_formats": []string{"auto", "json", "csv", "tsv"}, "log_kinds": []string{"web", "fw", "dns", "zpa"},
			"rules": zsRuleList(), "policy_rules": zspolRuleList(), "zdx_rules": zdxRuleList(), "zdx_metrics": len(zdxMetrics),
			"limits": map[string]int{"body_bytes": webBodyMax, "log_records": zsRecordsMax, "policy_rules": zpRulesMax, "zdx_rows": zdxRowsMax},
			"note":   zsNote})
	})
	read := func(w http.ResponseWriter, r *http.Request) (zscalerEnvelope, []byte, bool) {
		var env zscalerEnvelope
		if !webAdmin(w, r, token) {
			return env, nil, false
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return env, nil, false
		}
		q := r.URL.Query()
		env.Format, env.Host = q.Get("format"), q.Get("host")
		if t := strings.TrimSpace(string(raw[:min(len(raw), 64)])); strings.HasPrefix(t, "{") {
			var e zscalerEnvelope
			if json.Unmarshal(raw, &e) == nil && (e.Log != "" || e.Policy != nil || e.Probes != "") {
				if e.Format == "" {
					e.Format = env.Format
				}
				if e.Host == "" {
					e.Host = env.Host
				}
				env = e
			}
		}
		return env, raw, true
	}
	mux.HandleFunc("POST /v1/zscaler/logs", func(w http.ResponseWriter, r *http.Request) {
		env, raw, ok := read(w, r)
		if !ok {
			return
		}
		body := raw
		if env.Log != "" {
			body = []byte(env.Log)
		}
		opt, err := zsOptions(env)
		if err != nil {
			zsFail(w, err)
			return
		}
		rep, findings, err := ZscalerRun(body, env.Format, opt)
		if err != nil {
			zsFail(w, err)
			return
		}
		if rep.Parsed == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "no record could be parsed", "rejected": rep.Rejected, "errors": rep.Errors})
			return
		}
		zsRespond(w, store, rep, findings, func(n int) { rep.Findings = n })
	})
	mux.HandleFunc("POST /v1/zscaler/policy", func(w http.ResponseWriter, r *http.Request) {
		env, raw, ok := read(w, r)
		if !ok {
			return
		}
		body := raw
		if env.Policy != nil {
			if s, isStr := env.Policy.(string); isStr {
				body = []byte(s)
			} else {
				b, err := json.Marshal(env.Policy)
				if err != nil {
					zsFail(w, err)
					return
				}
				body = b
			}
		}
		opt := ZspolOptions{Host: zsHostLabel(env.Host)}
		if env.Now != "" {
			t, err := time.Parse(time.RFC3339, env.Now)
			if err != nil {
				http.Error(w, "now must be RFC 3339", http.StatusBadRequest)
				return
			}
			opt.Now = t.UTC()
		}
		rep, findings, err := ZspolRun(body, opt)
		if err != nil {
			zsFail(w, err)
			return
		}
		zsRespond(w, store, rep, findings, func(n int) { rep.Findings = n })
	})
	mux.HandleFunc("POST /v1/zscaler/zdx", func(w http.ResponseWriter, r *http.Request) {
		env, raw, ok := read(w, r)
		if !ok {
			return
		}
		body := raw
		if env.Probes != "" {
			body = []byte(env.Probes)
		}
		rep, findings, err := ZdxRun(body, zsHostLabel(env.Host))
		if err != nil {
			zsFail(w, err)
			return
		}
		zsRespond(w, store, rep, findings, func(n int) { rep.Findings = n })
	})
}
