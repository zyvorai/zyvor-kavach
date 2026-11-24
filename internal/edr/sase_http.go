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

type saseEnvelope struct {
	Log    string `json:"log"`
	Policy any    `json:"policy"`
	Format string `json:"format"`
	Host   string `json:"host"`
	Now    string `json:"now"`
}

func saseHostLabel(vendor, h string) string {
	if h == "" {
		return ""
	}
	return vendor + ":" + strings.ToLower(webTruncate(webSanitise(h), 120))
}

func saseFail(w http.ResponseWriter, err error) {
	if err == errNetTooMany {
		http.Error(w, fmt.Sprintf("too many records (max %d)", svRecordsMax), http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, "invalid input: "+webTruncate(webSanitise(err.Error()), 200), http.StatusBadRequest)
}

func saseRespond(w http.ResponseWriter, store *Store, rep any, findings []Finding, set func(int)) {
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

// RegisterSase mounts the Cloudflare and Cisco Umbrella export-analysis routes. POST routes need the
// admin token; nothing contacts either vendor and nothing is fetched.
func RegisterSase(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/cloudflare/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": "observe-only", "log_formats": []string{"auto", "json", "csv", "tsv"},
			"log_kinds": []string{"cf-http", "cf-fw", "cf-gwdns", "cf-gwhttp"}, "rules": svRuleList(cfRules), "policy_rules": svRuleList(cfPolRules),
			"limits": map[string]int{"body_bytes": webBodyMax, "log_records": svRecordsMax, "policy_rules": cfpMax}, "note": svNote})
	})
	mux.HandleFunc("GET /v1/umbrella/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": "observe-only", "log_formats": []string{"auto", "json", "csv", "tsv"},
			"log_kinds": []string{"umb-dns", "umb-proxy"}, "rules": svRuleList(umbRules), "headerless_csv": true,
			"limits": map[string]int{"body_bytes": webBodyMax, "log_records": svRecordsMax}, "note": svNote})
	})
	read := func(w http.ResponseWriter, r *http.Request) (saseEnvelope, []byte, bool) {
		var env saseEnvelope
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
			var e saseEnvelope
			if json.Unmarshal(raw, &e) == nil && (e.Log != "" || e.Policy != nil) {
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
	logRoute := func(vendor string, run func([]byte, string, SvOptions) (*SvReport, []Finding, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			env, raw, ok := read(w, r)
			if !ok {
				return
			}
			body := raw
			if env.Log != "" {
				body = []byte(env.Log)
			}
			rep, findings, err := run(body, env.Format, SvOptions{Host: saseHostLabel(vendor, env.Host)})
			if err != nil {
				saseFail(w, err)
				return
			}
			if rep.Parsed == 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "no record could be parsed", "rejected": rep.Rejected, "errors": rep.Errors})
				return
			}
			saseRespond(w, store, rep, findings, func(n int) { rep.Findings = n })
		}
	}
	mux.HandleFunc("POST /v1/cloudflare/logs", logRoute("cloudflare", CloudflareRun))
	mux.HandleFunc("POST /v1/umbrella/logs", logRoute("umbrella", UmbrellaRun))
	mux.HandleFunc("POST /v1/cloudflare/policy", func(w http.ResponseWriter, r *http.Request) {
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
					saseFail(w, err)
					return
				}
				body = b
			}
		}
		opt := CfPolOptions{Host: saseHostLabel("cloudflare", env.Host)}
		if env.Now != "" {
			t, err := time.Parse(time.RFC3339, env.Now)
			if err != nil {
				http.Error(w, "now must be RFC 3339", http.StatusBadRequest)
				return
			}
			opt.Now = t.UTC()
		}
		rep, findings, err := CfPolicyRun(body, opt)
		if err != nil {
			saseFail(w, err)
			return
		}
		saseRespond(w, store, rep, findings, func(n int) { rep.Findings = n })
	})
}
