// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type netcfgEnvelope struct {
	Config string `json:"config"`
	Old    string `json:"old"`
	New    string `json:"new"`
	Format string `json:"format"`
	Host   string `json:"host"`
	Now    string `json:"now"`
}

func netcfgHostLabel(h string) string {
	if h == "" {
		return ""
	}
	return "netcfg:" + strings.ToLower(webTruncate(webSanitise(h), 120))
}

func netcfgFail(w http.ResponseWriter, err error) {
	http.Error(w, "invalid configuration: "+webTruncate(webSanitise(err.Error()), 200), http.StatusBadRequest)
}

func netcfgOpts(env netcfgEnvelope, host string) (NetcfgOptions, bool) {
	opt := NetcfgOptions{Host: netcfgHostLabel(host)}
	if env.Now != "" {
		t, err := time.Parse(time.RFC3339, env.Now)
		if err != nil {
			return opt, false
		}
		opt.Now = t.UTC()
	}
	return opt, true
}

// RegisterNetcfg mounts the network-device configuration review routes. POST routes need the
// admin token; nothing contacts a device.
func RegisterNetcfg(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/netcfg/sources", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"mode": "observe-only", "formats": ncFormats, "rules": netcfgRuleList(),
			"limits": map[string]int{"body_bytes": webBodyMax, "lines": ncMaxLines, "line_bytes": ncMaxLine, "rules": ncMaxRules, "shadow_rules_per_scope": ncShadowMax, "shadow_comparisons": ncCompareMax, "xml_depth": ncXMLDepth, "xml_elements": ncXMLNodes, "findings_per_rule": ncCapPerRule},
			"note":   netcfgNote})
	})
	mux.HandleFunc("POST /v1/netcfg/analyze", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		q := r.URL.Query()
		env := netcfgEnvelope{Format: q.Get("format"), Host: q.Get("host")}
		cfg := raw
		if t := strings.TrimSpace(string(raw[:min(len(raw), 64)])); strings.HasPrefix(t, "{") {
			var e netcfgEnvelope
			if json.Unmarshal(raw, &e) == nil && e.Config != "" {
				env, cfg = e, []byte(e.Config)
			}
		}
		opt, ok := netcfgOpts(env, env.Host)
		if !ok {
			http.Error(w, "now must be RFC 3339", http.StatusBadRequest)
			return
		}
		rep, findings, err := NetcfgRun(cfg, env.Format, opt)
		if err != nil {
			netcfgFail(w, err)
			return
		}
		if len(findings) > webFindingsMx {
			findings = findings[:webFindingsMx]
		}
		stored, err := webStoreFindings(store, findings)
		if err != nil {
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
		rep.Findings = stored
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)
	})
	mux.HandleFunc("POST /v1/netcfg/diff", func(w http.ResponseWriter, r *http.Request) {
		if !webAdmin(w, r, token) {
			return
		}
		raw, ok := webReadBody(w, r)
		if !ok {
			return
		}
		var env netcfgEnvelope
		if json.Unmarshal(raw, &env) != nil || env.Old == "" || env.New == "" {
			http.Error(w, "body must be a JSON envelope with old and new configuration strings", http.StatusBadRequest)
			return
		}
		opt, ok := netcfgOpts(env, "")
		if !ok {
			http.Error(w, "now must be RFC 3339", http.StatusBadRequest)
			return
		}
		rep, err := NetcfgDiff([]byte(env.Old), []byte(env.New), env.Format, opt)
		if err != nil {
			netcfgFail(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rep)
	})
}
