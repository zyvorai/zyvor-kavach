// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// Attack-path (toxic combination) scoring. Individual findings are weak
// prioritisation signals; the same asset carrying internet exposure, a
// vulnerable package and an over-privileged identity is a path an attacker can
// walk. This module groups signals per asset and ranks the combinations with a
// transparent additive score. It is observation only and offline: it reads
// findings Kavach already holds (the findings store, exposure/SBOM matches) or
// signals the operator posts, and it never probes anything or changes state.
//
// Honest limits: signals are grouped by the host or asset label, not by a
// verified network or identity graph, so "same asset" is a label match, not
// proof that the exposure reaches the vulnerable process or that the identity
// can be assumed from it. Signal classification is keyword based (table below)
// and can over- or under-classify. The score is an ordering aid, not a
// probability.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Signal kinds, in path order.
const (
	APExposure  = "internet_exposure"
	APVuln      = "vulnerable_software"
	APActive    = "active_threat"
	APPrivilege = "excess_privilege"
	APData      = "sensitive_data"
)

var apKindOrder = []string{APExposure, APVuln, APActive, APPrivilege, APData}

var apKindWeight = map[string]float64{APExposure: 30, APVuln: 25, APActive: 25, APPrivilege: 25, APData: 20}

var apSevFactor = map[string]float64{"critical": 1, "high": 0.8, "medium": 0.5, "low": 0.25, "info": 0.1}

const (
	apMaxSignals  = 5000
	apMaxBody     = 1 << 20
	apMaxPaths    = 200
	apSynergy     = 10.0
	apKEVBonus    = 10.0
	apUnspecified = "(unspecified)"
)

// apKeywords maps a kind to lower-case substrings matched against a finding's
// id, title and tags. The table is deliberately small and visible.
var apKeywords = []struct {
	kind string
	subs []string
}{
	{APExposure, []string{"sg-open", "open-all", "open-admin", "open-data", "internet", "0.0.0.0/0", "world-", "any-any", "any-source", "selfip-allow", "t1190", "t1133", "publicly", "rds-public", "lb-open", "anonymous", "stub-status", "management-exposed"}},
	{APPrivilege, []string{"iam-admin", "wildcard", "passrole", "trust-any", "privileged", "cluster-admin", "hostpath", "docker.sock", "t1078", "t1098", "t1548", "host-network", "hostpid", "nopasswd", "run-as-root"}},
	{APData, []string{"s3-", "bucket", "storage-unencrypted", "rds-public", "secret", "credential", "t1530", "t1552", "database", "azure-storage"}},
	{APVuln, []string{"cfg-advisory-", "cve-", "exposure-match", "vulnerab", "known-exploited"}},
}

// APSignal is one classified observation about an asset.
type APSignal struct {
	Host     string `json:"host"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Detail   string `json:"detail,omitempty"`
	Severity string `json:"severity,omitempty"`
	KEV      bool   `json:"kev,omitempty"`
}

// APFinding is the minimal finding shape accepted on the evaluate endpoint.
type APFinding struct {
	Host     string   `json:"host"`
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Tags     []string `json:"tags"`
}

// APBreak says which signal to remove to break a path.
type APBreak struct {
	Kind   string `json:"kind"`
	Signal string `json:"signal"`
	Action string `json:"action"`
}

// APPath is one ranked toxic combination.
type APPath struct {
	Host        string             `json:"host"`
	Title       string             `json:"title"`
	Score       float64            `json:"score"`
	Level       string             `json:"level"`
	Steps       []string           `json:"steps"`
	Factors     map[string]float64 `json:"factors"`
	Signals     []APSignal         `json:"signals"`
	BreakPoints []APBreak          `json:"break_points"`
}

var apActions = map[string]string{
	APExposure:  "close or restrict the internet-facing entry point (security group, listener, bucket access, management interface)",
	APVuln:      "upgrade the affected software to a fixed version or apply the vendor mitigation",
	APActive:    "investigate and close the alert that shows activity on this asset",
	APPrivilege: "reduce the identity or runtime privilege to what the workload needs",
	APData:      "restrict or encrypt the sensitive data store and remove public access",
}

func apSevOf(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, ok := apSevFactor[s]; ok {
		return s
	}
	return "medium"
}

func apClip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ClassifyAPFinding returns the signal kinds suggested by a finding. Stored
// findings of high or critical severity that match no keyword are treated as
// active threat signals; "pass" and "unknown" configuration results never count.
func ClassifyAPFinding(f APFinding, stored bool) []string {
	t := strings.ToLower(f.Title)
	if strings.HasPrefix(t, "[pass]") || strings.HasPrefix(t, "[unknown]") || strings.HasPrefix(t, "[not_applicable]") {
		return nil
	}
	sev := apSevOf(f.Severity)
	if strings.EqualFold(f.Severity, "info") {
		return nil
	}
	hay := strings.ToLower(f.ID + " " + f.Title + " " + strings.Join(f.Tags, " "))
	var kinds []string
	for _, kw := range apKeywords {
		for _, s := range kw.subs {
			if strings.Contains(hay, s) {
				kinds = append(kinds, kw.kind)
				break
			}
		}
	}
	if len(kinds) == 0 && stored && (sev == "high" || sev == "critical") {
		kinds = append(kinds, APActive)
	}
	return kinds
}

// ScoreAttackPaths ranks toxic combinations from classified signals. Pure and
// deterministic: the same signals give the same paths.
func ScoreAttackPaths(signals []APSignal, minScore float64) []APPath {
	byHost := map[string][]APSignal{}
	for _, s := range signals {
		if s.Host == "" {
			s.Host = apUnspecified
		}
		byHost[s.Host] = append(byHost[s.Host], s)
	}
	hosts := make([]string, 0, len(byHost))
	for h := range byHost {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	var out []APPath
	for _, h := range hosts {
		sigs := byHost[h]
		best := map[string]float64{}
		kev := false
		top := map[string]APSignal{}
		for _, s := range sigs {
			f := apSevFactor[apSevOf(s.Severity)]
			if f >= best[s.Kind] {
				if f > best[s.Kind] || top[s.Kind].Source == "" {
					top[s.Kind] = s
				}
				best[s.Kind] = f
			}
			if s.Kind == APVuln && s.KEV {
				kev = true
			}
		}
		if len(best) < 2 || (best[APExposure] == 0 && best[APVuln] == 0 && best[APActive] == 0) {
			continue
		}
		p := APPath{Host: h, Factors: map[string]float64{}}
		total := 0.0
		for _, k := range apKindOrder {
			if best[k] == 0 {
				continue
			}
			c := apKindWeight[k] * best[k]
			if k == APVuln && kev {
				c += apKEVBonus
			}
			p.Factors[k] = round1(c)
			total += c
			p.Steps = append(p.Steps, k)
			t := top[k]
			p.BreakPoints = append(p.BreakPoints, APBreak{Kind: k, Signal: t.Source, Action: apActions[k]})
		}
		total += apSynergy * float64(len(p.Steps)-1)
		if total > 100 {
			total = 100
		}
		p.Score = round1(total)
		p.Level = apLevel(p.Score)
		p.Title = apTitle(best)
		for _, k := range apKindOrder {
			for _, s := range sigs {
				if s.Kind == k && len(p.Signals) < 30 {
					p.Signals = append(p.Signals, s)
				}
			}
		}
		if p.Score >= minScore {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Host < out[j].Host
	})
	if len(out) > apMaxPaths {
		out = out[:apMaxPaths]
	}
	return out
}

func apLevel(s float64) string {
	switch {
	case s >= 80:
		return "critical"
	case s >= 60:
		return "high"
	case s >= 40:
		return "medium"
	}
	return "low"
}

func apTitle(best map[string]float64) string {
	has := func(k string) bool { return best[k] > 0 }
	switch {
	case has(APActive) && (has(APExposure) || has(APVuln)):
		return "Activity observed on an exposed or vulnerable asset"
	case has(APExposure) && has(APVuln) && has(APPrivilege) && has(APData):
		return "Internet-exposed vulnerable asset with excess privilege and reachable sensitive data"
	case has(APExposure) && has(APVuln) && has(APPrivilege):
		return "Internet-exposed vulnerable asset with excess privilege"
	case has(APExposure) && has(APVuln):
		return "Internet-exposed vulnerable software"
	case has(APExposure) && has(APPrivilege):
		return "Internet-exposed asset with excess privilege"
	case has(APExposure) && has(APData):
		return "Internet-exposed sensitive data"
	case has(APVuln) && has(APPrivilege):
		return "Vulnerable software running with excess privilege"
	}
	return "Combined risk signals on one asset"
}

// apSignalsFromFindings classifies findings into signals.
func apSignalsFromFindings(fs []APFinding, stored bool) []APSignal {
	var out []APSignal
	for _, f := range fs {
		for _, k := range ClassifyAPFinding(f, stored) {
			out = append(out, APSignal{Host: apClip(strings.TrimSpace(f.Host), 253), Kind: k, Source: apClip(f.ID, 80), Detail: apClip(f.Title, 160), Severity: apSevOf(f.Severity)})
			if len(out) >= apMaxSignals {
				return out
			}
		}
	}
	return out
}

func apStoredSignals(store *Store) []APSignal {
	var fs []APFinding
	if store != nil {
		for _, f := range store.List() {
			fs = append(fs, APFinding{Host: f.Host, ID: f.Rule, Title: f.Description, Severity: f.Severity, Tags: f.Tags})
			if len(fs) >= apMaxSignals {
				break
			}
		}
	}
	sigs := apSignalsFromFindings(fs, true)
	if fn := expAssetsHook.Load(); fn != nil {
		for _, a := range (*fn)() {
			for _, m := range a.Matches {
				if len(sigs) >= apMaxSignals {
					break
				}
				sigs = append(sigs, APSignal{Host: a.Host, Kind: APVuln, Source: m.ID, Detail: apClip(m.Package+" "+m.Version, 120), Severity: apSevOf(m.Severity), KEV: m.KEV})
			}
		}
	}
	return sigs
}

// RegisterAttackPaths wires the read-only attack-path routes.
func RegisterAttackPaths(mux *http.ServeMux, token string, store *Store) {
	const note = "Observation only: signals are grouped by host label, not by a verified network or identity graph, and classification is keyword based. The score orders review work; it is not a probability or proof that a path is exploitable."
	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/exposure/attack-paths", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		min := 0.0
		if v := r.URL.Query().Get("min_score"); v != "" {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < 0 || f > 100 {
				http.Error(w, "min_score must be 0..100", http.StatusBadRequest)
				return
			}
			min = f
		}
		sigs := apStoredSignals(store)
		if h := r.URL.Query().Get("host"); h != "" {
			var keep []APSignal
			for _, s := range sigs {
				if s.Host == h {
					keep = append(keep, s)
				}
			}
			sigs = keep
		}
		paths := ScoreAttackPaths(sigs, min)
		out(w, 200, map[string]any{"mode": "observe-only", "signals": len(sigs), "count": len(paths), "paths": paths, "note": note})
	})
	mux.HandleFunc("POST /v1/exposure/attack-paths/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, apMaxBody))
		if err != nil {
			var mb *http.MaxBytesError
			if errors.As(err, &mb) {
				http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		var req struct {
			Signals       []APSignal  `json:"signals"`
			Findings      []APFinding `json:"findings"`
			IncludeStored bool        `json:"include_stored"`
			MinScore      float64     `json:"min_score"`
		}
		if err := json.Unmarshal(b, &req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.Signals)+len(req.Findings) > apMaxSignals {
			http.Error(w, fmt.Sprintf("more than %d signals and findings", apMaxSignals), http.StatusBadRequest)
			return
		}
		valid := map[string]bool{}
		for _, k := range apKindOrder {
			valid[k] = true
		}
		var sigs []APSignal
		for _, s := range req.Signals {
			if !valid[s.Kind] {
				http.Error(w, "unknown signal kind "+strconv.Quote(apClip(s.Kind, 40)), http.StatusBadRequest)
				return
			}
			s.Host, s.Source, s.Detail, s.Severity = apClip(s.Host, 253), apClip(s.Source, 80), apClip(s.Detail, 160), apSevOf(s.Severity)
			sigs = append(sigs, s)
		}
		sigs = append(sigs, apSignalsFromFindings(req.Findings, false)...)
		if req.IncludeStored {
			sigs = append(sigs, apStoredSignals(store)...)
		}
		if req.MinScore < 0 || req.MinScore > 100 {
			http.Error(w, "min_score must be 0..100", http.StatusBadRequest)
			return
		}
		paths := ScoreAttackPaths(sigs, req.MinScore)
		out(w, 200, map[string]any{"mode": "observe-only", "stateless": true, "signals": len(sigs), "count": len(paths), "paths": paths, "note": note})
	})
}
