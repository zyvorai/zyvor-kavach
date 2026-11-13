package edr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func chainEnvelope(m map[string]any) map[string]any {
	m["method"] = chainMethod
	m["limitations"] = chainLimitations
	return m
}

// chainProvenance maps finding id -> provenance story id for hosts that have findings.
func chainProvenance(store *Store, fs []Finding) map[string]string {
	out := map[string]string{}
	if len(fs) == 0 {
		return out
	}
	sn := provTake(store)
	hosts := map[string]bool{}
	for _, f := range fs {
		hosts[f.Host] = true
	}
	var hl []string
	for h := range hosts {
		if h != "" {
			hl = append(hl, h)
		}
	}
	sort.Strings(hl)
	if len(hl) > 50 {
		hl = hl[:50]
	}
	rar := sn.rarity(2000)
	for _, h := range hl {
		for _, s := range sn.graph(h, 2000).Stories(rar, 0) {
			for _, hit := range s.Hits {
				out[hit.FindingID] = s.ID
			}
		}
	}
	return out
}

func chainsCompute(store *Store, host string, minScore float64) []Chain {
	fs := store.List()
	return BuildChains(fs, chainProvenance(store, fs), host, minScore)
}

func chainTitle(c Chain) string {
	t := fmt.Sprintf("Attack chain on %s: %d findings", strings.Join(c.Hosts, ","), c.Size)
	if len(c.Tactics) > 0 {
		t += " (" + strings.Join(c.Tactics, " > ") + ")"
	}
	if len(t) > 190 {
		t = t[:190]
	}
	return t
}

func registerChains(mux *http.ServeMux, token string, store *Store, st *ctState) {
	caseOf := func(id string) string {
		st.mu.Lock()
		defer st.mu.Unlock()
		return st.d.ChainCases[id]
	}
	mux.HandleFunc("GET /v1/chains", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		q := r.URL.Query()
		minScore := 0.0
		if v, err := strconv.ParseFloat(q.Get("min_score"), 64); err == nil && v > 0 {
			minScore = v
		}
		limit := 50
		if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 200 {
			limit = v
		}
		cs := chainsCompute(store, q.Get("host"), minScore)
		total := len(cs)
		if len(cs) > limit {
			cs = cs[:limit]
		}
		for i := range cs {
			cs[i].CaseID = caseOf(cs[i].ID)
		}
		if cs == nil {
			cs = []Chain{}
		}
		wsJSON(w, 200, chainEnvelope(map[string]any{"chains": cs, "total": total, "returned": len(cs)}))
	})
	mux.HandleFunc("GET /v1/chains/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		for _, c := range chainsCompute(store, "", 0) {
			if c.ID != r.PathValue("id") {
				continue
			}
			c.CaseID = caseOf(c.ID)
			wsJSON(w, 200, chainEnvelope(map[string]any{
				"chain": c, "members": c.members, "timeline": c.members, "links": c.links,
				"links_truncated":     c.LinkCount > len(c.links),
				"tactics_in_order":    c.Tactics,
				"suggested_questions": chainQuestions(c.Tactics),
				"questions_note":      "Hints derived from tactics not yet seen; they are not findings.",
			}))
			return
		}
		http.Error(w, "not found", 404)
	})
	mux.HandleFunc("POST /v1/chains/{id}/case", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.PathValue("id")
		st.chainMu.Lock()
		defer st.chainMu.Unlock()
		if cid := caseOf(id); cid != "" {
			if c, code := ctGetCase(mux, r, cid); code == 200 {
				wsJSON(w, 200, map[string]any{"created": false, "case": c})
				return
			}
		}
		var chain *Chain
		for _, c := range chainsCompute(store, "", 0) {
			if c.ID == id {
				cc := c
				chain = &cc
				break
			}
		}
		if chain == nil {
			http.Error(w, "chain not found", 404)
			return
		}
		why := []string{}
		for _, x := range chain.WhySummary {
			why = append(why, fmt.Sprintf("%s (%.2f)", x.Reason, x.Weight))
		}
		body := map[string]any{
			"title": chainTitle(*chain), "severity": chain.Severity, "finding_ids": chain.FindingIDs,
			"tags":  []string{"chain:" + id},
			"notes": fmt.Sprintf("Created from attack chain %s (score %.2f). Grouped because: %s", id, chain.Score, strings.Join(why, "; ")),
		}
		code, b := internalCall(mux, r, "POST", "/v1/cases", body)
		if code != 201 {
			http.Error(w, "case creation failed: "+strings.TrimSpace(string(b)), code)
			return
		}
		var c IncCase
		_ = json.Unmarshal(b, &c)
		note := fmt.Sprintf("Timeline: %s to %s, %d findings on %s. Tactics: %s.",
			chain.First.Format("2006-01-02 15:04:05Z"), chain.Last.Format("2006-01-02 15:04:05Z"), chain.Size,
			strings.Join(chain.Hosts, ","), strings.Join(chain.Tactics, " > "))
		internalCall(mux, r, "POST", "/v1/cases/"+c.ID+"/comments", map[string]any{"text": note, "author": wsActor(admin)})
		st.mu.Lock()
		st.d.ChainCases[id] = c.ID
		st.journalLocked(wsActor(admin), "chain.case_create", id+" -> "+c.ID)
		err := st.saveLocked()
		st.mu.Unlock()
		if err != nil {
			http.Error(w, "persist failed", 500)
			return
		}
		c2, _ := ctGetCase(mux, r, c.ID)
		wsJSON(w, 201, map[string]any{"created": true, "case": c2})
	})
}
