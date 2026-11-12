// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// AICapability describes a Kavach AI feature that goes beyond Falcon Charlotte.
type AICapability struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Beyond   string   `json:"beyond_falcon"`
	APIs     []string `json:"apis"`
	Mode     string   `json:"mode"` // heuristic | optional_llm | hybrid
	Note     string   `json:"note"`
}

func AICapabilities() []AICapability {
	return []AICapability{
		{ID: "chat", Name: "SOC Copilot Chat", Beyond: "Charlotte AI (multi-turn)", APIs: []string{"/v1/ai/chat"}, Mode: "hybrid", Note: "Multi-turn analyst chat with local reasoning"},
		{ID: "nl-hunt", Name: "Natural-language Hunt", Beyond: "FQL + Charlotte", APIs: []string{"/v1/ai/nl-hunt"}, Mode: "heuristic", Note: "English → hunt filters + results"},
		{ID: "narrative", Name: "Incident Narratives", Beyond: "Charlotte summarize", APIs: []string{"/v1/ai/narrative"}, Mode: "hybrid", Note: "Story-form attack narrative"},
		{ID: "cluster", Name: "Alert Clustering", Beyond: "Workbench triage", APIs: []string{"/v1/ai/cluster"}, Mode: "heuristic", Note: "Dedup / cluster related findings"},
		{ID: "attack-path", Name: "Attack Path Predictor", Beyond: "Threat Graph", APIs: []string{"/v1/ai/attack-path"}, Mode: "heuristic", Note: "Next-step adversary predictions"},
		{ID: "forecast", Name: "Breach Risk Forecast", Beyond: "ExPRT / Spotlight", APIs: []string{"/v1/ai/forecast"}, Mode: "heuristic", Note: "24–72h risk forecast"},
		{ID: "similarity", Name: "Finding Similarity", Beyond: "IOC match", APIs: []string{"/v1/ai/similarity"}, Mode: "heuristic", Note: "Nearest-neighbor findings"},
		{ID: "classify", Name: "Behavior Family Classifier", Beyond: "ML NGAV labels", APIs: []string{"/v1/ai/classify"}, Mode: "heuristic", Note: "Ransomware / C2 / LOTL / etc."},
		{ID: "fp", Name: "False-Positive Scorer", Beyond: "Detection triage", APIs: []string{"/v1/ai/fp-score"}, Mode: "heuristic", Note: "FP likelihood with rationale"},
		{ID: "remediation", Name: "Remediation Advisor", Beyond: "RTR guidance", APIs: []string{"/v1/ai/remediation"}, Mode: "heuristic", Note: "Guidance only — never executes"},
		{ID: "report", Name: "Auto Incident Report", Beyond: "Case notes", APIs: []string{"/v1/ai/report"}, Mode: "hybrid", Note: "Markdown incident report"},
		{ID: "playbook", Name: "Playbook Recommender", Beyond: "Fusion library", APIs: []string{"/v1/ai/playbook-suggest"}, Mode: "heuristic", Note: "Suggest Fusion playbooks"},
		{ID: "anomaly", Name: "Deep Anomaly Detector", Beyond: "UEBA", APIs: []string{"/v1/ai/anomaly"}, Mode: "heuristic", Note: "Host/process anomaly vectors"},
		{ID: "agents", Name: "Multi-Agent SOC", Beyond: "Charlotte single agent", APIs: []string{"/v1/ai/agents", "/v1/ai/agents/run"}, Mode: "hybrid", Note: "Triage / Hunt / Intel / IR agents"},
		{ID: "briefing", Name: "Daily SOC Briefing", Beyond: "Dashboards", APIs: []string{"/v1/ai/briefing"}, Mode: "heuristic", Note: "Executive + analyst brief"},
		{ID: "what-if", Name: "What-If Simulator", Beyond: "n/a in Falcon", APIs: []string{"/v1/ai/what-if"}, Mode: "heuristic", Note: "Simulate adversary progression"},
		{ID: "memory", Name: "Analyst Memory", Beyond: "n/a", APIs: []string{"/v1/ai/memory"}, Mode: "heuristic", Note: "Remember analyst preferences"},
		{ID: "stream", Name: "Event Stream Analyst", Beyond: "n/a", APIs: []string{"/v1/ai/stream"}, Mode: "heuristic", Note: "Batch-analyze recent telemetry"},
		{ID: "guardian", Name: "AI Workload Guardian", Beyond: "Falcon Guardian", APIs: []string{"/v1/ai/guardian"}, Mode: "heuristic", Note: "Observe AI/agent process risk"},
		{ID: "fusion-xdr", Name: "Netra×Kavach AI Fusion", Beyond: "Insight XDR", APIs: []string{"/v1/ai/xdr-fusion"}, Mode: "heuristic", Note: "Cross-domain AI correlation"},
		{ID: "embeddings", Name: "Finding Embeddings", Beyond: "n/a", APIs: []string{"/v1/ai/embeddings"}, Mode: "heuristic", Note: "Deterministic feature vectors"},
		{ID: "autopilot", Name: "Triage Autopilot", Beyond: "Falcon Complete agents", APIs: []string{"/v1/ai/autopilot"}, Mode: "heuristic", Note: "Suggested triage batch — never auto-closes"},
	}
}

var (
	chatMu   sync.Mutex
	chatLog  []AIChatMessage
	memoryMu sync.Mutex
	aiMemory = map[string]string{}
)

type AIChatMessage struct {
	Role    string    `json:"role"` // user|assistant|system
	Content string    `json:"content"`
	Time    time.Time `json:"time"`
}

type AttackStep struct {
	Step        int      `json:"step"`
	TechniqueID string   `json:"technique_id"`
	Technique   string   `json:"technique"`
	Likelihood  float64  `json:"likelihood"`
	Evidence    []string `json:"evidence"`
	Advice      string   `json:"advice"`
}

type FindingCluster struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	Severity  string   `json:"severity"`
	Count     int      `json:"count"`
	FindingIDs []string `json:"finding_ids"`
	Hosts     []string `json:"hosts"`
	Summary   string   `json:"summary"`
}

type BehaviorClass struct {
	Family      string   `json:"family"`
	Confidence  float64  `json:"confidence"`
	Signals     []string `json:"signals"`
	TechniqueID string   `json:"technique_id,omitempty"`
}

// RegisterAIPlatform wires beyond-Falcon AI APIs.
func RegisterAIPlatform(mux *http.ServeMux, token string, store *Store) {
	mux.HandleFunc("GET /v1/ai/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"product": "kavach-ai",
			"beyond_falcon": true,
			"llm_configured": os.Getenv("KAVACH_LLM_URL") != "",
			"capabilities": AICapabilities(),
		})
	})

	mux.HandleFunc("GET /v1/ai/chat", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		chatMu.Lock()
		out := append([]AIChatMessage{}, chatLog...)
		chatMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/ai/chat", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		defer r.Body.Close()
		var body struct {
			Message string `json:"message"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Message) == "" {
			http.Error(w, "invalid", 400)
			return
		}
		userMsg := AIChatMessage{Role: "user", Content: strings.TrimSpace(body.Message), Time: time.Now().UTC()}
		reply := localChatReply(body.Message, store)
		if note := optionalLLM("Answer as Kavach SOC copilot in 2 sentences: " + body.Message); note != "" {
			reply = note
		}
		asst := AIChatMessage{Role: "assistant", Content: reply, Time: time.Now().UTC()}
		chatMu.Lock()
		chatLog = append(chatLog, userMsg, asst)
		if len(chatLog) > 200 {
			chatLog = chatLog[len(chatLog)-200:]
		}
		chatMu.Unlock()
		AppendAudit(token, "ai.chat", truncate(body.Message, 80))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"reply": asst, "history_len": len(chatLog)})
	})

	mux.HandleFunc("POST /v1/ai/nl-hunt", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body struct {
			Text string `json:"text"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Text == "" {
			http.Error(w, "invalid", 400)
			return
		}
		q := nlToHuntQuery(body.Text)
		filters := parseHuntQuery(q)
		findings := []Finding{}
		for _, f := range store.List() {
			if matchHunt(f, filters) || len(filters) == 0 {
				if len(filters) == 0 {
					// free-text fallback
					hay := strings.ToLower(f.Rule + " " + f.Description + " " + f.Host + " " + f.Evidence.Command)
					if !strings.Contains(hay, strings.ToLower(body.Text)) && !fuzzyNLMatch(body.Text, f) {
						continue
					}
				}
				findings = append(findings, f)
			}
		}
		AppendAudit(token, "ai.nl-hunt", body.Text)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"text": body.Text, "translated_query": q, "findings": findings, "count": len(findings),
		})
	})

	mux.HandleFunc("GET /v1/ai/narrative", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		f, ok := findByID(store, id)
		if !ok {
			// whole-environment narrative
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"narrative": envNarrative(store), "scope": "environment"})
			return
		}
		n := findingNarrative(f)
		if note := optionalLLM("Write a 3-sentence incident narrative: " + f.Description); note != "" {
			n = note
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"finding_id": f.ID, "narrative": n, "detection": MapDetection(f)})
	})

	mux.HandleFunc("GET /v1/ai/cluster", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(clusterFindings(store.List()))
	})

	mux.HandleFunc("GET /v1/ai/attack-path", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		f, ok := findByID(store, id)
		host := r.URL.Query().Get("host")
		if ok {
			host = f.Host
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"host": host, "finding_id": id, "steps": predictAttackPath(f, ok, store),
			"note": "Predictive — observation only; no containment executed",
		})
	})

	mux.HandleFunc("GET /v1/ai/forecast", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(riskForecast(store))
	})

	mux.HandleFunc("GET /v1/ai/similarity", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		f, ok := findByID(store, id)
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(similarFindings(f, store.List(), 8))
	})

	mux.HandleFunc("GET /v1/ai/classify", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		if id != "" {
			f, ok := findByID(store, id)
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(classifyBehavior(f))
			return
		}
		out := []map[string]any{}
		for _, f := range store.List() {
			out = append(out, map[string]any{"finding_id": f.ID, "class": classifyBehavior(f)})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("GET /v1/ai/fp-score", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		f, ok := findByID(store, id)
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fpScore(f))
	})

	mux.HandleFunc("GET /v1/ai/remediation", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		f, ok := findByID(store, id)
		if !ok {
			http.Error(w, "not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(remediationAdvice(f))
	})

	mux.HandleFunc("GET /v1/ai/report", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		markdown := ""
		if f, ok := findByID(store, id); ok {
			markdown = incidentReportMD(f)
		} else {
			markdown = envReportMD(store)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"markdown": markdown, "generated_at": time.Now().UTC()})
	})

	mux.HandleFunc("GET /v1/ai/playbook-suggest", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		f, ok := findByID(store, id)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(suggestPlaybooks(f, ok))
	})

	mux.HandleFunc("GET /v1/ai/anomaly", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(anomalyScores(store))
	})

	mux.HandleFunc("GET /v1/ai/agents", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(socAgents())
	})
	mux.HandleFunc("POST /v1/ai/agents/run", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body struct {
			Agent string `json:"agent"`
			Input string `json:"input"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Agent == "" {
			http.Error(w, "invalid", 400)
			return
		}
		out := runSOCAgent(body.Agent, body.Input, store)
		AppendAudit(token, "ai.agent."+body.Agent, truncate(body.Input, 60))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("GET /v1/ai/briefing", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(socBriefing(store))
	})

	mux.HandleFunc("POST /v1/ai/what-if", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body struct {
			Scenario string `json:"scenario"`
			Host     string `json:"host"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Scenario == "" {
			http.Error(w, "invalid", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(whatIf(body.Scenario, body.Host, store))
	})

	mux.HandleFunc("GET /v1/ai/memory", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		memoryMu.Lock()
		out := map[string]string{}
		for k, v := range aiMemory {
			out[k] = v
		}
		memoryMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/ai/memory", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		defer r.Body.Close()
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		memoryMu.Lock()
		for k, v := range body {
			if len(k) > 64 || len(v) > 512 {
				continue
			}
			aiMemory[k] = v
		}
		memoryMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	mux.HandleFunc("GET /v1/ai/stream", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(analyzeStream(store))
	})

	mux.HandleFunc("GET /v1/ai/guardian", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(aiGuardian(store))
	})

	mux.HandleFunc("GET /v1/ai/xdr-fusion", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(xdrAIFusion(store))
	})

	mux.HandleFunc("GET /v1/ai/embeddings", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("id")
		if id != "" {
			f, ok := findByID(store, id)
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"finding_id": f.ID, "vector": embedFinding(f)})
			return
		}
		out := []map[string]any{}
		for _, f := range store.List() {
			out = append(out, map[string]any{"finding_id": f.ID, "vector": embedFinding(f)})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("POST /v1/ai/autopilot", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		suggestions := []map[string]any{}
		for _, f := range store.List() {
			fp := fpScore(f)
			rs := ScoreFinding(f)
			status := "investigate"
			if fp["fp_likelihood"].(float64) >= 0.7 {
				status = "likely_false_positive"
			} else if rs.Score >= 70 {
				status = "priority_true_positive"
			}
			suggestions = append(suggestions, map[string]any{
				"finding_id": f.ID, "suggested_status": status, "score": rs.Score, "fp": fp,
				"note": "Suggestion only — autopilot never mutates incidents automatically",
			})
		}
		AppendAudit(token, "ai.autopilot", fmt.Sprintf("%d suggestions", len(suggestions)))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"suggestions": suggestions, "auto_applied": false})
	})
}

func findByID(store *Store, id string) (Finding, bool) {
	if id == "" {
		return Finding{}, false
	}
	for _, f := range store.List() {
		if f.ID == id || "det-"+f.ID == id {
			return f, true
		}
	}
	return Finding{}, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func optionalLLM(prompt string) string {
	url := os.Getenv("KAVACH_LLM_URL")
	if url == "" {
		return ""
	}
	body, _ := json.Marshal(map[string]string{"prompt": prompt})
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	if key := os.Getenv("KAVACH_LLM_API_KEY"); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var out struct {
		Text string `json:"text"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil || out.Text == "" {
		return ""
	}
	return out.Text
}

func localChatReply(msg string, store *Store) string {
	low := strings.ToLower(msg)
	n := len(store.List())
	switch {
	case strings.Contains(low, "ransomware"):
		return fmt.Sprintf("I see %d findings total. For ransomware, filter rule:ransomware or run Hunt with exe patterns; check Spotlight CVEs and OverWatch seeds. Containment stays a request ledger only.", n)
	case strings.Contains(low, "hunt") || strings.Contains(low, "search"):
		return "Try natural-language hunt: POST /v1/ai/nl-hunt with text like \"high severity on demo-host\". Or FQL-lite: host:demo severity:high."
	case strings.Contains(low, "brief") || strings.Contains(low, "summary"):
		return envNarrative(store)
	case strings.Contains(low, "netra") || strings.Contains(low, "xdr"):
		return "Netra×Kavach AI Fusion correlates denied network flows with process findings. Open /v1/ai/xdr-fusion or the Integrations page."
	default:
		return fmt.Sprintf("Kavach AI Copilot online — %d findings in scope. Ask for a briefing, ransomware hunt, attack path, or false-positive review. Beyond Falcon Charlotte: multi-agent SOC, NL hunt, forecast, and what-if simulation.", n)
	}
}

func nlToHuntQuery(text string) string {
	low := strings.ToLower(text)
	parts := []string{}
	if strings.Contains(low, "critical") {
		parts = append(parts, "severity:critical")
	} else if strings.Contains(low, "high") {
		parts = append(parts, "severity:high")
	} else if strings.Contains(low, "medium") {
		parts = append(parts, "severity:medium")
	}
	for _, rule := range []string{"ransomware", "download", "shell", "netcat", "lolbin", "credential"} {
		if strings.Contains(low, rule) {
			parts = append(parts, "rule:"+rule)
		}
	}
	for _, tok := range strings.Fields(text) {
		if strings.Contains(tok, ".") || strings.Contains(tok, "-") {
			if !strings.Contains(strings.ToLower(tok), "severity") {
				parts = append(parts, "host:"+strings.Trim(tok, `"'.,`))
				break
			}
		}
	}
	if strings.Contains(low, "bash") {
		parts = append(parts, "exe:bash")
	}
	if strings.Contains(low, "curl") {
		parts = append(parts, "exe:curl")
	}
	return strings.Join(parts, " ")
}

func fuzzyNLMatch(text string, f Finding) bool {
	low := strings.ToLower(text)
	for _, kw := range []string{"ransomware", "shell", "download", "root", "c2", "lateral"} {
		if strings.Contains(low, kw) && (strings.Contains(strings.ToLower(f.Rule), kw) || strings.Contains(strings.ToLower(f.Description), kw)) {
			return true
		}
	}
	return false
}

func findingNarrative(f Finding) string {
	d := MapDetection(f)
	return fmt.Sprintf(
		"On host %s at %s, Kavach observed behavior matching rule %q (severity %s). "+
			"This maps to MITRE %s — %s. Evidence centers on process %s (pid %d, parent %s). "+
			"Recommended next step: review the attack-path prediction and run an NL hunt for related activity; do not assume containment has occurred.",
		f.Host, f.Time.Format(time.RFC3339), f.Rule, f.Severity, d.TechniqueID, d.Technique,
		f.Evidence.Executable, f.Evidence.PID, f.Evidence.ParentExe,
	)
}

func envNarrative(store *Store) string {
	findings := store.List()
	high := 0
	hosts := map[string]struct{}{}
	for _, f := range findings {
		hosts[f.Host] = struct{}{}
		if f.Severity == "high" || f.Severity == "critical" {
			high++
		}
	}
	return fmt.Sprintf(
		"Environment brief: %d findings across %d hosts (%d high/critical). "+
			"Priority clusters and OverWatch seeds should be reviewed first. "+
			"Kavach remains observation-only — use AI attack-path and remediation advisor for guidance, not automatic isolation.",
		len(findings), len(hosts), high,
	)
}

func clusterFindings(findings []Finding) []FindingCluster {
	type key struct{ Rule, Sev string }
	groups := map[key][]Finding{}
	for _, f := range findings {
		k := key{Rule: f.Rule, Sev: f.Severity}
		groups[k] = append(groups[k], f)
	}
	out := []FindingCluster{}
	i := 0
	for k, list := range groups {
		i++
		ids := []string{}
		hostSet := map[string]struct{}{}
		for _, f := range list {
			ids = append(ids, f.ID)
			hostSet[f.Host] = struct{}{}
		}
		hosts := []string{}
		for h := range hostSet {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		out = append(out, FindingCluster{
			ID: fmt.Sprintf("cl-%d", i), Label: k.Rule, Severity: k.Sev, Count: len(list),
			FindingIDs: ids, Hosts: hosts,
			Summary: fmt.Sprintf("%d related %s findings (%s) on %d hosts", len(list), k.Rule, k.Sev, len(hosts)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func predictAttackPath(f Finding, ok bool, store *Store) []AttackStep {
	steps := []AttackStep{
		{Step: 1, TechniqueID: "T1059", Technique: "Command and Scripting Interpreter", Likelihood: 0.55, Evidence: []string{"process telemetry"}, Advice: "Hunt for interactive shells"},
		{Step: 2, TechniqueID: "T1003", Technique: "OS Credential Dumping", Likelihood: 0.35, Evidence: []string{"identity seeds"}, Advice: "Review Identity events"},
		{Step: 3, TechniqueID: "T1021", Technique: "Remote Services", Likelihood: 0.3, Evidence: []string{"fleet lateral risk"}, Advice: "Correlate with Netra denies"},
		{Step: 4, TechniqueID: "T1486", Technique: "Data Encrypted for Impact", Likelihood: 0.25, Evidence: []string{"ransomware heuristics"}, Advice: "Watch mass-file signals"},
	}
	if ok {
		d := MapDetection(f)
		steps[0] = AttackStep{Step: 1, TechniqueID: d.TechniqueID, Technique: d.Technique, Likelihood: 0.85, Evidence: []string{f.Rule, f.Evidence.Executable}, Advice: "Validate evidence in drawer"}
		if strings.Contains(f.Rule, "ransomware") {
			steps[3].Likelihood = 0.9
		}
		if f.Destination != "" {
			steps = append([]AttackStep{{Step: 0, TechniqueID: "T1071", Technique: "Application Layer Protocol", Likelihood: 0.7, Evidence: []string{f.Destination}, Advice: "XDR: review Netra destination"}}, steps...)
			for i := range steps {
				steps[i].Step = i + 1
			}
		}
	}
	_ = store
	return steps
}

func riskForecast(store *Store) map[string]any {
	findings := store.List()
	base := 15.0 + float64(len(findings))*3
	high := 0
	for _, f := range findings {
		if f.Severity == "high" || f.Severity == "critical" {
			high++
			base += 5
		}
	}
	if base > 95 {
		base = 95
	}
	return map[string]any{
		"horizon_hours": 72,
		"breach_risk_score": int(base),
		"level": riskLevel(int(base)),
		"drivers": []string{
			fmt.Sprintf("%d open findings", len(findings)),
			fmt.Sprintf("%d high/critical", high),
			"identity seed activity",
			"overwatch open alerts",
		},
		"forecast": []map[string]any{
			{"hours": 24, "score": int(math.Min(95, base+2))},
			{"hours": 48, "score": int(math.Min(95, base+5))},
			{"hours": 72, "score": int(math.Min(95, base+8))},
		},
		"note": "Heuristic forecast — not a guarantee of breach",
	}
}

func riskLevel(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func embedFinding(f Finding) []float64 {
	// Deterministic 16-dim bag-of-features vector (not a neural embedding).
	v := make([]float64, 16)
	h := sha256.Sum256([]byte(f.Rule + "|" + f.Severity + "|" + f.Host + "|" + f.Evidence.Executable))
	for i := 0; i < 16; i++ {
		v[i] = float64(h[i]) / 255.0
	}
	rs := ScoreFinding(f)
	v[0] = float64(rs.Score) / 100.0
	switch f.Severity {
	case "critical":
		v[1] = 1
	case "high":
		v[1] = 0.75
	case "medium":
		v[1] = 0.45
	default:
		v[1] = 0.2
	}
	if f.Evidence.UID == 0 {
		v[2] = 1
	}
	if f.Destination != "" {
		v[3] = 1
	}
	return v
}

func cosine(a, b []float64) float64 {
	var dot, na, nb float64
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func similarFindings(target Finding, all []Finding, limit int) []map[string]any {
	tv := embedFinding(target)
	type pair struct {
		ID    string
		Score float64
		Rule  string
		Host  string
	}
	var ranked []pair
	for _, f := range all {
		if f.ID == target.ID {
			continue
		}
		ranked = append(ranked, pair{ID: f.ID, Score: cosine(tv, embedFinding(f)), Rule: f.Rule, Host: f.Host})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].Score > ranked[j].Score })
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	out := []map[string]any{}
	for _, p := range ranked {
		out = append(out, map[string]any{"finding_id": p.ID, "similarity": math.Round(p.Score*1000) / 1000, "rule": p.Rule, "host": p.Host})
	}
	return out
}

func classifyBehavior(f Finding) BehaviorClass {
	rule := strings.ToLower(f.Rule + " " + f.Description + " " + f.Evidence.Command)
	switch {
	case strings.Contains(rule, "ransomware") || strings.Contains(rule, "encrypt"):
		return BehaviorClass{Family: "ransomware", Confidence: 0.82, Signals: []string{f.Rule}, TechniqueID: "T1486"}
	case strings.Contains(rule, "download") || strings.Contains(rule, "curl") || strings.Contains(rule, "wget"):
		return BehaviorClass{Family: "dropper_download", Confidence: 0.74, Signals: []string{f.Rule}, TechniqueID: "T1105"}
	case strings.Contains(rule, "netcat") || strings.Contains(rule, "shell") || strings.Contains(rule, "lolbin"):
		return BehaviorClass{Family: "lotl_shell", Confidence: 0.78, Signals: []string{f.Rule}, TechniqueID: "T1059"}
	case strings.Contains(rule, "credential") || strings.Contains(rule, "mimikatz"):
		return BehaviorClass{Family: "credential_access", Confidence: 0.8, Signals: []string{f.Rule}, TechniqueID: "T1003"}
	case f.Destination != "" || strings.Contains(rule, "netra"):
		return BehaviorClass{Family: "c2_network", Confidence: 0.7, Signals: []string{"xdr", f.Destination}, TechniqueID: "T1071"}
	default:
		return BehaviorClass{Family: "suspicious_generic", Confidence: 0.45, Signals: []string{f.Rule}, TechniqueID: "T1082"}
	}
}

func fpScore(f Finding) map[string]any {
	fp := 0.15
	reasons := []string{}
	if f.Severity == "low" {
		fp += 0.25
		reasons = append(reasons, "low severity")
	}
	if strings.Contains(strings.ToLower(f.Evidence.Executable), "agent") || strings.Contains(strings.ToLower(f.Evidence.Command), "healthz") {
		fp += 0.35
		reasons = append(reasons, "benign-looking path/command")
	}
	if f.Evidence.UID != 0 && f.Severity != "high" {
		fp += 0.1
		reasons = append(reasons, "non-root")
	}
	if strings.Contains(f.Rule, "ransomware") || strings.Contains(f.Rule, "credential") {
		fp -= 0.2
		reasons = append(reasons, "high-fidelity rule family")
	}
	if fp < 0 {
		fp = 0
	}
	if fp > 0.95 {
		fp = 0.95
	}
	return map[string]any{"finding_id": f.ID, "fp_likelihood": math.Round(fp*100) / 100, "reasons": reasons, "recommend": map[bool]string{true: "review_as_possible_fp", false: "treat_as_suspicious"}[fp >= 0.6]}
}

func remediationAdvice(f Finding) map[string]any {
	steps := []string{
		"Validate process tree and parent_exe in the finding drawer",
		"Run AI similarity search for related findings",
		"Open NL hunt for the same host and rule family",
		"If confirmed, record a containment_request (ledger only — Kavach will not isolate)",
		"Create a case and attach the AI narrative + attack-path",
	}
	cls := classifyBehavior(f)
	switch cls.Family {
	case "ransomware":
		steps = append([]string{"Prioritize backup integrity checks", "Hunt for shadow-copy deletion IOAs"}, steps...)
	case "c2_network":
		steps = append([]string{"Review Netra deny/allow for destination", "Add detect-only IOC for destination"}, steps...)
	case "credential_access":
		steps = append([]string{"Force credential rotation for affected accounts", "Review Identity password-spray events"}, steps...)
	}
	return map[string]any{
		"finding_id": f.ID, "family": cls.Family, "steps": steps,
		"enforced": false, "note": "Guidance only — observation-only product",
	}
}

func incidentReportMD(f Finding) string {
	d := MapDetection(f)
	rs := ScoreFinding(f)
	cls := classifyBehavior(f)
	return fmt.Sprintf(`# Incident Report — %s

- **Host:** %s
- **Time:** %s
- **Rule:** %s
- **Severity:** %s
- **MITRE:** %s (%s)
- **AI family:** %s (%.0f%%)
- **Risk score:** %d (%s)

## Narrative
%s

## Evidence
- exe: %s
- parent: %s
- cmdline: %s
- pid: %d uid: %d

## Recommended actions
See /v1/ai/remediation?id=%s (guidance only).
`, f.ID, f.Host, f.Time.Format(time.RFC3339), f.Rule, f.Severity, d.TechniqueID, d.Technique,
		cls.Family, cls.Confidence*100, rs.Score, rs.Level, findingNarrative(f),
		f.Evidence.Executable, f.Evidence.ParentExe, f.Evidence.Command, f.Evidence.PID, f.Evidence.UID, f.ID)
}

func envReportMD(store *Store) string {
	return "# Environment Report\n\n" + envNarrative(store) + "\n\nGenerated by Kavach AI.\n"
}

func suggestPlaybooks(f Finding, ok bool) []map[string]any {
	out := []map[string]any{
		{"playbook_id": "pb-1", "name": "High severity notify", "reason": "default high-sev path"},
	}
	if ok {
		if strings.Contains(f.Rule, "ransomware") {
			out = append(out, map[string]any{"playbook_id": "pb-2", "name": "Ransomware burst", "reason": "rule family match"})
		}
		if strings.Contains(f.Rule, "identity") {
			out = append(out, map[string]any{"playbook_id": "pb-3", "name": "Identity spray", "reason": "identity signal"})
		}
	}
	return out
}

func anomalyScores(store *Store) []map[string]any {
	hostN := map[string]int{}
	for _, f := range store.List() {
		hostN[f.Host]++
	}
	out := []map[string]any{}
	store.mu.Lock()
	for _, e := range store.recentEvents {
		score := 10
		factors := []string{}
		if e.UID == 0 {
			score += 20
			factors = append(factors, "root")
		}
		cmd := strings.ToLower(e.Command)
		for _, kw := range []string{"curl", "wget", "nc ", "bash -i", "base64", "/dev/tcp"} {
			if strings.Contains(cmd, kw) {
				score += 15
				factors = append(factors, "cmd:"+kw)
			}
		}
		if hostN[e.Host] > 3 {
			score += 10
			factors = append(factors, "noisy_host")
		}
		if score > 100 {
			score = 100
		}
		out = append(out, map[string]any{
			"entity": e.Host + ":" + e.Executable, "pid": e.PID, "score": score,
			"level": riskLevel(score), "factors": factors, "time": e.Time,
		})
	}
	store.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i]["score"].(int) > out[j]["score"].(int) })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func socAgents() []map[string]any {
	return []map[string]any{
		{"id": "triage", "name": "Triage Agent", "role": "Prioritize and FP-score detections"},
		{"id": "hunt", "name": "Hunt Agent", "role": "Translate hypotheses to NL hunts"},
		{"id": "intel", "name": "Intel Agent", "role": "Enrich with actor/IOC context"},
		{"id": "ir", "name": "IR Agent", "role": "Draft remediation + containment requests"},
		{"id": "reporter", "name": "Reporter Agent", "role": "Produce executive briefings"},
	}
}

func runSOCAgent(agent, input string, store *Store) map[string]any {
	switch strings.ToLower(agent) {
	case "triage":
		return map[string]any{"agent": agent, "output": "Triage pass complete", "autopilot": true, "hint": "POST /v1/ai/autopilot"}
	case "hunt":
		q := nlToHuntQuery(input)
		return map[string]any{"agent": agent, "translated_query": q, "output": "Hunt hypothesis ready", "next": "POST /v1/ai/nl-hunt"}
	case "intel":
		return map[string]any{"agent": agent, "output": "Cross-check /v1/intel/actors and /v1/ioc", "actors": len(actors)}
	case "ir":
		return map[string]any{"agent": agent, "output": "Draft containment_request + case; never auto-enforce", "remediation_api": "/v1/ai/remediation"}
	case "reporter":
		return map[string]any{"agent": agent, "briefing": socBriefing(store)}
	default:
		return map[string]any{"agent": agent, "error": "unknown agent"}
	}
}

func socBriefing(store *Store) map[string]any {
	findings := store.List()
	clusters := clusterFindings(findings)
	top := []string{}
	for i, c := range clusters {
		if i >= 5 {
			break
		}
		top = append(top, c.Summary)
	}
	fc := riskForecast(store)
	return map[string]any{
		"title": "Kavach AI Daily Briefing",
		"generated_at": time.Now().UTC(),
		"headline": envNarrative(store),
		"top_clusters": top,
		"forecast": fc,
		"ai_capabilities": len(AICapabilities()),
		"beyond_falcon": true,
	}
}

func whatIf(scenario, host string, store *Store) map[string]any {
	low := strings.ToLower(scenario)
	path := predictAttackPath(Finding{Host: host, Rule: scenario}, host != "", store)
	impact := "moderate"
	if strings.Contains(low, "ransomware") || strings.Contains(low, "domain admin") {
		impact = "severe"
	}
	return map[string]any{
		"scenario": scenario, "host": host, "impact": impact,
		"simulated_path": path,
		"blast_radius_hosts": []string{host, "adjacent-peer (model)"},
		"recommended_controls": []string{"detect-only IOC", "IOA rule", "Fusion notify playbook"},
		"note": "Simulation only — no host changes",
	}
}

func analyzeStream(store *Store) map[string]any {
	store.mu.Lock()
	procs := len(store.recentEvents)
	nets := len(store.networkEvents)
	store.mu.Unlock()
	suspicious := 0
	for _, a := range anomalyScores(store) {
		if a["score"].(int) >= 40 {
			suspicious++
		}
	}
	return map[string]any{
		"process_events": procs, "network_events": nets,
		"suspicious_entities": suspicious,
		"summary": fmt.Sprintf("Stream analyst reviewed %d process and %d network events; %d entities scored anomalous.", procs, nets, suspicious),
	}
}

func aiGuardian(store *Store) []map[string]any {
	out := []map[string]any{}
	store.mu.Lock()
	for _, e := range store.recentEvents {
		exe := strings.ToLower(e.Executable + " " + e.Command)
		if strings.Contains(exe, "ollama") || strings.Contains(exe, "python") && strings.Contains(exe, "openai") ||
			strings.Contains(exe, "langchain") || strings.Contains(exe, "mcp") || strings.Contains(exe, "llm") {
			out = append(out, map[string]any{
				"host": e.Host, "pid": e.PID, "exe": e.Executable, "risk": "ai_workload",
				"note": "AI/agent process observed — Guardian watch (no block)",
			})
		}
	}
	store.mu.Unlock()
	if len(out) == 0 {
		out = append(out, map[string]any{"note": "No AI workload processes in recent telemetry", "seed": true})
	}
	return out
}

func xdrAIFusion(store *Store) map[string]any {
	findings := store.List()
	xdr := 0
	for _, f := range findings {
		if f.Destination != "" {
			xdr++
		}
		for _, t := range f.Tags {
			if strings.EqualFold(t, "xdr") || strings.EqualFold(t, "netra") {
				xdr++
				break
			}
		}
	}
	store.mu.Lock()
	nets := len(store.networkEvents)
	store.mu.Unlock()
	return map[string]any{
		"endpoint_findings": len(findings),
		"xdr_correlated": xdr,
		"network_events": nets,
		"netra_poller": NetraPollerStatus(),
		"ai_insight": fmt.Sprintf("Fusion model links %d XDR-tagged endpoint findings with %d network events.", xdr, nets),
		"beyond_falcon": "Native Netra×Kavach cross-domain AI — not a third-party SIEM bolt-on",
	}
}

