package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Attack-chain grouping: deterministic, bounded, observation-only.

const (
	chainMaxFindings = 3000
	chainWindow      = 30 * time.Minute
	chainNear        = 10 * time.Minute
	chainMaxNeighbor = 200
	chainThreshold   = 2.0
	chainMaxLinks    = 50
)

const chainMethod = "Findings are nodes. A pair of findings gets an edge weight equal to the sum of independent reasons: " +
	"same provenance story (2.0), shared destination (2.0), shared file hash (2.0), same host within 10 min (1.0) or 30 min (0.5), " +
	"same-host kill-chain progression to a later tactic (1.0), same host and uid (0.25), same rule family (0.25). " +
	"Edges at or above 2.0 merge findings into one chain (union-find); components with fewer than two findings are not chains. " +
	"Pairs are only compared within 30 minutes of each other (provenance links are not time-limited). " +
	"Chain ids are derived from the earliest finding so they stay stable as a chain grows."

var chainLimitations = []string{
	"Heuristic grouping, not proof of a single intrusion: two unrelated activities on one host close in time can be merged.",
	"Only the most recent 3000 findings are considered and each finding is compared with at most 200 later neighbours.",
	"Links across hosts exist only through a shared destination, a shared file hash or a provenance story.",
	"Tactics come from the built-in rule-to-ATT&CK table; rules without a mapping contribute no kill-chain evidence.",
	"Suggested analyst questions are hints derived from tactics not yet seen, not findings.",
}

type ChainReason struct {
	Reason string  `json:"reason"`
	Weight float64 `json:"weight"`
}

type ChainLink struct {
	From    string        `json:"from"`
	To      string        `json:"to"`
	Weight  float64       `json:"weight"`
	Reasons []ChainReason `json:"reasons"`
}

type ChainMember struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Host     string    `json:"host"`
	Rule     string    `json:"rule"`
	Severity string    `json:"severity"`
	Tactic   string    `json:"tactic,omitempty"`
}

type Chain struct {
	ID         string         `json:"id"`
	Hosts      []string       `json:"hosts"`
	Score      float64        `json:"score"`
	ScoreParts map[string]any `json:"score_parts"`
	Severity   string         `json:"severity"`
	Size       int            `json:"size"`
	First      time.Time      `json:"first"`
	Last       time.Time      `json:"last"`
	Tactics    []string       `json:"tactics"`
	FindingIDs []string       `json:"finding_ids"`
	LinkCount  int            `json:"link_count"`
	WhySummary []ChainReason  `json:"why_summary"`
	CaseID     string         `json:"case_id,omitempty"`
	members    []ChainMember
	links      []ChainLink
}

var chainHashRe = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b`)

func chainHashes(f Finding) []string {
	txt := f.Description + " " + strings.Join(f.Tags, " ") + " " + f.Evidence.Command
	seen := map[string]bool{}
	var out []string
	for _, h := range chainHashRe.FindAllString(txt, -1) {
		h = strings.ToLower(h)
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func chainTactic(rule string) string {
	if t := provTacticOf(rule); t != "" {
		return t
	}
	if m, ok := ttpRuleMap()[rule]; ok {
		return m.Tactic
	}
	return ""
}

func chainFamily(rule string) string {
	if i := strings.IndexAny(rule, "._:-"); i > 0 {
		return rule[:i]
	}
	return rule
}

type chainPair struct{ a, b int }

// BuildChains groups findings into chains. prov maps finding id -> provenance story id (may be nil).
func BuildChains(all []Finding, prov map[string]string, host string, minScore float64) []Chain {
	fs := append([]Finding{}, all...)
	sort.SliceStable(fs, func(i, j int) bool {
		if !fs[i].Time.Equal(fs[j].Time) {
			return fs[i].Time.Before(fs[j].Time)
		}
		return fs[i].ID < fs[j].ID
	})
	if len(fs) > chainMaxFindings {
		fs = fs[len(fs)-chainMaxFindings:]
	}
	n := len(fs)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	tactic := make([]string, n)
	hashes := make([][]string, n)
	for i, f := range fs {
		tactic[i] = chainTactic(f.Rule)
		hashes[i] = chainHashes(f)
	}
	edges := map[chainPair]*ChainLink{}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n && j-i <= chainMaxNeighbor; j++ {
			gap := fs[j].Time.Sub(fs[i].Time)
			inWindow := gap <= chainWindow
			var rs []ChainReason
			add := func(r string, w float64) { rs = append(rs, ChainReason{r, w}) }
			si, sj := prov[fs[i].ID], prov[fs[j].ID]
			if si != "" && si == sj {
				add("same provenance story", 2.0)
			}
			if inWindow {
				if fs[i].Destination != "" && fs[i].Destination == fs[j].Destination {
					add("shared destination "+fs[i].Destination, 2.0)
				}
				for _, a := range hashes[i] {
					for _, b := range hashes[j] {
						if a == b {
							add("shared file hash "+a[:12], 2.0)
						}
					}
				}
				if fs[i].Host == fs[j].Host && fs[i].Host != "" {
					if gap <= chainNear {
						add("same host within 10 minutes", 1.0)
					} else {
						add("same host within 30 minutes", 0.5)
					}
					ri, rj := provTacticIndex(tactic[i]), provTacticIndex(tactic[j])
					if ri >= 0 && rj >= 0 && rj > ri {
						add("kill-chain progression "+tactic[i]+" -> "+tactic[j], 1.0)
					}
					if fs[i].Evidence.UID == fs[j].Evidence.UID {
						add("same uid", 0.25)
					}
				}
				if chainFamily(fs[i].Rule) == chainFamily(fs[j].Rule) {
					add("same rule family "+chainFamily(fs[i].Rule), 0.25)
				}
			}
			var tot float64
			for _, r := range rs {
				tot += r.Weight
			}
			if tot >= chainThreshold {
				edges[chainPair{i, j}] = &ChainLink{From: fs[i].ID, To: fs[j].ID, Weight: tot, Reasons: rs}
				if a, b := find(i), find(j); a != b {
					parent[b] = a
				}
			}
		}
	}
	groups := map[int][]int{}
	for i := 0; i < n; i++ {
		r := find(i)
		groups[r] = append(groups[r], i)
	}
	var out []Chain
	for _, g := range groups {
		if len(g) < 2 {
			continue
		}
		sort.Ints(g)
		anchor := fs[g[0]]
		sum := sha256.Sum256([]byte(anchor.ID + "|" + anchor.Time.UTC().Format(time.RFC3339Nano)))
		c := Chain{ID: "chn-" + hex.EncodeToString(sum[:6]), Size: len(g), First: anchor.Time, Last: fs[g[len(g)-1]].Time}
		hostSet, tacSet := map[string]bool{}, map[string]bool{}
		maxSev := ""
		for _, i := range g {
			f := fs[i]
			c.members = append(c.members, ChainMember{ID: f.ID, Time: f.Time, Host: f.Host, Rule: f.Rule, Severity: f.Severity, Tactic: tactic[i]})
			c.FindingIDs = append(c.FindingIDs, f.ID)
			hostSet[f.Host] = true
			if tactic[i] != "" {
				tacSet[tactic[i]] = true
			}
			if caseSeverities[f.Severity] > caseSeverities[maxSev] {
				maxSev = f.Severity
			}
		}
		if maxSev == "" {
			maxSev = "medium"
		}
		c.Severity = maxSev
		for h := range hostSet {
			c.Hosts = append(c.Hosts, h)
		}
		sort.Strings(c.Hosts)
		c.Tactics = []string{}
		for _, t := range attackTactics {
			if tacSet[t] {
				c.Tactics = append(c.Tactics, t)
			}
		}
		in := map[int]bool{}
		for _, i := range g {
			in[i] = true
		}
		var keys []chainPair
		for k := range edges {
			if in[k.a] {
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(x, y int) bool {
			ex, ey := edges[keys[x]], edges[keys[y]]
			if ex.Weight != ey.Weight {
				return ex.Weight > ey.Weight
			}
			if keys[x].a != keys[y].a {
				return keys[x].a < keys[y].a
			}
			return keys[x].b < keys[y].b
		})
		reasonTot := map[string]float64{}
		var wsum float64
		for _, k := range keys {
			e := edges[k]
			c.LinkCount++
			wsum += e.Weight
			if len(c.links) < chainMaxLinks {
				c.links = append(c.links, *e)
			}
			for _, r := range e.Reasons {
				reasonTot[r.Reason] += r.Weight
			}
		}
		for r, w := range reasonTot {
			c.WhySummary = append(c.WhySummary, ChainReason{r, round3(w)})
		}
		sort.Slice(c.WhySummary, func(i, j int) bool {
			if c.WhySummary[i].Weight != c.WhySummary[j].Weight {
				return c.WhySummary[i].Weight > c.WhySummary[j].Weight
			}
			return c.WhySummary[i].Reason < c.WhySummary[j].Reason
		})
		if len(c.WhySummary) > 8 {
			c.WhySummary = c.WhySummary[:8]
		}
		avg := 0.0
		if c.LinkCount > 0 {
			avg = wsum / float64(c.LinkCount)
		}
		c.ScoreParts = map[string]any{
			"distinct_tactics": len(c.Tactics),
			"severity_points":  caseSeverities[maxSev],
			"size_points":      round3(0.3 * float64(minInt(len(g), 10))),
			"host_points":      round3(0.5 * float64(len(c.Hosts)-1)),
			"avg_link_weight":  round3(avg),
		}
		c.Score = round3(float64(len(c.Tactics)) + float64(caseSeverities[maxSev]) + 0.3*float64(minInt(len(g), 10)) + 0.5*float64(len(c.Hosts)-1) + avg)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].ID < out[j].ID
	})
	var res []Chain
	for _, c := range out {
		if c.Score < minScore {
			continue
		}
		if host != "" {
			ok := false
			for _, h := range c.Hosts {
				ok = ok || h == host
			}
			if !ok {
				continue
			}
		}
		res = append(res, c)
	}
	return res
}

var chainQ = map[string]string{
	"Initial Access":       "How did this activity first reach the host (login, download, exposed service)? Nothing in the chain shows an entry point.",
	"Execution":            "What program or script started the observed behaviour? No execution-stage finding is in the chain.",
	"Persistence":          "Was anything left behind to survive a reboot (cron, systemd unit, startup item, keys)?",
	"Privilege Escalation": "Did the actor gain higher privileges than the account first used?",
	"Defense Evasion":      "Were logs, security tools or file timestamps altered around this time?",
	"Credential Access":    "Were credentials, tokens or key files read, and which accounts could they unlock?",
	"Discovery":            "Did the actor enumerate the system, users or network before moving on?",
	"Lateral Movement":     "Did this account or tool reach other hosts after the chain started?",
	"Collection":           "Which data was gathered or staged before any transfer?",
	"Command and Control":  "Is there recurring outbound traffic to a single destination from the affected hosts?",
	"Exfiltration":         "Did a large or unusual outbound transfer follow? Check volumes to the destinations seen.",
	"Impact":               "Were files encrypted, deleted or services stopped after this activity?",
}

// chainQuestions turns missing tactics into hints (never findings).
func chainQuestions(tactics []string) []string {
	have := map[string]bool{}
	lo, hi := len(attackTactics), -1
	for _, t := range tactics {
		have[t] = true
		if i := provTacticIndex(t); i >= 0 {
			lo, hi = minInt(lo, i), maxIntC(hi, i)
		}
	}
	out := []string{}
	if hi < 0 {
		return out
	}
	for i, t := range attackTactics {
		if have[t] || chainQ[t] == "" {
			continue
		}
		if (i < lo && i >= 2 && i <= 4) || (i > hi && i <= hi+2) {
			out = append(out, t+": "+chainQ[t])
		}
	}
	return out
}

func maxIntC(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ = fmt.Sprintf
