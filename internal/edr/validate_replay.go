// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// In-memory replay of synthetic scenario events through the detection engines. It never executes
// anything, never touches the host, and never writes to the Store, the ledger, the SIEM exporter or
// any other process-wide state: engines are invoked as pure functions against a private registry.

const valHost = "lab-host-01.synthetic"

func (sc *ValScenario) baseTime() time.Time {
	return time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
}

func (s *ValStep) when(sc *ValScenario, i int) time.Time {
	off := s.At
	if off == 0 {
		off = i * 2
	}
	return sc.baseTime().Add(time.Duration(off) * time.Second)
}

func (s *ValStep) telemetry(host string, t time.Time) TelemetryEvent {
	return TelemetryEvent{Time: t, Host: host, PID: s.PID, User: s.User, Key: s.Key, ValueName: s.ValueName,
		ValueData: s.ValueData, Operation: s.Operation, Query: s.Query, QType: s.QType, Answers: s.Answers,
		Resolver: s.Resolver, SourceIP: s.SourceIP, Method: s.Method, Outcome: s.Outcome,
		ModulePath: s.ModulePath, Hash: s.Hash, Signed: s.Signed, Signer: s.Signer, Kind: s.ModuleKind}
}

// ValFired is one detection that fired during replay.
type ValFired struct {
	Step        int    `json:"step"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Engine      string `json:"engine"` // builtin | content | ioc | ioa | correlation | file-rate | custom
	TechniqueID string `json:"technique_id,omitempty"`
	Tactic      string `json:"tactic,omitempty"`
	Mapped      bool   `json:"mapped"` // false: the rule has no ATT&CK mapping
}

// ValExpectOutcome is the verdict for one expectation.
type ValExpectOutcome struct {
	Expect string   `json:"expect"`
	Status string   `json:"status"` // detected | partial | missed
	Reason string   `json:"reason,omitempty"`
	Rules  []string `json:"rules,omitempty"`
}

// ValResult is the replay outcome of one scenario.
type ValResult struct {
	ID            string             `json:"id"`
	Name          string             `json:"name"`
	Kind          string             `json:"kind"`
	Benign        bool               `json:"benign"`
	Steps         int                `json:"steps"`
	Fired         []ValFired         `json:"fired"`
	Outcomes      []ValExpectOutcome `json:"outcomes,omitempty"`
	Pass          bool               `json:"pass"`
	FalsePositive bool               `json:"false_positive,omitempty"` // benign scenario fired at medium or above
	Detail        string             `json:"detail,omitempty"`
}

// ValOptions controls a replay.
type ValOptions struct {
	// IncludeCustom evaluates the live content registry (embedded plus customer rules) instead of the
	// isolated embedded-only registry.
	IncludeCustom bool
}

var (
	isoOnce sync.Once
	isoReg  *ContentRegistry
)

// valRegistry returns the private, immutable registry built from the embedded packs only.
func valRegistry(o ValOptions) *ContentRegistry {
	if o.IncludeCustom {
		if r := contentReg.Load(); r != nil {
			return r
		}
	}
	isoOnce.Do(func() {
		packs, err := embeddedContentPacks()
		if err == nil {
			isoReg, _ = buildContentRegistry(packs)
		}
		if isoReg == nil {
			isoReg = &ContentRegistry{byID: map[string]*ContentRule{}, byType: map[string][]*ContentRule{}}
		}
	})
	return isoReg
}

func engineOf(f Finding) string {
	for _, t := range f.Tags {
		switch t {
		case "content":
			return "content"
		case "ioc":
			return "ioc"
		case "ioa":
			return "ioa"
		case "custom-rule":
			return "custom"
		}
	}
	switch f.Rule {
	case "netra-denied-process":
		return "correlation"
	case "mass-file-activity":
		return "file-rate"
	}
	return "builtin"
}

// valTechnique resolves a finding to an ATT&CK technique WITHOUT the silent T1082 fallback that
// MapDetection applies: an unmapped rule is reported as unmapped.
func valTechnique(reg *ContentRegistry, f Finding) (id, tactic string, ok bool) {
	if m, found := ruleMITRE[f.Rule]; found {
		return m.ID, m.Tactic, true
	}
	if r := reg.byID[f.Rule]; r != nil {
		return r.Technique, r.Tactic, true
	}
	if engineOf(f) == "ioa" {
		for _, t := range f.Tags {
			if labTechRe.MatchString(t) {
				return t, valTacticFor(reg, t), true
			}
		}
	}
	return "", "", false
}

func valTacticFor(reg *ContentRegistry, tech string) string {
	for _, r := range reg.rules {
		if r.Technique == tech {
			return r.Tactic
		}
	}
	for _, m := range ruleMITRE {
		if m.ID == tech {
			return m.Tactic
		}
	}
	return ""
}

// ReplayScenario replays one scenario in memory and scores its expectations.
func ReplayScenario(sc ValScenario, o ValOptions) ValResult {
	reg := valRegistry(o)
	res := ValResult{ID: sc.ID, Name: sc.Name, Kind: sc.Kind, Benign: sc.Benign, Steps: len(sc.Steps), Fired: []ValFired{}}
	detector := &FileDetections{} // private, fresh rate window
	authBurst := &AuthBurstDetector{}
	var procs []Event
	var nets []NetworkEvent
	pidCounter := 4000
	record := func(step int, fs []Finding) {
		for _, f := range fs {
			id, tac, ok := valTechnique(reg, f)
			res.Fired = append(res.Fired, ValFired{Step: step, Rule: f.Rule, Severity: f.Severity,
				Engine: engineOf(f), TechniqueID: id, Tactic: tac, Mapped: ok})
		}
	}
	for i := range sc.Steps {
		s := &sc.Steps[i]
		t := s.when(&sc, i)
		pid := s.PID
		if pid == 0 {
			pid = pidCounter + i
		}
		switch s.Type {
		case "process":
			uid := 1000
			if s.UID != nil {
				uid = *s.UID
			}
			e := Event{Time: t, Host: valHost, PID: pid, PPID: 1, UID: uid, Executable: s.Executable, ParentExe: s.ParentExe, Command: s.Command}
			fs := Detect(e) // the live process detector: built-in rules, IOC, IOA, custom rules, content
			if !o.IncludeCustom {
				// Replace live-registry results with the isolated registry and drop process-global
				// customer rules so the measurement depends only on shipped content.
				kept := fs[:0:0]
				for _, f := range fs {
					if engineOf(f) == "content" || engineOf(f) == "custom" {
						continue
					}
					kept = append(kept, f)
				}
				fs = kept
				euid := e.UID
				fs = append(fs, contentEvaluateWith(reg, "process", LabEvent{Time: e.Time, Host: e.Host, UID: &euid,
					Executable: e.Executable, ParentExe: e.ParentExe, Command: e.Command},
					Finding{Time: e.Time, Host: e.Host, PID: e.PID, Evidence: e})...)
			}
			for _, n := range nets {
				if correlates(e, n) {
					fs = append(fs, correlationFinding(e, n))
				}
			}
			procs = append(procs, e)
			record(i, fs)
		case "network":
			n := NetworkEvent{Time: t, Host: valHost, PID: pid, Destination: s.Destination, Verdict: s.Verdict}
			fs := contentEvaluateWith(reg, "network", LabEvent{Time: t, Host: valHost, Destination: n.Destination},
				Finding{Time: t, Host: valHost, PID: pid, Destination: n.Destination, Evidence: Event{Time: t, Host: valHost, PID: pid}})
			for _, e := range procs {
				if correlates(e, n) {
					fs = append(fs, correlationFinding(e, n))
				}
			}
			nets = append(nets, n)
			record(i, fs)
		case "file":
			fe := FileEvent{Time: t, Host: valHost, Path: s.Path, Operation: s.Operation, Size: s.Size, PID: s.PID}
			fs := detector.Observe(fe)
			fs = append(fs, contentEvaluateWith(reg, "file", LabEvent{Time: t, Host: valHost, Path: fe.Path, Operation: fe.Operation},
				Finding{Time: t, Host: valHost, PID: fe.PID, Evidence: Event{Time: t, Host: valHost, PID: fe.PID, Command: fe.Operation + " " + fe.Path}})...)
			record(i, fs)
		default:
			te := s.telemetry(valHost, t)
			if err := te.Validate(s.Type); err != nil {
				res.Detail = fmt.Sprintf("step %d rejected by telemetry validation: %v", i, err)
				continue
			}
			summary := telemetrySummary(s.Type, te)
			base := Finding{Time: t, Host: valHost, PID: te.PID, Evidence: Event{Time: t, Host: valHost, PID: te.PID, Command: summary}}
			if s.Type == "dns" {
				base.Destination = te.Query
			}
			fs := contentEvaluateWith(reg, s.Type, contentTelemetryEvent(s.Type, te), base)
			if s.Type == "auth" {
				fs = append(fs, authBurst.Observe(te)...)
			}
			record(i, fs)
		}
	}
	sort.SliceStable(res.Fired, func(a, b int) bool { return res.Fired[a].Step < res.Fired[b].Step })
	scoreScenario(&sc, reg, &res)
	return res
}

func sameFamily(expected, got string) (exact bool, family bool) {
	if expected == got {
		return true, true
	}
	// A sub-technique detection satisfies an expectation of its parent technique.
	if !strings.Contains(expected, ".") && strings.HasPrefix(got, expected+".") {
		return false, true
	}
	return false, false
}

func scoreScenario(sc *ValScenario, reg *ContentRegistry, res *ValResult) {
	if sc.Benign {
		for _, f := range res.Fired {
			if valSevRank[f.Severity] >= valSevRank["medium"] {
				res.FalsePositive = true
			}
		}
		res.Pass = !res.FalsePositive
		if res.FalsePositive {
			var rs []string
			for _, f := range res.Fired {
				if valSevRank[f.Severity] >= valSevRank["medium"] {
					rs = append(rs, f.Rule)
				}
			}
			res.Detail = "benign control fired at medium or above: " + strings.Join(dedupSorted(rs), ", ")
		}
		return
	}
	res.Pass = true
	for _, x := range sc.Expectations() {
		o := ValExpectOutcome{Expect: x, Status: "missed"}
		if labTechRe.MatchString(x) {
			var tacticOfX string
			tacticOfX = valTacticFor(reg, x)
			for _, f := range res.Fired {
				if !f.Mapped {
					continue
				}
				if _, fam := sameFamily(x, f.TechniqueID); fam {
					o.Status = "detected"
					o.Rules = append(o.Rules, f.Rule)
				}
			}
			if o.Status != "detected" {
				parent, sameTactic, other := "", false, false
				for _, f := range res.Fired {
					o.Rules = append(o.Rules, f.Rule)
					switch {
					case f.Mapped && strings.HasPrefix(x, f.TechniqueID+"."):
						parent = f.TechniqueID
					case f.Mapped && tacticOfX != "" && f.Tactic == tacticOfX:
						sameTactic = true
					default:
						other = true
					}
				}
				switch {
				case parent != "":
					o.Status, o.Reason = "partial", "only the parent technique "+parent+" fired"
				case sameTactic:
					o.Status, o.Reason = "partial", "a different technique in the same tactic fired"
				case other:
					o.Status, o.Reason = "partial", "only rules for other tactics (or unmapped rules) fired"
				}
			}
		} else {
			for _, f := range res.Fired {
				if f.Rule == x {
					o.Status = "detected"
					o.Rules = append(o.Rules, f.Rule)
				}
			}
		}
		o.Rules = dedupSorted(o.Rules)
		if o.Status != "detected" {
			res.Pass = false
		}
		res.Outcomes = append(res.Outcomes, o)
	}
	// Step-level expectations must fire on that step (otherwise: detected later than expected).
	for i := range sc.Steps {
		for _, x := range sc.Steps[i].Expect {
			ok := false
			for _, f := range res.Fired {
				if f.Step != i {
					continue
				}
				if f.Rule == x {
					ok = true
				}
				if _, fam := sameFamily(x, f.TechniqueID); fam && f.Mapped {
					ok = true
				}
			}
			if !ok {
				res.Pass = false
				if res.Detail != "" {
					res.Detail += "; "
				}
				res.Detail += fmt.Sprintf("step %d expected %s but nothing matching fired on that step", i, x)
			}
		}
	}
}
