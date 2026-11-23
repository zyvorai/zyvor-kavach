// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Diff of two exports of the same device: permissive rules that appeared, deny rules that went
// away, rules whose match changed, and posture findings that are new or resolved. It reads both
// files and adds nothing to the store; the severity is the breadth of the rule, not proof of harm.

type NetcfgDiffItem struct {
	Change   string `json:"change"` // permit-added, deny-removed, deny-added, permit-removed, modified, rule-enabled, rule-disabled
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Location string `json:"location"`
	Detail   string `json:"detail"`
}

type NetcfgDiffSide struct {
	Format string `json:"format"`
	Rules  int    `json:"rules"`
	Score  int    `json:"posture_score"`
	Grade  string `json:"grade"`
}

type NetcfgDiffReport struct {
	Mode        string           `json:"mode"`
	Old         NetcfgDiffSide   `json:"old"`
	New         NetcfgDiffSide   `json:"new"`
	ScoreDelta  int              `json:"score_delta"`
	Items       []NetcfgDiffItem `json:"items"`
	NewFindings []NetcfgItem     `json:"new_findings"`
	Resolved    []NetcfgItem     `json:"resolved_findings"`
	Truncated   bool             `json:"truncated,omitempty"`
	Note        string           `json:"note"`
}

func ncSig(r *ncRule) string {
	return strings.Join([]string{r.Scope, actWord(r.Allow), fmt.Sprint(r.Disabled), strings.Join(r.SrcZ.list(), "+") + fmt.Sprint(r.SrcZ.Any), strings.Join(r.DstZ.list(), "+") + fmt.Sprint(r.DstZ.Any),
		r.Src.sig(), r.Dst.sig(), r.Svc.sig(), strings.Join(r.App.list(), "+") + fmt.Sprint(r.App.Any), r.Extra}, "|")
}

// matchSig is the signature without the enabled flag, so enabling or disabling is reported as such.
func ncSigNoState(r *ncRule) string {
	d := r.Disabled
	r.Disabled = false
	s := ncSig(r)
	r.Disabled = d
	return s
}

func NetcfgDiff(oldRaw, newRaw []byte, format string, opt NetcfgOptions) (*NetcfgDiffReport, error) {
	mo, fo, err := ncParse(oldRaw, format)
	if err != nil {
		return nil, fmt.Errorf("old export: %w", err)
	}
	if format == "" {
		format = "auto"
	}
	mn, fn, err := ncParse(newRaw, func() string {
		if format == "auto" {
			return fo
		}
		return format
	}())
	if err != nil {
		return nil, fmt.Errorf("new export: %w", err)
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now().UTC()
	}
	io, _ := ncAnalyze(mo, opt)
	in, _ := ncAnalyze(mn, opt)
	rep := &NetcfgDiffReport{Mode: "observe-only", Items: []NetcfgDiffItem{}, NewFindings: []NetcfgItem{}, Resolved: []NetcfgItem{}, Truncated: mo.truncated || mn.truncated,
		Note: "a comparison of two configuration exports you supplied; a changed or removed rule is a fact about the files, whether it is a problem needs the change record. Rules are matched by what they match, not by name, so a pure rename is not reported. Order changes are not reported."}
	so, go_ := ncScore(io)
	sn, gn := ncScore(in)
	rep.Old = NetcfgDiffSide{fo, len(mo.Rules), so, go_}
	rep.New = NetcfgDiffSide{fn, len(mn.Rules), sn, gn}
	rep.ScoreDelta = sn - so

	oldCount, newCount := map[string]int{}, map[string]int{}
	oldBy, newBy := map[string][]*ncRule{}, map[string][]*ncRule{}
	for _, r := range mo.Rules {
		k := ncSig(r)
		oldCount[k]++
		oldBy[k] = append(oldBy[k], r)
	}
	for _, r := range mn.Rules {
		k := ncSig(r)
		newCount[k]++
		newBy[k] = append(newBy[k], r)
	}
	// state changes first: same match, different enabled flag
	oldNS, newNS := map[string][]*ncRule{}, map[string][]*ncRule{}
	for _, r := range mo.Rules {
		oldNS[ncSigNoState(r)] = append(oldNS[ncSigNoState(r)], r)
	}
	for _, r := range mn.Rules {
		newNS[ncSigNoState(r)] = append(newNS[ncSigNoState(r)], r)
	}
	handled := map[*ncRule]bool{}
	for k, nr := range newNS {
		or := oldNS[k]
		if len(or) == 0 || len(or) != len(nr) {
			continue
		}
		for i := range nr {
			if or[i].Disabled != nr[i].Disabled {
				handled[or[i]], handled[nr[i]] = true, true
				ch := "rule-enabled"
				sev := "low"
				if nr[i].Disabled {
					ch = "rule-disabled"
				} else if nr[i].Allow {
					sev, _ = ncPermitSeverity(nr[i])
				}
				if !nr[i].Disabled && !nr[i].Allow {
					sev = "info"
				}
				rep.Items = append(rep.Items, NetcfgDiffItem{ch, sev, nr[i].Name, ncClean(nr[i].Loc), "rule " + ncClean(nr[i].Name) + " (" + actWord(nr[i].Allow) + ") is now " + map[bool]string{true: "disabled", false: "enabled"}[nr[i].Disabled]})
			}
		}
	}
	for k, nr := range newBy {
		extra := newCount[k] - oldCount[k]
		for i := len(nr) - 1; i >= 0 && extra > 0; i-- {
			r := nr[i]
			if handled[r] {
				continue
			}
			extra--
			if r.Disabled {
				continue
			}
			if r.Allow {
				sev, why := ncPermitSeverity(r)
				rep.Items = append(rep.Items, NetcfgDiffItem{"permit-added", sev, ncClean(r.Name), ncClean(r.Loc), "new permit rule: " + why})
			} else {
				rep.Items = append(rep.Items, NetcfgDiffItem{"deny-added", "info", ncClean(r.Name), ncClean(r.Loc), "new deny rule"})
			}
		}
	}
	for k, or := range oldBy {
		gone := oldCount[k] - newCount[k]
		for i := len(or) - 1; i >= 0 && gone > 0; i-- {
			r := or[i]
			if handled[r] {
				continue
			}
			gone--
			if r.Disabled {
				continue
			}
			if !r.Allow {
				sev := "medium"
				if r.Src.Any && r.Svc.Any {
					sev = "high"
				}
				rep.Items = append(rep.Items, NetcfgDiffItem{"deny-removed", sev, ncClean(r.Name), ncClean(r.Loc), "a deny rule that was in the old export is gone"})
			} else {
				rep.Items = append(rep.Items, NetcfgDiffItem{"permit-removed", "info", ncClean(r.Name), ncClean(r.Loc), "a permit rule that was in the old export is gone"})
			}
		}
	}
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(rep.Items, func(i, j int) bool {
		a, b := rep.Items[i], rep.Items[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Change != b.Change {
			return a.Change < b.Change
		}
		return a.Location < b.Location
	})
	if len(rep.Items) > 500 {
		rep.Items = rep.Items[:500]
		rep.Truncated = true
	}
	key := func(it NetcfgItem) string { return it.Rule + "|" + it.Detail }
	oldK, newK := map[string]bool{}, map[string]bool{}
	for _, it := range io {
		oldK[key(it)] = true
	}
	for _, it := range in {
		newK[key(it)] = true
	}
	for _, it := range in {
		if !oldK[key(it)] && len(rep.NewFindings) < 200 {
			rep.NewFindings = append(rep.NewFindings, it)
		}
	}
	for _, it := range io {
		if !newK[key(it)] && len(rep.Resolved) < 200 {
			rep.Resolved = append(rep.Resolved, it)
		}
	}
	return rep, nil
}
