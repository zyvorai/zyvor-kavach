// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Security configuration assessment analyzer (inspector kind "config").
//
// The analyst submits configuration text; it is sniffed, parsed and checked
// against the embedded policies. Parse-only: nothing is executed, included,
// fetched, applied or stored. Remediation text is advisory. Every finding has
// weight 0: a configuration finding says "this setting differs from a hardening
// expectation", not "this file is malicious", so the inspector's malware-style
// score and level are not meaningful for this kind (use meta config.summary).

import (
	"context"
	"fmt"
	"sort"
)

const cfgAssessNote = "The percentage covers only the submitted file and only the policies that apply to its format; " +
	"unknown and not_applicable results are excluded. It is not an audit of the host, and a file can be fully compliant " +
	"while the running system differs (other include files, drop-ins, defaults changed by the distribution, runtime overrides)."

// ConfigAssessment is the structured outcome of assessing one submitted file.
type ConfigAssessment struct {
	Format        string         `json:"format"`
	Counts        map[string]int `json:"counts"` // pass, fail, not_applicable, unknown
	CompliancePct *float64       `json:"compliance_pct"`
	Evaluated     int            `json:"policies_for_format"`
	OtherFormat   int            `json:"policies_other_formats"`
	Notes         []string       `json:"parse_notes,omitempty"`
	ParseError    string         `json:"parse_error,omitempty"`
	Results       []CfgResult    `json:"results"`
	Note          string         `json:"note"`
}

// AssessConfig sniffs, parses and evaluates text. It never executes anything.
func AssessConfig(ctx context.Context, name, text string) (*ConfigAssessment, error) {
	pols, err := ConfigPolicies()
	if err != nil {
		return nil, err
	}
	a := &ConfigAssessment{Counts: map[string]int{CfgPass: 0, CfgFail: 0, CfgNotApplicable: 0, CfgUnknown: 0}, Note: cfgAssessNote}
	a.Format = SniffConfigFormat(name, text)
	if a.Format == "" {
		return a, nil
	}
	d, perr := parseConfig(a.Format, text)
	if perr != nil {
		a.ParseError = perr.Error()
	}
	if d == nil {
		return a, nil
	}
	a.Notes = d.Notes
	for i := range pols {
		p := &pols[i]
		match := false
		for _, f := range p.AppliesTo.Formats {
			match = match || f == a.Format
		}
		if !match {
			a.OtherFormat++
			continue
		}
		if i%16 == 0 && ctx.Err() != nil {
			return a, ctx.Err()
		}
		r := p.Evaluate(d)
		a.Evaluated++
		a.Counts[r.Status]++
		a.Results = append(a.Results, r)
	}
	if den := a.Counts[CfgPass] + a.Counts[CfgFail]; den > 0 {
		v := float64(int(float64(a.Counts[CfgPass])*1000/float64(den)+0.5)) / 10
		a.CompliancePct = &v
	}
	return a, nil
}

func init() {
	RegisterAnalyzer("config-assess", []string{InspectKindConfig}, configAnalyzer)
}

func configAnalyzer(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	a, err := AssessConfig(ctx, in.Name, in.Text)
	if err != nil && a == nil {
		return err
	}
	if a.Format == "" {
		b.Finding(InspectFinding{ID: "cfg-unrecognized-format", Title: "Configuration format not recognised; no policy applied", Severity: "info"})
		b.Meta("summary", a)
		return nil
	}
	b.Format("config/" + a.Format)
	if a.ParseError != "" {
		b.Finding(InspectFinding{ID: "cfg-parse-error", Title: "Configuration could not be fully parsed: " + a.ParseError, Severity: "info"})
	}
	order := map[string]int{CfgFail: 0, CfgUnknown: 1, CfgPass: 2}
	sevRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	rs := append([]CfgResult(nil), a.Results...)
	sort.SliceStable(rs, func(i, j int) bool {
		if order[rs[i].Status] != order[rs[j].Status] {
			return order[rs[i].Status] < order[rs[j].Status]
		}
		return sevRank[rs[i].Severity] < sevRank[rs[j].Severity]
	})
	for _, r := range rs {
		if r.Status == CfgNotApplicable {
			continue
		}
		sev := "info"
		if r.Status == CfgFail {
			sev = r.Severity
		}
		ev := r.Reason
		if len(r.Evidence) > 0 {
			ev = fmt.Sprint(r.Evidence)
		}
		b.Finding(InspectFinding{ID: r.FindingID, Title: "[" + r.Status + "] " + r.Title, Severity: sev, Evidence: ev})
	}
	b.Meta("summary", a)
	return err
}
