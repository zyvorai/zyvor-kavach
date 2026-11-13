// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Configuration assessment: policy model, loader and condition evaluator.
//
// A policy is a small declarative condition over the settings parsed out of a
// submitted configuration file. Policies are original wording (see
// docs/config-assessment.md); they describe public hardening concepts and do
// not reproduce any benchmark text or numbering. Nothing here executes the
// submitted text or touches the host.

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed configpolicies/*.json
var configPolicyFS embed.FS

// Config formats the assessor understands.
const (
	CfgSSHD       = "sshd"
	CfgSysctl     = "sysctl"
	CfgLoginDefs  = "logindefs"
	CfgSudoers    = "sudoers"
	CfgAuditd     = "auditd"
	CfgPAM        = "pam"
	CfgNginx      = "nginx"
	CfgApache     = "apache"
	CfgK8s        = "k8s"
	CfgDockerfile = "dockerfile"
	CfgCompose    = "compose"
	CfgTerraform  = "terraform"
)

var cfgFormats = []string{CfgSSHD, CfgSysctl, CfgLoginDefs, CfgSudoers, CfgAuditd, CfgPAM, CfgNginx, CfgApache, CfgK8s, CfgDockerfile, CfgCompose, CfgTerraform}

const cfgMaxRegex = 256

// CfgSample is a self-test sample: Positive must make the policy fail,
// Negative must make it pass.
type CfgSample struct {
	Format   string `json:"format"`
	Positive string `json:"positive"`
	Negative string `json:"negative"`
}

// CfgPolicy is one configuration check.
type CfgPolicy struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Rationale   string `json:"rationale"`
	Severity    string `json:"severity"`
	Area        string `json:"area,omitempty"`
	AppliesTo   struct {
		Formats []string `json:"formats"`
		Hints   []string `json:"hints,omitempty"` // informational product hints
	} `json:"applies_to"`
	AppliesWhen *CfgCond `json:"applies_when,omitempty"` // false => not_applicable
	Check       *CfgCond `json:"check"`                  // true => pass
	// OnAbsent says what an absent setting means: fail | pass | unknown, or
	// "evaluate" when the check itself handles absence (present/absent ops).
	OnAbsent    string      `json:"on_absent"`
	AbsenceNote string      `json:"absence_note"` // documents the default that applies when absent
	Remediation string      `json:"remediation"`  // advisory only, never applied
	References  []string    `json:"references,omitempty"`
	Frameworks  []string    `json:"frameworks,omitempty"` // ATT&CK / NIST hints, optional
	Positive    string      `json:"positive"`
	Negative    string      `json:"negative"`
	More        []CfgSample `json:"more_samples,omitempty"`
}

// CfgCond is a declarative condition: a leaf over one setting, or all/any/not.
type CfgCond struct {
	Key      string     `json:"key,omitempty"`       // setting key (case-insensitive; '*' is a glob)
	KeyRegex string     `json:"key_regex,omitempty"` // alternative: match keys by regex
	Op       string     `json:"op,omitempty"`        // equals not_equals in not_in regex not_regex present absent lt le gt ge
	Value    string     `json:"value,omitempty"`
	Values   []string   `json:"values,omitempty"`
	Occ      string     `json:"occ,omitempty"` // all|any|first|last; default is the format's
	All      []*CfgCond `json:"all,omitempty"`
	Any      []*CfgCond `json:"any,omitempty"`
	Not      *CfgCond   `json:"not,omitempty"`

	re  *regexp.Regexp
	kre *regexp.Regexp
	num float64
}

type cfgPolicyFile struct {
	Area     string      `json:"area"`
	Policies []CfgPolicy `json:"policies"`
}

var (
	cfgPolicies   []CfgPolicy
	cfgPolicyErr  error
	cfgPolicyOnce sync.Once
)

var cfgIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,60}$`)

// ConfigPolicies returns the embedded, validated policies.
func ConfigPolicies() ([]CfgPolicy, error) {
	cfgPolicyOnce.Do(func() { cfgPolicies, cfgPolicyErr = loadConfigPolicies() })
	return cfgPolicies, cfgPolicyErr
}

func loadConfigPolicies() ([]CfgPolicy, error) {
	ents, err := configPolicyFS.ReadDir("configpolicies")
	if err != nil {
		return nil, err
	}
	var out []CfgPolicy
	seen := map[string]bool{}
	var errs []string
	for _, e := range ents {
		raw, err := configPolicyFS.ReadFile("configpolicies/" + e.Name())
		if err != nil {
			return nil, err
		}
		var f cfgPolicyFile
		if err := json.Unmarshal(raw, &f); err != nil {
			errs = append(errs, e.Name()+": "+err.Error())
			continue
		}
		for i := range f.Policies {
			p := f.Policies[i]
			p.Area = f.Area
			if seen[p.ID] {
				errs = append(errs, "duplicate id "+p.ID)
			}
			seen[p.ID] = true
			if err := p.validate(); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", p.ID, err))
			}
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(errs) > 0 {
		return out, fmt.Errorf("config policy errors: %s", strings.Join(errs, "; "))
	}
	return out, nil
}

func cfgKnownFormat(f string) bool {
	for _, x := range cfgFormats {
		if x == f {
			return true
		}
	}
	return false
}

func (p *CfgPolicy) validate() error {
	if !cfgIDRe.MatchString(p.ID) {
		return fmt.Errorf("bad id")
	}
	if strings.TrimSpace(p.Title) == "" || strings.TrimSpace(p.Description) == "" || strings.TrimSpace(p.Rationale) == "" {
		return fmt.Errorf("title, description and rationale are required")
	}
	if strings.TrimSpace(p.Remediation) == "" {
		return fmt.Errorf("remediation text is required")
	}
	if strings.TrimSpace(p.AbsenceNote) == "" {
		return fmt.Errorf("absence_note is required")
	}
	switch p.Severity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("invalid severity %q", p.Severity)
	}
	switch p.OnAbsent {
	case "fail", "pass", "unknown", "evaluate":
	default:
		return fmt.Errorf("invalid on_absent %q", p.OnAbsent)
	}
	if len(p.AppliesTo.Formats) == 0 {
		return fmt.Errorf("applies_to.formats is empty")
	}
	for _, f := range p.AppliesTo.Formats {
		if !cfgKnownFormat(f) {
			return fmt.Errorf("unknown format %q", f)
		}
	}
	if p.Check == nil {
		return fmt.Errorf("check is required")
	}
	if err := p.Check.compile(); err != nil {
		return err
	}
	if p.AppliesWhen != nil {
		if err := p.AppliesWhen.compile(); err != nil {
			return fmt.Errorf("applies_when: %v", err)
		}
	}
	if strings.TrimSpace(p.Positive) == "" || strings.TrimSpace(p.Negative) == "" {
		return fmt.Errorf("positive and negative samples are required")
	}
	return nil
}

func cfgCompileRe(s string) (*regexp.Regexp, error) {
	if len(s) > cfgMaxRegex {
		return nil, fmt.Errorf("regex longer than %d chars", cfgMaxRegex)
	}
	return regexp.Compile(s)
}

func (c *CfgCond) compile() error {
	n := 0
	if c.Key != "" || c.KeyRegex != "" {
		n++
	}
	if len(c.All) > 0 {
		n++
	}
	if len(c.Any) > 0 {
		n++
	}
	if c.Not != nil {
		n++
	}
	if n != 1 {
		return fmt.Errorf("a condition must be exactly one of a leaf, all, any or not")
	}
	switch {
	case len(c.All) > 0:
		for _, s := range c.All {
			if err := s.compile(); err != nil {
				return err
			}
		}
		return nil
	case len(c.Any) > 0:
		for _, s := range c.Any {
			if err := s.compile(); err != nil {
				return err
			}
		}
		return nil
	case c.Not != nil:
		return c.Not.compile()
	}
	if c.Key != "" && c.KeyRegex != "" {
		return fmt.Errorf("leaf has both key and key_regex")
	}
	c.Key = strings.ToLower(c.Key)
	if c.KeyRegex != "" {
		re, err := cfgCompileRe(c.KeyRegex)
		if err != nil {
			return fmt.Errorf("key_regex: %v", err)
		}
		c.kre = re
	} else if strings.Contains(c.Key, "*") {
		re, err := cfgCompileRe("^" + strings.ReplaceAll(regexp.QuoteMeta(c.Key), `\*`, ".*") + "$")
		if err != nil {
			return err
		}
		c.kre = re
	}
	switch c.Occ {
	case "", "all", "any", "first", "last":
	default:
		return fmt.Errorf("bad occ %q", c.Occ)
	}
	switch c.Op {
	case "present", "absent", "equals", "not_equals":
	case "in", "not_in":
		if len(c.Values) == 0 {
			return fmt.Errorf("op %s needs values", c.Op)
		}
	case "regex", "not_regex":
		re, err := cfgCompileRe(c.Value)
		if err != nil {
			return fmt.Errorf("value regex: %v", err)
		}
		c.re = re
	case "lt", "le", "gt", "ge":
		f, err := strconv.ParseFloat(strings.TrimSpace(c.Value), 64)
		if err != nil {
			return fmt.Errorf("op %s needs a numeric value", c.Op)
		}
		c.num = f
	default:
		return fmt.Errorf("unknown op %q", c.Op)
	}
	return nil
}

// ---- evaluation ----

type cfgEntry struct {
	Key   string
	Value string
	Line  int
}

type cfgDoc struct {
	Format  string
	Entries []cfgEntry
	DefOcc  string
	Notes   []string
	byKey   map[string][]int
}

func (d *cfgDoc) add(key, value string, line int) {
	if d.byKey == nil {
		d.byKey = map[string][]int{}
	}
	key = strings.ToLower(key)
	d.Entries = append(d.Entries, cfgEntry{Key: key, Value: value, Line: line})
	d.byKey[key] = append(d.byKey[key], len(d.Entries)-1)
}

func (c *CfgCond) selectEntries(d *cfgDoc) []cfgEntry {
	var out []cfgEntry
	if c.kre != nil {
		for _, e := range d.Entries {
			if c.kre.MatchString(e.Key) {
				out = append(out, e)
			}
		}
		return out
	}
	for _, i := range d.byKey[c.Key] {
		out = append(out, d.Entries[i])
	}
	return out
}

func cfgLeadingNumber(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && (s[end] >= '0' && s[end] <= '9' || s[end] == '.' || (end == 0 && (s[end] == '-' || s[end] == '+'))) {
		end++
	}
	if end == 0 {
		return 0, false
	}
	f, err := strconv.ParseFloat(s[:end], 64)
	return f, err == nil
}

func (c *CfgCond) valueOK(v string) bool {
	switch c.Op {
	case "equals":
		return strings.EqualFold(v, c.Value)
	case "not_equals":
		return !strings.EqualFold(v, c.Value)
	case "in", "not_in":
		hit := false
		for _, x := range c.Values {
			if strings.EqualFold(v, x) {
				hit = true
				break
			}
		}
		return hit == (c.Op == "in")
	case "regex":
		return c.re.MatchString(v)
	case "not_regex":
		return !c.re.MatchString(v)
	case "lt", "le", "gt", "ge":
		f, ok := cfgLeadingNumber(v)
		if !ok {
			return false
		}
		switch c.Op {
		case "lt":
			return f < c.num
		case "le":
			return f <= c.num
		case "gt":
			return f > c.num
		}
		return f >= c.num
	}
	return false
}

func (c *CfgCond) eval(d *cfgDoc) bool {
	switch {
	case len(c.All) > 0:
		for _, s := range c.All {
			if !s.eval(d) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for _, s := range c.Any {
			if s.eval(d) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !c.Not.eval(d)
	}
	es := c.selectEntries(d)
	switch c.Op {
	case "present":
		return len(es) > 0
	case "absent":
		return len(es) == 0
	}
	if len(es) == 0 {
		return false
	}
	occ := c.Occ
	if occ == "" {
		occ = d.DefOcc
	}
	switch occ {
	case "first":
		return c.valueOK(es[0].Value)
	case "last":
		return c.valueOK(es[len(es)-1].Value)
	case "any":
		for _, e := range es {
			if c.valueOK(e.Value) {
				return true
			}
		}
		return false
	}
	for _, e := range es {
		if !c.valueOK(e.Value) {
			return false
		}
	}
	return true
}

// leaves collects the leaf conditions (used for absence and evidence).
func (c *CfgCond) leaves(out *[]*CfgCond) {
	for _, s := range c.All {
		s.leaves(out)
	}
	for _, s := range c.Any {
		s.leaves(out)
	}
	if c.Not != nil {
		c.Not.leaves(out)
	}
	if c.Key != "" || c.KeyRegex != "" {
		*out = append(*out, c)
	}
}

// Status values.
const (
	CfgPass          = "pass"
	CfgFail          = "fail"
	CfgNotApplicable = "not_applicable"
	CfgUnknown       = "unknown"
)

// CfgResult is the outcome of one policy on one document.
type CfgResult struct {
	PolicyID    string   `json:"policy_id"`
	FindingID   string   `json:"finding_id"`
	Title       string   `json:"title"`
	Area        string   `json:"area"`
	Severity    string   `json:"severity"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	AbsenceNote string   `json:"absence_note,omitempty"`
	Frameworks  []string `json:"frameworks,omitempty"`
}

var cfgSecretKeyRe = regexp.MustCompile(`(?i)(passw(or)?d|secret|token|api_?key|access_?key|private_?key|credential)`)

func cfgEvidence(p *CfgPolicy, d *cfgDoc) []string {
	var ls []*CfgCond
	p.Check.leaves(&ls)
	var out []string
	seen := map[string]bool{}
	for _, l := range ls {
		for _, e := range l.selectEntries(d) {
			v := e.Value
			if cfgSecretKeyRe.MatchString(e.Key) {
				v = "[redacted]"
			} else if i := strings.Index(v, "="); i > 0 && cfgSecretKeyRe.MatchString(v[:i]) {
				v = v[:i] + "=[redacted]"
			}
			if len(v) > 120 {
				v = v[:120] + "..."
			}
			s := e.Key + " = " + v
			if e.Line > 0 {
				s = fmt.Sprintf("line %d: %s", e.Line, s)
			}
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
			if len(out) >= 4 {
				return out
			}
		}
	}
	return out
}

// Evaluate runs the policy on a parsed document.
func (p *CfgPolicy) Evaluate(d *cfgDoc) CfgResult {
	r := CfgResult{PolicyID: p.ID, FindingID: "cfg-" + p.ID, Title: p.Title, Area: p.Area, Severity: p.Severity,
		Remediation: p.Remediation, AbsenceNote: p.AbsenceNote, Frameworks: p.Frameworks}
	if p.AppliesWhen != nil && !p.AppliesWhen.eval(d) {
		r.Status = CfgNotApplicable
		r.Reason = "precondition for this policy is not met by the submitted file"
		return r
	}
	if p.OnAbsent != "evaluate" {
		var ls []*CfgCond
		p.Check.leaves(&ls)
		seen := false
		for _, l := range ls {
			if len(l.selectEntries(d)) > 0 {
				seen = true
				break
			}
		}
		if !seen {
			r.Status = p.OnAbsent
			r.Reason = "setting not present; default applies: " + p.AbsenceNote
			return r
		}
	}
	if p.Check.eval(d) {
		r.Status = CfgPass
	} else {
		r.Status = CfgFail
	}
	r.Evidence = cfgEvidence(p, d)
	return r
}

// cfgSelfTest verifies a policy's declared samples.
func cfgSelfTest(p *CfgPolicy) error {
	samples := append([]CfgSample{{Format: p.AppliesTo.Formats[0], Positive: p.Positive, Negative: p.Negative}}, p.More...)
	for i, s := range samples {
		if s.Format == "" {
			s.Format = p.AppliesTo.Formats[0]
		}
		ok := false
		for _, f := range p.AppliesTo.Formats {
			ok = ok || f == s.Format
		}
		if !ok {
			return fmt.Errorf("sample %d: format %s not in applies_to", i, s.Format)
		}
		for _, c := range []struct{ text, want string }{{s.Positive, CfgFail}, {s.Negative, CfgPass}} {
			d, err := parseConfig(s.Format, c.text)
			if err != nil {
				return fmt.Errorf("sample %d (%s): parse: %v", i, c.want, err)
			}
			if got := p.Evaluate(d); got.Status != c.want {
				return fmt.Errorf("sample %d: want %s got %s (%s)", i, c.want, got.Status, got.Reason)
			}
		}
	}
	return nil
}
