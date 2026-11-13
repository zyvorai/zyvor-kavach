// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Loader and inspector analyzer for the byte-pattern packs (bytecontent/*.json).
// Validation runs at load: schema, unique ids, regex/hex compilation, sample
// self-tests and the benign-fixture gate. A bad pack fails the load as a whole.

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

//go:embed bytecontent/*.json
var byteContentFS embed.FS

const (
	bytePackMaxBytes   = 8 << 20
	byteMaxFindingsRun = 60 // findings one inspection can raise from byte rules
	byteAnalyzerName   = "byte-patterns"
)

type bytePack struct {
	Pack  string      `json:"pack,omitempty"`
	Rules []*ByteRule `json:"rules"`
}

// ParseBytePack decodes one pack strictly (unknown fields are errors) and
// compiles every rule. It does not run sample or benign checks.
func ParseBytePack(raw []byte) ([]*ByteRule, error) {
	if len(raw) > bytePackMaxBytes {
		return nil, fmt.Errorf("pack larger than %d bytes", bytePackMaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p bytePack
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	for i, r := range p.Rules {
		if r == nil {
			return nil, fmt.Errorf("rule %d is null", i)
		}
		if err := r.compile(); err != nil {
			return nil, err
		}
	}
	return p.Rules, nil
}

// LoadByteRules loads and fully validates every *.json file in dir of fsys.
func LoadByteRules(fsys fs.FS, dir string) (*ByteRuleSet, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var all []*ByteRule
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		rules, err := ParseBytePack(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		all = append(all, rules...)
		if len(all) > byteMaxRules {
			return nil, fmt.Errorf("more than %d rules", byteMaxRules)
		}
	}
	return buildByteRuleSet(all)
}

func buildByteRuleSet(all []*ByteRule) (*ByteRuleSet, error) {
	set := &ByteRuleSet{byID: map[string]*ByteRule{}}
	for _, r := range all {
		if set.byID[r.ID] != nil {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		set.byID[r.ID] = r
		set.Rules = append(set.Rules, r)
	}
	sort.Slice(set.Rules, func(i, j int) bool { return set.Rules[i].ID < set.Rules[j].ID })
	for _, r := range set.Rules {
		if err := r.selfTest(); err != nil {
			return nil, err
		}
	}
	if err := set.checkBenign(); err != nil {
		return nil, err
	}
	return set, nil
}

// sampleKinds are the inspector kinds a rule's samples are evaluated under.
func (r *ByteRule) sampleKinds() []string {
	switch r.AppliesTo {
	case "file":
		return []string{InspectKindFile}
	case "script":
		return []string{InspectKindScript}
	}
	return []string{InspectKindFile, InspectKindScript}
}

func (r *ByteRule) selfTest() error {
	if len(r.Samples.Positive) == 0 || len(r.Samples.Negative) == 0 {
		return fmt.Errorf("rule %q: needs at least one positive and one negative sample", r.ID)
	}
	if len(r.Samples.Positive) > 8 || len(r.Samples.Negative) > 8 {
		return fmt.Errorf("rule %q: at most 8 samples of each kind", r.ID)
	}
	check := func(list []ByteSample, want bool, label string) error {
		for i, s := range list {
			data, err := s.bytes()
			if err != nil {
				return fmt.Errorf("rule %q: %s sample %d: %v", r.ID, label, i, err)
			}
			if len(data) == 0 || len(data) > byteMaxSampleBytes {
				return fmt.Errorf("rule %q: %s sample %d: size must be 1..%d bytes", r.ID, label, i, byteMaxSampleBytes)
			}
			for _, kind := range r.sampleKinds() {
				_, got := r.match(newByteScan(kind, data))
				if got != want {
					return fmt.Errorf("rule %q: %s sample %d (kind %s): matched=%v, want %v", r.ID, label, i, kind, got, want)
				}
			}
		}
		return nil
	}
	if err := check(r.Samples.Positive, true, "positive"); err != nil {
		return err
	}
	return check(r.Samples.Negative, false, "negative")
}

// checkBenign fails when any rule at medium or above matches ordinary content.
func (set *ByteRuleSet) checkBenign() error {
	for _, f := range byteBenignFixtures() {
		for _, kind := range f.kinds {
			s := newByteScan(kind, f.data)
			for _, r := range set.Rules {
				if byteSeverities[r.Severity] < byteSeverities["medium"] {
					continue
				}
				if _, ok := r.match(s); ok {
					return fmt.Errorf("rule %q (%s) matches benign fixture %q as %s", r.ID, r.Severity, f.name, kind)
				}
			}
		}
	}
	return nil
}

// ---- registry and analyzer ----

var (
	byteSetOnce sync.Once
	byteSet     *ByteRuleSet
	byteSetErr  error
)

// BuiltinByteRules returns the embedded, validated rule set (loaded once).
func BuiltinByteRules() (*ByteRuleSet, error) {
	byteSetOnce.Do(func() {
		byteSet, byteSetErr = LoadByteRules(byteContentFS, "bytecontent")
	})
	return byteSet, byteSetErr
}

func init() {
	RegisterAnalyzer(byteAnalyzerName, []string{InspectKindFile, InspectKindScript}, analyzeBytePatterns)
}

func analyzeBytePatterns(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	set, err := BuiltinByteRules()
	if err != nil {
		return fmt.Errorf("byte rule pack: %w", err)
	}
	data := in.Data
	if in.Kind == InspectKindScript {
		data = []byte(in.Text)
	}
	hits, truncated := set.Scan(ctx, in.Kind, data)
	if truncated {
		b.LimitHit("scan-window")
	}
	for i, h := range hits {
		if i >= byteMaxFindingsRun {
			b.LimitHit("byte-findings")
			break
		}
		r := h.Rule
		ev := make([]string, 0, len(h.Matched))
		for _, n := range h.Matched {
			ev = append(ev, fmt.Sprintf("%s@%d", n, h.Offsets[n]))
		}
		title := r.Name
		if r.Noisy() {
			title += " (noisy-risk)"
		}
		b.Finding(InspectFinding{
			ID:        r.ID,
			Title:     title,
			Severity:  r.Severity,
			Technique: r.Technique,
			Evidence:  "matched " + strings.Join(ev, ", "),
			Weight:    r.Weight,
		})
	}
	b.Meta("rules_evaluated", len(set.Rules))
	b.Meta("rules_matched", len(hits))
	return nil
}
