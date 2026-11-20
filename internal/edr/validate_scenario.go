// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Detection validation lab: scenario format and loader. A scenario is an ordered list of SYNTHETIC
// EVENTS (data only). Nothing here executes anything; the replay engine (validate_replay.go) feeds
// the events to the detection engines in memory. Scenarios are original to this project.

//go:embed scenarios/*.json
var scenarioFS embed.FS

const (
	valMaxSteps     = 40
	valMaxScenarios = 600
	valNote         = "Synthetic data replayed in memory; measured on Kavach's own scenarios; not a guarantee against real attacks."
)

var (
	valIDRe       = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	valPlatforms  = map[string]bool{"linux": true, "macos": true, "windows": true}
	valStepTypes  = map[string]bool{"process": true, "network": true, "file": true, "registry": true, "dns": true, "auth": true, "module": true}
	valKinds      = map[string]bool{"single": true, "chain": true, "benign": true}
	valStepFields = map[string][]string{} // filled in init: allowed fields per step type
	valSevRank    = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
)

// ValStep is one synthetic event. Only the fields that belong to the step type may be set.
type ValStep struct {
	Type   string   `json:"type"`
	At     int      `json:"at,omitempty"` // seconds after scenario start (default: 2s per step)
	Note   string   `json:"note,omitempty"`
	Expect []string `json:"expect,omitempty"` // technique ids or rule ids expected to fire on this step

	PID int `json:"pid,omitempty"`
	// process
	UID        *int   `json:"uid,omitempty"`
	Executable string `json:"executable,omitempty"`
	ParentExe  string `json:"parent_exe,omitempty"`
	Command    string `json:"command,omitempty"`
	// network
	Destination string `json:"destination,omitempty"`
	Verdict     string `json:"verdict,omitempty"`
	// file
	Path      string `json:"path,omitempty"`
	Operation string `json:"operation,omitempty"`
	Size      int64  `json:"size,omitempty"`
	// registry
	Key       string `json:"key,omitempty"`
	ValueName string `json:"value_name,omitempty"`
	ValueData string `json:"value_data,omitempty"`
	// dns
	Query    string   `json:"query,omitempty"`
	QType    string   `json:"qtype,omitempty"`
	Answers  []string `json:"answers,omitempty"`
	Resolver string   `json:"resolver,omitempty"`
	// auth
	User     string `json:"user,omitempty"`
	SourceIP string `json:"source_ip,omitempty"`
	Method   string `json:"method,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	// module
	ModulePath string `json:"module_path,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Signed     bool   `json:"signed,omitempty"`
	Signer     string `json:"signer,omitempty"`
	ModuleKind string `json:"module_kind,omitempty"`
}

// ValScenario is one validation scenario.
type ValScenario struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Kind        string    `json:"kind"` // single | chain | benign
	Platform    string    `json:"platform"`
	Tactics     []string  `json:"tactics,omitempty"`
	Techniques  []string  `json:"techniques,omitempty"` // techniques the scenario emulates
	Benign      bool      `json:"benign"`               // negative control: nothing at medium+ may fire
	Steps       []ValStep `json:"steps"`
	Expect      []string  `json:"expect,omitempty"` // overall expectations (technique ids or rule ids)
}

type valFile struct {
	Scenarios []ValScenario `json:"scenarios"`
}

type valNotTestableFile struct {
	// Technique id -> reason Kavach cannot be measured for it with synthetic events.
	NotTestable map[string]string `json:"not_testable"`
}

// stepFieldSet reports which optional fields a step carries (by json name).
func (s *ValStep) fieldsSet() []string {
	var f []string
	add := func(ok bool, n string) {
		if ok {
			f = append(f, n)
		}
	}
	add(s.UID != nil, "uid")
	add(s.Executable != "", "executable")
	add(s.ParentExe != "", "parent_exe")
	add(s.Command != "", "command")
	add(s.Destination != "", "destination")
	add(s.Verdict != "", "verdict")
	add(s.Path != "", "path")
	add(s.Operation != "", "operation")
	add(s.Size != 0, "size")
	add(s.Key != "", "key")
	add(s.ValueName != "", "value_name")
	add(s.ValueData != "", "value_data")
	add(s.Query != "", "query")
	add(s.QType != "", "qtype")
	add(len(s.Answers) > 0, "answers")
	add(s.Resolver != "", "resolver")
	add(s.User != "", "user")
	add(s.SourceIP != "", "source_ip")
	add(s.Method != "", "method")
	add(s.Outcome != "", "outcome")
	add(s.ModulePath != "", "module_path")
	add(s.Hash != "", "hash")
	add(s.Signed, "signed")
	add(s.Signer != "", "signer")
	add(s.ModuleKind != "", "module_kind")
	return f
}

func init() {
	valStepFields["process"] = []string{"uid", "executable", "parent_exe", "command"}
	valStepFields["network"] = []string{"destination", "verdict"}
	valStepFields["file"] = []string{"path", "operation", "size"}
	valStepFields["registry"] = []string{"key", "value_name", "value_data", "operation", "user"}
	valStepFields["dns"] = []string{"query", "qtype", "answers", "resolver", "user"}
	valStepFields["auth"] = []string{"user", "source_ip", "method", "outcome"}
	valStepFields["module"] = []string{"module_path", "hash", "signed", "signer", "module_kind", "user"}
}

func valTechOrRule(x string) bool { return labTechRe.MatchString(x) }

// Validate checks a scenario against the schema.
func (sc *ValScenario) Validate() error {
	fail := func(f string, a ...any) error { return fmt.Errorf("scenario %q: %s", sc.ID, fmt.Sprintf(f, a...)) }
	if len(sc.ID) == 0 || len(sc.ID) > 64 || !valIDRe.MatchString(sc.ID) {
		return fail("id must be kebab-case, max 64 chars")
	}
	if strings.TrimSpace(sc.Name) == "" || len(sc.Name) > 120 {
		return fail("name: required, max 120 chars")
	}
	if strings.TrimSpace(sc.Description) == "" || len(sc.Description) > 1000 {
		return fail("description: required, max 1000 chars")
	}
	if !valKinds[sc.Kind] {
		return fail("kind %q must be single|chain|benign", sc.Kind)
	}
	if (sc.Kind == "benign") != sc.Benign {
		return fail("benign flag must be true exactly when kind is benign")
	}
	if !valPlatforms[sc.Platform] {
		return fail("platform %q must be linux|macos|windows", sc.Platform)
	}
	for _, t := range sc.Tactics {
		ok := false
		for _, a := range attackTactics {
			if a == t {
				ok = true
			}
		}
		if !ok {
			return fail("tactic %q is not an ATT&CK Enterprise tactic", t)
		}
	}
	for _, t := range sc.Techniques {
		if !labTechRe.MatchString(t) {
			return fail("technique %q is not an ATT&CK id", t)
		}
	}
	if sc.Benign {
		if len(sc.Expect) > 0 || len(sc.Techniques) > 0 {
			return fail("benign scenarios must not declare techniques or expectations")
		}
	} else {
		if len(sc.Techniques) == 0 || len(sc.Tactics) == 0 {
			return fail("techniques and tactics are required for non-benign scenarios")
		}
		if sc.Kind == "single" && len(sc.Techniques) != 1 {
			return fail("single-technique scenarios must list exactly one technique")
		}
		if sc.Kind == "chain" && len(sc.Steps) < 3 {
			return fail("chains need at least 3 steps")
		}
		if len(sc.Expectations()) == 0 {
			return fail("at least one expectation (scenario or step level) is required")
		}
	}
	if len(sc.Steps) == 0 || len(sc.Steps) > valMaxSteps {
		return fail("steps: need 1..%d", valMaxSteps)
	}
	for i := range sc.Steps {
		s := &sc.Steps[i]
		if !valStepTypes[s.Type] {
			return fail("step %d: type %q unknown", i, s.Type)
		}
		allowed := map[string]bool{}
		for _, f := range valStepFields[s.Type] {
			allowed[f] = true
		}
		for _, f := range s.fieldsSet() {
			if !allowed[f] {
				return fail("step %d (%s): field %q does not belong to this event type", i, s.Type, f)
			}
		}
		switch s.Type {
		case "process":
			if s.Executable == "" || s.Command == "" {
				return fail("step %d: process needs executable and command", i)
			}
		case "network":
			if s.Destination == "" {
				return fail("step %d: network needs destination", i)
			}
		case "file":
			if s.Path == "" || s.Operation == "" {
				return fail("step %d: file needs path and operation", i)
			}
		}
		if s.At < 0 || s.At > 86400 {
			return fail("step %d: at must be 0..86400", i)
		}
		if s.Type != "process" && s.Type != "network" && s.Type != "file" {
			te := s.telemetry("lab-host", sc.baseTime())
			if err := te.Validate(s.Type); err != nil {
				return fail("step %d (%s): %v", i, s.Type, err)
			}
		}
		for _, x := range s.Expect {
			if x == "" {
				return fail("step %d: empty expectation", i)
			}
		}
	}
	for _, x := range sc.Expect {
		if x == "" {
			return fail("empty expectation")
		}
	}
	return nil
}

// Expectations returns the deduplicated expectations (scenario level plus every step).
func (sc *ValScenario) Expectations() []string {
	seen := map[string]bool{}
	var out []string
	add := func(x string) {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	for _, x := range sc.Expect {
		add(x)
	}
	for _, s := range sc.Steps {
		for _, x := range s.Expect {
			add(x)
		}
	}
	return out
}

var (
	valOnce   sync.Once
	valScens  []ValScenario
	valNotTes map[string]string
	valErr    error
)

func parseScenarioFiles(files map[string][]byte) ([]ValScenario, map[string]string, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []ValScenario
	notTest := map[string]string{}
	var errs []error
	seen := map[string]bool{}
	for _, n := range names {
		dec := json.NewDecoder(bytes.NewReader(files[n]))
		dec.DisallowUnknownFields()
		if n == "not_testable.json" {
			var f valNotTestableFile
			if err := dec.Decode(&f); err != nil {
				errs = append(errs, fmt.Errorf("%s: %v", n, err))
				continue
			}
			for k, v := range f.NotTestable {
				if !labTechRe.MatchString(k) || strings.TrimSpace(v) == "" {
					errs = append(errs, fmt.Errorf("%s: invalid entry %q", n, k))
					continue
				}
				notTest[k] = v
			}
			continue
		}
		var f valFile
		if err := dec.Decode(&f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", n, err))
			continue
		}
		for i := range f.Scenarios {
			sc := f.Scenarios[i]
			if err := sc.Validate(); err != nil {
				errs = append(errs, fmt.Errorf("%s: %v", n, err))
				continue
			}
			if seen[sc.ID] {
				errs = append(errs, fmt.Errorf("%s: scenario %q: duplicate id", n, sc.ID))
				continue
			}
			if len(out) >= valMaxScenarios {
				errs = append(errs, fmt.Errorf("scenario cap of %d reached", valMaxScenarios))
				break
			}
			seen[sc.ID] = true
			out = append(out, sc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, notTest, errors.Join(errs...)
}

// LoadValidationScenarios loads the embedded scenarios once (invalid ones are reported in the error).
func LoadValidationScenarios() ([]ValScenario, map[string]string, error) {
	valOnce.Do(func() {
		entries, err := scenarioFS.ReadDir("scenarios")
		if err != nil {
			valErr = err
			return
		}
		files := map[string][]byte{}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			b, err := scenarioFS.ReadFile("scenarios/" + e.Name())
			if err != nil {
				valErr = err
				return
			}
			files[e.Name()] = b
		}
		valScens, valNotTes, valErr = parseScenarioFiles(files)
	})
	return valScens, valNotTes, valErr
}
