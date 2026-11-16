package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"time"
)

// State for case templates, per-case workflow and chain->case links.
// Stored in <store>.casetemplates.json. Observation-only: nothing here touches a host.

const ctMaxJournal = 5000

// ctNow is the clock; tests replace it.
var ctNow = func() time.Time { return time.Now().UTC() }

type CaseTemplate struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	CaseType  string         `json:"case_type"`
	Severity  string         `json:"default_severity"`
	Checklist []string       `json:"checklist"`
	SLAHours  map[string]int `json:"sla_hours"` // severity -> resolve hours
	Tags      []string       `json:"default_tags,omitempty"`
	BuiltIn   bool           `json:"built_in"`
	UpdatedAt time.Time      `json:"updated_at,omitempty"`
}

type ChecklistItem struct {
	Text   string     `json:"text"`
	Done   bool       `json:"done"`
	By     string     `json:"by,omitempty"`
	DoneAt *time.Time `json:"done_at,omitempty"`
}

type CaseWorkflow struct {
	CaseID     string          `json:"case_id"`
	TemplateID string          `json:"template_id,omitempty"`
	Template   string          `json:"template_name,omitempty"`
	AppliedAt  time.Time       `json:"applied_at,omitempty"`
	SLAHours   map[string]int  `json:"sla_hours,omitempty"`
	Checklist  []ChecklistItem `json:"checklist"`
}

type ctData struct {
	Templates  []CaseTemplate           `json:"templates"`
	Workflows  map[string]*CaseWorkflow `json:"workflows"`
	ChainCases map[string]string        `json:"chain_cases"`
	Journal    []JournalEntry           `json:"journal"`
}

type ctState struct {
	mu   sync.Mutex
	path string
	d    ctData
	// chainMu serialises chain->case creation so it stays idempotent under concurrency.
	chainMu sync.Mutex
}

func newCTState(path string) *ctState {
	s := &ctState{path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.d)
	}
	if s.d.Workflows == nil {
		s.d.Workflows = map[string]*CaseWorkflow{}
	}
	if s.d.ChainCases == nil {
		s.d.ChainCases = map[string]string{}
	}
	return s
}

func (s *ctState) saveLocked() error {
	b, err := json.Marshal(s.d)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// journalLocked appends a hash-chained record (same scheme as the analyst journal).
func (s *ctState) journalLocked(actor, action, target string) {
	e := JournalEntry{Seq: 1, Time: ctNow(), Actor: actor, Action: action, Target: target}
	if n := len(s.d.Journal); n > 0 {
		last := s.d.Journal[n-1]
		e.Seq, e.Prev = last.Seq+1, last.Hash
	}
	e.Hash = entryHash(e)
	s.d.Journal = append(s.d.Journal, e)
	if len(s.d.Journal) > ctMaxJournal {
		s.d.Journal = s.d.Journal[len(s.d.Journal)-ctMaxJournal:]
	}
}

// verifyLocked returns the seq of the first broken entry (0 when intact).
func (s *ctState) verifyLocked() (int, string) {
	for i, e := range s.d.Journal {
		if i > 0 && e.Prev != s.d.Journal[i-1].Hash {
			return e.Seq, "prev_hash does not match previous entry"
		}
		if entryHash(e) != e.Hash {
			return e.Seq, "entry hash mismatch"
		}
	}
	return 0, ""
}

// record journals and persists in one step.
func (s *ctState) record(actor, action, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.journalLocked(actor, action, target)
	return s.saveLocked()
}

// internalCall invokes an existing endpoint on the same mux with the caller's credentials.
func internalCall(mux *http.ServeMux, r *http.Request, method, path string, body any) (int, []byte) {
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header = r.Header.Clone()
	req.Header.Set("Content-Type", "application/json")
	for _, c := range r.Cookies() {
		_ = c
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func ctGetCase(mux *http.ServeMux, r *http.Request, id string) (IncCase, int) {
	code, b := internalCall(mux, r, "GET", "/v1/cases/"+id, nil)
	var c IncCase
	if code == 200 {
		_ = json.Unmarshal(b, &c)
	}
	return c, code
}
