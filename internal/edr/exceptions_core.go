// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Rule exceptions with mandatory expiry (observation only).
//
// An exception suppresses the REPORTING of matching findings in the main findings list. Kavach never
// blocks, kills or contains anything: a suppressed finding is moved to a suppressed list (and counted
// against its exception), never silently dropped. Every create/update/expire/delete is recorded in a
// hash-chained history using the same scheme as the analyst journal. Expired exceptions stop applying
// by themselves and are listed as expired.

const (
	excMaxLifetime   = 365 * 24 * time.Hour
	excMaxActive     = 500
	excSuppressedMax = 1000
	excHistoryMax    = 5000
	excFlushEvery    = 2 * time.Second
)

// Exception is one scoped, owned, expiring reporting suppression.
type Exception struct {
	ID             string    `json:"id"`
	Rule           string    `json:"rule"`           // rule id or glob (required; "*" alone is refused)
	Host           string    `json:"host,omitempty"` // host or glob
	Path           string    `json:"path,omitempty"` // executable/path glob, matched against the finding's executable
	Reason         string    `json:"reason"`
	Owner          string    `json:"owner"`
	Created        time.Time `json:"created"`
	Updated        time.Time `json:"updated"`
	Expires        time.Time `json:"expires"`
	By             string    `json:"by"`
	Suppressed     int       `json:"suppressed_count"`
	LastSuppressed time.Time `json:"last_suppressed,omitempty"`
	ExpiryLogged   bool      `json:"expiry_logged,omitempty"`
}

// ExceptionView is an exception plus its computed status.
type ExceptionView struct {
	Exception
	Status string `json:"status"` // active | expired
	Note   string `json:"note"`
}

// SuppressedFinding is a finding whose reporting an exception suppressed.
type SuppressedFinding struct {
	ExceptionID string    `json:"exception_id"`
	At          time.Time `json:"suppressed_at"`
	Finding     Finding   `json:"finding"`
}

// ExceptionHistory is one hash-chained change record.
type ExceptionHistory struct {
	Seq    int       `json:"seq"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"` // create|update|expire|delete
	Target string    `json:"target"`
	Detail string    `json:"detail"`
	Prev   string    `json:"prev_hash"`
	Hash   string    `json:"hash"`
}

func excEntryHash(e ExceptionHistory) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s\n%s\n%s", e.Seq, e.Time.UTC().Format(time.RFC3339Nano), e.Actor, e.Action, e.Target, e.Detail, e.Prev)
	return hex.EncodeToString(h.Sum(nil))
}

type exceptionFile struct {
	Exceptions []Exception         `json:"exceptions"`
	Suppressed []SuppressedFinding `json:"suppressed"`
	History    []ExceptionHistory  `json:"history"`
	Seq        int                 `json:"seq"`
}

type exceptionService struct {
	mu        sync.Mutex
	path      string
	now       func() time.Time
	d         exceptionFile
	dirty     bool
	lastSaved time.Time
}

var excSvc atomic.Pointer[exceptionService]

func newExceptionService(path string, now func() time.Time) *exceptionService {
	s := &exceptionService{path: path, now: now}
	s.load()
	return s
}

func (s *exceptionService) load() {
	if s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f exceptionFile
	if json.Unmarshal(b, &f) == nil {
		s.d = f
	}
}

func (s *exceptionService) saveLocked() {
	s.dirty = false
	s.lastSaved = s.now()
	if s.path == "" {
		return
	}
	b, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func (s *exceptionService) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.now())
	if s.dirty {
		s.saveLocked()
	}
}

func (s *exceptionService) appendLocked(actor, action, target, detail string) {
	e := ExceptionHistory{Seq: 1, Time: s.now().UTC(), Actor: actor, Action: action, Target: target, Detail: detail}
	if n := len(s.d.History); n > 0 {
		last := s.d.History[n-1]
		e.Seq, e.Prev = last.Seq+1, last.Hash
	}
	e.Hash = excEntryHash(e)
	s.d.History = append(s.d.History, e)
	if len(s.d.History) > excHistoryMax {
		s.d.History = s.d.History[len(s.d.History)-excHistoryMax:]
	}
}

// verifyLocked walks the chain; returns ok and the seq of the first broken entry. The first retained
// entry is the anchor.
func (s *exceptionService) verifyLocked() (bool, int) {
	for i, e := range s.d.History {
		if i > 0 && e.Prev != s.d.History[i-1].Hash {
			return false, e.Seq
		}
		if excEntryHash(e) != e.Hash {
			return false, e.Seq
		}
	}
	return true, 0
}

func excDetail(e Exception) string {
	return fmt.Sprintf("rule=%q host=%q path=%q owner=%q expires=%s reason=%q", e.Rule, e.Host, e.Path, e.Owner,
		e.Expires.UTC().Format(time.RFC3339), e.Reason)
}

// sweepLocked records the expiry of exceptions whose time has passed (once each).
func (s *exceptionService) sweepLocked(now time.Time) {
	for i := range s.d.Exceptions {
		e := &s.d.Exceptions[i]
		if !now.Before(e.Expires) && !e.ExpiryLogged {
			e.ExpiryLogged = true
			s.appendLocked("system", "expire", e.ID, "expired at "+e.Expires.UTC().Format(time.RFC3339)+"; reporting resumes")
			s.dirty = true
		}
	}
	if s.dirty {
		s.saveLocked()
	}
}

func (e Exception) matches(f Finding) bool {
	if !globMatch(strings.ToLower(e.Rule), strings.ToLower(f.Rule)) {
		return false
	}
	if e.Host != "" && !globMatch(strings.ToLower(e.Host), strings.ToLower(f.Host)) {
		return false
	}
	if e.Path != "" {
		p := strings.ToLower(f.Evidence.Executable)
		if p == "" || !globMatch(strings.ToLower(e.Path), p) {
			return false
		}
	}
	return true
}

// firstMatchLocked returns the index of an active exception matching f, or -1.
func (s *exceptionService) firstMatchLocked(f Finding, now time.Time) int {
	for i, e := range s.d.Exceptions {
		if now.Before(e.Expires) && e.matches(f) {
			return i
		}
	}
	return -1
}

// would reports whether f would currently be suppressed, without recording anything.
func (s *exceptionService) would(f Finding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firstMatchLocked(f, s.now()) >= 0
}

// suppress moves f to the suppressed list when an active exception matches.
func (s *exceptionService) suppress(f Finding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	i := s.firstMatchLocked(f, now)
	if i < 0 {
		return false
	}
	e := &s.d.Exceptions[i]
	e.Suppressed++
	e.LastSuppressed = now.UTC()
	s.d.Suppressed = append(s.d.Suppressed, SuppressedFinding{ExceptionID: e.ID, At: now.UTC(), Finding: f})
	if len(s.d.Suppressed) > excSuppressedMax {
		s.d.Suppressed = s.d.Suppressed[len(s.d.Suppressed)-excSuppressedMax:]
	}
	s.dirty = true
	if now.Sub(s.lastSaved) >= excFlushEvery {
		s.saveLocked()
	}
	return true
}

// exceptionSuppress is the single hook called from appendFindingLocked. It is a no-op until the
// exception service is registered, so existing behaviour is unchanged by default.
func exceptionSuppress(f Finding) bool {
	s := excSvc.Load()
	return s != nil && s.suppress(f)
}

func (s *exceptionService) views(now time.Time) []ExceptionView {
	out := make([]ExceptionView, 0, len(s.d.Exceptions))
	for _, e := range s.d.Exceptions {
		v := ExceptionView{Exception: e, Status: "active", Note: "suppresses reporting only; nothing is blocked"}
		if !now.Before(e.Expires) {
			v.Status, v.Note = "expired", "expired; findings are reported again"
		}
		out = append(out, v)
	}
	return out
}

func (s *exceptionService) nextID() string {
	s.d.Seq++
	return fmt.Sprintf("exc-%d", s.d.Seq)
}
