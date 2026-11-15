// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Analyst feedback loop: append-only, hash-chained verdicts on findings.
// Observation only: nothing here changes a rule, a suppression or a host.

const (
	VerdictTruePositive   = "true_positive"
	VerdictFalsePositive  = "false_positive"
	VerdictBenignExpected = "benign_expected"
	VerdictNeedsMoreData  = "needs_more_data"

	maxFeedbackKept = 100000
	maxFeedbackNote = 1000
)

var validVerdicts = map[string]bool{
	VerdictTruePositive: true, VerdictFalsePositive: true,
	VerdictBenignExpected: true, VerdictNeedsMoreData: true,
}

// FeedbackEntry is one verdict. Entries are never rewritten; a retraction is a
// later entry by the same actor (for example needs_more_data).
type FeedbackEntry struct {
	Seq         int       `json:"seq"`
	Time        time.Time `json:"time"`
	FindingID   string    `json:"finding_id"`
	Verdict     string    `json:"verdict"`
	Note        string    `json:"note,omitempty"`
	Actor       string    `json:"actor"`
	Rule        string    `json:"rule"`
	Host        string    `json:"host"`
	FindingTime time.Time `json:"finding_time"`
	Prev        string    `json:"prev_hash"`
	Hash        string    `json:"hash"`
}

func feedbackHash(e FeedbackEntry) string {
	// JSON array encoding keeps field boundaries unambiguous (notes may hold newlines).
	b, _ := json.Marshal([]any{e.Seq, e.Time.UTC().Format(time.RFC3339Nano), e.FindingID, e.Verdict, e.Note,
		e.Actor, e.Rule, e.Host, e.FindingTime.UTC().Format(time.RFC3339Nano), e.Prev})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type feedbackData struct {
	Entries []FeedbackEntry `json:"entries"`
}

type feedbackSvc struct {
	mu   sync.Mutex
	path string
	data feedbackData
}

func newFeedbackSvc(store *Store) *feedbackSvc {
	s := &feedbackSvc{path: store.path + ".feedback.json"}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &s.data)
	}
	return s
}

func (s *feedbackSvc) saveLocked() error {
	b, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// appendLocked chains and stores a new entry; on a save failure the in-memory
// append is rolled back so memory never diverges from disk.
func (s *feedbackSvc) appendLocked(e FeedbackEntry) (FeedbackEntry, error) {
	e.Seq = 1
	if n := len(s.data.Entries); n > 0 {
		last := s.data.Entries[n-1]
		e.Seq, e.Prev = last.Seq+1, last.Hash
	}
	e.Time = e.Time.UTC()
	e.Hash = feedbackHash(e)
	old := s.data.Entries
	s.data.Entries = append(append([]FeedbackEntry{}, old...), e)
	if len(s.data.Entries) > maxFeedbackKept {
		s.data.Entries = s.data.Entries[len(s.data.Entries)-maxFeedbackKept:]
	}
	if err := s.saveLocked(); err != nil {
		s.data.Entries = old
		return e, err
	}
	return e, nil
}

// verifyFeedbackChain returns the seq of the first broken entry (0 when intact).
func verifyFeedbackChain(entries []FeedbackEntry) (int, string) {
	for i, e := range entries {
		if i > 0 && e.Prev != entries[i-1].Hash {
			return e.Seq, "prev_hash does not match previous entry"
		}
		if feedbackHash(e) != e.Hash {
			return e.Seq, "entry hash mismatch"
		}
	}
	return 0, ""
}

func (s *feedbackSvc) snapshot() []FeedbackEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]FeedbackEntry{}, s.data.Entries...)
}
