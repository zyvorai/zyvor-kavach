package edr

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NetworkEvent is a deliberately small, normalized Netra adapter contract.
// No dependency on Netra's internal maps, schemas or enforcement logic.
type NetworkEvent struct {
	ID           string    `json:"id,omitempty"`
	Time         time.Time `json:"time"`
	Host         string    `json:"host"`
	PID          int       `json:"pid"`
	ProcessStart string    `json:"process_start,omitempty"`
	Destination  string    `json:"destination"`
	Verdict      string    `json:"verdict,omitempty"`
	Source       string    `json:"source,omitempty"`
}

type ledgerEntry struct {
	Process *Event        `json:"process,omitempty"`
	Network *NetworkEvent `json:"network,omitempty"`
	File    *FileEvent    `json:"file,omitempty"`
}

func eventID(e Event) string {
	if e.ID != "" {
		return e.ID
	}
	b, _ := json.Marshal(e)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func networkID(e NetworkEvent) string {
	if e.ID != "" {
		return e.ID
	}
	b, _ := json.Marshal(e)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func appendRecord(path string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
func (s *Store) loadEvents() error {
	f, err := os.Open(s.eventPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		var v ledgerEntry
		if json.Unmarshal(sc.Bytes(), &v) != nil {
			return fmt.Errorf("corrupt event ledger")
		}
		if v.Process != nil {
			e := *v.Process
			s.seen["p:"+eventID(e)] = struct{}{}
			s.recentEvents = append(s.recentEvents, e)
		}
		if v.File != nil {
			fe := *v.File
			s.seen["f:"+fileID(fe)] = struct{}{}
			s.fileEvents = append(s.fileEvents, fe)
		}
		if v.Network != nil {
			n := *v.Network
			s.seen["n:"+networkID(n)] = struct{}{}
			s.networkEvents = append(s.networkEvents, n)
		}
	}
	s.trimRecent()
	return sc.Err()
}
func (s *Store) trimRecent() {
	if len(s.recentEvents) > s.max {
		s.recentEvents = s.recentEvents[len(s.recentEvents)-s.max:]
	}
	if len(s.networkEvents) > s.max {
		s.networkEvents = s.networkEvents[len(s.networkEvents)-s.max:]
	}
	if len(s.fileEvents) > s.max {
		s.fileEvents = s.fileEvents[len(s.fileEvents)-s.max:]
	}
}

// Ingest persists before ACK; replay of the same event ID is idempotent.
func (s *Store) Ingest(e Event) ([]Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.ID != "" && len(e.ID) > 128 {
		return nil, fmt.Errorf("oversized id")
	}
	key := "p:" + eventID(e)
	if _, ok := s.seen[key]; ok {
		return nil, nil
	}
	if err := appendRecord(s.eventPath, ledgerEntry{Process: &e}); err != nil {
		return nil, err
	}
	s.seen[key] = struct{}{}
	s.recentEvents = append(s.recentEvents, e)
	s.trimRecent()
	findings := Detect(e)
	for _, n := range s.networkEvents {
		if correlates(e, n) {
			findings = append(findings, correlationFinding(e, n))
		}
	}
	for _, x := range findings {
		if err := s.appendFindingLocked(x); err != nil {
			return findings, err
		}
	}
	return findings, nil
}
func correlates(e Event, n NetworkEvent) bool {
	d := e.Time.Sub(n.Time)
	return e.Host == n.Host && e.PID == n.PID && (e.ProcessStart == "" || n.ProcessStart == "" || e.ProcessStart == n.ProcessStart) && d >= -5*time.Minute && d <= 5*time.Minute && strings.EqualFold(n.Verdict, "deny")
}
func correlationFinding(e Event, n NetworkEvent) Finding {
	desc := "XDR: process correlated with a denied Netra network flow"
	if n.Destination != "" {
		desc += " → " + n.Destination
	}
	return Finding{
		ID: "netra:" + eventID(e) + ":" + networkID(n), Time: e.Time, Host: e.Host, PID: e.PID,
		Rule: "netra-denied-process", Severity: "medium", Description: desc, Evidence: e,
		Tags: []string{"xdr", "multi-signal", "netra"}, Destination: n.Destination,
	}
}
func (s *Store) IngestNetwork(n NetworkEvent) ([]Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.ID != "" && len(n.ID) > 128 {
		return nil, fmt.Errorf("oversized id")
	}
	key := "n:" + networkID(n)
	if _, ok := s.seen[key]; ok {
		return nil, nil
	}
	if err := appendRecord(s.eventPath, ledgerEntry{Network: &n}); err != nil {
		return nil, err
	}
	s.seen[key] = struct{}{}
	s.networkEvents = append(s.networkEvents, n)
	s.trimRecent()
	findings := contentNetworkFindings(n)
	for _, e := range s.recentEvents {
		if correlates(e, n) {
			findings = append(findings, correlationFinding(e, n))
		}
	}
	for _, x := range findings {
		if err := s.appendFindingLocked(x); err != nil {
			return findings, err
		}
	}
	return findings, nil
}
func (s *Store) appendFindingLocked(x Finding) error {
	if ruleShadowed(x) { // rule lifecycle "testing": recorded as a shadow finding, not in the main list
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	if err := appendRecord(s.path, x); err != nil {
		return err
	}
	s.findings = append(s.findings, x)
	if len(s.findings) > s.max {
		s.findings = s.findings[len(s.findings)-s.max:]
	}
	if DefaultSIEM != nil {
		DefaultSIEM.ExportFinding(x)
	}
	return nil
}

// IngestFile persists file metadata before any detection, then stores findings.
func (s *Store) IngestFile(e FileEvent, detector *FileDetections) ([]Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(e.ID) > 128 {
		return nil, fmt.Errorf("oversized id")
	}
	key := "f:" + fileID(e)
	if _, exists := s.seen[key]; exists {
		return nil, nil
	}
	if err := appendRecord(s.eventPath, ledgerEntry{File: &e}); err != nil {
		return nil, err
	}
	s.seen[key] = struct{}{}
	s.fileEvents = append(s.fileEvents, e)
	if len(s.fileEvents) > s.max {
		s.fileEvents = s.fileEvents[len(s.fileEvents)-s.max:]
	}
	findings := detector.Observe(e)
	findings = append(findings, RansomwareFindings(e.Host, []FileEvent{e}, e.Time)...)
	findings = append(findings, contentFileFindings(e)...)
	for _, f := range findings {
		if err := s.appendFindingLocked(f); err != nil {
			return findings, err
		}
	}
	return findings, nil
}
