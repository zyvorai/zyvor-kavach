// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Analyst workspace: saved searches, finding notes and a tamper-evident
// activity journal. Observation only; nothing here acts on a host.

const (
	maxSavedSearches = 100
	maxNotesPerItem  = 200
	maxNoteLen       = 2000
	maxNameLen       = 80
	maxQueryLen      = 500
	maxJournalKept   = 5000
)

type SavedSearch struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Scope   string    `json:"scope"` // detections | findings | hosts
	Query   string    `json:"query"`
	Author  string    `json:"author"`
	Created time.Time `json:"created"`
}

type Note struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	Author    string    `json:"author"`
	Text      string    `json:"text"`
	Created   time.Time `json:"created"`
}

type JournalEntry struct {
	Seq    int       `json:"seq"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Prev   string    `json:"prev_hash"`
	Hash   string    `json:"hash"`
}

type workspaceData struct {
	Searches []SavedSearch  `json:"searches"`
	Notes    []Note         `json:"notes"`
	Journal  []JournalEntry `json:"journal"`
}

type Workspace struct {
	mu   sync.Mutex
	path string
	data workspaceData
}

func entryHash(e JournalEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\n%s\n%s\n%s\n%s\n%s", e.Seq, e.Time.UTC().Format(time.RFC3339Nano), e.Actor, e.Action, e.Target, e.Prev)
	return hex.EncodeToString(h.Sum(nil))
}

func newWSID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// cleanText strips control characters, trims and HTML-escapes.
func cleanText(s string, multiline bool) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' && multiline {
			return r
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	return html.EscapeString(strings.TrimSpace(s))
}

func NewWorkspace(store *Store) *Workspace {
	w := &Workspace{path: store.path + ".workspace.json"}
	if b, err := os.ReadFile(w.path); err == nil {
		_ = json.Unmarshal(b, &w.data)
	}
	return w
}

func (w *Workspace) saveLocked() error {
	b, err := json.Marshal(w.data)
	if err != nil {
		return err
	}
	tmp := w.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.path)
}

func (w *Workspace) appendJournalLocked(actor, action, target string) {
	e := JournalEntry{Seq: 1, Time: time.Now().UTC(), Actor: actor, Action: action, Target: target}
	if n := len(w.data.Journal); n > 0 {
		last := w.data.Journal[n-1]
		e.Seq, e.Prev = last.Seq+1, last.Hash
	}
	e.Hash = entryHash(e)
	w.data.Journal = append(w.data.Journal, e)
	if len(w.data.Journal) > maxJournalKept {
		w.data.Journal = w.data.Journal[len(w.data.Journal)-maxJournalKept:]
	}
}

// verifyLocked re-walks the chain; returns the seq of the first broken link or 0.
func (w *Workspace) verifyLocked() (int, string) {
	for i, e := range w.data.Journal {
		if i > 0 && e.Prev != w.data.Journal[i-1].Hash {
			return e.Seq, "prev_hash does not match previous entry"
		}
		if entryHash(e) != e.Hash {
			return e.Seq, "entry hash mismatch"
		}
	}
	return 0, ""
}

func wsActor(admin bool) string {
	if admin {
		return "admin"
	}
	return "session"
}

func wsJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// RegisterAnalystWorkspace wires saved searches, notes and the journal.
func RegisterAnalystWorkspace(mux *http.ServeMux, token string, store *Store) *Workspace {
	ws := NewWorkspace(store)

	mux.HandleFunc("GET /v1/saved-searches", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ws.mu.Lock()
		out := append([]SavedSearch{}, ws.data.Searches...)
		ws.mu.Unlock()
		wsJSON(w, 200, map[string]any{"saved_searches": out})
	})
	mux.HandleFunc("POST /v1/saved-searches", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8*1024)
		var in SavedSearch
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		in.Name = cleanText(in.Name, false)
		in.Query = cleanText(in.Query, false)
		in.Scope = strings.ToLower(strings.TrimSpace(in.Scope))
		if in.Name == "" || len(in.Name) > maxNameLen {
			http.Error(w, "name required, max 80 chars", 400)
			return
		}
		if len(in.Query) > maxQueryLen {
			http.Error(w, "query too long", 400)
			return
		}
		if in.Scope != "detections" && in.Scope != "findings" && in.Scope != "hosts" {
			http.Error(w, "scope must be detections, findings or hosts", 400)
			return
		}
		in.ID, in.Created, in.Author = newWSID("ss-"), time.Now().UTC(), wsActor(admin)
		ws.mu.Lock()
		defer ws.mu.Unlock()
		if len(ws.data.Searches) >= maxSavedSearches {
			http.Error(w, "too many saved searches", 400)
			return
		}
		ws.data.Searches = append(ws.data.Searches, in)
		ws.appendJournalLocked(in.Author, "saved_search.create", in.ID+" "+in.Name)
		if err := ws.saveLocked(); err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		wsJSON(w, 201, in)
	})
	mux.HandleFunc("DELETE /v1/saved-searches", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.URL.Query().Get("id")
		ws.mu.Lock()
		defer ws.mu.Unlock()
		for i, x := range ws.data.Searches {
			if x.ID == id {
				ws.data.Searches = append(ws.data.Searches[:i:i], ws.data.Searches[i+1:]...)
				ws.appendJournalLocked(wsActor(admin), "saved_search.delete", id)
				if err := ws.saveLocked(); err != nil {
					http.Error(w, "storage error", 500)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Error(w, "not found", 404)
	})

	mux.HandleFunc("GET /v1/notes", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		fid := r.URL.Query().Get("finding_id")
		if fid == "" || len(fid) > 128 {
			http.Error(w, "finding_id required", 400)
			return
		}
		fid = cleanText(fid, false)
		out := []Note{}
		ws.mu.Lock()
		for _, n := range ws.data.Notes {
			if n.FindingID == fid {
				out = append(out, n)
			}
		}
		ws.mu.Unlock()
		wsJSON(w, 200, map[string]any{"notes": out})
	})
	mux.HandleFunc("POST /v1/notes", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		var in Note
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		raw := strings.TrimSpace(in.Text)
		if raw == "" || len([]rune(raw)) > maxNoteLen {
			http.Error(w, "text required, max 2000 chars", 400)
			return
		}
		in.FindingID = cleanText(in.FindingID, false)
		if in.FindingID == "" || len(in.FindingID) > 128 {
			http.Error(w, "finding_id required", 400)
			return
		}
		in.Text = cleanText(raw, true)
		in.ID, in.Created, in.Author = newWSID("note-"), time.Now().UTC(), wsActor(admin)
		ws.mu.Lock()
		defer ws.mu.Unlock()
		n := 0
		for _, x := range ws.data.Notes {
			if x.FindingID == in.FindingID {
				n++
			}
		}
		if n >= maxNotesPerItem {
			http.Error(w, "too many notes for this finding", 400)
			return
		}
		ws.data.Notes = append(ws.data.Notes, in)
		ws.appendJournalLocked(in.Author, "note.create", in.ID+" on "+in.FindingID)
		if err := ws.saveLocked(); err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		wsJSON(w, 201, in)
	})
	mux.HandleFunc("DELETE /v1/notes", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		id := r.URL.Query().Get("id")
		ws.mu.Lock()
		defer ws.mu.Unlock()
		for i, x := range ws.data.Notes {
			if x.ID == id {
				ws.data.Notes = append(ws.data.Notes[:i:i], ws.data.Notes[i+1:]...)
				ws.appendJournalLocked(wsActor(admin), "note.delete", id+" on "+x.FindingID)
				if err := ws.saveLocked(); err != nil {
					http.Error(w, "storage error", 500)
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		http.Error(w, "not found", 404)
	})

	mux.HandleFunc("GET /v1/journal", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ws.mu.Lock()
		out := append([]JournalEntry{}, ws.data.Journal...)
		ws.mu.Unlock()
		wsJSON(w, 200, map[string]any{"entries": out})
	})
	// Alert-rule changes are made through /v1/alerts/rules; clients record them
	// here so they join the chain (action must be alert_rule.create|delete).
	mux.HandleFunc("POST /v1/journal", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
		var in struct{ Action, Target string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "invalid json", 400)
			return
		}
		if in.Action != "alert_rule.create" && in.Action != "alert_rule.delete" {
			http.Error(w, "action must be alert_rule.create or alert_rule.delete", 400)
			return
		}
		target := cleanText(in.Target, false)
		if len(target) > 200 {
			http.Error(w, "target too long", 400)
			return
		}
		ws.mu.Lock()
		defer ws.mu.Unlock()
		ws.appendJournalLocked(wsActor(admin), in.Action, target)
		if err := ws.saveLocked(); err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		wsJSON(w, 201, ws.data.Journal[len(ws.data.Journal)-1])
	})
	mux.HandleFunc("GET /v1/journal/verify", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		ws.mu.Lock()
		seq, why := ws.verifyLocked()
		n := len(ws.data.Journal)
		ws.mu.Unlock()
		res := map[string]any{"valid": seq == 0, "entries": n}
		if seq != 0 {
			res["first_broken_seq"], res["reason"] = seq, why
		}
		wsJSON(w, 200, res)
	})
	return ws
}
