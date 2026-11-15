// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package edr

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type excInput struct {
	Rule    *string `json:"rule"`
	Host    *string `json:"host"`
	Path    *string `json:"path"`
	Reason  *string `json:"reason"`
	Owner   *string `json:"owner"`
	Expires *string `json:"expires"` // RFC3339
	Expire  bool    `json:"expire_now"`
}

func detReply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func detErr(w http.ResponseWriter, code int, msg string) {
	detReply(w, code, map[string]any{"error": msg})
}

func (s *exceptionService) validate(e *Exception, now time.Time) string {
	e.Rule, e.Host, e.Path = strings.TrimSpace(e.Rule), strings.TrimSpace(e.Host), strings.TrimSpace(e.Path)
	e.Reason, e.Owner = strings.TrimSpace(e.Reason), strings.TrimSpace(e.Owner)
	switch {
	case e.Rule == "" || strings.Trim(e.Rule, "*") == "":
		return "rule is required (a rule id or glob; a bare * is refused)"
	case e.Reason == "" || e.Owner == "":
		return "reason and owner are required"
	case len(e.Rule) > 200 || len(e.Host) > 200 || len(e.Path) > 400 || len(e.Reason) > 1000 || len(e.Owner) > 200:
		return "field too long"
	case e.Expires.IsZero():
		return "expires is required (RFC3339)"
	case !e.Expires.After(now):
		return "expires must be in the future"
	case e.Expires.After(now.Add(excMaxLifetime)):
		return "expires is more than 365 days away"
	}
	return ""
}

func registerExceptionRoutes(mux *http.ServeMux, token string, s *exceptionService) {
	admin := func(w http.ResponseWriter, r *http.Request) (string, bool) {
		isAdmin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return "", false
		}
		if !isAdmin {
			detErr(w, http.StatusForbidden, "admin token required to create or change exceptions")
			return "", false
		}
		return "admin", true
	}
	mux.HandleFunc("GET /v1/exceptions", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		now := s.now()
		s.sweepLocked(now)
		views := s.views(now)
		if st := r.URL.Query().Get("status"); st != "" {
			f := views[:0:0]
			for _, v := range views {
				if v.Status == st {
					f = append(f, v)
				}
			}
			views = f
		}
		ok, at := s.verifyLocked()
		detReply(w, 200, map[string]any{"exceptions": views, "count": len(views),
			"chain":             map[string]any{"ok": ok, "broken_at_seq": at, "entries": len(s.d.History)},
			"max_lifetime_days": 365,
			"semantics":         "an exception suppresses REPORTING of matching findings from the main list; they are kept in the suppressed list. Kavach never blocks anything."})
	})
	mux.HandleFunc("GET /v1/exceptions/history", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		ok, at := s.verifyLocked()
		detReply(w, 200, map[string]any{"history": s.d.History, "chain_ok": ok, "broken_at_seq": at})
	})
	mux.HandleFunc("GET /v1/exceptions/suppressed", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		id := r.URL.Query().Get("exception")
		s.mu.Lock()
		defer s.mu.Unlock()
		out := []SuppressedFinding{}
		for i := len(s.d.Suppressed) - 1; i >= 0 && len(out) < 200; i-- {
			if id == "" || s.d.Suppressed[i].ExceptionID == id {
				out = append(out, s.d.Suppressed[i])
			}
		}
		counts := map[string]int{}
		total := 0
		for _, e := range s.d.Exceptions {
			counts[e.ID] = e.Suppressed
			total += e.Suppressed
		}
		detReply(w, 200, map[string]any{"suppressed": out, "counts": counts, "total_suppressed": total,
			"retained": len(s.d.Suppressed), "retained_max": excSuppressedMax})
	})
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	mux.HandleFunc("POST /v1/exceptions", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := admin(w, r)
		if !ok {
			return
		}
		var in excInput
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			detErr(w, 400, "invalid json body")
			return
		}
		e := Exception{Rule: str(in.Rule), Host: str(in.Host), Path: str(in.Path), Reason: str(in.Reason), Owner: str(in.Owner)}
		s.mu.Lock()
		defer s.mu.Unlock()
		now := s.now()
		if in.Expires != nil {
			t, err := time.Parse(time.RFC3339, *in.Expires)
			if err != nil {
				detErr(w, 400, "expires must be RFC3339")
				return
			}
			e.Expires = t.UTC()
		}
		if msg := s.validate(&e, now); msg != "" {
			detErr(w, 400, msg)
			return
		}
		active := 0
		for _, x := range s.d.Exceptions {
			if now.Before(x.Expires) {
				active++
			}
		}
		if active >= excMaxActive {
			detErr(w, 429, "too many active exceptions")
			return
		}
		e.ID, e.Created, e.Updated, e.By = s.nextID(), now.UTC(), now.UTC(), actor
		s.d.Exceptions = append(s.d.Exceptions, e)
		s.appendLocked(actor, "create", e.ID, excDetail(e))
		s.saveLocked()
		AppendAudit(token, "exception.create", e.ID)
		detReply(w, 201, e)
	})
	mux.HandleFunc("PUT /v1/exceptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := admin(w, r)
		if !ok {
			return
		}
		var in excInput
		r.Body = http.MaxBytesReader(w, r.Body, 16384)
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			detErr(w, 400, "invalid json body")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		now := s.now()
		for i := range s.d.Exceptions {
			e := &s.d.Exceptions[i]
			if e.ID != r.PathValue("id") {
				continue
			}
			if in.Expire {
				e.Expires, e.Updated, e.ExpiryLogged = now.UTC(), now.UTC(), true
				s.appendLocked(actor, "expire", e.ID, "expired manually; reporting resumes")
				s.saveLocked()
				detReply(w, 200, e)
				return
			}
			n := *e
			if in.Rule != nil {
				n.Rule = *in.Rule
			}
			if in.Host != nil {
				n.Host = *in.Host
			}
			if in.Path != nil {
				n.Path = *in.Path
			}
			if in.Reason != nil {
				n.Reason = *in.Reason
			}
			if in.Owner != nil {
				n.Owner = *in.Owner
			}
			if in.Expires != nil {
				t, err := time.Parse(time.RFC3339, *in.Expires)
				if err != nil {
					detErr(w, 400, "expires must be RFC3339")
					return
				}
				n.Expires, n.ExpiryLogged = t.UTC(), false
			}
			if msg := s.validate(&n, now); msg != "" {
				detErr(w, 400, msg)
				return
			}
			n.Updated, n.By = now.UTC(), actor
			*e = n
			s.appendLocked(actor, "update", n.ID, excDetail(n))
			s.saveLocked()
			AppendAudit(token, "exception.update", n.ID)
			detReply(w, 200, n)
			return
		}
		detErr(w, 404, "exception not found")
	})
	mux.HandleFunc("DELETE /v1/exceptions/{id}", func(w http.ResponseWriter, r *http.Request) {
		actor, ok := admin(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, e := range s.d.Exceptions {
			if e.ID == r.PathValue("id") {
				s.d.Exceptions = append(s.d.Exceptions[:i:i], s.d.Exceptions[i+1:]...)
				s.appendLocked(actor, "delete", e.ID, excDetail(e))
				s.saveLocked()
				AppendAudit(token, "exception.delete", e.ID)
				detReply(w, 200, map[string]any{"deleted": e.ID, "suppressed_findings_kept": true})
				return
			}
		}
		detErr(w, 404, "exception not found")
	})
}
