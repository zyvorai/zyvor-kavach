// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	evMaxTotal    = 32 << 20
	evMaxArtefact = 4 << 20
	evMaxCount    = 64
)

type evSummaryRow struct {
	ID        string    `json:"id"`
	Case      string    `json:"case"`
	Host      string    `json:"host"`
	HostLabel string    `json:"host_label"`
	CreatedAt time.Time `json:"created_at"`
	Artefacts int       `json:"artefacts"`
	Events    int       `json:"events"`
	Findings  int       `json:"findings"`
	Promoted  bool      `json:"promoted"`
	Metadata  bool      `json:"metadata_only,omitempty"`
}

type evJSONReq struct {
	Case        string `json:"case"`
	Host        string `json:"host"`
	CollectedAt string `json:"collected_at"`
	Artefacts   []struct {
		Name    string `json:"name"`
		Format  string `json:"format"`
		Content string `json:"content"`
	} `json:"artefacts"`
}

func evJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func evErr(w http.ResponseWriter, code int, msg string) {
	evJSON(w, code, map[string]any{"error": msg})
}

// RegisterEvidenceImport wires the offline evidence import endpoints. Imports are analysed in an
// isolated in-memory case; only POST .../promote (admin) ever writes to the live store.
func RegisterEvidenceImport(mux *http.ServeMux, token string, store *Store) {
	sp := ""
	if store != nil {
		sp = store.path
	}
	mgr := newEvManager(sp)

	mux.HandleFunc("POST /v1/evidence/import", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		select {
		case mgr.slots <- struct{}{}:
			defer func() { <-mgr.slots }()
		default:
			w.Header().Set("Retry-After", "5")
			evErr(w, http.StatusTooManyRequests, "too many imports in progress")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, evMaxTotal+(2<<20))
		var label, host, collected string
		var in []evInput
		ct := r.Header.Get("Content-Type")
		if strings.HasPrefix(strings.ToLower(ct), "multipart/") {
			mr, err := r.MultipartReader()
			if err != nil {
				evErr(w, 400, "invalid multipart body")
				return
			}
			total := 0
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					evErr(w, 413, "body too large or malformed")
					return
				}
				name, fn := p.FormName(), p.FileName()
				lim := int64(evMaxArtefact)
				if fn == "" {
					lim = 1024
				}
				b, err := io.ReadAll(io.LimitReader(p, lim+1))
				if err != nil {
					evErr(w, 413, "body too large or malformed")
					return
				}
				if fn == "" {
					switch name {
					case "case":
						label = strings.TrimSpace(string(b))
					case "host":
						host = strings.TrimSpace(string(b))
					case "collected_at":
						collected = strings.TrimSpace(string(b))
					}
					continue
				}
				if len(in) >= evMaxCount {
					evErr(w, 400, "too many artefacts")
					return
				}
				a := evInput{Name: fn, Hint: name, Content: b}
				if int64(len(b)) > lim {
					a.TooBig, a.Content = true, b[:0]
				}
				total += len(b)
				if total > evMaxTotal {
					evErr(w, 413, "total artefact size exceeds 32 MiB")
					return
				}
				in = append(in, a)
			}
		} else {
			var req evJSONReq
			dec := json.NewDecoder(r.Body)
			if err := dec.Decode(&req); err != nil {
				if strings.Contains(err.Error(), "too large") {
					evErr(w, 413, "total size exceeds 32 MiB")
					return
				}
				evErr(w, 400, "invalid JSON")
				return
			}
			if len(req.Artefacts) > evMaxCount {
				evErr(w, 400, "too many artefacts")
				return
			}
			label, host, collected = strings.TrimSpace(req.Case), strings.TrimSpace(req.Host), req.CollectedAt
			total := 0
			for _, a := range req.Artefacts {
				total += len(a.Content)
				if total > evMaxTotal {
					evErr(w, 413, "total artefact size exceeds 32 MiB")
					return
				}
				x := evInput{Name: a.Name, Hint: a.Format, Content: []byte(a.Content)}
				if len(a.Content) > evMaxArtefact {
					x.TooBig, x.Content = true, nil
				}
				in = append(in, x)
			}
		}
		if !evValidLabel(host) {
			evErr(w, 400, "host label required: 1-64 characters [A-Za-z0-9._-], no ':' (it is namespaced as import:<case>:<host>)")
			return
		}
		if label != "" && !evValidLabel(label) {
			evErr(w, 400, "case label must be 1-64 characters [A-Za-z0-9._-]")
			return
		}
		if len(in) == 0 {
			evErr(w, 400, "no artefacts supplied")
			return
		}
		var at time.Time
		if collected != "" {
			t, err := time.Parse(time.RFC3339, collected)
			if err != nil {
				evErr(w, 400, "collected_at must be RFC3339")
				return
			}
			at = t.UTC()
		}
		c := BuildEvidenceCase(label, host, at, in)
		mgr.add(c)
		evJSON(w, http.StatusCreated, c)
	})

	mux.HandleFunc("GET /v1/evidence/cases", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		mgr.mu.Lock()
		rows := make([]evSummaryRow, 0, len(mgr.cases))
		for i := len(mgr.cases) - 1; i >= 0; i-- {
			c := mgr.cases[i]
			rows = append(rows, evSummaryRow{c.ID, c.Label, c.Host, c.HostLabel, c.CreatedAt, len(c.Artefacts), c.Totals.Events, len(c.Findings), c.Promoted, c.MetadataOnly})
		}
		mgr.mu.Unlock()
		evJSON(w, 200, map[string]any{"cases": rows, "count": len(rows), "max_cases": evMaxCases, "formats": EvidenceFormats(), "note": evCaseNote})
	})

	mux.HandleFunc("GET /v1/evidence/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		mgr.mu.Lock()
		c := mgr.get(r.PathValue("id"))
		var cp EvidenceCase
		if c != nil {
			cp = *c
		}
		mgr.mu.Unlock()
		if c == nil {
			evErr(w, 404, "case not found")
			return
		}
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", `attachment; filename="`+cp.ID+`.json"`)
		}
		evJSON(w, 200, cp)
	})

	mux.HandleFunc("DELETE /v1/evidence/cases/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := requireAdminOrSession(w, r, token); !ok {
			return
		}
		if !mgr.remove(r.PathValue("id")) {
			evErr(w, 404, "case not found")
			return
		}
		evJSON(w, 200, map[string]any{"deleted": r.PathValue("id")})
	})

	mux.HandleFunc("POST /v1/evidence/cases/{id}/promote", func(w http.ResponseWriter, r *http.Request) {
		admin, ok := requireAdminOrSession(w, r, token)
		if !ok {
			return
		}
		if !admin {
			evErr(w, http.StatusForbidden, "promote requires the admin token")
			return
		}
		n, err, code := mgr.promote(r.PathValue("id"), store)
		if err != nil {
			evErr(w, code, err.Error())
			return
		}
		evJSON(w, 200, map[string]any{"promoted": n, "tag": "evidence-import", "case": r.PathValue("id")})
	})
}
