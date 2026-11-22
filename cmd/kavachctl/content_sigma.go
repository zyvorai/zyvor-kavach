// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const sigmaUsage = `usage:
  kavachctl content import-sigma FILE|DIR [--apply] [--json]   offline Sigma importer; dry run unless --apply (admin token)
  kavachctl content export-sigma [--ids a,b] [--out FILE]       export custom rules as Sigma YAML (lossless ones only)`

const sigmaCtlMaxBytes = 1 << 20 // mirrors the server limit so oversized files fail before upload

// sigmaFiles expands FILE or DIR (non-recursive, .yml .yaml .json) into a sorted file list.
func sigmaFiles(target string) ([]string, error) {
	st, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{target}, nil
	}
	ents, err := os.ReadDir(target)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if !e.IsDir() && (ext == ".yml" || ext == ".yaml" || ext == ".json") {
			out = append(out, filepath.Join(target, e.Name()))
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no .yml, .yaml or .json files in %s", target)
	}
	return out, nil
}

// sigmaDispatch handles `kavachctl content import-sigma|export-sigma`; other commands fall through.
func sigmaDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 2 || args[0] != "content" || (args[1] != "import-sigma" && args[1] != "export-sigma") {
		return false, nil
	}
	pos, f, b := omParse(args[2:], "ids", "out")
	if args[1] == "export-sigma" {
		payload := []byte("{}")
		if f["ids"] != "" {
			payload, _ = json.Marshal(map[string]any{"ids": strings.Split(f["ids"], ",")})
		}
		resp, code, err := doRequest("POST", "/v1/content/export/sigma", payload, nil)
		if err != nil {
			return true, err
		}
		if code >= 300 {
			return true, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(resp)), 400))
		}
		var r struct {
			YAML    string `json:"yaml"`
			Skipped []struct {
				ID     string `json:"id"`
				Reason string `json:"reason"`
			} `json:"skipped"`
		}
		if err := json.Unmarshal(resp, &r); err != nil {
			return true, err
		}
		for _, s := range r.Skipped {
			fmt.Fprintf(os.Stderr, "skipped %s: %s\n", s.ID, s.Reason)
		}
		if f["out"] != "" {
			if err := os.WriteFile(f["out"], []byte(r.YAML), 0600); err != nil {
				return true, err
			}
			fmt.Fprintf(out, "wrote %s\n", f["out"])
			return true, nil
		}
		fmt.Fprint(out, r.YAML)
		return true, nil
	}
	if len(pos) != 1 {
		return true, fmt.Errorf("%s", sigmaUsage)
	}
	files, err := sigmaFiles(pos[0])
	if err != nil {
		return true, err
	}
	path := "/v1/content/import/sigma?dry_run=true"
	if b["apply"] {
		path = "/v1/content/import/sigma?dry_run=false"
	} else {
		fmt.Fprintln(out, "dry run: nothing is stored (pass --apply to import)")
	}
	failed := 0
	for _, fn := range files {
		data, err := os.ReadFile(fn)
		if err != nil {
			return true, err
		}
		if len(data) > sigmaCtlMaxBytes {
			fmt.Fprintf(out, "== %s: skipped, %d bytes exceeds the %d byte limit\n", fn, len(data), sigmaCtlMaxBytes)
			failed++
			continue
		}
		fmt.Fprintf(out, "== %s\n", fn)
		if err := ccRaw(out, "POST", path, data, b["json"]); err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
			failed++
		}
	}
	if failed > 0 {
		return true, fmt.Errorf("%d of %d file(s) failed", failed, len(files))
	}
	return true, nil
}
