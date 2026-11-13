// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Lockfile parsers: requirements.txt, Pipfile.lock, poetry.lock, Cargo.lock.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ---- requirements.txt ----
// Only "name==X.Y.Z" counts as pinned. Everything else is reported as
// unpinned (no constraint) or range (other operators / wildcard). Includes
// (-r, -c) are not followed: files are never read from disk.

var lfReqRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)

func lfPyNorm(n string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(n))
}

func lfParseRequirements(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "requirements.txt"}
	// join continuation lines
	var lines []string
	var acc strings.Builder
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.HasSuffix(ln, "\\") {
			acc.WriteString(strings.TrimSuffix(ln, "\\") + " ")
			if acc.Len() > 1<<20 {
				r.note("continuation line over 1 MiB truncated")
				lines, acc = append(lines, acc.String()), strings.Builder{}
			}
			continue
		}
		acc.WriteString(ln)
		lines = append(lines, acc.String())
		acc.Reset()
	}
	if acc.Len() > 0 {
		lines = append(lines, acc.String())
	}
	sawHash, includes := false, 0
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if i := strings.Index(t, " #"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "-") {
			low := strings.ToLower(t)
			switch {
			case strings.HasPrefix(low, "-r ") || strings.HasPrefix(low, "--requirement") || strings.HasPrefix(low, "-c ") || strings.HasPrefix(low, "--constraint"):
				includes++
			case strings.HasPrefix(low, "--index-url") || strings.HasPrefix(low, "-i ") || strings.HasPrefix(low, "--extra-index-url") || strings.HasPrefix(low, "--find-links") || strings.HasPrefix(low, "-f "):
				if strings.Contains(low, "http://") {
					r.hy("insecure-registry", "package index over plain http: "+firstURL(t))
				}
			case strings.HasPrefix(low, "-e ") || strings.HasPrefix(low, "--editable"):
				if lfLooksGit(t) {
					r.hy("git-dependency", "editable git install: "+truncInspect(t))
				}
			}
			continue
		}
		// strip per-requirement options and environment markers
		hashes := false
		if i := strings.Index(t, " --hash"); i >= 0 {
			hashes = true
			sawHash = true
			t = strings.TrimSpace(t[:i])
		}
		if i := strings.Index(t, ";"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if strings.Contains(t, "://") || strings.HasPrefix(t, "git+") {
			// "name @ url" or a bare URL: direct reference, never a registry pin
			name := ""
			if m := lfReqRe.FindStringSubmatch(t); m != nil && strings.Contains(t, "@") {
				name = m[1]
			}
			if name == "" {
				name = "(url)"
			}
			c := lfComp{Eco: "pypi", Name: lfPyNorm(name), Resolved: t, Git: lfLooksGit(t) || strings.Contains(t, "git+"), Unpinned: true, Direct: "direct"}
			r.add(c)
			continue
		}
		m := lfReqRe.FindStringSubmatch(t)
		if m == nil {
			r.note("unparsed line %q", truncInspect(t))
			continue
		}
		name, spec := lfPyNorm(m[1]), strings.TrimSpace(m[3])
		c := lfComp{Eco: "pypi", Name: name, Spec: spec, Direct: "direct"}
		if hashes {
			c.Integrity = "present"
		}
		switch {
		case spec == "":
			c.Unpinned = true
		case strings.HasPrefix(spec, "==") && !strings.HasPrefix(spec, "===") && !strings.ContainsAny(spec, "*,<>!~"):
			v := strings.TrimSpace(spec[2:])
			if v != "" {
				c.Version = v
			} else {
				c.Unpinned = true
			}
		case strings.HasPrefix(spec, "===") && !strings.ContainsAny(spec, "*,<>!~"):
			c.Version = strings.TrimSpace(spec[3:])
		default:
			c.Range = true
		}
		if !r.add(c) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.ExpectIntegrity = sawHash // only demand hashes when the file uses --require-hashes style at all
	if includes > 0 {
		r.note("%d -r/-c include line(s) not followed: files are never read from disk", includes)
	}
	r.note("requirements.txt is a manifest: transitive dependencies are not listed; all entries marked direct")
	return r, nil
}

func firstURL(s string) string {
	for _, f := range strings.Fields(s) {
		if strings.Contains(f, "://") {
			return f
		}
	}
	return s
}

// ---- Pipfile.lock ----

type lfPipEntry struct {
	Version string   `json:"version"`
	Hashes  []string `json:"hashes"`
	Git     string   `json:"git"`
	Ref     string   `json:"ref"`
	Path    string   `json:"path"`
	File    string   `json:"file"`
}

func lfParsePipfileLock(data []byte) (*lfResult, error) {
	var l struct {
		Default map[string]lfPipEntry `json:"default"`
		Develop map[string]lfPipEntry `json:"develop"`
	}
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("Pipfile.lock: %v", err)
	}
	r := &lfResult{Format: "Pipfile.lock", ExpectIntegrity: true}
	for _, grp := range []map[string]lfPipEntry{l.Default, l.Develop} {
		for n, e := range grp {
			c := lfComp{Eco: "pypi", Name: lfPyNorm(n), Git: e.Git != "", Resolved: e.Git + e.File}
			if v := strings.TrimSpace(e.Version); strings.HasPrefix(v, "==") {
				c.Version = strings.TrimSpace(v[2:])
			} else if v != "" {
				c.Range, c.Spec = true, v
			}
			if len(e.Hashes) > 0 {
				c.Integrity = e.Hashes[0]
			}
			if !r.add(c) {
				break
			}
		}
	}
	r.note("Pipfile.lock does not record direct vs transitive; marked unknown")
	return r, nil
}

// ---- TOML subset: [[package]] tables (poetry.lock, Cargo.lock) ----
// Supported: [[package]] array-of-tables headers, key = "string" pairs,
// [package.source]-style sub-tables (keys exposed as "source.key"), and the
// first hash = "..." inside a files = [...] array. Everything else (inline
// tables elsewhere, dotted keys, multi-line strings) is skipped. This is not
// a general TOML parser and never errors on unknown syntax.

type lfTomlPkg map[string]string

func lfParseTomlPackages(text string) []lfTomlPkg {
	var pkgs []lfTomlPkg
	var cur lfTomlPkg
	sub := ""
	arrDepth := 0
	hashRe := regexp.MustCompile(`hash\s*=\s*"([^"]*)"`)
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if arrDepth > 0 { // inside a multi-line array
			if cur != nil && sub == "" {
				if m := hashRe.FindStringSubmatch(t); m != nil && cur["hash"] == "" {
					cur["hash"] = m[1]
				}
			}
			arrDepth += strings.Count(t, "[") - strings.Count(t, "]")
			continue
		}
		if strings.HasPrefix(t, "[[") {
			name := strings.Trim(strings.TrimSpace(t), "[]")
			if name == "package" {
				cur = lfTomlPkg{}
				pkgs = append(pkgs, cur)
				sub = ""
			} else {
				cur, sub = nil, ""
			}
			continue
		}
		if strings.HasPrefix(t, "[") {
			name := strings.Trim(t, "[] ")
			sub = ""
			if strings.HasPrefix(name, "package.") && cur != nil {
				sub = strings.TrimPrefix(name, "package.")
			} else {
				cur = nil
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if strings.HasPrefix(v, "[") {
			if d := strings.Count(v, "[") - strings.Count(v, "]"); d > 0 {
				arrDepth = d
			}
			if k == "files" && sub == "" {
				if m := hashRe.FindStringSubmatch(v); m != nil && cur["hash"] == "" {
					cur["hash"] = m[1]
				}
			}
			continue
		}
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
			if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
				v = v[1 : 1+end]
			}
		}
		if sub != "" {
			if sub == "source" {
				cur["source."+k] = v
			}
			continue
		}
		cur[k] = v
	}
	return pkgs
}

func lfParsePoetry(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "poetry.lock", ExpectIntegrity: true}
	for _, p := range lfParseTomlPackages(string(data)) {
		if p["name"] == "" || p["version"] == "" {
			continue
		}
		c := lfComp{Eco: "pypi", Name: lfPyNorm(p["name"]), Version: p["version"], Integrity: p["hash"]}
		switch p["source.type"] {
		case "git":
			c.Git, c.Resolved = true, p["source.url"]
		case "url", "legacy":
			c.Resolved = p["source.url"]
		case "directory", "file":
			c.Resolved = p["source.url"]
			c.Integrity = "n/a-local"
		}
		if !r.add(c) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.note("poetry.lock does not record direct vs transitive in [[package]] tables; marked unknown")
	return r, nil
}

func lfParseCargo(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "Cargo.lock", ExpectIntegrity: true}
	for _, p := range lfParseTomlPackages(string(data)) {
		if p["name"] == "" || p["version"] == "" {
			continue
		}
		src := p["source"]
		if src == "" {
			continue // workspace member or path dependency: first-party, no registry
		}
		c := lfComp{Eco: "cargo", Name: p["name"], Version: p["version"], Resolved: src, Integrity: p["checksum"]}
		if strings.HasPrefix(src, "git+") {
			c.Git = true
			c.Integrity = "n/a-git"
		}
		if !r.add(c) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.note("Cargo.lock does not record direct vs transitive; first-party (sourceless) packages skipped; marked unknown")
	return r, nil
}
