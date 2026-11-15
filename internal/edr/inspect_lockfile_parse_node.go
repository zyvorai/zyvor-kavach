// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Lockfile parsers, JavaScript family: package-lock.json, yarn.lock (v1),
// pnpm-lock.yaml. Parse only; nothing is executed or fetched.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// lfComp is one extracted dependency.
type lfComp struct {
	Eco       string
	Name      string
	Version   string // resolved/pinned version; "" when not pinned
	Spec      string // original specifier when the file is a manifest
	Direct    string // "direct", "transitive" or "" (unknown)
	Integrity string // as written: sri string, hex digest, h1:...
	Resolved  string // resolved URL when present
	Unpinned  bool   // no version constraint at all
	Range     bool   // constraint present but not an exact pin
	Git       bool   // fetched from a git URL
	HTTP      bool   // plain http:// source
	Note      string // per-component remark (e.g. unresolved property)
}

// lfResult is what a parser returns.
type lfResult struct {
	Format          string
	Comps           []lfComp
	Notes           []string // limits and unsupported constructs found in this file
	ExpectIntegrity bool     // the format normally carries a hash per package
	Extra           []lfHy   // file-level hygiene observations (not tied to a component)
}

// lfHy is a hygiene observation that is not a component (e.g. an insecure index URL).
type lfHy struct{ Kind, Evidence string }

func (r *lfResult) hy(kind, ev string) {
	if len(r.Extra) < 50 {
		r.Extra = append(r.Extra, lfHy{kind, ev})
	}
}

func (r *lfResult) note(f string, a ...any) {
	if len(r.Notes) < 50 {
		r.Notes = append(r.Notes, fmt.Sprintf(f, a...))
	}
}

const lfMaxComps = 50000

func (r *lfResult) add(c lfComp) bool {
	if len(r.Comps) >= lfMaxComps {
		return false
	}
	if strings.HasPrefix(strings.ToLower(c.Resolved), "http://") {
		c.HTTP = true
	}
	r.Comps = append(r.Comps, c)
	return true
}

func lfLooksGit(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "git+") || strings.HasPrefix(l, "git://") || strings.HasPrefix(l, "github:") ||
		strings.HasPrefix(l, "gitlab:") || strings.HasPrefix(l, "bitbucket:") || strings.HasPrefix(l, "git@") ||
		strings.Contains(l, ".git#") || strings.HasSuffix(l, ".git")
}

// ---- package-lock.json (lockfileVersion 1, 2, 3) ----

type lfNPMEntry struct {
	Version      string            `json:"version"`
	Resolved     string            `json:"resolved"`
	Integrity    string            `json:"integrity"`
	Link         bool              `json:"link"`
	Name         string            `json:"name"`
	Dependencies map[string]any    `json:"dependencies"` // v1: nested objects; v2/3 root: name -> range string
	Dev          map[string]string `json:"devDependencies"`
	Optional     map[string]string `json:"optionalDependencies"`
}

type lfNPMLock struct {
	LockfileVersion int                   `json:"lockfileVersion"`
	Packages        map[string]lfNPMEntry `json:"packages"`
	Dependencies    map[string]lfNPMV1    `json:"dependencies"`
}

type lfNPMV1 struct {
	Version      string             `json:"version"`
	Resolved     string             `json:"resolved"`
	Integrity    string             `json:"integrity"`
	Dependencies map[string]lfNPMV1 `json:"dependencies"`
}

func lfParseNPM(data []byte) (*lfResult, error) {
	var l lfNPMLock
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("package-lock.json: %v", err)
	}
	r := &lfResult{Format: "package-lock.json", ExpectIntegrity: true}
	if len(l.Packages) > 0 {
		root := l.Packages[""]
		directs := map[string]bool{}
		for n := range root.Dependencies {
			directs[n] = true
		}
		for n := range root.Dev {
			directs[n] = true
		}
		for n := range root.Optional {
			directs[n] = true
		}
		keys := make([]string, 0, len(l.Packages))
		for k := range l.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				continue
			}
			e := l.Packages[k]
			if e.Link {
				continue
			}
			name := e.Name
			idx := strings.LastIndex(k, "node_modules/")
			if idx >= 0 {
				name = k[idx+len("node_modules/"):]
			} else if name == "" {
				continue // workspace member path
			}
			dir := "transitive"
			if k == "node_modules/"+name {
				if len(directs) == 0 || directs[name] {
					dir = "direct"
				}
			}
			if len(directs) == 0 {
				dir = ""
			}
			c := lfComp{Eco: "npm", Name: name, Version: e.Version, Direct: dir, Integrity: e.Integrity, Resolved: e.Resolved}
			if lfLooksGit(e.Resolved) || lfLooksGit(e.Version) {
				c.Git = true
			}
			if !r.add(c) {
				r.note("component cap %d reached", lfMaxComps)
				break
			}
		}
		return r, nil
	}
	if len(l.Dependencies) > 0 {
		r.note("lockfileVersion %d: direct/transitive is not recorded; marked unknown", l.LockfileVersion)
		var walk func(m map[string]lfNPMV1, depth int)
		walk = func(m map[string]lfNPMV1, depth int) {
			names := make([]string, 0, len(m))
			for n := range m {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				e := m[n]
				c := lfComp{Eco: "npm", Name: n, Version: e.Version, Integrity: e.Integrity, Resolved: e.Resolved}
				if lfLooksGit(e.Resolved) || lfLooksGit(e.Version) {
					c.Git = true
				}
				if !r.add(c) {
					return
				}
				if depth < 64 {
					walk(e.Dependencies, depth+1)
				} else {
					r.note("nesting deeper than 64 levels truncated")
				}
			}
		}
		walk(l.Dependencies, 0)
		return r, nil
	}
	if l.LockfileVersion == 0 {
		return nil, fmt.Errorf("package-lock.json: no lockfileVersion, packages or dependencies")
	}
	return r, nil
}

// ---- yarn.lock (classic v1) ----
// Yarn Berry (v2+, "__metadata:") uses a different YAML dialect and is not
// parsed; the analyzer reports that instead of guessing.

func lfYarnName(spec string) string {
	spec = strings.Trim(strings.TrimSpace(spec), `"`)
	i := strings.LastIndex(spec, "@")
	if i <= 0 {
		return ""
	}
	return spec[:i]
}

func lfParseYarn(data []byte) (*lfResult, error) {
	text := string(data)
	r := &lfResult{Format: "yarn.lock", ExpectIntegrity: true}
	if strings.Contains(text, "\n__metadata:") || strings.HasPrefix(text, "__metadata:") {
		r.note("yarn.lock is Yarn Berry (v2+) format: not parsed (only the classic v1 format is supported)")
		return r, nil
	}
	var cur *lfComp
	var names []string
	flush := func() {
		if cur != nil && cur.Name != "" && cur.Version != "" {
			if lfLooksGit(cur.Resolved) {
				cur.Git = true
			}
			if !r.add(*cur) {
				return
			}
		}
		cur = nil
	}
	seen := 0
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if seen++; seen > 2_000_000 {
			r.note("line cap reached")
			break
		}
		if strings.TrimSpace(ln) == "" || strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		if ln[0] != ' ' {
			flush()
			if !strings.HasSuffix(ln, ":") {
				continue
			}
			names = nil
			for _, s := range strings.Split(strings.TrimSuffix(ln, ":"), ",") {
				if n := lfYarnName(s); n != "" {
					names = append(names, n)
				}
			}
			if len(names) > 0 {
				cur = &lfComp{Eco: "npm", Name: names[0]}
			}
			continue
		}
		if cur == nil || strings.HasPrefix(ln, "    ") { // nested dependency listing
			continue
		}
		t := strings.TrimSpace(ln)
		k, v, ok := strings.Cut(t, " ")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch k {
		case "version":
			cur.Version = v
		case "resolved":
			cur.Resolved = v
			if i := strings.LastIndex(v, "#"); i >= 0 && !lfLooksGit(v) {
				cur.Integrity = "sha1-" + v[i+1:]
			}
		case "integrity":
			cur.Integrity = v
		}
	}
	flush()
	r.note("yarn.lock v1 does not record direct vs transitive; marked unknown")
	return r, nil
}

// ---- pnpm-lock.yaml ----
// Uses the repo's miniYAMLParse (block mappings and sequences, scalars, flow
// lists). It has no flow mappings, anchors or multi-document support, so
// "resolution: {integrity: ..}" lines are first rewritten to block form and
// other flow-mapping values ("engines: {node: '>=8'}") are dropped. Anything
// else the mini parser rejects makes the whole file unparsed (reported).

var lfPnpmResRe = regexp.MustCompile(`^(\s*)(resolution):\s*\{(.*)\}\s*$`)
var lfPnpmFlowRe = regexp.MustCompile(`^(\s*)([^\s#][^:]*|'[^']*'|"[^"]*"):\s*\{.*\}\s*$`)

func lfPnpmPrepare(text string) string {
	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines)+16)
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r")
		if m := lfPnpmResRe.FindStringSubmatch(ln); m != nil {
			out = append(out, m[1]+"resolution:")
			for _, kv := range strings.Split(m[3], ",") {
				k, v, ok := strings.Cut(strings.TrimSpace(kv), ":")
				if !ok {
					continue
				}
				k, v = strings.TrimSpace(k), strings.TrimSpace(v)
				// a value like "https://x" was split at the first ':' correctly
				out = append(out, m[1]+"  "+k+": "+lfYAMLQuote(v))
			}
			continue
		}
		if m := lfPnpmFlowRe.FindStringSubmatch(ln); m != nil {
			out = append(out, m[1]+strings.TrimSpace(m[2])+":")
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func lfYAMLQuote(v string) string {
	v = strings.Trim(v, `'"`)
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

func lfAsMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func lfStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// lfPnpmSplit splits a packages key into name and version for the v5
// ("/name/1.0.0" or "/name/1.0.0_peer"), v6 ("/name@1.0.0(peer@1)") and v9
// ("name@1.0.0") shapes.
func lfPnpmSplit(key string) (name, ver string) {
	k := strings.Trim(key, `'"`)
	k = strings.TrimPrefix(k, "/")
	if i := strings.IndexByte(k, '('); i >= 0 {
		k = k[:i]
	}
	if i := strings.LastIndex(k, "@"); i > 0 {
		return k[:i], k[i+1:]
	}
	// v5: name/version
	if i := strings.LastIndex(k, "/"); i > 0 {
		name, ver = k[:i], k[i+1:]
		if j := strings.IndexByte(ver, '_'); j > 0 {
			ver = ver[:j]
		}
		return name, ver
	}
	return "", ""
}

func lfParsePnpm(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "pnpm-lock.yaml", ExpectIntegrity: true}
	doc, err := miniYAMLParse(lfPnpmPrepare(string(data)))
	if err != nil {
		return nil, fmt.Errorf("pnpm-lock.yaml: unsupported YAML (%v)", err)
	}
	root := lfAsMap(doc)
	if root == nil {
		return nil, fmt.Errorf("pnpm-lock.yaml: top level is not a mapping")
	}
	directs := map[string]bool{}
	collect := func(m map[string]any) {
		for _, sec := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			for n := range lfAsMap(m[sec]) {
				directs[n] = true
			}
		}
	}
	collect(root) // v5
	for _, imp := range lfAsMap(root["importers"]) {
		collect(lfAsMap(imp)) // v6+
	}
	pk := lfAsMap(root["packages"])
	keys := make([]string, 0, len(pk))
	for k := range pk {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	for _, k := range keys {
		name, ver := lfPnpmSplit(k)
		if name == "" || ver == "" {
			r.note("packages key %q not understood; skipped", truncInspect(k))
			continue
		}
		id := name + "@" + ver
		if seen[id] {
			continue // peer-dependency variants of the same version
		}
		seen[id] = true
		e := lfAsMap(pk[k])
		res := lfAsMap(e["resolution"])
		c := lfComp{Eco: "npm", Name: name, Version: ver, Integrity: lfStr(res["integrity"]), Resolved: lfStr(res["tarball"])}
		if lfStr(res["type"]) == "git" || lfLooksGit(lfStr(res["repo"])) || lfLooksGit(c.Resolved) {
			c.Git = true
		}
		if len(directs) > 0 {
			c.Direct = "transitive"
			if directs[name] {
				c.Direct = "direct"
			}
		}
		if !r.add(c) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	if len(r.Comps) == 0 && len(pk) == 0 {
		r.note("no packages: section found")
	}
	return r, nil
}
