// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Lockfile parsers: go.mod, go.sum, Gemfile.lock, composer.lock, pom.xml,
// Gradle lockfiles, NuGet packages.lock.json, and dpkg/rpm/apk package lists.

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// ---- go.mod ----

func lfParseGoMod(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "go.mod"}
	inReq, inOther := false, false
	replaces := 0
	for _, ln := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(strings.TrimRight(ln, "\r"))
		indirect := strings.Contains(t, "// indirect")
		if i := strings.Index(t, "//"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t == "" {
			continue
		}
		switch {
		case inReq && t == ")":
			inReq = false
			continue
		case inOther && t == ")":
			inOther = false
			continue
		case !inReq && !inOther && strings.HasSuffix(t, "(") && !strings.Contains(t, "=>"):
			kw := strings.TrimSpace(strings.TrimSuffix(t, "("))
			inReq = kw == "require"
			inOther = !inReq
			if kw == "replace" {
				replaces++
			}
			continue
		}
		var spec string
		switch {
		case inReq:
			spec = t
		case strings.HasPrefix(t, "require "):
			spec = strings.TrimSpace(strings.TrimPrefix(t, "require "))
		case strings.HasPrefix(t, "replace ") || (inOther && strings.Contains(t, "=>")):
			replaces++
			continue
		default:
			continue
		}
		f := strings.Fields(spec)
		if len(f) < 2 {
			continue
		}
		dir := "direct"
		if indirect {
			dir = "transitive"
		}
		if !r.add(lfComp{Eco: "go", Name: f[0], Version: f[1], Direct: dir}) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	if replaces > 0 {
		r.note("%d replace directive(s) not applied: replaced modules are reported with their go.mod version", replaces)
	}
	r.note("go.mod has no integrity hashes; submit go.sum too")
	return r, nil
}

// ---- go.sum ----

func lfParseGoSum(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "go.sum", ExpectIntegrity: true}
	seen := map[string]bool{}
	for _, ln := range strings.Split(string(data), "\n") {
		f := strings.Fields(strings.TrimSpace(ln))
		if len(f) != 3 || !strings.HasPrefix(f[2], "h1:") {
			continue
		}
		if strings.HasSuffix(f[1], "/go.mod") {
			continue // module-graph hash, not the module content
		}
		k := f[0] + "@" + f[1]
		if seen[k] {
			continue
		}
		seen[k] = true
		if !r.add(lfComp{Eco: "go", Name: f[0], Version: f[1], Integrity: f[2]}) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.note("go.sum does not record direct vs transitive; marked unknown")
	return r, nil
}

// ---- Gemfile.lock ----

func lfParseGemfileLock(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "Gemfile.lock"}
	section, remote := "", ""
	inSpecs := false
	directs := map[string]bool{}
	sums := map[string]string{}
	type gem struct {
		name, ver, remote string
		git               bool
	}
	var gems []gem
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" {
			continue
		}
		if ln[0] != ' ' {
			section, remote, inSpecs = strings.TrimSpace(ln), "", false
			continue
		}
		t := strings.TrimSpace(ln)
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		switch section {
		case "GEM", "GIT", "PATH":
			switch {
			case strings.HasPrefix(t, "remote:"):
				remote = strings.TrimSpace(strings.TrimPrefix(t, "remote:"))
			case t == "specs:":
				inSpecs = true
			case inSpecs && indent == 4:
				name, rest, ok := strings.Cut(t, " (")
				if !ok {
					continue
				}
				ver := strings.TrimSuffix(rest, ")")
				if i := strings.IndexByte(ver, '-'); i > 0 { // platform suffix
					ver = ver[:i]
				}
				if section == "PATH" {
					continue // first-party
				}
				gems = append(gems, gem{name, ver, remote, section == "GIT"})
			}
		case "DEPENDENCIES":
			name := t
			if i := strings.IndexAny(t, " !"); i > 0 {
				name = t[:i]
			}
			directs[name] = true
		case "CHECKSUMS":
			if name, rest, ok := strings.Cut(t, " ("); ok {
				ver, sum, _ := strings.Cut(rest, ") ")
				sums[name+"@"+ver] = strings.TrimSpace(sum)
			}
		}
	}
	hasSums := len(sums) > 0
	for _, g := range gems {
		c := lfComp{Eco: "gem", Name: g.name, Version: g.ver, Resolved: g.remote, Git: g.git}
		if len(directs) > 0 {
			c.Direct = "transitive"
			if directs[g.name] {
				c.Direct = "direct"
			}
		}
		c.Integrity = sums[g.name+"@"+g.ver]
		if !r.add(c) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.ExpectIntegrity = hasSums
	if !hasSums {
		r.note("Gemfile.lock has no CHECKSUMS section: integrity hashes not available")
	}
	return r, nil
}

// ---- composer.lock ----

func lfParseComposer(data []byte) (*lfResult, error) {
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Source  struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"source"`
		Dist struct {
			URL    string `json:"url"`
			Shasum string `json:"shasum"`
		} `json:"dist"`
	}
	var l struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("composer.lock: %v", err)
	}
	r := &lfResult{Format: "composer.lock", ExpectIntegrity: true}
	for _, p := range append(l.Packages, l.PackagesDev...) {
		if p.Name == "" {
			continue
		}
		c := lfComp{Eco: "composer", Name: strings.ToLower(p.Name), Version: strings.TrimPrefix(p.Version, "v"), Integrity: p.Dist.Shasum, Resolved: p.Dist.URL}
		if c.Resolved == "" {
			c.Resolved = p.Source.URL
		}
		if p.Dist.URL == "" && p.Source.Type == "git" {
			c.Git = true
		}
		if strings.HasPrefix(p.Version, "dev-") {
			c.Note = "dev branch version"
			c.Git = true
		}
		if !r.add(c) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.note("composer.lock does not record direct vs transitive; marked unknown. The dist shasum is SHA-1 and is often empty")
	return r, nil
}

// ---- pom.xml ----
// Direct <dependencies> under <project> with literal versions only. Not
// supported: property substitution (${...}), parent POM inheritance,
// dependencyManagement resolution, BOM imports, profiles. Those components
// are listed but get no version, and are reported.

type lfPom struct {
	Dependencies struct {
		Dep []struct {
			Group   string `xml:"groupId"`
			Artif   string `xml:"artifactId"`
			Version string `xml:"version"`
			Scope   string `xml:"scope"`
		} `xml:"dependency"`
	} `xml:"dependencies"`
	Repos struct {
		Repo []struct {
			URL string `xml:"url"`
		} `xml:"repository"`
	} `xml:"repositories"`
}

func lfParsePom(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "pom.xml"}
	d := xml.NewDecoder(strings.NewReader(string(data)))
	d.Strict = true
	d.CharsetReader = func(cs string, in io.Reader) (io.Reader, error) { return in, nil }
	var p lfPom
	// Decode only the top-level <project>: custom entities are not expanded
	// (Go's decoder does not resolve DTD entities) so entity bombs cannot occur.
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("pom.xml: %v", err)
	}
	unresolved, managed, ranges := 0, 0, 0
	for _, dep := range p.Dependencies.Dep {
		g, a, v := strings.TrimSpace(dep.Group), strings.TrimSpace(dep.Artif), strings.TrimSpace(dep.Version)
		if a == "" {
			continue
		}
		c := lfComp{Eco: "maven", Name: g + ":" + a, Direct: "direct"}
		switch {
		case v == "":
			c.Unpinned = true
			c.Note = "no literal version (inherited or managed elsewhere)"
			managed++
		case strings.Contains(v, "${"):
			c.Unpinned = true
			c.Spec = v
			c.Note = "version uses property substitution: not resolved"
			unresolved++
		case strings.ContainsAny(v, "[](),") || v == "LATEST" || v == "RELEASE":
			c.Range, c.Spec = true, v
			ranges++
		default:
			c.Version = v
		}
		if !r.add(c) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	for _, rp := range p.Repos.Repo {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rp.URL)), "http://") {
			r.hy("insecure-registry", "repository over plain http: "+strings.TrimSpace(rp.URL))
		}
	}
	if unresolved > 0 {
		r.note("%d dependency version(s) use ${property} substitution: out of scope, not matched", unresolved)
	}
	if managed > 0 {
		r.note("%d dependency(ies) have no version (parent/dependencyManagement not resolved): not matched", managed)
	}
	r.note("pom.xml is a manifest: only direct dependencies are listed, transitives are not resolved; no integrity hashes")
	return r, nil
}

// ---- Gradle lockfile (gradle.lockfile, *.lockfile) ----

func lfParseGradle(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "gradle.lockfile"}
	seen := map[string]bool{}
	for _, ln := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "empty=") {
			continue
		}
		coord, _, _ := strings.Cut(t, "=")
		f := strings.Split(coord, ":")
		if len(f) != 3 || f[0] == "" || f[1] == "" || f[2] == "" {
			continue
		}
		name := f[0] + ":" + f[1]
		if seen[name+"@"+f[2]] {
			continue
		}
		seen[name+"@"+f[2]] = true
		if !r.add(lfComp{Eco: "maven", Name: name, Version: f[2]}) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.note("Gradle lockfiles do not record direct vs transitive or hashes; marked unknown")
	return r, nil
}

// ---- NuGet packages.lock.json ----

func lfParseNuGet(data []byte) (*lfResult, error) {
	var l struct {
		Version      int `json:"version"`
		Dependencies map[string]map[string]struct {
			Type        string `json:"type"`
			Requested   string `json:"requested"`
			Resolved    string `json:"resolved"`
			ContentHash string `json:"contentHash"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("packages.lock.json: %v", err)
	}
	r := &lfResult{Format: "packages.lock.json", ExpectIntegrity: true}
	seen := map[string]bool{}
	for _, fw := range l.Dependencies {
		for n, e := range fw {
			if strings.EqualFold(e.Type, "Project") || e.Resolved == "" {
				continue
			}
			k := strings.ToLower(n) + "@" + e.Resolved
			if seen[k] {
				continue
			}
			seen[k] = true
			dir := ""
			switch strings.ToLower(e.Type) {
			case "direct":
				dir = "direct"
			case "transitive":
				dir = "transitive"
			}
			if !r.add(lfComp{Eco: "nuget", Name: n, Version: e.Resolved, Direct: dir, Integrity: e.ContentHash}) {
				r.note("component cap %d reached", lfMaxComps)
				return r, nil
			}
		}
	}
	return r, nil
}

// ---- dpkg -l / rpm -qa / apk info -v ----

var lfDpkgRe = regexp.MustCompile(`^(ii|hi|iU|iF)\s+(\S+)\s+(\S+)\s+(\S+)`)
var lfRPMRe = regexp.MustCompile(`^(.+)-([^-\s]+)-([^-\s]+)\.([A-Za-z0-9_]+)$`)
var lfApkRe = regexp.MustCompile(`^(.+?)-(\d[^\s]*-r\d+)$`)

func lfParseDpkg(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "dpkg -l"}
	for _, ln := range strings.Split(string(data), "\n") {
		m := lfDpkgRe.FindStringSubmatch(strings.TrimRight(ln, "\r"))
		if m == nil {
			continue
		}
		name := m[2]
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i]
		}
		if !r.add(lfComp{Eco: "deb", Name: name, Version: m[3]}) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.note("package lists carry no direct/transitive information or hashes")
	return r, nil
}

func lfParseRPMList(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "rpm -qa"}
	for _, ln := range strings.Split(string(data), "\n") {
		m := lfRPMRe.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		if !r.add(lfComp{Eco: "rpm", Name: m[1], Version: m[2] + "-" + m[3]}) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.note("package lists carry no direct/transitive information or hashes; rpm -qa output has no epoch, so epoch is assumed 0")
	return r, nil
}

func lfParseApkList(data []byte) (*lfResult, error) {
	r := &lfResult{Format: "apk info -v"}
	for _, ln := range strings.Split(string(data), "\n") {
		m := lfApkRe.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		if !r.add(lfComp{Eco: "apk", Name: m[1], Version: m[2]}) {
			r.note("component cap %d reached", lfMaxComps)
			break
		}
	}
	r.note("package lists carry no direct/transitive information or hashes")
	return r, nil
}
