// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectLockfileKindRegistered(t *testing.T) {
	found := false
	for _, k := range inspectKinds {
		if k == InspectKindLockfile {
			found = true
		}
	}
	if !found || InspectKindLockfile != "lockfile" {
		t.Fatal("lockfile kind missing from inspectKinds")
	}
	if got := InspectAnalyzerNames()[InspectKindLockfile]; len(got) != 1 || got[0] != "lockfile" {
		t.Fatalf("analyzers for lockfile kind: %v", got)
	}
}

func lfSetAdvisories(t *testing.T, advs []VMAdvisory) {
	t.Helper()
	b, _ := json.Marshal(advs)
	p := filepath.Join(t.TempDir(), "cve.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KAVACH_CVE_FILE", p)
}

func lfRun(name, data string) *InspectReport {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return RunAnalyzers(ctx, InspectInput{Kind: InspectKindLockfile, Name: name, Data: []byte(data)})
}

func lfFind(r *InspectReport, id string) *InspectFinding {
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			return &r.Findings[i]
		}
	}
	return nil
}

var lfTestAdvisories = []VMAdvisory{
	{CVE: "CVE-2099-0001", Package: "lodash", FixedIn: "4.17.21", CVSS: 9.1, Summary: "synthetic lodash"},
	{CVE: "CVE-2099-0002", Package: "django", FixedIn: "3.2.5", CVSS: 7.5, Summary: "synthetic django"},
	{CVE: "CVE-2099-0003", Package: "openssl", FixedIn: "1:1.1.1n-0", CVSS: 5.0, Summary: "synthetic openssl"},
	{CVE: "CVE-2099-0004", Package: "serde", FixedIn: "1.0.150", CVSS: 3.0, Summary: "synthetic serde"},
	{CVE: "CVE-2099-0005", Package: "org.apache.logging.log4j:log4j-core", FixedIn: "2.17.1", CVSS: 10, Summary: "synthetic log4j"},
	{CVE: "CVE-2099-0006", Package: "github.com/x/y", FixedIn: "v1.2.3", CVSS: 8, Summary: "synthetic go"},
	{CVE: "CVE-2099-0007", Package: "rails", FixedIn: "6.1.4", CVSS: 6, Summary: "synthetic rails"},
	{CVE: "CVE-2099-0008", Package: "weird", FixedIn: "not a version!", CVSS: 8, Summary: "unparseable fix"},
}

// goldenFixtures: one fixture per format, expected to yield these components.
var goldenFixtures = []struct {
	name, file, data string
	format           string
	want             []string // eco|name|version
	direct           map[string]string
}{
	{name: "npm v3", file: "package-lock.json", format: "package-lock.json",
		data: `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"lodash":"^4.17.0"}},
"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz","integrity":"sha512-aGVsbG8="},
"node_modules/lodash/node_modules/@scope/dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/@scope/dep/-/dep-1.0.0.tgz","integrity":"sha512-aGVsbG8="}}}`,
		want:   []string{"npm|lodash|4.17.20", "npm|@scope/dep|1.0.0"},
		direct: map[string]string{"lodash": "direct", "@scope/dep": "transitive"}},
	{name: "npm v1", file: "package-lock.json", format: "package-lock.json",
		data: `{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","integrity":"sha1-aGVsbG8=","dependencies":{"b":{"version":"2.0.0","integrity":"sha1-aGVsbG8="}}}}}`,
		want: []string{"npm|a|1.0.0", "npm|b|2.0.0"}},
	{name: "yarn v1", file: "yarn.lock", format: "yarn.lock",
		data: "# yarn lockfile v1\n\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.1.2\"\n  resolved \"https://registry.yarnpkg.com/@babel/core/-/core-7.1.2.tgz#abcdef\"\n  integrity sha512-aGVsbG8=\n  dependencies:\n    foo \"^1.0.0\"\n\nfoo@^1.0.0:\n  version \"1.2.3\"\n  resolved \"https://registry.yarnpkg.com/foo/-/foo-1.2.3.tgz#0123\"\n",
		want: []string{"npm|@babel/core|7.1.2", "npm|foo|1.2.3"}},
	{name: "pnpm v9", file: "pnpm-lock.yaml", format: "pnpm-lock.yaml",
		data:   "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n        version: 4.17.20\npackages:\n  lodash@4.17.20:\n    resolution: {integrity: sha512-aGVsbG8=}\n  '@scope/dep@1.0.0(react@18.0.0)':\n    resolution: {integrity: sha512-aGVsbG8=}\n    engines: {node: '>=8'}\nsnapshots:\n  lodash@4.17.20: {}\n",
		want:   []string{"npm|lodash|4.17.20", "npm|@scope/dep|1.0.0"},
		direct: map[string]string{"lodash": "direct", "@scope/dep": "transitive"}},
	{name: "requirements", file: "requirements.txt", format: "requirements.txt",
		data: "# c\nDjango==3.2.4 \\\n  --hash=sha256:aa\nrequests>=2.0\nflask\nPyYAML[extra]==5.4.1 ; python_version<'3.9'\n-r other.txt\n",
		want: []string{"pypi|django|3.2.4", "pypi|requests|", "pypi|flask|", "pypi|pyyaml|5.4.1"}},
	{name: "Pipfile.lock", file: "Pipfile.lock", format: "Pipfile.lock",
		data: `{"_meta":{},"default":{"django":{"version":"==3.2.4","hashes":["sha256:aa"]}},"develop":{"pytest":{"version":"==7.0.0","hashes":["sha256:bb"]}}}`,
		want: []string{"pypi|django|3.2.4", "pypi|pytest|7.0.0"}},
	{name: "poetry.lock", file: "poetry.lock", format: "poetry.lock",
		data: "[[package]]\nname = \"Django\"\nversion = \"3.2.4\"\ndescription = \"x\"\nfiles = [\n    {file = \"d.whl\", hash = \"sha256:aa\"},\n]\n\n[package.dependencies]\nasgiref = \">=3\"\n\n[[package]]\nname = \"mylib\"\nversion = \"0.1.0\"\n\n[package.source]\ntype = \"git\"\nurl = \"https://github.com/a/mylib\"\n\n[metadata]\ncontent-hash = \"abc\"\n",
		want: []string{"pypi|django|3.2.4", "pypi|mylib|0.1.0"}},
	{name: "go.mod", file: "go.mod", format: "go.mod",
		data:   "module example.com/m\n\ngo 1.21\n\nrequire (\n\tgithub.com/x/y v1.2.0\n\tgolang.org/x/text v0.3.0 // indirect\n)\n\nrequire github.com/a/b v0.0.1\n",
		want:   []string{"go|github.com/x/y|v1.2.0", "go|golang.org/x/text|v0.3.0", "go|github.com/a/b|v0.0.1"},
		direct: map[string]string{"github.com/x/y": "direct", "golang.org/x/text": "transitive"}},
	{name: "go.sum", file: "go.sum", format: "go.sum",
		data: "github.com/x/y v1.2.0 h1:abc=\ngithub.com/x/y v1.2.0/go.mod h1:def=\n",
		want: []string{"go|github.com/x/y|v1.2.0"}},
	{name: "Cargo.lock", file: "Cargo.lock", format: "Cargo.lock",
		data: "# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\ndependencies = [\n \"serde_derive\",\n]\n\n[[package]]\nname = \"myapp\"\nversion = \"0.1.0\"\n",
		want: []string{"cargo|serde|1.0.100"}},
	{name: "Gemfile.lock", file: "Gemfile.lock", format: "Gemfile.lock",
		data:   "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n    rails (6.1.0)\n      rack (>= 2.0)\n    nokogiri (1.13.0-x86_64-linux)\n\nDEPENDENCIES\n  rails (~> 6.1)\n\nBUNDLED WITH\n   2.3.0\n",
		want:   []string{"gem|rack|2.2.3", "gem|rails|6.1.0", "gem|nokogiri|1.13.0"},
		direct: map[string]string{"rails": "direct", "rack": "transitive"}},
	{name: "composer.lock", file: "composer.lock", format: "composer.lock",
		data: `{"content-hash":"x","packages":[{"name":"Monolog/Monolog","version":"v2.0.1","dist":{"url":"https://api.github.com/x","shasum":"0123456789abcdef0123456789abcdef01234567"}}],"packages-dev":[]}`,
		want: []string{"composer|monolog/monolog|2.0.1"}},
	{name: "pom.xml", file: "pom.xml", format: "pom.xml",
		data: `<?xml version="1.0"?><project><dependencies>
<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
<dependency><groupId>g</groupId><artifactId>prop</artifactId><version>${p.version}</version></dependency>
</dependencies></project>`,
		want: []string{"maven|org.apache.logging.log4j:log4j-core|2.14.1", "maven|g:prop|"}},
	{name: "gradle lockfile", file: "gradle.lockfile", format: "gradle.lockfile",
		data: "# comment\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n",
		want: []string{"maven|org.apache.logging.log4j:log4j-core|2.14.1"}},
	{name: "NuGet", file: "packages.lock.json", format: "packages.lock.json",
		data: `{"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1","contentHash":"abc=="},"Proj":{"type":"Project"}}}}`,
		want: []string{"nuget|Newtonsoft.Json|13.0.1"}},
	{name: "dpkg", file: "dpkg.txt", format: "dpkg -l",
		data: "Desired=Unknown/Install/Remove/Purge/Hold\n||/ Name Version Architecture Description\n+++-==-=-=-=\nii  openssl  1.1.1k-1  amd64  SSL\nrc  gone  1.0  amd64  removed\nii  libc6:amd64  2.31-13  amd64  libc\n",
		want: []string{"deb|openssl|1.1.1k-1", "deb|libc6|2.31-13"}},
	{name: "rpm", file: "rpm.txt", format: "rpm -qa",
		data: "openssl-1.1.1k-7.el8_6.x86_64\nbash-5.1.8-4.el9.aarch64\n",
		want: []string{"rpm|openssl|1.1.1k-7.el8_6", "rpm|bash|5.1.8-4.el9"}},
	{name: "apk", file: "apk.txt", format: "apk info -v",
		data: "musl-1.2.3-r0\nbusybox-1.35.0-r17\nca-certificates-bundle-20220614-r0\n",
		want: []string{"apk|musl|1.2.3-r0", "apk|busybox|1.35.0-r17", "apk|ca-certificates-bundle|20220614-r0"}},
}

func TestLockfileGoldenFixtures(t *testing.T) {
	for _, f := range goldenFixtures {
		for _, name := range []string{f.file, ""} { // by name and by content sniffing
			if name == "" && (f.file == "dpkg.txt" && false) {
				continue
			}
			t.Run(f.name+"/"+map[bool]string{true: "name", false: "sniff"}[name != ""], func(t *testing.T) {
				format := lfDetect(name, []byte(f.data))
				res, err := lfParse(format, []byte(f.data))
				if err != nil {
					t.Fatalf("parse (%s): %v", format, err)
				}
				if res.Format != f.format {
					t.Fatalf("format %q want %q", res.Format, f.format)
				}
				got := map[string]lfComp{}
				for _, c := range res.Comps {
					got[c.Eco+"|"+c.Name+"|"+c.Version] = c
				}
				for _, w := range f.want {
					if _, ok := got[w]; !ok {
						t.Errorf("missing component %q; have %v", w, lfKeysOf(got))
					}
				}
				if len(got) != len(f.want) {
					t.Errorf("component count %d want %d: %v", len(got), len(f.want), lfKeysOf(got))
				}
				for n, d := range f.direct {
					for _, c := range res.Comps {
						if c.Name == n && c.Direct != d {
							t.Errorf("%s direct=%q want %q", n, c.Direct, d)
						}
					}
				}
			})
		}
	}
}

func lfKeysOf(m map[string]lfComp) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}

func TestLockfileMatchingSynthetic(t *testing.T) {
	lfSetAdvisories(t, lfTestAdvisories)
	r := lfRun("package-lock.json", goldenFixtures[0].data)
	f := lfFind(r, "sca-cve-2099-0001")
	if f == nil {
		t.Fatalf("no sca finding; findings=%+v errs=%v", r.Findings, r.Errors)
	}
	if f.Severity != "critical" || f.Weight != 40 {
		t.Errorf("severity/weight %s/%d", f.Severity, f.Weight)
	}
	for _, want := range []string{"lodash@4.17.20", "fixed in 4.17.21", "SSVC"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("evidence %q lacks %q", f.Evidence, want)
		}
	}
	// fixed version is not flagged
	r = lfRun("package-lock.json", strings.ReplaceAll(goldenFixtures[0].data, "4.17.20", "4.17.21"))
	if lfFind(r, "sca-cve-2099-0001") != nil {
		t.Error("fixed version flagged")
	}
	// PEP 440 ordering decides pypi
	r = lfRun("requirements.txt", "django==3.2.4\n")
	if lfFind(r, "sca-cve-2099-0002") == nil {
		t.Error("django 3.2.4 should match")
	}
	r = lfRun("requirements.txt", "django==3.2.5\n")
	if lfFind(r, "sca-cve-2099-0002") != nil {
		t.Error("django 3.2.5 should not match")
	}
	// Debian epoch: 1:1.1.1n-0 fixed; 1.1.1k-1 has epoch 0 so it is older
	r = lfRun("dpkg.txt", "ii  openssl  1.1.1k-1  amd64  x\n")
	if lfFind(r, "sca-cve-2099-0003") == nil {
		t.Error("openssl without epoch should be older than 1:1.1.1n-0")
	}
	r = lfRun("dpkg.txt", "ii  openssl  1:1.1.1n-0+deb11u1  amd64  x\n")
	if lfFind(r, "sca-cve-2099-0003") != nil {
		t.Error("openssl with epoch 1 and newer upstream should not match")
	}
	// maven, go, gem, cargo
	if lfFind(lfRun("gradle.lockfile", "org.apache.logging.log4j:log4j-core:2.14.1=x\n"), "sca-cve-2099-0005") == nil {
		t.Error("log4j should match")
	}
	if lfFind(lfRun("go.mod", "module m\nrequire github.com/x/y v1.2.0\n"), "sca-cve-2099-0006") == nil {
		t.Error("go module should match")
	}
	if lfFind(lfRun("Gemfile.lock", goldenFixtures[10].data), "sca-cve-2099-0007") == nil {
		t.Error("rails 6.1.0 should match")
	}
	f = lfFind(lfRun("Cargo.lock", goldenFixtures[9].data), "sca-cve-2099-0004")
	if f == nil || f.Severity != "low" {
		t.Errorf("cargo serde: %+v", f)
	}
}

func TestLockfileUnknownComparisonFallsBack(t *testing.T) {
	lfSetAdvisories(t, lfTestAdvisories)
	r := lfRun("requirements.txt", "weird==1.0\n")
	f := lfFind(r, "sca-cve-2099-0008")
	if f == nil {
		t.Fatal("expected an unverified finding")
	}
	if f.Severity != "low" || f.Weight > 5 || !strings.Contains(f.Evidence, "UNVERIFIED") {
		t.Errorf("unknown comparison must not be reported as confident: %+v", f)
	}
}

func TestLockfileSCAWeightCap(t *testing.T) {
	var advs []VMAdvisory
	var lines []string
	for i := 0; i < 6; i++ {
		n := "pkg" + string(rune('a'+i))
		advs = append(advs, VMAdvisory{CVE: "CVE-2099-10" + string(rune('0'+i)), Package: n, FixedIn: "2.0.0", CVSS: 9.8, Summary: "s"})
		lines = append(lines, n+"==1.0.0")
	}
	lfSetAdvisories(t, advs)
	r := lfRun("requirements.txt", strings.Join(lines, "\n"))
	total := 0
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "sca-cve-") {
			total += f.Weight
		}
	}
	if total != 60 {
		t.Errorf("SCA weight total %d want cap 60", total)
	}
}

func TestLockfileHygiene(t *testing.T) {
	lfSetAdvisories(t, lfTestAdvisories[:1])
	data := "requests>=2.0\nflask\nlodahs==1.0.0\n--index-url http://pypi.example/simple\n-e git+https://example.com/x.git#egg=x\n"
	r := lfRun("requirements.txt", data)
	for _, id := range []string{"sca-unpinned", "sca-range", "sca-insecure-registry", "sca-git-dependency"} {
		if lfFind(r, id) == nil {
			t.Errorf("missing %s; findings %+v", id, r.Findings)
		}
	}
	r = lfRun("package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/lodahs":{"version":"1.0.0","resolved":"http://registry.example/x.tgz"},"node_modules/g":{"version":"1.0.0","resolved":"git+ssh://git@github.com/a/g.git#abc","integrity":"sha512-aGVsbG8="}}}`)
	for _, id := range []string{"sca-no-integrity", "sca-insecure-registry", "sca-git-dependency", "sca-typosquat"} {
		if lfFind(r, id) == nil {
			t.Errorf("npm: missing %s; findings %+v", id, r.Findings)
		}
	}
	if f := lfFind(r, "sca-typosquat"); f != nil && (f.Severity != "low" || !strings.Contains(f.Evidence, "lodash")) {
		t.Errorf("typosquat finding: %+v", f)
	}
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "sca-") && f.Weight > 6 && !strings.HasPrefix(f.ID, "sca-cve") && f.ID != "sca-known-malicious" {
			t.Errorf("hygiene weight %d for %s out of 2-6", f.Weight, f.ID)
		}
	}
	// a popular name itself is not flagged
	if _, ok := lfTyposquat("npm", "lodash"); ok {
		t.Error("popular name flagged")
	}
	if p, ok := lfTyposquat("pypi", "reqeusts"); !ok || p != "requests" {
		t.Errorf("transposition: %q %v", p, ok)
	}
}

func TestLockfileKnownMaliciousOnlyFromIOCStore(t *testing.T) {
	lfSetAdvisories(t, lfTestAdvisories[:1])
	data := `{"lockfileVersion":3,"packages":{"":{},"node_modules/evil-pkg":{"version":"1.0.0","integrity":"sha512-aGVsbG8="}}}`
	if lfFind(lfRun("package-lock.json", data), "sca-known-malicious") != nil {
		t.Fatal("flagged without an IOC entry")
	}
	iocMu.Lock()
	saved := iocs
	iocs = append(append([]IOC{}, iocs...), IOC{ID: "ioc-test-pkg", Type: "domain", Value: "evil-pkg", Enabled: true})
	iocMu.Unlock()
	defer func() { iocMu.Lock(); iocs = saved; iocMu.Unlock() }()
	if lfFind(lfRun("package-lock.json", data), "sca-known-malicious") == nil {
		t.Fatal("IOC-store name not flagged")
	}
}

func TestLockfileHostileInputs(t *testing.T) {
	lfSetAdvisories(t, lfTestAdvisories[:1])
	deep := strings.Repeat("[", 100000) + strings.Repeat("]", 100000)
	cases := map[string]string{
		"package-lock.json":  `{"lockfileVersion":3,"packages":` + deep + `}`,
		"yarn.lock":          "\"\n:\n" + strings.Repeat("a@1:\n  version \"", 1000),
		"pnpm-lock.yaml":     "lockfileVersion: 5\npackages:\n\t/a/1:\n",
		"requirements.txt":   strings.Repeat("a==1\\\n", 20000) + "\x00\xff",
		"poetry.lock":        "[[package]]\nname = \"a\"\nversion = \"1\"\nfiles = [\n[[[[\n",
		"pom.xml":            `<?xml version="1.0"?><!DOCTYPE p [<!ENTITY a "&b;&b;"><!ENTITY b "&c;&c;">]><project>&a;</project>`,
		"Cargo.lock":         strings.Repeat("[[package]]\n", 10000),
		"Gemfile.lock":       "GEM\n  specs:\n    (\n    a (\n",
		"go.mod":             "require (\n" + strings.Repeat("(\n", 1000),
		"composer.lock":      `{"packages":[null,1,{"name":5}]}`,
		"packages.lock.json": `{"dependencies":{"x":null}}`,
		"unknown.bin":        "\x00\x01\x02garbage",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan *InspectReport, 1)
			go func() { done <- lfRun(name, data) }()
			select {
			case r := <-done:
				if len(r.Errors) > 0 {
					for _, e := range r.Errors {
						if strings.Contains(e, "panic") {
							t.Fatalf("panic: %v", e)
						}
					}
				}
			case <-time.After(25 * time.Second):
				t.Fatal("hung")
			}
		})
	}
	if r := lfRun("x.bin", ""); len(r.Errors) == 0 {
		t.Error("empty input should error")
	}
}

func TestLockfileUnsupportedReported(t *testing.T) {
	r := lfRun("yarn.lock", "__metadata:\n  version: 6\n\n\"a@npm:^1\":\n  version: 1.0.0\n")
	f := lfFind(r, "sca-limits")
	if f == nil || !strings.Contains(f.Evidence, "Berry") {
		t.Errorf("yarn berry not reported: %+v", r.Findings)
	}
	r = lfRun("pnpm-lock.yaml", "lockfileVersion: 9\nx: &anchor\n  a: 1\n")
	if lfFind(r, "sca-parse-error") == nil {
		t.Errorf("unsupported YAML should be a parse error finding: %+v", r.Findings)
	}
	r = lfRun("pom.xml", goldenFixtures[12].data)
	f = lfFind(r, "sca-limits")
	if f == nil || !strings.Contains(f.Evidence, "property substitution") {
		t.Errorf("pom property substitution not reported: %+v", r.Findings)
	}
}

// ---- version comparison tables ----

func TestLockfileVersionTables(t *testing.T) {
	type row struct {
		a, b string
		want int
		ok   bool
	}
	tables := map[string][]row{
		"npm": {
			{"1.2.3", "1.2.4", -1, true}, {"1.10.0", "1.9.0", 1, true}, {"1.0.0", "1.0.0", 0, true},
			{"1.0.0-alpha", "1.0.0", -1, true}, {"1.0.0-alpha.1", "1.0.0-alpha.beta", -1, true},
			{"1.0.0-beta.2", "1.0.0-beta.11", -1, true}, {"v2.0.0", "1.9.9", 1, true},
			{"1.0.0+build", "1.0.0", 0, true}, {"1.x", "1.0.0", 0, false}, {"^1.0.0", "1.0.0", 0, false},
			{"99999999999999999999.0.0", "99999999999999999998.0.0", 1, true},
		},
		"go": {
			{"v1.2.3", "v1.2.4", -1, true}, {"v0.0.0-20200101000000-abcdef", "v0.0.1", -1, true},
			{"v2.0.0+incompatible", "v2.0.0", 0, true},
		},
		"nuget":    {{"1.0.0.1", "1.0.0", 1, true}, {"13.0.1", "13.0.3", -1, true}},
		"composer": {{"2.0.1", "2.0.10", -1, true}, {"dev-master", "1.0", 0, false}},
		"pypi": {
			{"1.0", "1.0.0", 0, true}, {"1.0a1", "1.0", -1, true}, {"1.0rc1", "1.0b2", 1, true},
			{"1.0.post1", "1.0", 1, true}, {"1.0.dev1", "1.0a1", -1, true}, {"1!0.5", "9.9", 1, true},
			{"3.2.4", "3.2.5", -1, true}, {"1.0+local", "1.0", 0, true}, {"1.0.dev1", "1.0", -1, true},
			{"not-a-version", "1.0", 0, false}, {"2.0b1", "2.0.beta1", 0, true},
		},
		"maven": {
			{"2.14.1", "2.17.1", -1, true}, {"1.0-alpha", "1.0", -1, true}, {"1.0", "1.0.0", 0, true},
			{"1.0-rc1", "1.0-beta2", 1, true}, {"1.0-SNAPSHOT", "1.0", -1, true}, {"1.0-sp1", "1.0", 1, true},
			{"1.0-weirdqualifier", "1.0", 0, false}, {"1.0.1", "1.0-sp1", 1, true},
		},
		"deb": {
			{"1:1.0", "2.0", 1, true}, {"1.0~rc1", "1.0", -1, true}, {"1.0-1", "1.0-2", -1, true},
			{"1.1.1k-1", "1.1.1n-0", -1, true}, {"2.31-13", "2.31-13", 0, true}, {"1.0+dfsg", "1.0", 1, true},
			{"1.10", "1.9", 1, true}, {"x:1", "1", 0, false},
		},
		"rpm": {
			{"1.1.1k-7.el8", "1.1.1k-8.el8", -1, true}, {"1.0~rc1-1", "1.0-1", -1, true},
			{"2:1.0-1", "1:9.0-1", 1, true}, {"5.1.8-4.el9", "5.1.8-4.el9", 0, true}, {"1.10-1", "1.9-1", 1, true},
		},
		"apk": {
			{"1.2.3-r0", "1.2.3-r1", -1, true}, {"1.2.3_rc1-r0", "1.2.3-r0", -1, true},
			{"1.2.3_p1-r0", "1.2.3-r0", 1, true}, {"1.1.1n-r0", "1.1.1k-r5", 1, true}, {"1.2.3_bogus-r0", "1.2.3-r0", 0, false},
		},
		"gem": {
			{"6.1.0", "6.1.4", -1, true}, {"1.0.0.pre", "1.0.0", -1, true}, {"1.0", "1.0.0", 0, true},
			{"2.0.0.rc1", "2.0.0.beta2", 1, true}, {"1.10", "1.9", 1, true},
		},
	}
	for eco, rows := range tables {
		for _, r := range rows {
			got, ok := lfCompare(eco, r.a, r.b)
			if ok != r.ok || (ok && got != r.want) {
				t.Errorf("%s: cmp(%q,%q)=%d,%v want %d,%v", eco, r.a, r.b, got, ok, r.want, r.ok)
			}
			if ok { // antisymmetry
				back, _ := lfCompare(eco, r.b, r.a)
				if back != -got {
					t.Errorf("%s: cmp(%q,%q) not antisymmetric: %d vs %d", eco, r.a, r.b, got, back)
				}
			}
		}
	}
	if _, ok := lfCompare("unknown-eco", "1", "2"); ok {
		t.Error("unknown ecosystem must be unknown")
	}
}

// ---- CycloneDX ----

func TestLockfileCycloneDXValid(t *testing.T) {
	lfSetAdvisories(t, lfTestAdvisories)
	r := lfRun("package-lock.json", goldenFixtures[0].data)
	raw, ok := r.Meta["lockfile.sbom"]
	if !ok {
		t.Fatal("no sbom in Meta")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BomFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
		} `json:"metadata"`
		Components []struct {
			Type    string `json:"type"`
			BomRef  string `json:"bom-ref"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Purl    string `json:"purl"`
			Hashes  []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			} `json:"hashes"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Affects []struct {
				Ref string `json:"ref"`
			} `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BomFormat != "CycloneDX" || bom.SpecVersion != "1.5" || bom.Version < 1 {
		t.Errorf("header %+v", bom)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") || len(bom.SerialNumber) != len("urn:uuid:")+36 {
		t.Errorf("serial %q", bom.SerialNumber)
	}
	if _, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp); err != nil {
		t.Errorf("timestamp: %v", err)
	}
	refs := map[string]bool{}
	for _, c := range bom.Components {
		if c.Type != "library" || c.BomRef == "" || c.Name == "" || !strings.HasPrefix(c.Purl, "pkg:") {
			t.Errorf("bad component %+v", c)
		}
		if refs[c.BomRef] {
			t.Errorf("duplicate bom-ref %q", c.BomRef)
		}
		refs[c.BomRef] = true
		for _, h := range c.Hashes {
			if h.Alg != "SHA-512" || len(h.Content) != 10 { // base64 "aGVsbG8=" = "hello" = 10 hex chars
				t.Errorf("hash %+v", h)
			}
		}
	}
	if len(bom.Components) != 2 {
		t.Fatalf("components %d", len(bom.Components))
	}
	foundScoped := false
	for _, c := range bom.Components {
		if c.Purl == "pkg:npm/%40scope/dep@1.0.0" {
			foundScoped = true
		}
	}
	if !foundScoped {
		t.Errorf("scoped npm purl wrong: %+v", bom.Components)
	}
	if len(bom.Vulnerabilities) != 1 || !refs[bom.Vulnerabilities[0].Affects[0].Ref] {
		t.Errorf("vulnerabilities must reference existing components: %+v", bom.Vulnerabilities)
	}
}

func TestLockfilePurls(t *testing.T) {
	for _, c := range []struct {
		c    lfComp
		want string
	}{
		{lfComp{Eco: "go", Name: "github.com/x/y", Version: "v1.0.0"}, "pkg:golang/github.com/x/y@v1.0.0"},
		{lfComp{Eco: "maven", Name: "g:a", Version: "1"}, "pkg:maven/g/a@1"},
		{lfComp{Eco: "deb", Name: "openssl", Version: "1:1.1"}, "pkg:deb/debian/openssl@1%3A1.1"},
		{lfComp{Eco: "composer", Name: "a/b", Version: "1"}, "pkg:composer/a/b@1"},
		{lfComp{Eco: "pypi", Name: "django"}, "pkg:pypi/django"},
	} {
		if got := lfPurl(c.c); got != c.want {
			t.Errorf("purl %q want %q", got, c.want)
		}
	}
}

// ---- structure: the analyzer never touches the network ----

func TestLockfileAnalyzerHasNoNetworkImports(t *testing.T) {
	files, _ := filepath.Glob("inspect_lockfile_*.go")
	if len(files) < 5 {
		t.Fatalf("expected the analyzer files, got %v", files)
	}
	banned := []string{"net", "net/http", "net/url_fetch", "os/exec", "plugin", "syscall"}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			for _, b := range banned {
				if p == b || strings.HasPrefix(p, "net/http") {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
		src, _ := os.ReadFile(f)
		for _, bad := range []string{"http.Get", "http.Client", "Refresh(", ".Dial(", "exec.Command", "os.ReadFile", "os.Open"} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
	}
}

// ---- fuzz: each parser must never panic ----

func lfFuzzSeeds(f *testing.F, file string) {
	for _, g := range goldenFixtures {
		if g.file == file {
			f.Add([]byte(g.data))
		}
	}
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("[[package]]\n"))
}

func FuzzLockfileNPM(f *testing.F) {
	lfFuzzSeeds(f, "package-lock.json")
	f.Fuzz(func(t *testing.T, d []byte) { lfParseNPM(d) })
}
func FuzzLockfileYarn(f *testing.F) {
	lfFuzzSeeds(f, "yarn.lock")
	f.Fuzz(func(t *testing.T, d []byte) { lfParseYarn(d) })
}
func FuzzLockfilePnpm(f *testing.F) {
	lfFuzzSeeds(f, "pnpm-lock.yaml")
	f.Fuzz(func(t *testing.T, d []byte) { lfParsePnpm(d) })
}
func FuzzLockfileRequirements(f *testing.F) {
	lfFuzzSeeds(f, "requirements.txt")
	f.Fuzz(func(t *testing.T, d []byte) { lfParseRequirements(d) })
}
func FuzzLockfilePipfile(f *testing.F) {
	lfFuzzSeeds(f, "Pipfile.lock")
	f.Fuzz(func(t *testing.T, d []byte) { lfParsePipfileLock(d) })
}
func FuzzLockfilePoetry(f *testing.F) {
	lfFuzzSeeds(f, "poetry.lock")
	f.Fuzz(func(t *testing.T, d []byte) { lfParsePoetry(d); lfParseCargo(d) })
}
func FuzzLockfileGo(f *testing.F) {
	lfFuzzSeeds(f, "go.mod")
	f.Fuzz(func(t *testing.T, d []byte) { lfParseGoMod(d); lfParseGoSum(d) })
}
func FuzzLockfileGem(f *testing.F) {
	lfFuzzSeeds(f, "Gemfile.lock")
	f.Fuzz(func(t *testing.T, d []byte) { lfParseGemfileLock(d) })
}
func FuzzLockfileComposer(f *testing.F) {
	lfFuzzSeeds(f, "composer.lock")
	f.Fuzz(func(t *testing.T, d []byte) { lfParseComposer(d) })
}
func FuzzLockfilePom(f *testing.F) {
	lfFuzzSeeds(f, "pom.xml")
	f.Fuzz(func(t *testing.T, d []byte) { lfParsePom(d) })
}
func FuzzLockfileGradleNuGet(f *testing.F) {
	lfFuzzSeeds(f, "gradle.lockfile")
	f.Fuzz(func(t *testing.T, d []byte) { lfParseGradle(d); lfParseNuGet(d) })
}
func FuzzLockfileLists(f *testing.F) {
	lfFuzzSeeds(f, "dpkg.txt")
	f.Fuzz(func(t *testing.T, d []byte) { lfParseDpkg(d); lfParseRPMList(d); lfParseApkList(d); lfDetect("", d) })
}
func FuzzLockfileVersions(f *testing.F) {
	f.Add("1.0", "1.0.1")
	f.Add("1:2.0~rc1-3", "2.0")
	f.Fuzz(func(t *testing.T, a, b string) {
		for _, e := range []string{"npm", "pypi", "maven", "deb", "rpm", "apk", "gem"} {
			lfCompare(e, a, b)
		}
	})
}
