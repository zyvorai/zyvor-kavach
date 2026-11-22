// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// Browser-extension manifests (Chrome/Firefox manifest.json) and npm / PyPI
// install-time scripts (package.json lifecycle scripts, setup.py). Parse-only:
// JSON is decoded and text is matched with regexes; nothing is installed,
// imported, run or fetched. Accepts raw manifest/package/setup text (kinds
// lockfile and script) or a file (kind file) that is a zip/CRX/npm tarball/PyPI
// sdist, from which only manifest.json, package.json and setup.py (plus the
// small .js/.py/.sh files an install script names) are read, with caps.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	pkgMaxMember     = 1 << 20  // bytes read per archive member
	pkgMaxArchiveTot = 16 << 20 // decompressed bytes read per archive
	pkgMaxMembers    = 4000
	pkgMaxSideFiles  = 48
	pkgMaxText       = 2 << 20
)

func init() {
	RegisterAnalyzer("pkg-manifest", []string{InspectKindFile, InspectKindLockfile, InspectKindScript},
		func(ctx context.Context, in InspectInput, b *InspectBuilder) (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("pkg-manifest: recovered: %v", r)
				}
			}()
			analyzePkg(ctx, in, b)
			return nil
		})
}

type pkgDoc struct {
	name string // path inside the archive or client label
	text string
}

func analyzePkg(ctx context.Context, in InspectInput, b *InspectBuilder) {
	var docs []pkgDoc
	side := map[string]string{}
	if in.Kind == InspectKindFile {
		docs, side = pkgFromArchive(ctx, in.Data, b)
	} else {
		t := in.Text
		if len(t) > pkgMaxText {
			t = t[:pkgMaxText]
			b.LimitHit("pkg-text-truncated")
		}
		docs = []pkgDoc{{name: in.Name, text: t}}
	}
	for _, d := range docs {
		if ctx.Err() != nil {
			return
		}
		trim := strings.TrimSpace(d.text)
		base := strings.ToLower(path.Base(d.name))
		switch {
		case strings.HasPrefix(trim, "{") && strings.Contains(trim, `"manifest_version"`):
			pkgExtension(b, trim)
		case strings.HasPrefix(trim, "{") && (base == "package.json" || (strings.Contains(trim, `"scripts"`) && strings.Contains(trim, `"version"`))):
			pkgNPM(b, trim, side)
		case base == "setup.py" || (strings.Contains(trim, "setup(") && (strings.Contains(trim, "setuptools") || strings.Contains(trim, "distutils"))):
			pkgSetupPy(b, trim)
		}
	}
}

// pkgFromArchive finds manifests in a zip/CRX or tar.gz. Plain JSON/py text is returned as one doc.
func pkgFromArchive(ctx context.Context, data []byte, b *InspectBuilder) ([]pkgDoc, map[string]string) {
	side := map[string]string{}
	var docs []pkgDoc
	want := func(n string) bool {
		base := strings.ToLower(path.Base(n))
		return base == "manifest.json" || base == "package.json" || base == "setup.py"
	}
	wantSide := func(n string) bool {
		l := strings.ToLower(n)
		return strings.HasSuffix(l, ".js") || strings.HasSuffix(l, ".cjs") || strings.HasSuffix(l, ".mjs") || strings.HasSuffix(l, ".py") || strings.HasSuffix(l, ".sh")
	}
	depthOK := func(n string) bool { return strings.Count(strings.Trim(n, "/"), "/") <= 2 }
	total := 0
	// CRX3 header: "Cr24", version, header length, then a zip.
	if len(data) > 12 && string(data[:4]) == "Cr24" {
		hl := int(uint32(data[8]) | uint32(data[9])<<8 | uint32(data[10])<<16 | uint32(data[11])<<24)
		if hl >= 0 && 12+hl < len(data) {
			data = data[12+hl:]
		}
	}
	switch {
	case len(data) > 4 && string(data[:2]) == "PK":
		zr, refused, err := zipSafeReader(data)
		if err != nil || zr == nil {
			if refused {
				b.LimitHit("pkg-zip-entries")
			}
			return nil, side
		}
		for i, f := range zr.File {
			if i >= pkgMaxMembers {
				b.LimitHit("pkg-members")
				break
			}
			if ctx.Err() != nil || f.FileInfo().IsDir() || f.UncompressedSize64 > pkgMaxMember*4 {
				continue
			}
			isDoc, isSide := want(f.Name), wantSide(f.Name) && f.UncompressedSize64 <= 256<<10
			if (!isDoc && !isSide) || !depthOK(f.Name) || (isSide && len(side) >= pkgMaxSideFiles) {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(rc, pkgMaxMember))
			rc.Close()
			total += len(body)
			if total > pkgMaxArchiveTot {
				b.LimitHit("pkg-archive-bytes")
				break
			}
			if isDoc {
				docs = append(docs, pkgDoc{name: f.Name, text: string(body)})
			} else {
				side[f.Name] = string(body)
			}
		}
	case len(data) > 3 && data[0] == 0x1f && data[1] == 0x8b:
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, side
		}
		tr := tar.NewReader(io.LimitReader(gz, pkgMaxArchiveTot))
		for i := 0; ; i++ {
			if i >= pkgMaxMembers {
				b.LimitHit("pkg-members")
				break
			}
			if ctx.Err() != nil {
				break
			}
			h, err := tr.Next()
			if err != nil {
				break
			}
			if h.Typeflag != tar.TypeReg || h.Size > pkgMaxMember*4 {
				continue
			}
			isDoc, isSide := want(h.Name), wantSide(h.Name) && h.Size <= 256<<10
			if (!isDoc && !isSide) || !depthOK(h.Name) || (isSide && len(side) >= pkgMaxSideFiles) {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(tr, pkgMaxMember))
			if isDoc {
				docs = append(docs, pkgDoc{name: h.Name, text: string(body)})
			} else {
				side[h.Name] = string(body)
			}
		}
	default:
		if len(data) > 0 && len(data) <= pkgMaxText && bytes.IndexByte(data, 0) < 0 {
			docs = append(docs, pkgDoc{name: "", text: string(data)})
		}
	}
	// Normalise side file keys to their path below the package root ("package/x.js" -> "x.js").
	norm := map[string]string{}
	for k, v := range side {
		norm[k] = v
		if i := strings.IndexByte(k, '/'); i >= 0 {
			norm[k[i+1:]] = v
		}
	}
	return docs, norm
}

// ---- browser extensions ----

var pkgHostAll = map[string]bool{"<all_urls>": true, "*://*/*": true, "http://*/*": true, "https://*/*": true, "*://*/": true, "file:///*": false}

var pkgPermRisk = map[string]struct {
	w   int
	sev string
	why string
}{
	"debugger":           {14, "high", "attach the DevTools debugger to any tab"},
	"nativeMessaging":    {12, "high", "talk to a native program outside the browser"},
	"proxy":              {12, "high", "control the browser proxy settings"},
	"management":         {8, "medium", "inspect and disable other extensions"},
	"cookies":            {6, "medium", "read and write cookies"},
	"webRequestBlocking": {8, "medium", "block and rewrite requests"},
	"clipboardRead":      {6, "medium", "read the clipboard"},
	"history":            {4, "low", "read browsing history"},
	"browsingData":       {4, "low", "clear browsing data"},
	"privacy":            {4, "low", "change privacy settings"},
	"desktopCapture":     {6, "medium", "capture the screen"},
	"tabCapture":         {5, "medium", "capture tab audio/video"},
	"downloads":          {4, "low", "start and read downloads"},
	"webNavigation":      {3, "low", "observe navigation"},
	"contentSettings":    {3, "low", "change site content settings"},
	"pageCapture":        {4, "low", "save pages as MHTML"},
}

func pkgStrings(v any) []string {
	var out []string
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			switch t := x.(type) {
			case string:
				out = append(out, t)
			case map[string]any: // MV3 host_permissions never are objects; tolerate odd shapes
			}
		}
	}
	return out
}

var cspUnsafeEval = regexp.MustCompile(`(?i)'unsafe-eval'`)
var cspRemoteSrc = regexp.MustCompile(`(?i)script-src[^;]*\s(https?://[^\s;']+)`)

func pkgExtension(b *InspectBuilder, text string) {
	var m map[string]any
	if json.Unmarshal([]byte(text), &m) != nil {
		fileFinding(b, "ext-invalid-json", "Extension manifest is not valid JSON", "info", "", "", 0)
		return
	}
	mv, _ := m["manifest_version"].(float64)
	name, _ := m["name"].(string)
	b.Format("Browser extension manifest")
	_, gecko := m["browser_specific_settings"]
	if _, a := m["applications"]; a {
		gecko = true
	}
	meta := map[string]any{"name": truncInspect(name), "manifest_version": mv, "firefox": gecko}

	perms := pkgStrings(m["permissions"])
	perms = append(perms, pkgStrings(m["optional_permissions"])...)
	hosts := pkgStrings(m["host_permissions"])
	hosts = append(hosts, pkgStrings(m["optional_host_permissions"])...)
	var cs []any
	if v, ok := m["content_scripts"].([]any); ok {
		cs = v
	}
	var csAll []string
	for _, c := range cs {
		if cm, ok := c.(map[string]any); ok {
			for _, mt := range pkgStrings(cm["matches"]) {
				csAll = append(csAll, mt)
			}
		}
	}
	// MV2 puts host patterns inside permissions.
	var broad []string
	for _, p := range append(append([]string{}, perms...), hosts...) {
		if pkgHostAll[p] {
			broad = append(broad, p)
		}
	}
	for _, p := range csAll {
		if pkgHostAll[p] {
			broad = append(broad, "content_scripts:"+p)
		}
	}
	sort.Strings(perms)
	meta["permissions"] = capStrings(perms, 60)
	meta["host_permissions"] = capStrings(hosts, 60)
	b.Meta("extension", meta)

	hasPerm := func(n string) bool {
		for _, p := range perms {
			if p == n {
				return true
			}
		}
		return false
	}
	seenP := map[string]bool{}
	for _, p := range perms {
		if r, ok := pkgPermRisk[p]; ok && !seenP[p] {
			seenP[p] = true
			fileFinding(b, "ext-perm-"+strings.ToLower(p), "Extension requests the "+p+" permission ("+r.why+")", r.sev, "T1176", p, r.w)
		}
	}
	if len(broad) > 0 {
		fileFinding(b, "ext-broad-host-access", "Extension can run on or read every website", "medium", "T1176", fileJoinCap(broad, 4), 10)
		if hasPerm("cookies") {
			fileFinding(b, "ext-cookies-all-sites", "Cookies permission combined with all-sites access (session theft capability)", "high", "T1539", "cookies + "+broad[0], 14)
		}
		if hasPerm("webRequestBlocking") || hasPerm("webRequest") && hasPerm("proxy") {
			fileFinding(b, "ext-intercept-all-sites", "Request interception combined with all-sites access", "high", "T1557", "webRequestBlocking/proxy + "+broad[0], 12)
		}
	}
	if hasPerm("nativeMessaging") {
		b.IOC("path", "nativeMessaging")
	}

	// Content-security policy and remote code.
	csp := ""
	switch v := m["content_security_policy"].(type) {
	case string:
		csp = v
	case map[string]any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				csp += s + "; "
			}
		}
	}
	if csp != "" {
		meta["csp"] = truncInspect(csp)
		if cspUnsafeEval.MatchString(csp) {
			fileFinding(b, "ext-csp-unsafe-eval", "Extension CSP allows 'unsafe-eval'", "high", "T1059.007", truncInspect(csp), 16)
		}
		if mm := cspRemoteSrc.FindStringSubmatch(csp); mm != nil {
			fileFinding(b, "ext-remote-code", "Extension CSP allows scripts from a remote origin", "high", "T1105", mm[1], 18)
			b.IOC("url", mm[1])
		}
	}
	if u, ok := m["update_url"].(string); ok && u != "" && !strings.Contains(u, "clients2.google.com") && !strings.Contains(u, "edge.microsoft.com") && !strings.Contains(u, "addons.mozilla.org") {
		fileFinding(b, "ext-self-hosted-update", "Extension updates from a non-store URL", "medium", "T1176", u, 12)
		b.IOC("url", u)
	}
	if ec, ok := m["externally_connectable"].(map[string]any); ok {
		for _, mt := range pkgStrings(ec["matches"]) {
			if pkgHostAll[mt] || strings.HasPrefix(mt, "*://*.") && strings.Count(mt, ".") < 2 {
				fileFinding(b, "ext-externally-connectable-broad", "Any web page may message the extension (externally_connectable)", "medium", "T1176", mt, 8)
				break
			}
		}
	}
	if _, ok := m["chrome_settings_overrides"]; ok {
		fileFinding(b, "ext-settings-override", "Extension overrides search provider or homepage", "medium", "T1176", "chrome_settings_overrides", 8)
	}
	if war, ok := m["web_accessible_resources"]; ok {
		if j, _ := json.Marshal(war); strings.Contains(string(j), "<all_urls>") || strings.Contains(string(j), `"*://*/*"`) {
			fileFinding(b, "ext-war-all-sites", "Resources are web-accessible to every site", "low", "T1176", "web_accessible_resources", 4)
		}
	}
	for _, c := range cs {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if rv, _ := cm["run_at"].(string); rv == "document_start" {
			for _, mt := range pkgStrings(cm["matches"]) {
				if pkgHostAll[mt] {
					fileFinding(b, "ext-content-script-all-start", "Content script injects into every page at document_start", "low", "T1176", mt, 4)
					return
				}
			}
		}
	}
}

// ---- npm ----

type pkgRule struct {
	id, title, tech, sev string
	re                   *regexp.Regexp
	w                    int
}

var pkgWebhook = `discord(?:app)?\.com/api/webhooks|/api/webhooks/\d+/|hooks\.slack\.com|webhook\.site|pipedream\.net|requestbin|requestcatcher|ngrok(?:-free)?\.(?:io|app|dev)|oast(?:ify)?\.(?:pro|live|site|online|fun|me)|interact\.sh|burpcollaborator|canarytokens|api\.telegram\.org/bot|transfer\.sh|pastebin\.com|paste\.ee|ghostbin|iplogger|grabify|beeceptor|mockbin|hookbin|eo[0-9a-z]+\.m\.pipedream`

var pkgRules = []pkgRule{
	{"pkg-exfil-webhook", "Install-time code contacts a webhook or out-of-band collection service", "T1567", "high", regexp.MustCompile(`(?i)` + pkgWebhook), 30},
	{"pkg-obfuscated-eval", "Install-time code evaluates a decoded or packed blob", "T1027", "high", regexp.MustCompile(`(?is)(?:\beval|\bexec|new\s+Function|Function\s*\(|vm\.run\w*|compile)\s*\(?[^\n;]{0,80}(?:atob|Buffer\.from\([^)]*['"]base64|b64decode|base64\.|zlib\.(?:decompress|inflate)|marshal\.loads|fromCharCode|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}|rot13|codecs\.decode|bytes\.fromhex|unhexlify)`), 28},
	{"pkg-download-exec", "Install-time code downloads and runs remote content", "T1105", "high", regexp.MustCompile(`(?is)(?:curl|wget|fetch|iwr|Invoke-WebRequest|certutil[^\n]{0,40}urlcache)[^\n|]{0,160}\|\s*(?:sh|bash|node|python3?|powershell|iex)\b|(?:urlopen|requests\.get|https?\.get|axios\.get|fetch)\s*\([^)]{0,200}\)[^\n]{0,80}(?:exec|eval|spawn|system)|(?:exec|eval)\s*\(\s*(?:urlopen|requests\.get)`), 28},
	{"pkg-env-harvest", "Install-time code reads environment variables and sends them over the network", "T1552.001", "high", regexp.MustCompile(`(?is)(?:process\.env|os\.environ|os\.getenv)[\s\S]{0,400}(?:https?\.request|https?\.get|fetch\(|axios|requests\.(?:post|get|put)|urllib|urlopen|socket\.|XMLHttpRequest|\.post\()`), 22},
	{"pkg-credential-files", "Install-time code touches credential stores", "T1552.001", "high", regexp.MustCompile(`(?i)\.ssh/id_|\.npmrc|\.pypirc|\.aws/credentials|\.docker/config\.json|\.kube/config|\.git-credentials|Login Data|wallet\.dat|/etc/shadow|keychain|\.gnupg`), 20},
	{"pkg-shell-spawn", "Install-time code spawns a shell with a network or encoded command", "T1059", "medium", regexp.MustCompile(`(?i)(?:child_process|execSync|spawnSync|subprocess\.(?:Popen|call|run|check_output)|os\.system|os\.popen)[^\n]{0,160}(?:curl|wget|powershell|base64|\bnc\b|/dev/tcp|bash\s+-i)`), 14},
	{"pkg-reverse-shell", "Install-time code opens a reverse shell", "T1059", "critical", regexp.MustCompile(`(?i)/dev/tcp/|nc(?:at)?\s+-e|bash\s+-i\s*>&|socket\.socket\([^)]*\)[\s\S]{0,200}(?:dup2|subprocess|pty\.spawn)|net\.Socket\(\)[\s\S]{0,200}spawn\(`), 40},
}

var pkgHooks = []string{"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly", "preuninstall", "postuninstall"}

var pkgBenignHook = regexp.MustCompile(`(?i)^\s*(?:node-gyp(?: rebuild)?|prebuild-install(?: \|\| node-gyp rebuild)?|husky(?: install)?|npm run (?:build|compile|tsc|prepare)\S*|tsc(?: -p \S+)?|node-pre-gyp install(?: --fallback-to-build)?|patch-package|(?:npx )?(?:only-allow \S+|ngcc|opencollective-postinstall)|echo\b[^|;&]*|exit 0|true|cmake-js compile|napi-postinstall \S+)\s*$`)

var pkgSideRef = regexp.MustCompile(`(?:^|[\s;&|])(?:node|python3?|sh|bash)\s+(?:\./)?([\w./\-]+\.(?:js|cjs|mjs|py|sh))`)

func pkgScan(b *InspectBuilder, where, text string) int {
	n := 0
	if len(text) > pkgMaxText {
		text = text[:pkgMaxText]
	}
	for _, r := range pkgRules {
		if loc := r.re.FindStringIndex(text); loc != nil {
			ev := text[loc[0]:loc[1]]
			if len(ev) > 160 {
				ev = ev[:160]
			}
			fileFinding(b, r.id, r.title+" ("+where+")", r.sev, r.tech, strings.TrimSpace(ev), r.w)
			n++
		}
	}
	for _, u := range oneURLRe.FindAllString(text, 10) {
		b.IOC("url", u)
	}
	return n
}

func pkgNPM(b *InspectBuilder, text string, side map[string]string) {
	var m map[string]any
	if json.Unmarshal([]byte(text), &m) != nil {
		fileFinding(b, "npm-invalid-json", "package.json is not valid JSON", "info", "", "", 0)
		return
	}
	b.Format("npm package.json")
	name, _ := m["name"].(string)
	ver, _ := m["version"].(string)
	scripts, _ := m["scripts"].(map[string]any)
	var found []string
	for _, h := range pkgHooks {
		s, ok := scripts[h].(string)
		if !ok || strings.TrimSpace(s) == "" {
			continue
		}
		found = append(found, h+": "+truncInspect(s))
		hits := pkgScan(b, "scripts."+h, s)
		// Follow one level into a script file the hook names, when the archive had it.
		for _, mm := range pkgSideRef.FindAllStringSubmatch(s, 4) {
			if body, ok := side[mm[1]]; ok {
				hits += pkgScan(b, mm[1], body)
			}
		}
		if hits == 0 && !pkgBenignHook.MatchString(s) {
			if h == "preinstall" || h == "install" || h == "postinstall" {
				fileFinding(b, "npm-install-script", "Package runs an install-time script ("+h+")", "low", "T1195.002", truncInspect(s), 6)
			}
		}
	}
	for _, k := range []string{"dependencies", "optionalDependencies"} {
		if d, ok := m[k].(map[string]any); ok {
			for dn, dv := range d {
				if s, _ := dv.(string); strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "git+http://") || strings.Contains(s, "://") && !strings.Contains(s, "registry.npmjs.org") && !strings.HasPrefix(s, "git+https://github.com/") && !strings.HasPrefix(s, "https://github.com/") {
					fileFinding(b, "npm-url-dependency", "Dependency "+dn+" is fetched from a URL, not the registry", "low", "T1195.001", s, 5)
					break
				}
			}
		}
	}
	b.Meta("package", map[string]any{"ecosystem": "npm", "name": truncInspect(name), "version": ver, "install_hooks": found})
}

// ---- PyPI setup.py ----

var pyCmdclass = regexp.MustCompile(`(?s)class\s+\w+\s*\(\s*(?:\w+\.)*(install|develop|egg_info|build_py|build_ext|sdist|bdist_wheel)\s*\)\s*:(.{0,1000})`)
var pyCmdclassArg = regexp.MustCompile(`cmdclass\s*=\s*\{`)

func pkgSetupPy(b *InspectBuilder, text string) {
	b.Format("Python setup.py")
	hooks := pyCmdclassArg.MatchString(text)
	if m := pyCmdclass.FindStringSubmatch(text); m != nil && hooks {
		body := m[2]
		fileFinding(b, "pypi-cmdclass-hook", "setup.py overrides the "+m[1]+" command (code runs at install)", "medium", "T1195.002", truncInspect(strings.SplitN(strings.TrimSpace(body), "\n", 2)[0]), 8)
	} else if hooks {
		fileFinding(b, "pypi-cmdclass-hook", "setup.py registers custom commands (cmdclass)", "low", "T1195.002", "cmdclass={...}", 4)
	}
	// Top-level code outside setup() also runs at install time: scan the whole file.
	pkgScan(b, "setup.py", text)
	b.Meta("package", map[string]any{"ecosystem": "pypi", "cmdclass": hooks})
}
