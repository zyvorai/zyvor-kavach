// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Hand-built fixtures for the file analyzers. Nothing here is real malware:
// every byte is generated in code and carries only the structure under test.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/binary"
	"strings"
	"testing"
)

func filePrand(n int, seed uint64) []byte {
	out := make([]byte, n)
	x := seed | 1
	for i := range out {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = byte(x >> 24)
	}
	return out
}

// ---- PE ----

type filePESec struct {
	name  string
	va    uint32
	chars uint32
	data  []byte
}

type filePESpec struct {
	ts       uint32
	entry    uint32
	secs     []filePESec
	imports  []string // placed in an extra .idata section at RVA 0x8000
	certSize uint32   // security directory, certificate appended as overlay
	overlay  int
}

const (
	fileScnCode = 0x20000020 // code + execute
	fileScnRX   = 0x60000020
	fileScnRWX  = 0xE0000020
	fileScnData = 0xC0000040
)

func fileBuildPE(sp filePESpec) []byte {
	secs := append([]filePESec(nil), sp.secs...)
	var impDir [2]uint32
	if len(sp.imports) > 0 {
		const va = 0x8000
		n := len(sp.imports)
		buf := make([]byte, 40+(n+1)*8)
		nameOff := len(buf)
		var names []byte
		hnOffs := make([]int, n)
		for i, f := range sp.imports {
			hnOffs[i] = nameOff + len(names)
			names = append(names, 0, 0)
			names = append(names, f...)
			names = append(names, 0)
			if len(names)%2 == 1 {
				names = append(names, 0)
			}
		}
		dllOff := nameOff + len(names)
		names = append(names, "kernel32.dll\x00"...)
		binary.LittleEndian.PutUint32(buf[0:], va+40)
		binary.LittleEndian.PutUint32(buf[12:], uint32(va+dllOff))
		binary.LittleEndian.PutUint32(buf[16:], va+40)
		for i := range sp.imports {
			binary.LittleEndian.PutUint64(buf[40+i*8:], uint64(va+hnOffs[i]))
		}
		secs = append(secs, filePESec{".idata", va, fileScnData, append(buf, names...)})
		impDir = [2]uint32{va, 40}
	}
	const hdrSize, optSize = 0x200, 240
	out := make([]byte, hdrSize)
	out[0], out[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(out[0x3c:], 0x40)
	copy(out[0x40:], "PE\x00\x00")
	c := out[0x44:]
	binary.LittleEndian.PutUint16(c[0:], 0x8664)
	binary.LittleEndian.PutUint16(c[2:], uint16(len(secs)))
	binary.LittleEndian.PutUint32(c[4:], sp.ts)
	binary.LittleEndian.PutUint16(c[16:], optSize)
	binary.LittleEndian.PutUint16(c[18:], 0x22)
	o := out[0x58:]
	binary.LittleEndian.PutUint16(o[0:], 0x20b)
	binary.LittleEndian.PutUint32(o[16:], sp.entry)
	binary.LittleEndian.PutUint64(o[24:], 0x140000000)
	binary.LittleEndian.PutUint32(o[32:], 0x1000)
	binary.LittleEndian.PutUint32(o[36:], 0x200)
	binary.LittleEndian.PutUint32(o[56:], 0x10000)
	binary.LittleEndian.PutUint32(o[60:], hdrSize)
	binary.LittleEndian.PutUint16(o[68:], 3)
	binary.LittleEndian.PutUint32(o[108:], 16)
	binary.LittleEndian.PutUint32(o[112+8:], impDir[0])
	binary.LittleEndian.PutUint32(o[112+12:], impDir[1])
	sh := out[0x58+optSize:]
	var body []byte
	for i, s := range secs {
		raw := len(s.data)
		if raw%0x200 != 0 {
			raw += 0x200 - raw%0x200
		}
		e := sh[i*40:]
		copy(e[0:8], s.name)
		binary.LittleEndian.PutUint32(e[8:], uint32(len(s.data)))
		binary.LittleEndian.PutUint32(e[12:], s.va)
		binary.LittleEndian.PutUint32(e[16:], uint32(raw))
		binary.LittleEndian.PutUint32(e[20:], uint32(hdrSize+len(body)))
		binary.LittleEndian.PutUint32(e[36:], s.chars)
		body = append(body, s.data...)
		body = append(body, make([]byte, raw-len(s.data))...)
	}
	out = append(out, body...)
	if sp.certSize > 0 {
		binary.LittleEndian.PutUint32(out[0x58+112+32:], uint32(len(out)))
		binary.LittleEndian.PutUint32(out[0x58+112+36:], sp.certSize)
		out = append(out, make([]byte, sp.certSize)...)
	}
	out = append(out, make([]byte, sp.overlay)...)
	return out
}

func fileBenignPE() []byte {
	text := bytes.Repeat([]byte("\x55\x48\x89\xe5\x90\x90\xc3\x00"), 300)
	return fileBuildPE(filePESpec{ts: 1700000000, entry: 0x1000,
		secs:    []filePESec{{".text", 0x1000, fileScnCode, text}, {".data", 0x2000, fileScnData, make([]byte, 600)}},
		imports: []string{"GetLastError", "ExitProcess", "WriteFile", "CreateFileW", "CloseHandle"}})
}

// ---- ELF ----

type fileELFSpec struct {
	interp   string
	loadFlag uint32 // flags of the second PT_LOAD (5 = R+X, 7 = RWX)
	secFlags uint64 // flags of .text
	secName  string
	imports  []string
	noSecs   bool
	text     []byte
	noSymtab bool
	extra    []byte // appended to .text data
}

func fileBuildELF(sp fileELFSpec) []byte {
	if sp.text == nil {
		sp.text = bytes.Repeat([]byte("\x90\x90\xcc\xc3"), 64)
	}
	if sp.secName == "" {
		sp.secName = ".text"
	}
	text := append(append([]byte(nil), sp.text...), sp.extra...)
	const nph = 3
	base := 64 + nph*56
	interp := append([]byte(sp.interp), 0)
	textOff := base + len(interp)
	// dynsym: null + one per import
	var dynstr = []byte{0}
	dynsym := make([]byte, 24)
	for _, im := range sp.imports {
		off := len(dynstr)
		dynstr = append(dynstr, im...)
		dynstr = append(dynstr, 0)
		s := make([]byte, 24)
		binary.LittleEndian.PutUint32(s[0:], uint32(off))
		s[4] = 0x12 // GLOBAL FUNC
		dynsym = append(dynsym, s...)
	}
	shstr := []byte("\x00" + sp.secName + "\x00.dynsym\x00.dynstr\x00.shstrtab\x00")
	nameOf := func(n string) uint32 { return uint32(bytes.Index(shstr, []byte("\x00"+n+"\x00")) + 1) }
	dynsymOff := textOff + len(text)
	dynstrOff := dynsymOff + len(dynsym)
	shstrOff := dynstrOff + len(dynstr)
	shOff := shstrOff + len(shstr)
	if sp.noSecs {
		shOff = shstrOff
	}
	total := shOff
	nsec := 5
	if sp.noSecs {
		nsec = 0
	} else {
		total += nsec * 64
	}
	out := make([]byte, total)
	copy(out, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(out[16:], 2)
	binary.LittleEndian.PutUint16(out[18:], 62)
	binary.LittleEndian.PutUint32(out[20:], 1)
	binary.LittleEndian.PutUint64(out[24:], 0x400000+uint64(textOff))
	binary.LittleEndian.PutUint64(out[32:], 64)
	if !sp.noSecs {
		binary.LittleEndian.PutUint64(out[40:], uint64(shOff))
	}
	binary.LittleEndian.PutUint16(out[52:], 64)
	binary.LittleEndian.PutUint16(out[54:], 56)
	binary.LittleEndian.PutUint16(out[56:], nph)
	binary.LittleEndian.PutUint16(out[58:], 64)
	binary.LittleEndian.PutUint16(out[60:], uint16(nsec))
	if nsec > 0 {
		binary.LittleEndian.PutUint16(out[62:], 4)
	}
	ph := func(i int, typ, flags uint32, off, sz uint64) {
		p := out[64+i*56:]
		binary.LittleEndian.PutUint32(p[0:], typ)
		binary.LittleEndian.PutUint32(p[4:], flags)
		binary.LittleEndian.PutUint64(p[8:], off)
		binary.LittleEndian.PutUint64(p[16:], 0x400000+off)
		binary.LittleEndian.PutUint64(p[32:], sz)
		binary.LittleEndian.PutUint64(p[40:], sz)
	}
	ph(0, 3, 4, uint64(base), uint64(len(interp)))
	ph(1, 1, 4, 0, uint64(total))
	ph(2, 1, sp.loadFlag, 0, uint64(total))
	copy(out[base:], interp)
	copy(out[textOff:], text)
	copy(out[dynsymOff:], dynsym)
	copy(out[dynstrOff:], dynstr)
	copy(out[shstrOff:], shstr)
	if !sp.noSecs {
		sec := func(i int, name string, typ uint32, flags, off, sz uint64, link, info uint32, ent uint64) {
			e := out[shOff+i*64:]
			binary.LittleEndian.PutUint32(e[0:], nameOf(name))
			binary.LittleEndian.PutUint32(e[4:], typ)
			binary.LittleEndian.PutUint64(e[8:], flags)
			binary.LittleEndian.PutUint64(e[24:], off)
			binary.LittleEndian.PutUint64(e[32:], sz)
			binary.LittleEndian.PutUint32(e[40:], link)
			binary.LittleEndian.PutUint32(e[44:], info)
			binary.LittleEndian.PutUint64(e[56:], ent)
		}
		sec(1, sp.secName, 1, sp.secFlags, uint64(textOff), uint64(len(text)), 0, 0, 0)
		sec(2, ".dynsym", 11, 2, uint64(dynsymOff), uint64(len(dynsym)), 3, 1, 24)
		sec(3, ".dynstr", 3, 2, uint64(dynstrOff), uint64(len(dynstr)), 0, 0, 0)
		sec(4, ".shstrtab", 3, 0, uint64(shstrOff), uint64(len(shstr)), 0, 0, 0)
	}
	return out
}

func fileBenignELF() []byte {
	return fileBuildELF(fileELFSpec{interp: "/lib64/ld-linux-x86-64.so.2", loadFlag: 5, secFlags: 6, imports: []string{"printf", "malloc"}})
}

// ---- Mach-O ----

type fileMachoSpec struct {
	arm64     bool
	dylibs    []string
	signed    bool
	segProt   uint32
	trailer   string
	importSym []string
}

func fileBuildMachO(sp fileMachoSpec) []byte {
	var cmds [][]byte
	seg := make([]byte, 72)
	binary.LittleEndian.PutUint32(seg[0:], 0x19)
	binary.LittleEndian.PutUint32(seg[4:], 72)
	copy(seg[8:], "__TEXT")
	binary.LittleEndian.PutUint64(seg[24:], 0x1000)
	binary.LittleEndian.PutUint32(seg[56:], 7)
	prot := sp.segProt
	if prot == 0 {
		prot = 5
	}
	binary.LittleEndian.PutUint32(seg[60:], prot)
	cmds = append(cmds, seg)
	for _, d := range sp.dylibs {
		n := 24 + len(d) + 1
		n += (8 - n%8) % 8
		c := make([]byte, n)
		binary.LittleEndian.PutUint32(c[0:], 0xc)
		binary.LittleEndian.PutUint32(c[4:], uint32(n))
		binary.LittleEndian.PutUint32(c[8:], 24)
		copy(c[24:], d)
		cmds = append(cmds, c)
	}
	if sp.signed {
		c := make([]byte, 16)
		binary.LittleEndian.PutUint32(c[0:], 0x1d)
		binary.LittleEndian.PutUint32(c[4:], 16)
		cmds = append(cmds, c)
	}
	size := 0
	for _, c := range cmds {
		size += len(c)
	}
	h := make([]byte, 32)
	binary.LittleEndian.PutUint32(h[0:], 0xfeedfacf)
	cpu := uint32(0x01000007)
	if sp.arm64 {
		cpu = 0x0100000c
	}
	binary.LittleEndian.PutUint32(h[4:], cpu)
	binary.LittleEndian.PutUint32(h[12:], 2)
	binary.LittleEndian.PutUint32(h[16:], uint32(len(cmds)))
	binary.LittleEndian.PutUint32(h[20:], uint32(size))
	out := h
	for _, c := range cmds {
		out = append(out, c...)
	}
	out = append(out, sp.trailer...)
	return out
}

func fileBuildFat(inner []byte) []byte {
	h := make([]byte, 8+20)
	copy(h, "\xca\xfe\xba\xbe")
	binary.BigEndian.PutUint32(h[4:], 1)
	binary.BigEndian.PutUint32(h[8:], 0x01000007)
	binary.BigEndian.PutUint32(h[16:], 64)
	binary.BigEndian.PutUint32(h[20:], uint32(len(inner)))
	h = append(h, make([]byte, 64-len(h))...)
	return append(h, inner...)
}

// ---- zip / documents ----

type fileZent struct {
	name   string
	data   []byte
	method uint16
}

func fileBuildZip(ents []fileZent) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range ents {
		m := e.method
		if m == 0 && !strings.HasSuffix(e.name, "\x00stored") {
			m = zip.Deflate
		}
		name := strings.TrimSuffix(e.name, "\x00stored")
		f, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: m})
		if err != nil {
			panic(err)
		}
		f.Write(e.data)
	}
	w.Close()
	return buf.Bytes()
}

func fileBuildDocx(extra ...fileZent) []byte {
	base := []fileZent{
		{name: "[Content_Types].xml", data: []byte(`<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`)},
		{name: "word/document.xml", data: []byte(`<w:document><w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p></w:body></w:document>`)},
		{name: "word/_rels/document.xml.rels", data: []byte(`<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.org/" TargetMode="External"/></Relationships>`)},
	}
	return fileBuildZip(append(base, extra...))
}

func fileGz(p []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(p)
	w.Close()
	return b.Bytes()
}

func fileZl(p []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	w.Write(p)
	w.Close()
	return b.Bytes()
}

// fileRun runs every registered file analyzer and returns the report.
func fileRun(data []byte) *InspectReport {
	return RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindFile, Name: "fixture", Data: data})
}

func fileFindingIDs(r *InspectReport) map[string]InspectFinding {
	m := map[string]InspectFinding{}
	for _, f := range r.Findings {
		m[f.ID] = f
	}
	return m
}

func fileTestBuilder() *InspectBuilder {
	return &InspectBuilder{r: &InspectReport{}, seenIOC: map[string]bool{}, analyzer: "test"}
}

func fileHasIOC(r *InspectReport, typ, val string) bool {
	for _, i := range r.IOCs {
		if i.Type == typ && i.Value == val {
			return true
		}
	}
	return false
}

func fileMustHave(t *testing.T, r *InspectReport, ids ...string) {
	t.Helper()
	m := fileFindingIDs(r)
	for _, id := range ids {
		f, ok := m[id]
		if !ok {
			t.Errorf("missing finding %q; have %v errors=%v", id, fileKeysOf(m), r.Errors)
			continue
		}
		if f.Technique == "" && f.Weight > 0 && !strings.Contains("file-arch-bomb file-arch-traversal", id) {
			t.Logf("note: %s has no technique", id)
		}
	}
}

func fileMustNotHave(t *testing.T, r *InspectReport, ids ...string) {
	t.Helper()
	m := fileFindingIDs(r)
	for _, id := range ids {
		if _, ok := m[id]; ok {
			t.Errorf("unexpected finding %q", id)
		}
	}
}

func fileKeysOf(m map[string]InspectFinding) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}
