// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// .NET assembly triage for kind file. Parse-only: the PE optional header's CLR
// data directory, the CLR (COR20) header, the metadata root, the stream
// headers and the #~ tables stream are read with bounds checks. Nothing is
// loaded, JIT-compiled or executed. Only the tables needed for triage are
// decoded (Assembly, AssemblyRef, TypeRef, MemberRef, ModuleRef, ImplMap,
// ManifestResource); every other table is only sized so the decoder can skip
// to the ones it needs.

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	dnMaxRows       = 1 << 22 // rows accepted per table
	dnMaxStrLen     = 256
	dnMaxRefs       = 400 // assembly refs / pinvokes / resources listed
	dnMaxMemberRefs = 20000
	dnMaxResBytes   = 8 << 20 // bytes hashed per resource for entropy
	dnMaxStreams    = 16
	dnPackedEntropy = 7.2
	dnPackedMin     = 16 << 10
)

func init() {
	registerFileAnalyzer("file-dotnet", func(ctx context.Context, data []byte, b *InspectBuilder) {
		if detectFileFormat(data) == "PE" {
			analyzeDotNet(ctx, data, b)
		}
	})
}

type dnSection struct{ va, vsize, raw, rsize uint32 }

type dnPE struct {
	data     []byte
	sections []dnSection
	clrRVA   uint32
	clrSize  uint32
	is64     bool
}

func dnParsePE(data []byte) (p dnPE, ok bool) {
	p.data = data
	if len(data) < 0x40 {
		return p, false
	}
	lf := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if lf < 0 || lf+24 > len(data) || string(data[lf:lf+4]) != "PE\x00\x00" {
		return p, false
	}
	nsec := int(binary.LittleEndian.Uint16(data[lf+6:]))
	optSize := int(binary.LittleEndian.Uint16(data[lf+20:]))
	opt := lf + 24
	if opt+optSize > len(data) || optSize < 96 {
		return p, false
	}
	var ddOff int
	switch binary.LittleEndian.Uint16(data[opt:]) {
	case 0x10b:
		ddOff = opt + 96
	case 0x20b:
		ddOff = opt + 112
		p.is64 = true
	default:
		return p, false
	}
	if ddOff+15*8 > opt+optSize {
		return p, false // no room for the CLR directory entry
	}
	p.clrRVA = binary.LittleEndian.Uint32(data[ddOff+14*8:])
	p.clrSize = binary.LittleEndian.Uint32(data[ddOff+14*8+4:])
	if nsec > fileMaxSections {
		nsec = fileMaxSections
	}
	so := opt + optSize
	for i := 0; i < nsec; i++ {
		o := so + i*40
		if o+40 > len(data) {
			break
		}
		p.sections = append(p.sections, dnSection{
			vsize: binary.LittleEndian.Uint32(data[o+8:]), va: binary.LittleEndian.Uint32(data[o+12:]),
			rsize: binary.LittleEndian.Uint32(data[o+16:]), raw: binary.LittleEndian.Uint32(data[o+20:]),
		})
	}
	return p, true
}

// slice returns n bytes at rva, or nil when it is not fully inside one section's raw data.
func (p *dnPE) slice(rva, n uint32) []byte {
	for _, s := range p.sections {
		if rva < s.va || uint64(rva)+uint64(n) > uint64(s.va)+uint64(s.rsize) {
			continue
		}
		off := uint64(s.raw) + uint64(rva-s.va)
		if off+uint64(n) <= uint64(len(p.data)) {
			return p.data[off : off+uint64(n)]
		}
	}
	return nil
}

// dnTables is the decoded subset of the metadata tables.
type dnTables struct {
	strs, blob, us []byte
	assemblyName   string
	assemblyVer    string
	asmRefs        []string
	typeRefs       []string
	memberRefs     []string
	moduleRefs     []string
	pinvokes       []string // "dll!func"
	resources      []dnResource
	methodDefs     int
	typeDefs       int
	allStrings     int
	weirdStrings   int
}

type dnResource struct {
	name   string
	offset uint32
}

func (t *dnTables) str(i uint32) string {
	if int(i) >= len(t.strs) {
		return ""
	}
	e := int(i)
	for e < len(t.strs) && t.strs[e] != 0 && e-int(i) < dnMaxStrLen {
		e++
	}
	return string(t.strs[i:e])
}

type dnCol int

// Column kinds: fixed byte widths 1,2,4 are the literal values; others are symbolic.
const (
	cStr dnCol = -1 - iota
	cGuid
	cBlob
)

// coded index tag tables (-1 = unused tag).
var dnCoded = map[string][]int{
	"TypeDefOrRef": {0x02, 0x01, 0x1B}, "HasConstant": {0x04, 0x08, 0x17},
	"HasCustomAttribute": {0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B},
	"HasFieldMarshal":    {0x04, 0x08}, "HasDeclSecurity": {0x02, 0x06, 0x20},
	"MemberRefParent": {0x02, 0x01, 0x1A, 0x06, 0x1B}, "HasSemantics": {0x14, 0x17},
	"MethodDefOrRef": {0x06, 0x0A}, "MemberForwarded": {0x04, 0x06},
	"Implementation":      {0x26, 0x23, 0x27},
	"CustomAttributeType": {-1, -1, 0x06, 0x0A, -1}, "ResolutionScope": {0x00, 0x1A, 0x23, 0x01},
	"TypeOrMethodDef": {0x02, 0x06},
}

// col descriptors: an int width, cStr/cGuid/cBlob, a "T:xx" simple table index or "C:name" coded index.
type dnC struct {
	k   dnCol
	t   int
	cod string
}

func w(n int) dnC              { return dnC{k: dnCol(n)} }
func tbl(t int) dnC            { return dnC{k: 0, t: t + 1} }
func cod(n string) dnC         { return dnC{k: 0, cod: n} }
func hs(k dnCol) dnC           { return dnC{k: k} }
func rowsOf(cols ...dnC) []dnC { return cols }

var dnSchema = map[int][]dnC{
	0x00: rowsOf(w(2), hs(cStr), hs(cGuid), hs(cGuid), hs(cGuid)),
	0x01: rowsOf(cod("ResolutionScope"), hs(cStr), hs(cStr)),
	0x02: rowsOf(w(4), hs(cStr), hs(cStr), cod("TypeDefOrRef"), tbl(0x04), tbl(0x06)),
	0x03: rowsOf(tbl(0x04)),
	0x04: rowsOf(w(2), hs(cStr), hs(cBlob)),
	0x05: rowsOf(tbl(0x06)),
	0x06: rowsOf(w(4), w(2), w(2), hs(cStr), hs(cBlob), tbl(0x08)),
	0x07: rowsOf(tbl(0x08)),
	0x08: rowsOf(w(2), w(2), hs(cStr)),
	0x09: rowsOf(tbl(0x02), cod("TypeDefOrRef")),
	0x0A: rowsOf(cod("MemberRefParent"), hs(cStr), hs(cBlob)),
	0x0B: rowsOf(w(2), cod("HasConstant"), hs(cBlob)),
	0x0C: rowsOf(cod("HasCustomAttribute"), cod("CustomAttributeType"), hs(cBlob)),
	0x0D: rowsOf(cod("HasFieldMarshal"), hs(cBlob)),
	0x0E: rowsOf(w(2), cod("HasDeclSecurity"), hs(cBlob)),
	0x0F: rowsOf(w(2), w(4), tbl(0x02)),
	0x10: rowsOf(w(4), tbl(0x04)),
	0x11: rowsOf(hs(cBlob)),
	0x12: rowsOf(tbl(0x02), tbl(0x14)),
	0x13: rowsOf(tbl(0x14)),
	0x14: rowsOf(w(2), hs(cStr), cod("TypeDefOrRef")),
	0x15: rowsOf(tbl(0x02), tbl(0x17)),
	0x16: rowsOf(tbl(0x17)),
	0x17: rowsOf(w(2), hs(cStr), hs(cBlob)),
	0x18: rowsOf(w(2), tbl(0x06), cod("HasSemantics")),
	0x19: rowsOf(tbl(0x02), cod("MethodDefOrRef"), cod("MethodDefOrRef")),
	0x1A: rowsOf(hs(cStr)),
	0x1B: rowsOf(hs(cBlob)),
	0x1C: rowsOf(w(2), cod("MemberForwarded"), hs(cStr), tbl(0x1A)),
	0x1D: rowsOf(w(4), tbl(0x04)),
	0x1E: rowsOf(w(4), w(4)),
	0x1F: rowsOf(w(4)),
	0x20: rowsOf(w(4), w(2), w(2), w(2), w(2), w(4), hs(cBlob), hs(cStr), hs(cStr)),
	0x21: rowsOf(w(4)),
	0x22: rowsOf(w(4), w(4), w(4)),
	0x23: rowsOf(w(2), w(2), w(2), w(2), w(4), hs(cBlob), hs(cStr), hs(cStr), hs(cBlob)),
	0x24: rowsOf(w(4), tbl(0x23)),
	0x25: rowsOf(w(4), w(4), w(4), tbl(0x23)),
	0x26: rowsOf(w(4), hs(cStr), hs(cBlob)),
	0x27: rowsOf(w(4), w(4), hs(cStr), hs(cStr), cod("Implementation")),
	0x28: rowsOf(w(4), w(4), hs(cStr), cod("Implementation")),
	0x29: rowsOf(tbl(0x02), tbl(0x02)),
	0x2A: rowsOf(w(2), w(2), cod("TypeOrMethodDef"), hs(cStr)),
	0x2B: rowsOf(cod("MethodDefOrRef"), hs(cBlob)),
	0x2C: rowsOf(tbl(0x2A), cod("TypeDefOrRef")),
}

// dnLayout computes per-table column widths from row counts and heap sizes.
func dnLayout(rows [64]uint32, strW, guidW, blobW int) (rowSize [64]int, colW [64][]int) {
	codedW := func(name string) int {
		tags := dnCoded[name]
		bits := 0
		for (1 << bits) < len(tags) {
			bits++
		}
		var mx uint32
		for _, t := range tags {
			if t >= 0 && rows[t] > mx {
				mx = rows[t]
			}
		}
		if mx < (1 << (16 - bits)) {
			return 2
		}
		return 4
	}
	for t := 0; t < 64; t++ {
		sch, ok := dnSchema[t]
		if !ok {
			continue
		}
		for _, c := range sch {
			var n int
			switch {
			case c.cod != "":
				n = codedW(c.cod)
			case c.t > 0:
				if rows[c.t-1] < 1<<16 {
					n = 2
				} else {
					n = 4
				}
			case c.k == cStr:
				n = strW
			case c.k == cGuid:
				n = guidW
			case c.k == cBlob:
				n = blobW
			default:
				n = int(c.k)
			}
			colW[t] = append(colW[t], n)
			rowSize[t] += n
		}
	}
	return
}

func dnReadN(b []byte, n int) uint32 {
	if n == 2 {
		return uint32(binary.LittleEndian.Uint16(b))
	}
	return binary.LittleEndian.Uint32(b)
}

// dnParseMeta decodes the metadata root and the tables stream.
func dnParseMeta(md []byte) (t dnTables, runtime string, streams []string, ok bool) {
	if len(md) < 20 || binary.LittleEndian.Uint32(md) != 0x424A5342 {
		return
	}
	vl := int(binary.LittleEndian.Uint32(md[12:]))
	if vl < 0 || vl > 255 || 16+vl+4 > len(md) {
		return
	}
	runtime = strings.TrimRight(string(md[16:16+vl]), "\x00")
	p := 16 + vl + 2
	ns := int(binary.LittleEndian.Uint16(md[p:]))
	p += 2
	if ns > dnMaxStreams {
		ns = dnMaxStreams
	}
	var tab []byte
	for i := 0; i < ns; i++ {
		if p+8 > len(md) {
			return
		}
		off, sz := binary.LittleEndian.Uint32(md[p:]), binary.LittleEndian.Uint32(md[p+4:])
		e := p + 8
		for e < len(md) && md[e] != 0 && e-p < 40 {
			e++
		}
		name := string(md[p+8 : e])
		p = (e + 4) &^ 3
		streams = append(streams, name)
		if uint64(off)+uint64(sz) > uint64(len(md)) {
			continue
		}
		s := md[off : off+sz]
		switch name {
		case "#~", "#-":
			tab = s
		case "#Strings":
			t.strs = s
		case "#Blob":
			t.blob = s
		case "#US":
			t.us = s
		}
	}
	ok = true
	if len(tab) < 24 {
		return
	}
	heap := tab[6]
	strW, guidW, blobW := 2, 2, 2
	if heap&1 != 0 {
		strW = 4
	}
	if heap&2 != 0 {
		guidW = 4
	}
	if heap&4 != 0 {
		blobW = 4
	}
	valid := binary.LittleEndian.Uint64(tab[8:])
	var rows [64]uint32
	q := 24
	for i := 0; i < 64; i++ {
		if valid&(1<<uint(i)) == 0 {
			continue
		}
		if q+4 > len(tab) {
			return
		}
		rows[i] = binary.LittleEndian.Uint32(tab[q:])
		if rows[i] > dnMaxRows {
			return
		}
		q += 4
	}
	rowSize, colW := dnLayout(rows, strW, guidW, blobW)
	// every present table must have a known schema to locate later ones
	cur := q
	var start [64]int
	for i := 0; i < 64; i++ {
		start[i] = cur
		if rows[i] == 0 {
			continue
		}
		if rowSize[i] == 0 || cur+int(rows[i])*rowSize[i] > len(tab) {
			// unknown or truncated table: later tables cannot be located
			for j := i; j < 64; j++ {
				rows[j] = 0
			}
			break
		}
		cur += int(rows[i]) * rowSize[i]
	}
	row := func(tab_ int, i int) []byte {
		o := start[tab_] + i*rowSize[tab_]
		if rowSize[tab_] == 0 || o+rowSize[tab_] > len(tab) {
			return nil
		}
		return tab[o : o+rowSize[tab_]]
	}
	col := func(tab_ int, r []byte, c int) uint32 {
		o := 0
		for k := 0; k < c; k++ {
			o += colW[tab_][k]
		}
		return dnReadN(r[o:], colW[tab_][c])
	}
	t.typeDefs, t.methodDefs = int(rows[0x02]), int(rows[0x06])
	if r := row(0x20, 0); rows[0x20] > 0 && r != nil {
		t.assemblyName = t.str(col(0x20, r, 7))
		t.assemblyVer = fmt.Sprintf("%d.%d.%d.%d", col(0x20, r, 1), col(0x20, r, 2), col(0x20, r, 3), col(0x20, r, 4))
	}
	for i := 0; i < int(rows[0x23]) && i < dnMaxRefs; i++ {
		if r := row(0x23, i); r != nil {
			t.asmRefs = append(t.asmRefs, t.str(col(0x23, r, 6)))
		}
	}
	for i := 0; i < int(rows[0x01]) && i < dnMaxMemberRefs; i++ {
		if r := row(0x01, i); r != nil {
			t.typeRefs = append(t.typeRefs, t.str(col(0x01, r, 1)))
		}
	}
	for i := 0; i < int(rows[0x0A]) && i < dnMaxMemberRefs; i++ {
		if r := row(0x0A, i); r != nil {
			t.memberRefs = append(t.memberRefs, t.str(col(0x0A, r, 1)))
		}
	}
	for i := 0; i < int(rows[0x1A]) && i < dnMaxRefs; i++ {
		if r := row(0x1A, i); r != nil {
			t.moduleRefs = append(t.moduleRefs, t.str(col(0x1A, r, 0)))
		}
	}
	for i := 0; i < int(rows[0x1C]) && i < dnMaxRefs; i++ {
		if r := row(0x1C, i); r != nil {
			fn := t.str(col(0x1C, r, 2))
			mi := int(col(0x1C, r, 3))
			dll := "?"
			if mi >= 1 && mi <= len(t.moduleRefs) {
				dll = t.moduleRefs[mi-1]
			}
			t.pinvokes = append(t.pinvokes, dll+"!"+fn)
		}
	}
	for i := 0; i < int(rows[0x28]) && i < dnMaxRefs; i++ {
		if r := row(0x28, i); r != nil {
			// only embedded resources (Implementation == 0)
			if col(0x28, r, 3) == 0 {
				t.resources = append(t.resources, dnResource{name: t.str(col(0x28, r, 2)), offset: col(0x28, r, 0)})
			}
		}
	}
	// obfuscated-name statistics over the #Strings heap
	n := 0
	for _, s := range strings.Split(string(t.strs), "\x00") {
		if s == "" {
			continue
		}
		n++
		if n > 20000 {
			break
		}
		t.allStrings++
		if !utf8.ValidString(s) || strings.ContainsAny(s, "\u200b\u200e\u200f\u202a\u202b\u202c\u202d\u202e\ufeff") || dnNonPrintable(s) {
			t.weirdStrings++
		}
	}
	return
}

func dnNonPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return true
		}
	}
	return false
}

var dnObfuscatorMarkers = []struct{ marker, name string }{
	{"ConfusedByAttribute", "ConfuserEx"}, {"Confused by ConfuserEx", "ConfuserEx"}, {"ConfuserEx", "ConfuserEx"},
	{"DotfuscatorAttribute", "Dotfuscator"}, {"SmartAssembly", "SmartAssembly"}, {"PoweredByAttribute", "SmartAssembly"},
	{"Eazfuscator", "Eazfuscator.NET"}, {"BabelObfuscatorAttribute", "Babel"}, {"ObfuscatedByAttribute", "generic obfuscator"},
	{"CryptoObfuscator", "Crypto Obfuscator"}, {"CliSecureRt", "CliSecure"}, {"Agile.NET", "Agile.NET"},
	{"ArmDot", "ArmDot"}, {"DNGuard", "DNGuard"}, {"NETReactor", ".NET Reactor"}, {"<Module>{", "unnamed obfuscator"},
	{"ProtectedWithCryptoObfuscator", "Crypto Obfuscator"}, {"Xenocode", "Xenocode"}, {"Goliath", "Goliath.NET"}, {"Skater", "Skater .NET"},
}

var dnInjectAPIs = []string{"virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread", "createthread", "queueuserapc", "ntunmapviewofsection", "setthreadcontext", "resumethread", "openprocess", "ntcreatethreadex", "virtualprotect", "rtlmovememory", "getprocaddress", "loadlibrary", "loadlibrarya", "loadlibraryw", "ntallocatevirtualmemory", "ntwritevirtualmemory"}

func analyzeDotNet(ctx context.Context, data []byte, b *InspectBuilder) {
	p, ok := dnParsePE(data)
	if !ok || p.clrRVA == 0 || p.clrSize < 72 {
		return // not a managed assembly
	}
	b.Format("PE (.NET)")
	clr := p.slice(p.clrRVA, 72)
	if clr == nil {
		fileFinding(b, "dotnet-malformed", ".NET CLR header points outside the file", "low", "T1027", fmt.Sprintf("clr rva=%#x size=%d", p.clrRVA, p.clrSize), 4)
		return
	}
	flags := binary.LittleEndian.Uint32(clr[16:])
	mdRVA, mdSize := binary.LittleEndian.Uint32(clr[8:]), binary.LittleEndian.Uint32(clr[12:])
	resRVA, resSize := binary.LittleEndian.Uint32(clr[24:]), binary.LittleEndian.Uint32(clr[28:])
	entry := binary.LittleEndian.Uint32(clr[20:])
	sn := binary.LittleEndian.Uint32(clr[32:])
	if mdSize > 64<<20 {
		mdSize = 64 << 20
	}
	md := p.slice(mdRVA, mdSize)
	if md == nil {
		fileFinding(b, "dotnet-malformed", ".NET metadata directory points outside the file", "low", "T1027", fmt.Sprintf("metadata rva=%#x size=%d", mdRVA, mdSize), 4)
		return
	}
	t, runtime, streams, ok := dnParseMeta(md)
	if !ok {
		fileFinding(b, "dotnet-malformed", ".NET metadata root is malformed", "low", "T1027", "bad BSJB root or stream directory", 4)
		return
	}
	if ctx.Err() != nil {
		return
	}
	meta := map[string]any{
		"runtime": runtime, "assembly": t.assemblyName, "version": t.assemblyVer, "streams": streams,
		"ilonly": flags&1 != 0, "strong_name_signed": flags&8 != 0 && sn != 0, "entry_point_token": entry,
		"types": t.typeDefs, "methods": t.methodDefs, "assembly_refs": capStrings(t.asmRefs, 80),
		"pinvokes": capStrings(t.pinvokes, 80), "native_entry": flags&0x10 != 0,
	}
	if len(t.asmRefs) >= dnMaxRefs || len(t.pinvokes) >= dnMaxRefs || len(t.resources) >= dnMaxRefs {
		b.LimitHit("dotnet-table-rows")
	}

	// P/Invoke imports
	injected := map[string]bool{}
	var apiNames []string
	for _, pi := range t.pinvokes {
		if i := strings.IndexByte(pi, '!'); i >= 0 {
			fn := strings.ToLower(pi[i+1:])
			apiNames = append(apiNames, fn)
			for _, a := range dnInjectAPIs {
				if fn == a {
					injected[a] = true
				}
			}
		}
	}
	if len(injected) >= 3 {
		var ks []string
		for k := range injected {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		fileFinding(b, "dotnet-pinvoke-injection", "P/Invoke imports form a memory-injection/loader combination", "high", "T1055", fileJoinCap(ks, 8), 28)
	}
	if len(t.pinvokes) > 0 {
		fileFinding(b, "dotnet-pinvoke", fmt.Sprintf("Assembly declares %d P/Invoke import(s)", len(t.pinvokes)), "info", "T1106", fileJoinCap(t.pinvokes, 8), 0)
	}

	// Type / member name combinations (reflection loaders, droppers).
	has := func(list []string, names ...string) bool {
		for _, s := range list {
			for _, n := range names {
				if s == n {
					return true
				}
			}
		}
		return false
	}
	loads := has(t.memberRefs, "Load", "LoadFrom", "LoadFile", "GetDelegateForFunctionPointer") && has(t.typeRefs, "Assembly", "Marshal")
	decodes := has(t.memberRefs, "FromBase64String", "Decompress", "TransformFinalBlock", "GetManifestResourceStream", "GetManifestResourceBytes", "Read")
	if loads && decodes {
		fileFinding(b, "dotnet-reflective-load", "Loads code reflectively from decoded or embedded data", "high", "T1620", "Assembly.Load/GetDelegateForFunctionPointer with base64/decompress/resource reads", 30)
	}
	if has(t.memberRefs, "DownloadString", "DownloadData", "DownloadFile", "OpenRead") && has(t.memberRefs, "Start", "Load", "Invoke", "CreateInstance") {
		fileFinding(b, "dotnet-download-exec", "Downloads data and can start or load it", "medium", "T1105", "WebClient download members with Process.Start/Assembly.Load/Invoke", 14)
	}
	for _, r := range t.asmRefs {
		if strings.EqualFold(r, "System.Management.Automation") {
			fileFinding(b, "dotnet-powershell-host", "Hosts the PowerShell engine (System.Management.Automation)", "low", "T1059.001", "assembly reference System.Management.Automation", 8)
			break
		}
	}

	// Obfuscator markers.
	seen := map[string]bool{}
	hay := string(t.strs)
	for _, m := range dnObfuscatorMarkers {
		if m.marker == "<Module>{" || seen[m.name] {
			continue
		}
		if strings.Contains(hay, m.marker) {
			seen[m.name] = true
			fileFinding(b, "obf-dotnet-obfuscator", "Assembly carries "+m.name+" obfuscator markers", "low", "T1027", m.marker, 15)
		}
	}
	if t.allStrings >= 20 && t.weirdStrings*100/t.allStrings >= 30 {
		fileFinding(b, "obf-dotnet-names", "Many metadata names are unprintable or invisible-unicode (renaming obfuscation)", "low", "T1027", fmt.Sprintf("%d of %d names", t.weirdStrings, t.allStrings), 12)
	}

	// Resources.
	var resMeta []map[string]any
	if resRVA != 0 && resSize > 0 {
		rs := p.slice(resRVA, resSize)
		if rs == nil && resSize > 0 {
			b.LimitHit("dotnet-resource-range")
		}
		for _, r := range t.resources {
			if ctx.Err() != nil || rs == nil {
				break
			}
			if uint64(r.offset)+4 > uint64(len(rs)) {
				continue
			}
			ln := binary.LittleEndian.Uint32(rs[r.offset:])
			if uint64(r.offset)+4+uint64(ln) > uint64(len(rs)) {
				continue
			}
			body := rs[r.offset+4 : r.offset+4+ln]
			ent := fileEntropy(body)
			item := map[string]any{"name": truncInspect(r.name), "size": ln, "entropy": fmt.Sprintf("%.2f", ent)}
			resMeta = append(resMeta, item)
			if len(body) > 2 && body[0] == 'M' && body[1] == 'Z' {
				fileFinding(b, "dotnet-resource-pe", "Embedded resource is itself a PE file", "high", "T1027.009", fmt.Sprintf("%s (%d bytes)", r.name, ln), 25)
			} else if ln >= dnPackedMin && ent >= dnPackedEntropy {
				fileFinding(b, "dotnet-resource-packed", "Large high-entropy embedded resource (possible packed or encrypted payload)", "medium", "T1027.002", fmt.Sprintf("%s: %d bytes, entropy %.2f", r.name, ln, ent), 20)
			}
		}
	}
	meta["resources"] = resMeta
	b.Meta("dotnet", meta)
	fileFinding(b, "dotnet-assembly", "Managed .NET assembly "+t.assemblyName+" "+t.assemblyVer+" (runtime "+runtime+")", "info", "", fmt.Sprintf("%d types, %d methods, %d assembly refs, %d P/Invokes, %d resources", t.typeDefs, t.methodDefs, len(t.asmRefs), len(t.pinvokes), len(t.resources)), 0)
}

func capStrings(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
