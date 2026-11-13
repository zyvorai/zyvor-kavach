// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The file-binary analyzer detects the format and parses native
// executables (PE, ELF, Mach-O). See inspect_file_elf.go / _macho.go.
func init() {
	registerFileAnalyzer("file-binary", func(ctx context.Context, data []byte, b *InspectBuilder) {
		f := detectFileFormat(data)
		if f != "" {
			b.Format(f)
		}
		switch f {
		case "PE", "DOS/MZ":
			analyzePE(ctx, data, b)
		case "ELF":
			analyzeELF(ctx, data, b)
		case "Mach-O", "Mach-O fat":
			analyzeMachO(ctx, data, b)
		}
	})
}

type apiGroup struct {
	id, title, tech string
	min             int
	weight          int
	sev             string
	apis            []string
}

// Suspicious-API combinations. A single API is never reported: it takes a
// minimum number of distinct members of one group.
var peAPIGroups = []apiGroup{
	{"file-pe-api-injection", "Imports process-injection API combination", "T1055", 3, 28, "high",
		[]string{"virtualallocex", "writeprocessmemory", "createremotethread", "createremotethreadex", "ntcreatethreadex", "queueuserapc", "setthreadcontext", "ntmapviewofsection", "ntunmapviewofsection", "rtlcreateuserthread", "ntwritevirtualmemory", "ntallocatevirtualmemory", "resumethread", "openprocess"}},
	{"file-pe-api-credential", "Imports credential-access API combination", "T1003", 2, 20, "high",
		[]string{"minidumpwritedump", "lsaretrieveprivatedata", "credenumeratea", "credenumeratew", "cryptunprotectdata", "samconnect", "samropenuser", "lsaenumeratelogonsessions", "lsaopenpolicy", "ntreadvirtualmemory", "adjusttokenprivileges", "lookupprivilegevaluea", "lookupprivilegevaluew"}},
	{"file-pe-api-antidebug", "Imports anti-debugging API combination", "T1622", 2, 10, "medium",
		[]string{"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa", "outputdebugstringw", "ntsetinformationthread", "zwsetinformationthread", "queryperformancecounter", "gettickcount", "debugactiveprocess"}},
}

var (
	peNetAPIs    = []string{"internetopena", "internetopenw", "internetopenurla", "internetopenurlw", "internetreadfile", "httpsendrequesta", "httpsendrequestw", "winhttpopen", "winhttpsendrequest", "urldownloadtofilea", "urldownloadtofilew", "wsastartup", "wsasocketa", "wsasocketw", "getaddrinfo"}
	peCryptoAPIs = []string{"cryptencrypt", "cryptacquirecontexta", "cryptacquirecontextw", "cryptgenkey", "cryptderivekey", "bcryptencrypt", "bcryptgeneratesymmetrickey", "cryptimportkey"}
	peUPXNames   = map[string]string{"upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".themida": "Themida", ".winlice": "WinLicense", ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect", ".petite": "Petite", ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".enigma1": "Enigma", ".enigma2": "Enigma", ".nsp0": "NsPack", ".nsp1": "NsPack", ".perplex": "PELock", "pec1": "PECompact", "pec2": "PECompact", ".packed": "generic packer", ".yp": "Yoda protector"}
)

const (
	peSCNExec  = 0x20000000
	peSCNWrite = 0x80000000
	peSCNCode  = 0x20
)

func analyzePE(ctx context.Context, data []byte, b *InspectBuilder) {
	// The stdlib allocates from NumberOfSymbols; neutralise an out-of-bounds
	// symbol table on a private copy so a hostile header cannot drive memory.
	src := data
	if len(data) >= 0x40 {
		lf := int(binary.LittleEndian.Uint32(data[0x3c:]))
		if lf >= 0 && lf+24 <= len(data) && string(data[lf:lf+4]) == "PE\x00\x00" {
			ptr := binary.LittleEndian.Uint32(data[lf+12:])
			cnt := binary.LittleEndian.Uint32(data[lf+16:])
			if cnt > 0 && uint64(ptr)+uint64(cnt)*18 > uint64(len(data)) {
				src = append([]byte(nil), data...)
				binary.LittleEndian.PutUint32(src[lf+12:], 0)
				binary.LittleEndian.PutUint32(src[lf+16:], 0)
				fileFinding(b, "file-pe-symtab-oob", "PE COFF symbol table points outside the file", "low", "T1027", fmt.Sprintf("ptr=%d count=%d size=%d", ptr, cnt, len(data)), 3)
			}
		}
	}
	var f *pe.File
	var err error
	if fileSafeCall(func() { f, err = pe.NewFile(bytes.NewReader(src)) }) || err != nil || f == nil {
		fileFinding(b, "file-pe-malformed", "File has an MZ header but the PE structure does not parse", "low", "T1027", fmt.Sprintf("%v", err), 5)
		return
	}
	defer f.Close()
	if fileCtxDone(ctx) {
		return
	}

	var (
		is64                    bool
		entryRVA, sizeOfHeaders uint32
		dd                      [16]pe.DataDirectory
	)
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		is64, entryRVA, sizeOfHeaders, dd = true, oh.AddressOfEntryPoint, oh.SizeOfHeaders, oh.DataDirectory
		b.Format("PE32+")
	case *pe.OptionalHeader32:
		entryRVA, sizeOfHeaders, dd = oh.AddressOfEntryPoint, oh.SizeOfHeaders, oh.DataDirectory
	default:
		fileFinding(b, "file-pe-no-optional-header", "PE has no optional header", "low", "T1027", "", 4)
	}
	_ = is64
	b.Meta("pe.machine", fmt.Sprintf("0x%x", f.Machine))
	b.Meta("pe.sections", len(f.Sections))

	// Compile timestamp.
	ts := f.TimeDateStamp
	now := time.Now()
	switch {
	case ts == 0:
		fileFinding(b, "file-pe-timestamp-zero", "PE compile timestamp is zero", "low", "T1070.006", "", 3)
	case time.Unix(int64(ts), 0).After(now.Add(24 * time.Hour)):
		fileFinding(b, "file-pe-timestamp-future", "PE compile timestamp is in the future", "low", "T1070.006", time.Unix(int64(ts), 0).UTC().Format(time.RFC3339), 5)
	case ts < 757382400: // before 1994-01-01, earlier than PE tooling in practice
		fileFinding(b, "file-pe-timestamp-old", "PE compile timestamp predates the PE toolchain", "low", "T1070.006", time.Unix(int64(ts), 0).UTC().Format(time.RFC3339), 3)
	default:
		b.Meta("pe.compiled", time.Unix(int64(ts), 0).UTC().Format(time.RFC3339))
	}

	// Sections.
	var (
		rwx, packers, highEntExec []string
		maxEnd                    = uint64(sizeOfHeaders)
		epSection                 *pe.Section
		epIndex                   = -1
		truncated                 bool
		secInfo                   []map[string]any
	)
	for i, s := range f.Sections {
		if i >= fileMaxSections {
			b.LimitHit("pe-sections")
			break
		}
		if fileCtxDone(ctx) {
			return
		}
		name := strings.ToLower(strings.TrimRight(s.Name, "\x00 "))
		var ent float64
		off, size := uint64(s.Offset), uint64(s.Size)
		if size > 0 && off < uint64(len(data)) {
			end := off + size
			if end > uint64(len(data)) {
				end = uint64(len(data))
				truncated = true
			}
			ent = fileEntropy(data[off:end])
			if off+size > maxEnd {
				maxEnd = off + size
			}
		} else if size > 0 {
			truncated = true
		}
		exec := s.Characteristics&(peSCNExec|peSCNCode) != 0
		wr := s.Characteristics&peSCNWrite != 0
		if exec && wr {
			rwx = append(rwx, s.Name)
		}
		if p, ok := peUPXNames[name]; ok {
			packers = append(packers, p+":"+s.Name)
		}
		if exec && ent >= 7.2 && size >= 1024 {
			highEntExec = append(highEntExec, fmt.Sprintf("%s=%.2f", s.Name, ent))
		}
		va, vs := uint64(s.VirtualAddress), uint64(s.VirtualSize)
		if vs == 0 {
			vs = size
		}
		if entryRVA != 0 && epSection == nil && uint64(entryRVA) >= va && uint64(entryRVA) < va+vs {
			epSection, epIndex = s, i
		}
		secInfo = append(secInfo, map[string]any{"name": s.Name, "raw": s.Size, "virtual": s.VirtualSize, "entropy": float64(int(ent*100)) / 100, "exec": exec, "write": wr})
	}
	b.Meta("pe.section_table", secInfo)
	if truncated {
		fileFinding(b, "file-pe-truncated", "PE section raw data extends past the end of the file", "low", "T1027", "", 4)
	}
	if len(rwx) > 0 {
		fileFinding(b, "file-pe-rwx-section", "Section is both writable and executable", "medium", "T1027.002", fileJoinCap(rwx, 8), 8)
	}
	if len(packers) > 0 {
		fileFinding(b, "file-pe-packer-section", "Section names match a known packer or protector", "medium", "T1027.002", fileJoinCap(packers, 8), 12)
	}
	if len(highEntExec) > 0 {
		fileFinding(b, "file-pe-high-entropy-exec", "Executable section has packed or encrypted-looking entropy", "medium", "T1027.002", fileJoinCap(highEntExec, 8), 10)
	}
	if bytes.Contains(data, []byte("UPX!")) && bytes.Contains(data, []byte("UPX0")) {
		fileFinding(b, "file-pe-upx-marker", "UPX packer marker present", "medium", "T1027.002", "UPX! / UPX0", 8)
	}

	// Entry point.
	if entryRVA != 0 {
		switch {
		case epSection == nil:
			fileFinding(b, "file-pe-entry-outside", "Entry point lies outside every section", "medium", "T1027", fmt.Sprintf("rva=0x%x", entryRVA), 8)
		case epSection.Characteristics&peSCNExec == 0 && epSection.Characteristics&peSCNCode == 0:
			fileFinding(b, "file-pe-entry-nonexec", "Entry point is in a section not marked as code", "medium", "T1027", epSection.Name, 8)
		case epIndex == len(f.Sections)-1 && len(f.Sections) > 1:
			fileFinding(b, "file-pe-entry-last-section", "Entry point is in the last section", "low", "T1027.002", epSection.Name, 6)
		}
	}

	// Overlay and Authenticode.
	certOff, certSize := uint64(dd[4].VirtualAddress), uint64(dd[4].Size)
	if certSize > 0 {
		fileFinding(b, "file-pe-authenticode-present", "Authenticode signature directory present (not verified)", "info", "", fmt.Sprintf("offset=%d size=%d; Kavach does not validate the signature or chain", certOff, certSize), 0)
		b.Meta("pe.authenticode_verified", false)
	}
	if maxEnd > 0 && uint64(len(data)) > maxEnd {
		overlay := uint64(len(data)) - maxEnd
		if certSize > 0 && certOff >= maxEnd && certOff+certSize <= uint64(len(data)) {
			if overlay >= certSize {
				overlay -= certSize
			} else {
				overlay = 0
			}
		}
		b.Meta("pe.overlay_bytes", overlay)
		if overlay >= 64<<10 && overlay*2 >= uint64(len(data)) {
			fileFinding(b, "file-pe-overlay-large", "Large overlay after the last section (embedded payload?)", "low", "T1027.009", fmt.Sprintf("%d of %d bytes", overlay, len(data)), 6)
		}
	}

	// Imports.
	var syms []string
	fileSafeCall(func() { syms, _ = f.ImportedSymbols() })
	if len(syms) > fileMaxImports {
		syms = syms[:fileMaxImports]
		b.LimitHit("pe-imports")
	}
	have := map[string]bool{}
	dlls := map[string]bool{}
	for _, s := range syms {
		fn, dll, _ := strings.Cut(s, ":")
		have[strings.ToLower(fn)] = true
		dlls[strings.ToLower(dll)] = true
	}
	var dl []string
	for d := range dlls {
		dl = append(dl, d)
	}
	sort.Strings(dl)
	if len(dl) > 40 {
		dl = dl[:40]
	}
	b.Meta("pe.import_count", len(syms))
	b.Meta("pe.dlls", dl)
	for _, g := range peAPIGroups {
		hits := fileMatchAPIs(have, g.apis)
		if len(hits) >= g.min {
			fileFinding(b, g.id, g.title, g.sev, g.tech, fileJoinCap(hits, 10), g.weight)
		}
	}
	if n, c := fileMatchAPIs(have, peNetAPIs), fileMatchAPIs(have, peCryptoAPIs); len(n) > 0 && len(c) > 0 {
		fileFinding(b, "file-pe-api-netcrypto", "Imports networking plus cryptography APIs", "low", "T1071", fileJoinCap(append(n, c...), 10), 6)
	}
	if len(syms) > 0 && len(syms) <= 4 && (have["loadlibrarya"] || have["loadlibraryw"] || have["getprocaddress"]) {
		fileFinding(b, "file-pe-minimal-imports", "Import table is minimal (only loader APIs), typical of packed or dynamically resolved code", "low", "T1027.007", fileJoinCap(fileSortedKeys(have), 6), 6)
	}
}

func fileMatchAPIs(have map[string]bool, apis []string) []string {
	var out []string
	for _, a := range apis {
		if have[a] {
			out = append(out, a)
		}
	}
	return out
}

func fileSortedKeys(m map[string]bool) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	sort.Strings(o)
	return o
}
