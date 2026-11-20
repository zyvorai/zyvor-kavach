// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"strings"
)

var elfStdInterps = []string{"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/local/lib", "/nix/store/", "/system/bin/linker", "/libexec/ld-elf", "/lib32/", "/libx32/", "/usr/libexec/ld.so"}

func analyzeELF(ctx context.Context, data []byte, b *InspectBuilder) {
	var f *elf.File
	var err error
	if fileSafeCall(func() { f, err = elf.NewFile(bytes.NewReader(data)) }) || err != nil || f == nil {
		fileFinding(b, "file-elf-malformed", "File has an ELF magic but the structure does not parse", "low", "T1027", fmt.Sprintf("%v", err), 5)
		return
	}
	defer f.Close()
	b.Meta("elf.class", f.Class.String())
	b.Meta("elf.machine", f.Machine.String())
	b.Meta("elf.type", f.Type.String())
	b.Meta("elf.sections", len(f.Sections))

	// Stripped / no section headers.
	if len(f.Sections) == 0 && len(f.Progs) > 0 {
		fileFinding(b, "file-elf-no-sections", "ELF has no section headers (stripped by hand or packed)", "low", "T1027.002", "", 5)
	} else if f.Section(".symtab") == nil {
		b.Meta("elf.stripped", true)
		fileFinding(b, "file-elf-stripped", "ELF is stripped of its symbol table", "info", "T1027", "common in release builds; weak signal", 2)
	}

	// Segments.
	var rwx []string
	var interps []string
	entryInExec := false
	for i, p := range f.Progs {
		if i >= 512 || fileCtxDone(ctx) {
			b.LimitHit("elf-segments")
			break
		}
		if p.Type == elf.PT_LOAD {
			if p.Flags&elf.PF_X != 0 && p.Flags&elf.PF_W != 0 {
				rwx = append(rwx, fmt.Sprintf("0x%x", p.Vaddr))
			}
			if p.Flags&elf.PF_X != 0 && f.Entry >= p.Vaddr && f.Entry < p.Vaddr+p.Memsz {
				entryInExec = true
			}
		}
		if p.Type == elf.PT_INTERP {
			if p.Filesz == 0 || p.Off > uint64(len(data)) || p.Filesz > 4096 || p.Off+p.Filesz > uint64(len(data)) {
				interps = append(interps, "<out-of-bounds>")
				continue
			}
			interps = append(interps, strings.TrimRight(string(data[p.Off:p.Off+p.Filesz]), "\x00"))
		}
	}
	if len(rwx) > 0 {
		fileFinding(b, "file-elf-rwx-segment", "Loadable segment is writable and executable", "medium", "T1027.002", fileJoinCap(rwx, 6), 8)
	}
	if f.Entry != 0 && len(f.Progs) > 0 && !entryInExec && f.Type == elf.ET_EXEC {
		fileFinding(b, "file-elf-entry-outside", "Entry point is outside every executable segment", "medium", "T1027", fmt.Sprintf("0x%x", f.Entry), 8)
	}
	if len(interps) > 1 {
		fileFinding(b, "file-elf-multi-interp", "More than one PT_INTERP segment", "medium", "T1574", fileJoinCap(interps, 4), 10)
	}
	for _, ip := range interps {
		ok := false
		for _, pre := range elfStdInterps {
			if strings.HasPrefix(ip, pre) {
				ok = true
			}
		}
		if ip == "<out-of-bounds>" || !ok || strings.Contains(ip, "..") || strings.Contains(ip, "/tmp/") || strings.Contains(ip, "/dev/shm") {
			fileFinding(b, "file-elf-odd-interp", "ELF interpreter path is not a standard system loader", "medium", "T1574", ip, 15)
		}
		b.Meta("elf.interp", ip)
	}

	// Sections.
	var wx, odd, hiEnt []string
	for i, s := range f.Sections {
		if i >= fileMaxSections*2 || fileCtxDone(ctx) {
			b.LimitHit("elf-sections")
			break
		}
		lname := strings.ToLower(s.Name)
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Flags&elf.SHF_WRITE != 0 {
			wx = append(wx, s.Name)
		}
		if strings.HasPrefix(lname, "upx") || strings.HasPrefix(lname, ".upx") || strings.HasPrefix(lname, ".packed") || lname == ".shellcode" {
			odd = append(odd, s.Name)
		}
		if s.Flags&elf.SHF_EXECINSTR != 0 && s.Type != elf.SHT_NOBITS && s.Offset < uint64(len(data)) && s.FileSize >= 4096 {
			end := s.Offset + s.FileSize
			if end > uint64(len(data)) {
				end = uint64(len(data))
			}
			if e := fileEntropy(data[s.Offset:end]); e >= 7.3 {
				hiEnt = append(hiEnt, fmt.Sprintf("%s=%.2f", s.Name, e))
			}
		}
	}
	if len(wx) > 0 {
		fileFinding(b, "file-elf-wx-section", "Section is both writable and executable", "medium", "T1027.002", fileJoinCap(wx, 6), 6)
	}
	if len(odd) > 0 {
		fileFinding(b, "file-elf-suspicious-section", "Section name matches a packer or shellcode convention", "medium", "T1027.002", fileJoinCap(odd, 6), 10)
	}
	if len(hiEnt) > 0 {
		fileFinding(b, "file-elf-high-entropy-exec", "Executable section has packed or encrypted-looking entropy", "medium", "T1027.002", fileJoinCap(hiEnt, 6), 10)
	}
	head := data[:min(len(data), 8192)]
	if bytes.Contains(head, []byte("UPX!")) || bytes.Contains(data, []byte("$Info: This file is packed with the UPX")) {
		fileFinding(b, "file-elf-upx", "UPX packer marker present", "medium", "T1027.002", "UPX! / $Info", 12)
	}

	// Imports.
	var imps []elf.ImportedSymbol
	fileSafeCall(func() { imps, _ = f.ImportedSymbols() })
	if len(imps) > fileMaxImports {
		imps = imps[:fileMaxImports]
		b.LimitHit("elf-imports")
	}
	have := map[string]bool{}
	var libs []string
	for _, im := range imps {
		have[strings.ToLower(im.Name)] = true
	}
	fileSafeCall(func() { libs, _ = f.ImportedLibraries() })
	if len(libs) > 40 {
		libs = libs[:40]
	}
	b.Meta("elf.needed", libs)
	b.Meta("elf.import_count", len(imps))
	if len(imps) == 0 && len(f.Sections) > 0 && f.Section(".dynamic") == nil {
		b.Meta("elf.static", true)
	}
	var inj []string
	for _, n := range []string{"ptrace", "process_vm_writev", "process_vm_readv"} {
		if have[n] {
			inj = append(inj, n)
		}
	}
	if len(inj) > 0 {
		fileFinding(b, "file-elf-ptrace", "Imports process-tracing or cross-process memory APIs", "medium", "T1055.008", fileJoinCap(inj, 4), 10)
	}
	if have["memfd_create"] && (have["fexecve"] || have["execveat"]) {
		fileFinding(b, "file-elf-fileless-exec", "Imports memfd_create with fexecve/execveat (fileless execution)", "high", "T1620", "memfd_create+fexecve", 18)
	}
	if bytes.Contains(data, []byte("LD_PRELOAD")) && (have["dlsym"] || have["dlopen"]) {
		fileFinding(b, "file-elf-ld-preload", "References LD_PRELOAD together with dlsym/dlopen (library hooking)", "medium", "T1574.006", "LD_PRELOAD", 8)
	}
	if bytes.Contains(data, []byte("/proc/self/mem")) || bytes.Contains(data, []byte("/etc/ld.so.preload")) {
		fileFinding(b, "file-elf-proc-mem", "References /proc/self/mem or /etc/ld.so.preload", "medium", "T1574.006", "", 8)
	}
}
