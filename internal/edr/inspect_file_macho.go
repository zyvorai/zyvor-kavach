// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"debug/macho"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	lcCodeSignature = 0x1d
	lcEncryption    = 0x21
	lcEncryption64  = 0x2c
)

var machoEntitlementRe = regexp.MustCompile(`com\.apple\.(?:security|private|developer)\.[a-z0-9.\-]{2,80}|get-task-allow|task_for_pid-allow`)

var machoRiskyEnt = map[string]bool{
	"com.apple.security.cs.disable-library-validation":         true,
	"com.apple.security.cs.allow-dyld-environment-variables":   true,
	"com.apple.security.cs.allow-unsigned-executable-memory":   true,
	"com.apple.security.cs.disable-executable-page-protection": true,
	"com.apple.security.get-task-allow":                        true,
	"get-task-allow":                                           true,
	"task_for_pid-allow":                                       true,
}

func analyzeMachO(ctx context.Context, data []byte, b *InspectBuilder) {
	machoByteScans(data, b)
	if len(data) >= 4 && string(data[:4]) == "\xca\xfe\xba\xbe" {
		var ff *macho.FatFile
		var err error
		if fileSafeCall(func() { ff, err = macho.NewFatFile(bytes.NewReader(data)) }) || err != nil || ff == nil {
			fileFinding(b, "file-macho-malformed", "Mach-O fat header does not parse", "low", "T1027", fmt.Sprintf("%v", err), 5)
			return
		}
		defer ff.Close()
		var archs []string
		for i, a := range ff.Arches {
			if i >= 8 || fileCtxDone(ctx) {
				b.LimitHit("macho-arches")
				break
			}
			archs = append(archs, a.Cpu.String())
			if a.File != nil {
				analyzeMachOFile(ctx, data, a.File, b, a.Cpu.String())
			}
		}
		b.Meta("macho.arches", archs)
		return
	}
	var f *macho.File
	var err error
	if fileSafeCall(func() { f, err = macho.NewFile(bytes.NewReader(data)) }) || err != nil || f == nil {
		fileFinding(b, "file-macho-malformed", "Mach-O header does not parse", "low", "T1027", fmt.Sprintf("%v", err), 5)
		return
	}
	defer f.Close()
	analyzeMachOFile(ctx, data, f, b, f.Cpu.String())
}

func analyzeMachOFile(ctx context.Context, data []byte, f *macho.File, b *InspectBuilder, arch string) {
	b.Meta("macho.type."+arch, f.Type.String())
	signed, encrypted := false, false
	for i, l := range f.Loads {
		if i >= 1024 || fileCtxDone(ctx) {
			b.LimitHit("macho-loads")
			break
		}
		raw := l.Raw()
		if len(raw) < 4 {
			continue
		}
		switch f.ByteOrder.Uint32(raw[:4]) {
		case lcCodeSignature:
			signed = true
		case lcEncryption, lcEncryption64:
			if len(raw) >= 20 && f.ByteOrder.Uint32(raw[16:20]) != 0 {
				encrypted = true
			}
		}
	}
	b.Meta("macho.code_signature."+arch, signed)
	execLike := f.Type == macho.TypeExec || f.Type == macho.TypeDylib || f.Type == macho.TypeBundle
	if !signed && execLike {
		w := 3
		if f.Cpu == macho.CpuArm64 {
			w = 5 // arm64 macOS refuses unsigned code, so absence is a bit stranger
		}
		fileFinding(b, "file-macho-unsigned", "Mach-O has no code signature load command", "low", "T1553.002", arch+": presence only, validity is never checked", w)
	}
	if encrypted {
		fileFinding(b, "file-macho-encrypted", "Mach-O segments are marked encrypted", "medium", "T1027.002", arch, 10)
	}
	var rwx []string
	for _, l := range f.Loads {
		if s, ok := l.(*macho.Segment); ok && s.Name != "__PAGEZERO" && s.Prot&7 == 7 {
			rwx = append(rwx, s.Name)
		}
	}
	if len(rwx) > 0 {
		fileFinding(b, "file-macho-rwx-segment", "Segment is readable, writable and executable", "medium", "T1027.002", fileJoinCap(rwx, 5), 8)
	}

	var libs []string
	fileSafeCall(func() { libs, _ = f.ImportedLibraries() })
	if len(libs) > 64 {
		libs = libs[:64]
	}
	b.Meta("macho.dylibs."+arch, libs)
	var oddLibs []string
	for _, l := range libs {
		ok := strings.HasPrefix(l, "/usr/lib/") || strings.HasPrefix(l, "/System/") || strings.HasPrefix(l, "@rpath/") ||
			strings.HasPrefix(l, "@executable_path/") || strings.HasPrefix(l, "@loader_path/") || strings.HasPrefix(l, "/Library/")
		if !ok || strings.Contains(l, "/tmp/") || strings.Contains(l, "/Users/Shared") || strings.Contains(l, "/private/var/tmp") {
			oddLibs = append(oddLibs, l)
		}
	}
	if len(oddLibs) > 0 {
		fileFinding(b, "file-macho-odd-dylib", "Links a dylib from an unusual location", "low", "T1574.004", fileJoinCap(oddLibs, 5), 6)
	}

	if arch != "" {
		var syms []string
		if f.Symtab != nil {
			for i, s := range f.Symtab.Syms {
				if i > 50000 {
					b.LimitHit("macho-symbols")
					break
				}
				if s.Type&0x0e == 0 || s.Sect == 0 { // undefined externals
					syms = append(syms, s.Name)
				}
			}
		}
		var hits []string
		for _, s := range syms {
			switch strings.TrimPrefix(s, "_") {
			case "ptrace", "task_for_pid", "mach_vm_write", "mach_vm_protect", "thread_create_running", "vm_write":
				hits = append(hits, s)
			}
		}
		sort.Strings(hits)
		if len(hits) >= 2 || (len(hits) == 1 && strings.Contains(hits[0], "task_for_pid")) {
			fileFinding(b, "file-macho-injection-api", "Imports task-port / cross-process memory APIs", "medium", "T1055", fileJoinCap(hits, 6), 12)
		}
	}
}

// machoSharedScans runs the arch-independent byte scans (entitlement-like
// strings, DYLD injection variable) once per file.
func machoByteScans(data []byte, b *InspectBuilder) {
	found := map[string]bool{}
	for _, m := range machoEntitlementRe.FindAll(data, 200) {
		found[string(m)] = true
	}
	var all, risky []string
	for k := range found {
		all = append(all, k)
		if machoRiskyEnt[k] || strings.HasPrefix(k, "com.apple.private.") {
			risky = append(risky, k)
		}
	}
	sort.Strings(all)
	sort.Strings(risky)
	if len(all) > 0 {
		b.Meta("macho.entitlement_strings", all)
	}
	if len(risky) > 0 {
		w := 4 + 2*len(risky)
		if w > 12 {
			w = 12
		}
		fileFinding(b, "file-macho-risky-entitlements", "Entitlement-like strings that weaken library or process protections", "low", "T1548", fileJoinCap(risky, 6)+" (string match only, not parsed from a signature)", w)
	}
	if bytes.Contains(data, []byte("DYLD_INSERT_LIBRARIES")) {
		fileFinding(b, "file-macho-dyld-insert", "References DYLD_INSERT_LIBRARIES", "medium", "T1574.006", "", 8)
	}
}
