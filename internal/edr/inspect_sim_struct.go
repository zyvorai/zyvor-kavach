// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Structure-aware hashes for native executables, plus ComputeDigests which
// gathers every similarity value for a byte slice.
//
//   - PE import hash ("imphash" practice, popularised by Mandiant in 2014): the
//     imports are listed in import-table order as "dll.function", lowercased,
//     with a trailing .dll/.ocx/.sys removed from the library name, joined with
//     commas, and hashed with MD5 (the public convention; MD5 is used here only
//     as an identifier, not for security). We do NOT claim value-compatibility
//     with any other tool: ordinal-only imports and corner cases may differ.
//   - ELF symbol hash (the idea behind telfhash, without its TLSH step): the
//     undefined dynamic symbols (case preserved), de-duplicated and sorted,
//     hashed with SHA-256 (first 32 hex characters).
//   - Mach-O hash: sorted lowercased dylib base names plus sorted imported
//     symbols, SHA-256 (first 32 hex).
//   - Section-entropy vector: Shannon entropy of each section (at most 64,
//     at most 8 MiB read per section) quantised to half-bit steps and written
//     as one hex digit per section; also hashed so equal layouts compare cheaply.
//
// All parsers run on a private view of the bytes, never write, and recover
// from stdlib panics.

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math"
	"sort"
	"strings"
)

const (
	simMaxSymbols  = 20000
	simMaxSections = 64
	simSectionRead = 8 << 20
)

// SimDigests is the full set of similarity values for one file.
type SimDigests struct {
	Format      string `json:"format,omitempty"`
	CTPH        string `json:"ctph,omitempty"`
	LSH         string `json:"lsh,omitempty"`
	ImpHash     string `json:"imphash,omitempty"`
	ELFSymHash  string `json:"elf_symhash,omitempty"`
	MachOHash   string `json:"macho_hash,omitempty"`
	EntropyVec  string `json:"entropy_vec,omitempty"`
	EntropyVecH string `json:"entropy_vec_hash,omitempty"`
}

// ComputeDigests computes every similarity digest that applies to data. It
// never panics. Inputs above InspectMaxBytes are truncated for the digests.
// Parts that do not apply (too small, wrong format) are left empty.
func ComputeDigests(data []byte) SimDigests {
	return computeDigestsCtx(context.Background(), data)
}

func computeDigestsCtx(ctx context.Context, data []byte) (d SimDigests) {
	defer func() { _ = recover() }()
	if len(data) > InspectMaxBytes {
		data = data[:InspectMaxBytes]
	}
	d.CTPH, _ = CTPHDigest(ctx, data)
	d.LSH, _ = LSHDigest(ctx, data)
	if ctx.Err() != nil {
		return d
	}
	func() {
		defer func() { _ = recover() }()
		switch {
		case bytes.HasPrefix(data, []byte("MZ")):
			d.Format = "PE"
			d.ImpHash, d.EntropyVec = peStructure(data)
		case bytes.HasPrefix(data, []byte("\x7fELF")):
			d.Format = "ELF"
			d.ELFSymHash, d.EntropyVec = elfStructure(data)
		case len(data) >= 4 && isMachOMagic(data):
			d.Format = "Mach-O"
			d.MachOHash, d.EntropyVec = machoStructure(data)
		}
	}()
	if d.EntropyVec != "" {
		s := sha256.Sum256([]byte(d.EntropyVec))
		d.EntropyVecH = hex.EncodeToString(s[:8])
	}
	return d
}

func isMachOMagic(b []byte) bool {
	switch binary.BigEndian.Uint32(b) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe:
		return true
	}
	return false
}

// quantEntropy returns a section's Shannon entropy (0-8 bits/byte) in half-bit
// steps, 0-15.
func quantEntropy(r io.Reader) (byte, bool) {
	var cnt [256]int
	buf := make([]byte, 32<<10)
	total := 0
	lr := io.LimitReader(r, simSectionRead)
	for {
		n, err := lr.Read(buf)
		for _, c := range buf[:n] {
			cnt[c]++
		}
		total += n
		if err != nil {
			break
		}
	}
	if total == 0 {
		return 0, false
	}
	h := 0.0
	for _, c := range cnt {
		if c > 0 {
			p := float64(c) / float64(total)
			h -= p * math.Log2(p)
		}
	}
	q := int(h * 2)
	if q > 15 {
		q = 15
	}
	return byte(q), true
}

const hexDigits = "0123456789abcdef"

func peImpHash(syms []string) string {
	parts := make([]string, 0, len(syms))
	for _, s := range syms {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			continue
		}
		fn, dll := strings.ToLower(s[:i]), strings.ToLower(s[i+1:])
		for _, ext := range []string{".dll", ".ocx", ".sys"} {
			if strings.HasSuffix(dll, ext) {
				dll = strings.TrimSuffix(dll, ext)
				break
			}
		}
		parts = append(parts, dll+"."+fn)
	}
	if len(parts) == 0 {
		return ""
	}
	sum := md5.Sum([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:])
}

func peStructure(data []byte) (imp, vec string) {
	src := data
	if len(data) >= 0x40 {
		lf := int(binary.LittleEndian.Uint32(data[0x3c:]))
		if lf >= 0 && lf+24 <= len(data) && string(data[lf:lf+4]) == "PE\x00\x00" {
			ptr := binary.LittleEndian.Uint32(data[lf+12:])
			cnt := binary.LittleEndian.Uint32(data[lf+16:])
			if cnt > 0 && uint64(ptr)+uint64(cnt)*18 > uint64(len(data)) {
				src = append([]byte(nil), data...) // never mutate the caller's bytes
				binary.LittleEndian.PutUint32(src[lf+12:], 0)
				binary.LittleEndian.PutUint32(src[lf+16:], 0)
			}
		}
	}
	f, err := pe.NewFile(bytes.NewReader(src))
	if err != nil {
		return "", ""
	}
	defer f.Close()
	fileSafeCall(func() {
		syms, _ := f.ImportedSymbols()
		if len(syms) > simMaxSymbols {
			syms = syms[:simMaxSymbols]
		}
		imp = peImpHash(syms)
	})
	var sb strings.Builder
	for i, s := range f.Sections {
		if i >= simMaxSections {
			break
		}
		q, _ := quantEntropy(s.Open())
		sb.WriteByte(hexDigits[q])
	}
	return imp, sb.String()
}

func uniqSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func hash32(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	s := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(s[:16])
}

func elfStructure(data []byte) (sym, vec string) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return "", ""
	}
	defer f.Close()
	fileSafeCall(func() {
		ds, _ := f.DynamicSymbols()
		var names []string
		for _, s := range ds {
			if s.Section == elf.SHN_UNDEF && s.Name != "" {
				names = append(names, s.Name)
				if len(names) >= simMaxSymbols {
					break
				}
			}
		}
		sym = hash32(uniqSorted(names))
	})
	var sb strings.Builder
	n := 0
	for _, s := range f.Sections {
		if n >= simMaxSections {
			break
		}
		if s.Type == elf.SHT_NOBITS || s.Type == elf.SHT_NULL || s.Size == 0 {
			continue
		}
		if q, ok := quantEntropy(s.Open()); ok {
			sb.WriteByte(hexDigits[q])
			n++
		}
	}
	return sym, sb.String()
}

func machoStructure(data []byte) (h, vec string) {
	var f *macho.File
	if fat, err := macho.NewFatFile(bytes.NewReader(data)); err == nil && len(fat.Arches) > 0 {
		f = fat.Arches[0].File
	} else if m, err := macho.NewFile(bytes.NewReader(data)); err == nil {
		f = m
	}
	if f == nil {
		return "", ""
	}
	fileSafeCall(func() {
		libs, _ := f.ImportedLibraries()
		syms, _ := f.ImportedSymbols()
		if len(syms) > simMaxSymbols {
			syms = syms[:simMaxSymbols]
		}
		var parts []string
		for _, l := range libs {
			if i := strings.LastIndexByte(l, '/'); i >= 0 {
				l = l[i+1:]
			}
			parts = append(parts, "L:"+strings.ToLower(l))
		}
		for _, s := range syms {
			parts = append(parts, "S:"+s)
		}
		h = hash32(uniqSorted(parts))
	})
	var sb strings.Builder
	n := 0
	for _, s := range f.Sections {
		if n >= simMaxSections {
			break
		}
		if s.Size == 0 || s.Offset == 0 {
			continue
		}
		if q, ok := quantEntropy(s.Open()); ok {
			sb.WriteByte(hexDigits[q])
			n++
		}
	}
	return h, sb.String()
}
