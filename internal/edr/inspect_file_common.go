// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// File analyzers: shared helpers. Everything here parses bytes in memory only;
// nothing is executed, written or fetched. Every parser bounds-checks, caps its
// work and honours ctx; the recover in registerFileAnalyzer is a safety net only.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

const (
	fileEntropyCap     = 8 << 20 // bytes hashed per section for entropy
	fileMaxSections    = 96
	fileMaxImports     = 5000
	fileMaxZipEntries  = 20000 // entries listed per archive
	fileNestedReadCap  = 16 << 20
	fileDecompressTot  = 64 << 20 // total decompressed across one archive tree
	fileSniffEntries   = 2000
	fileUnzipRatioFlag = 200
)

// registerFileAnalyzer registers fn for kind file with an inner recover.
func registerFileAnalyzer(name string, fn func(ctx context.Context, data []byte, b *InspectBuilder)) {
	RegisterAnalyzer(name, []string{InspectKindFile}, func(ctx context.Context, in InspectInput, b *InspectBuilder) (err error) {
		if len(in.Data) == 0 {
			return nil
		}
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%s: recovered: %v", name, r)
			}
		}()
		fn(ctx, in.Data, b)
		return nil
	})
}

func fileFinding(b *InspectBuilder, id, title, sev, tech, evidence string, weight int) {
	b.Finding(InspectFinding{ID: id, Title: title, Severity: sev, Technique: tech, Evidence: evidence, Weight: weight})
}

// fileSafeCall runs f and swallows a panic from a stdlib parser fed hostile bytes.
func fileSafeCall(f func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	f()
	return false
}

func fileEntropy(p []byte) float64 {
	if len(p) == 0 {
		return 0
	}
	if len(p) > fileEntropyCap {
		p = p[:fileEntropyCap]
	}
	var c [256]int
	for _, x := range p {
		c[x]++
	}
	n := float64(len(p))
	h := 0.0
	for _, v := range c {
		if v > 0 {
			q := float64(v) / n
			h -= q * math.Log2(q)
		}
	}
	return h
}

func fileCtxDone(ctx context.Context) bool { return ctx.Err() != nil }

func fileJoinCap(items []string, n int) string {
	if len(items) > n {
		return strings.Join(items[:n], ", ") + fmt.Sprintf(" (+%d more)", len(items)-n)
	}
	return strings.Join(items, ", ")
}

// zipSafeReader opens a zip only when its declared entry count is bounded, so
// a hostile central directory cannot make the stdlib allocate without limit.
// The bool result is true when the archive was refused for being unbounded.
func zipSafeReader(data []byte) (*zip.Reader, bool, error) {
	n, ok := zipDeclaredEntries(data)
	if !ok {
		return nil, false, fmt.Errorf("no end-of-central-directory record")
	}
	if n >= 0xFFFF { // zip64 or maxed counter: not parsed
		return nil, true, fmt.Errorf("entry count not bounded")
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if errors.Is(err, zip.ErrInsecurePath) && zr != nil {
		err = nil // names are inspected by the archive analyzer, not rejected
	}
	return zr, false, err
}

func zipDeclaredEntries(data []byte) (int, bool) {
	lo := len(data) - (22 + 65535)
	if lo < 0 {
		lo = 0
	}
	i := bytes.LastIndex(data[lo:], []byte("PK\x05\x06"))
	if i < 0 || lo+i+22 > len(data) {
		return 0, false
	}
	return int(binary.LittleEndian.Uint16(data[lo+i+10:])), true
}

// detectFileFormat identifies a file by magic bytes.
func detectFileFormat(data []byte) string {
	n := len(data)
	switch {
	case n >= 2 && data[0] == 'M' && data[1] == 'Z':
		if n >= 0x40 {
			off := int(binary.LittleEndian.Uint32(data[0x3c:]))
			if off >= 0 && off+4 <= n && string(data[off:off+4]) == "PE\x00\x00" {
				return "PE"
			}
		}
		return "DOS/MZ"
	case n >= 4 && string(data[:4]) == "\x7fELF":
		return "ELF"
	case n >= 4 && isMachoMagic(data[:4]):
		return "Mach-O"
	case n >= 8 && (string(data[:4]) == "\xca\xfe\xba\xbe" || string(data[:4]) == "\xca\xfe\xba\xbf"):
		if binary.BigEndian.Uint32(data[4:8]) <= 20 {
			return "Mach-O fat"
		}
		return "Java class"
	case n >= 4 && (string(data[:4]) == "PK\x03\x04" || string(data[:4]) == "PK\x05\x06"):
		return detectZipFlavour(data)
	case bytes.Contains(data[:min(n, 1024)], []byte("%PDF-")):
		return "PDF"
	case n >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8:
		return "gzip"
	case n >= 8 && string(data[:8]) == "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
		return "OLE2"
	case n >= 8 && string(data[:8]) == "\x4c\x00\x00\x00\x01\x14\x02\x00":
		return "LNK"
	case isoHeader(data):
		return "ISO9660"
	case n >= 2 && data[0] == '#' && data[1] == '!':
		return "script (shebang)"
	}
	return ""
}

func isMachoMagic(m []byte) bool {
	switch string(m) {
	case "\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe":
		return true
	}
	return false
}

func isoHeader(data []byte) bool {
	for _, off := range []int{0x8001, 0x8801, 0x9001} {
		if len(data) >= off+5 && string(data[off:off+5]) == "CD001" {
			return true
		}
	}
	return false
}

func detectZipFlavour(data []byte) string {
	zr, _, err := zipSafeReader(data)
	if err != nil || zr == nil {
		return "ZIP"
	}
	var ooxml, manifest, dex, androidManifest bool
	for i, f := range zr.File {
		if i >= fileMaxZipEntries {
			break
		}
		switch strings.ToLower(f.Name) {
		case "[content_types].xml":
			ooxml = true
		case "meta-inf/manifest.mf":
			manifest = true
		case "classes.dex":
			dex = true
		case "androidmanifest.xml":
			androidManifest = true
		}
	}
	switch {
	case ooxml:
		return "OOXML"
	case dex && androidManifest:
		return "APK"
	case manifest:
		return "JAR"
	}
	return "ZIP"
}
