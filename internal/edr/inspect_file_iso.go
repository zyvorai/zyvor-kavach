// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Disk-image analyzer for kind file: lists an ISO 9660 image (primary and
// Joliet volume descriptors) from memory and flags autorun, executables and
// shortcuts inside. Parse-only: nothing is mounted, extracted or executed, file
// contents are never read. Not parsed: UDF-only images, Rock Ridge long names,
// multi-extent files, VHD/VHDX/DMG/WIM/IMG (only recognised and reported).

import (
	"context"
	"encoding/binary"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	isoSector     = 2048
	isoMaxEntries = 5000
	isoMaxDirs    = 800
	isoMaxDirSize = 1 << 20
	isoMaxDepth   = 8
	isoListCap    = 200 // names kept in meta
)

func init() {
	registerFileAnalyzer("file-diskimage", analyzeDiskImage)
}

type isoEntry struct {
	Path string
	Size uint32
	Dir  bool
}

var isoExecExt = map[string]bool{".exe": true, ".dll": true, ".scr": true, ".com": true, ".msi": true, ".sys": true, ".cpl": true, ".jar": true}
var isoScriptExt = map[string]bool{".bat": true, ".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".hta": true, ".wsf": true, ".sh": true, ".py": true}

func analyzeDiskImage(ctx context.Context, data []byte, b *InspectBuilder) {
	n := len(data)
	switch {
	case isoHeader(data):
		analyzeISO(ctx, data, b)
	case n >= 8 && string(data[:8]) == "vhdxfile":
		b.Format("VHDX")
		fileFinding(b, "disk-image-unlisted", "VHDX virtual disk (contents are not listed by this inspector)", "low", "T1553.005", "", 6)
	case n >= 512 && (string(data[:8]) == "conectix" || string(data[n-512:n-504]) == "conectix"):
		b.Format("VHD")
		fileFinding(b, "disk-image-unlisted", "VHD virtual disk (contents are not listed by this inspector)", "low", "T1553.005", "", 6)
	case n >= 512 && string(data[n-512:n-508]) == "koly":
		b.Format("DMG")
		fileFinding(b, "disk-image-unlisted", "Apple DMG disk image (contents are not listed by this inspector)", "low", "T1553.005", "", 4)
	}
}

func analyzeISO(ctx context.Context, data []byte, b *InspectBuilder) {
	// Volume descriptors start at sector 16; prefer Joliet (type 2) when present.
	var pvd, joliet []byte
	for s := 16; s < 16+32 && (s+1)*isoSector <= len(data); s++ {
		d := data[s*isoSector : (s+1)*isoSector]
		if string(d[1:6]) != "CD001" || d[0] == 255 {
			break
		}
		if d[0] == 1 && pvd == nil {
			pvd = d
		}
		if d[0] == 2 && joliet == nil && strings.HasPrefix(string(d[88:90]), "%/") {
			joliet = d
		}
	}
	if pvd == nil && joliet == nil {
		b.Format("ISO9660 (UDF or unparsed)")
		fileFinding(b, "disk-image-unlisted", "Optical image has no readable ISO 9660 volume descriptor (UDF-only?); contents not listed", "low", "T1553.005", "", 6)
		return
	}
	b.Format("ISO9660")
	vd, ucs := pvd, false
	if joliet != nil {
		vd, ucs = joliet, true
	}
	label := strings.TrimSpace(string(vd[40:72]))
	if ucs {
		label = strings.TrimSpace(ucs2BE(vd[40:72]))
	}
	entries, limited := isoWalk(ctx, data, vd[156:190], ucs)
	if limited != "" {
		b.LimitHit(limited)
	}
	b.Meta("iso.volume_label", label)
	b.Meta("iso.entry_count", len(entries))
	names := make([]string, 0, isoListCap)
	for i, e := range entries {
		if i >= isoListCap {
			b.LimitHit("iso-listing")
			break
		}
		names = append(names, e.Path)
	}
	b.Meta("iso.entries", names)

	var autorun, execs, scripts, lnks []string
	for _, e := range entries {
		if e.Dir {
			continue
		}
		base := e.Path[strings.LastIndex(e.Path, "/")+1:]
		ext := ""
		if i := strings.LastIndex(base, "."); i >= 0 {
			ext = base[i:]
		}
		switch {
		case base == "autorun.inf" && strings.Count(e.Path, "/") == 1:
			autorun = append(autorun, e.Path)
		case ext == ".lnk":
			lnks = append(lnks, e.Path)
		case isoExecExt[ext]:
			execs = append(execs, e.Path)
		case isoScriptExt[ext]:
			scripts = append(scripts, e.Path)
		}
	}
	if len(autorun) > 0 {
		fileFinding(b, "iso-autorun", "Disk image contains autorun.inf at its root", "medium", "T1091", fileJoinCap(autorun, 3), 20)
	}
	if len(execs) > 0 {
		fileFinding(b, "iso-executable", "Disk image contains executables or libraries", "medium", "T1204.002", fileJoinCap(execs, 5), 15)
	}
	if len(lnks) > 0 {
		fileFinding(b, "iso-shortcut", "Disk image contains Windows shortcut (.lnk) files", "medium", "T1204.002", fileJoinCap(lnks, 5), 18)
	}
	if len(scripts) > 0 {
		fileFinding(b, "iso-script", "Disk image contains script files", "medium", "T1059", fileJoinCap(scripts, 5), 12)
	}
	if len(lnks) > 0 && (len(execs) > 0 || len(scripts) > 0) {
		fileFinding(b, "iso-lnk-plus-payload", "Image pairs a shortcut with a payload (container used to carry files without mark-of-the-web)", "high", "T1553.005", "", 20)
	}
	if len(entries) == 0 {
		fileFinding(b, "iso-empty", "ISO 9660 image lists no files", "info", "", "", 0)
	}
}

func ucs2BE(p []byte) string {
	u := make([]uint16, 0, len(p)/2)
	for i := 0; i+1 < len(p); i += 2 {
		u = append(u, binary.BigEndian.Uint16(p[i:]))
	}
	return string(utf16.Decode(u))
}

// isoWalk lists the tree under a root directory record (34 bytes). The second
// result names the limit that stopped the walk early, or "".
func isoWalk(ctx context.Context, data []byte, root []byte, ucs bool) ([]isoEntry, string) {
	type dirRef struct {
		lba, size uint32
		path      string
		depth     int
	}
	var out []isoEntry
	limited := ""
	queue := []dirRef{{binary.LittleEndian.Uint32(root[2:]), binary.LittleEndian.Uint32(root[10:]), "", 0}}
	seen := map[uint32]bool{}
	dirs := 0
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d.lba] {
			continue
		}
		seen[d.lba] = true
		if dirs++; dirs > isoMaxDirs {
			return out, "iso-dirs"
		}
		if ctx.Err() != nil {
			return out, "iso-time"
		}
		start := uint64(d.lba) * isoSector
		if d.size > isoMaxDirSize {
			d.size = isoMaxDirSize
			limited = "iso-dir-size"
		}
		if start >= uint64(len(data)) {
			continue
		}
		end := start + uint64(d.size)
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
		blk := data[start:end]
		for p := 0; p < len(blk); {
			l := int(blk[p])
			if l == 0 { // padding to the next sector
				p = (p/isoSector + 1) * isoSector
				continue
			}
			if l < 34 || p+l > len(blk) {
				break
			}
			rec := blk[p : p+l]
			p += l
			nl := int(rec[32])
			if 33+nl > len(rec) {
				continue
			}
			raw := rec[33 : 33+nl]
			if nl == 1 && (raw[0] == 0 || raw[0] == 1) {
				continue
			}
			var name string
			if ucs {
				name = ucs2BE(raw)
			} else {
				name = string(raw)
			}
			if i := strings.LastIndex(name, ";"); i >= 0 {
				name = name[:i]
			}
			name = strings.ToLower(strings.TrimSuffix(name, "."))
			isDir := rec[25]&2 != 0
			e := isoEntry{Path: d.path + "/" + name, Size: binary.LittleEndian.Uint32(rec[10:]), Dir: isDir}
			if len(out) >= isoMaxEntries {
				return out, "iso-entries"
			}
			out = append(out, e)
			if isDir && d.depth < isoMaxDepth {
				queue = append(queue, dirRef{binary.LittleEndian.Uint32(rec[2:]), e.Size, e.Path, d.depth + 1})
			} else if isDir {
				limited = "iso-depth"
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, limited
}
