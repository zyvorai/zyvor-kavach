// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

func init() {
	registerFileAnalyzer("file-archive", analyzeArchive)
}

var (
	archExeExt    = setOf("exe", "dll", "scr", "com", "pif", "cpl", "msi", "sys", "ocx")
	archScriptExt = setOf("bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "sh", "py", "reg")
	archImageExt  = setOf("iso", "img", "vhd", "vhdx", "dmg")
	archLinkExt   = setOf("lnk", "chm", "url", "scf")
	archDocExt    = setOf("pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "csv", "zip")
	reDriveLetter = regexp.MustCompile(`^[A-Za-z]:`)
)

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

type archState struct {
	ctx       context.Context
	b         *InspectBuilder
	budget    int64 // decompressed bytes still allowed across the whole tree
	entries   int
	totalDecl uint64
	maxDepth  int
	traversal []string
	dblExt    []string
	execs     []string
	scripts   []string
	images    []string
	links     []string
	disguised []string
	encrypted []string
	bombs     []string
}

func analyzeArchive(ctx context.Context, data []byte, b *InspectBuilder) {
	st := &archState{ctx: ctx, b: b, budget: fileDecompressTot}
	switch {
	case len(data) >= 4 && (string(data[:4]) == "PK\x03\x04" || string(data[:4]) == "PK\x05\x06"):
		scanZip(st, data, 0, "")
	case len(data) >= 3 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 8:
		scanGzip(st, data, 0, "")
	default:
		return
	}
	st.report()
}

func (st *archState) report() {
	b := st.b
	b.Meta("archive.entries", st.entries)
	b.Meta("archive.declared_uncompressed_bytes", st.totalDecl)
	b.Meta("archive.max_depth", st.maxDepth)
	if len(st.bombs) > 0 {
		fileFinding(b, "file-arch-bomb", "Archive has decompression-bomb characteristics (extreme ratio or size)", "high", "", fileJoinCap(st.bombs, 5), 30)
	}
	if st.maxDepth >= 4 {
		fileFinding(b, "file-arch-deep-nesting", "Archives nested unusually deeply", "medium", "T1027", fmt.Sprintf("depth %d", st.maxDepth), 12)
	}
	if len(st.traversal) > 0 {
		fileFinding(b, "file-arch-traversal", "Entry names use path traversal or absolute paths", "high", "", fileJoinCap(st.traversal, 5), 25)
	}
	if len(st.dblExt) > 0 {
		fileFinding(b, "file-arch-double-extension", "Entry has a document-style extension followed by an executable one", "high", "T1036.007", fileJoinCap(st.dblExt, 5), 25)
	}
	if len(st.disguised) > 0 {
		fileFinding(b, "file-arch-disguised-exec", "Entry content is an executable but its name says otherwise", "high", "T1036.008", fileJoinCap(st.disguised, 5), 14)
	}
	if len(st.execs) > 0 {
		fileFinding(b, "file-arch-executable", "Archive contains executable files", "medium", "T1204.002", fileJoinCap(st.execs, 5), 8)
	}
	if len(st.scripts) > 0 {
		fileFinding(b, "file-arch-script", "Archive contains script or launcher files", "low", "T1059", fileJoinCap(st.scripts, 5), 6)
	}
	if len(st.images) > 0 {
		fileFinding(b, "file-arch-disk-image", "Archive contains a disk image (can bypass mark-of-the-web)", "medium", "T1553.005", fileJoinCap(st.images, 5), 8)
	}
	if len(st.links) > 0 {
		fileFinding(b, "file-arch-shortcut", "Archive contains shortcut or help launcher files", "medium", "T1204.002", fileJoinCap(st.links, 5), 8)
	}
	if len(st.encrypted) > 0 {
		fileFinding(b, "file-arch-encrypted", "Archive has password-protected entries (contents not inspectable)", "low", "T1027.013", fileJoinCap(st.encrypted, 5), 6)
	}
}

func (st *archState) addCapped(dst *[]string, s string) {
	if len(*dst) < 50 {
		*dst = append(*dst, s)
	}
}

func looksTraversal(name string) bool {
	n := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(n, "/") || reDriveLetter.MatchString(n) {
		return true
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

func magicClass(p []byte) string {
	switch {
	case len(p) >= 2 && p[0] == 'M' && p[1] == 'Z':
		return "exe"
	case len(p) >= 4 && string(p[:4]) == "\x7fELF", len(p) >= 4 && isMachoMagic(p[:4]):
		return "exe"
	case len(p) >= 4 && string(p[:4]) == "PK\x03\x04":
		return "zip"
	case len(p) >= 3 && p[0] == 0x1f && p[1] == 0x8b && p[2] == 8:
		return "gzip"
	}
	return ""
}

func classifyName(st *archState, full string) (isExec bool) {
	base := strings.ToLower(path.Base(strings.ReplaceAll(full, "\\", "/")))
	parts := strings.Split(base, ".")
	if len(parts) < 2 {
		return false
	}
	ext := parts[len(parts)-1]
	if len(parts) >= 3 && archDocExt[parts[len(parts)-2]] && (archExeExt[ext] || archScriptExt[ext] || ext == "lnk") {
		st.addCapped(&st.dblExt, full)
	}
	switch {
	case archExeExt[ext]:
		st.addCapped(&st.execs, full)
		return true
	case archScriptExt[ext]:
		st.addCapped(&st.scripts, full)
	case archImageExt[ext]:
		st.addCapped(&st.images, full)
	case archLinkExt[ext]:
		st.addCapped(&st.links, full)
	}
	return false
}

func scanZip(st *archState, data []byte, depth int, prefix string) {
	if depth > st.maxDepth {
		st.maxDepth = depth
	}
	if depth > InspectMaxDepth {
		st.b.LimitHit("archive-depth")
		return
	}
	zr, refused, err := zipSafeReader(data)
	if zr == nil {
		if refused {
			st.b.LimitHit("zip-entry-count")
			st.addCapped(&st.bombs, prefix+"<entry count not bounded>")
		}
		_ = err
		return
	}
	for i, f := range zr.File {
		if i >= fileMaxZipEntries {
			st.b.LimitHit("archive-entries")
			break
		}
		if fileCtxDone(st.ctx) {
			return
		}
		st.entries++
		full := prefix + f.Name
		if looksTraversal(f.Name) {
			st.addCapped(&st.traversal, full)
		}
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		st.totalDecl += f.UncompressedSize64
		enc := f.Flags&1 != 0
		if enc {
			st.addCapped(&st.encrypted, full)
		}
		nameExec := classifyName(st, full)
		if f.UncompressedSize64 >= 1<<20 {
			if f.CompressedSize64 == 0 || f.UncompressedSize64/f.CompressedSize64 >= fileUnzipRatioFlag {
				st.addCapped(&st.bombs, fmt.Sprintf("%s ratio>=%d (%d bytes)", full, fileUnzipRatioFlag, f.UncompressedSize64))
			}
		}
		if enc || i >= fileSniffEntries || f.UncompressedSize64 == 0 || st.budget <= 0 {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var head [16]byte
		n, _ := io.ReadFull(io.LimitReader(rc, 16), head[:])
		cls := magicClass(head[:n])
		st.budget -= int64(n)
		if cls == "exe" && !nameExec {
			if base := strings.ToLower(path.Ext(f.Name)); !archExeExt[strings.TrimPrefix(base, ".")] {
				st.addCapped(&st.disguised, full)
			}
		}
		if cls == "exe" && nameExec {
			// already counted by name
		} else if cls == "exe" {
			st.addCapped(&st.execs, full)
		}
		if (cls == "zip" || cls == "gzip") && depth+1 <= InspectMaxDepth && f.UncompressedSize64 <= fileNestedReadCap {
			lim := int64(fileNestedReadCap)
			if st.budget < lim {
				lim = st.budget
			}
			if lim <= 0 {
				st.b.LimitHit("archive-budget")
				rc.Close()
				continue
			}
			rest, _ := io.ReadAll(io.LimitReader(rc, lim))
			st.budget -= int64(len(rest))
			inner := append(append([]byte(nil), head[:n]...), rest...)
			st.b.Layer(InspectLayer{Depth: depth + 1, Method: "archive:" + cls, Bytes: len(inner), Preview: full})
			if cls == "zip" {
				scanZip(st, inner, depth+1, full+"!")
			} else {
				scanGzip(st, inner, depth+1, full+"!")
			}
		} else if cls == "zip" || cls == "gzip" {
			if depth+1 > InspectMaxDepth {
				st.maxDepth = depth + 1
				st.b.LimitHit("archive-depth")
			} else {
				st.b.LimitHit("archive-nested-size")
			}
		}
		rc.Close()
	}
}

func scanGzip(st *archState, data []byte, depth int, prefix string) {
	if depth > st.maxDepth {
		st.maxDepth = depth
	}
	if depth > InspectMaxDepth {
		st.b.LimitHit("archive-depth")
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return
	}
	defer zr.Close()
	lim := int64(fileNestedReadCap)
	if st.budget < lim {
		lim = st.budget
	}
	if lim <= 0 {
		st.b.LimitHit("archive-budget")
		return
	}
	out, _ := io.ReadAll(io.LimitReader(zr, lim+1))
	capped := int64(len(out)) > lim
	if capped {
		out = out[:lim]
	}
	st.budget -= int64(len(out))
	st.entries++
	st.totalDecl += uint64(len(out))
	if len(data) > 0 && (capped && int64(len(out))/int64(len(data)) >= 50 || len(out) >= 1<<20 && len(out)/len(data) >= fileUnzipRatioFlag) {
		st.addCapped(&st.bombs, fmt.Sprintf("%sgzip ratio>=%d (>=%d bytes out of %d)", prefix, fileUnzipRatioFlag, len(out), len(data)))
	}
	st.b.Layer(InspectLayer{Depth: depth, Method: "gzip", Bytes: len(out), Preview: prefix})
	switch magicClass(out[:min(len(out), 16)]) {
	case "exe":
		st.addCapped(&st.execs, prefix+"<gzip payload>")
	case "zip":
		scanZip(st, out, depth+1, prefix+"<gzip>!")
	case "gzip":
		scanGzip(st, out, depth+1, prefix+"<gzip>!")
	}
}
