// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// VBA macro heuristics for kind file (OOXML vbaProject.bin and legacy OLE2
// Office files). The compressed module source (MS-OVBA) is carved out of the
// bytes by its "Attribute VB_" prologue and decompressed in memory; the text is
// then pattern-matched. Nothing is executed or evaluated. This is not a full
// CFB/VBA parser: modules that the container stores in fragmented sectors or in
// the mini-stream are not carved (reported as vba-no-source when a VBA project
// is present but no source could be recovered), and p-code only files show no
// source at all.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	vbaMaxModules   = 64
	vbaMaxSource    = 1 << 20 // decompressed bytes kept per module
	vbaMaxCarve     = 400     // candidate positions tried
	vbaProjectRead  = 8 << 20
	vbaChrChainMin  = 8
	vbaLongLineMin  = 1000
	vbaConcatMinOps = 40
)

func init() {
	registerFileAnalyzer("file-vba", func(ctx context.Context, data []byte, b *InspectBuilder) {
		switch detectFileFormat(data) {
		case "OOXML":
			analyzeVBAOOXML(ctx, data, b)
		case "OLE2":
			analyzeVBAProject(ctx, data, b)
		}
	})
}

func analyzeVBAOOXML(ctx context.Context, data []byte, b *InspectBuilder) {
	zr, _, _ := zipSafeReader(data)
	if zr == nil {
		return
	}
	read := int64(0)
	for i, f := range zr.File {
		if i >= fileMaxZipEntries || ctx.Err() != nil {
			return
		}
		if !strings.HasSuffix(strings.ToLower(f.Name), "vbaproject.bin") {
			continue
		}
		if read >= vbaProjectRead {
			b.LimitHit("vba-read-budget")
			return
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(rc, vbaProjectRead))
		rc.Close()
		read += int64(len(raw))
		analyzeVBAProject(ctx, raw, b)
	}
}

// ovbaDecompress decodes an MS-OVBA compressed container (signature byte 0x01
// followed by chunks). It is lenient: a malformed chunk ends decoding and what
// was recovered is returned.
func ovbaDecompress(src []byte) []byte {
	if len(src) < 3 || src[0] != 1 {
		return nil
	}
	var out []byte
	p := 1
	for p+2 <= len(src) && len(out) < vbaMaxSource {
		hdr := int(src[p]) | int(src[p+1])<<8
		if hdr&0x7000 != 0x3000 {
			break
		}
		size := hdr&0x0fff + 3
		end := p + size
		if end > len(src) {
			end = len(src)
		}
		chunkStart := len(out)
		q := p + 2
		if hdr&0x8000 == 0 { // raw chunk
			out = append(out, src[q:min(q+4096, end)]...)
			p = end
			continue
		}
		for q < end && len(out) < vbaMaxSource {
			flags := src[q]
			q++
			for bit := 0; bit < 8 && q < end; bit++ {
				if flags&(1<<bit) == 0 {
					out = append(out, src[q])
					q++
					continue
				}
				if q+2 > end {
					q = end
					break
				}
				tok := int(src[q]) | int(src[q+1])<<8
				q += 2
				pos := len(out) - chunkStart
				bits := 4
				for 1<<bits < pos && bits < 12 {
					bits++
				}
				length := tok&(0xffff>>bits) + 3
				off := tok>>(16-bits) + 1
				if off > pos {
					return out
				}
				for i := 0; i < length; i++ {
					out = append(out, out[len(out)-off])
				}
			}
		}
		p = end
	}
	return out
}

// carveVBAModules finds compressed module sources by their prologue.
func carveVBAModules(ctx context.Context, data []byte, b *InspectBuilder) []string {
	var mods []string
	needle := []byte("\x00Attribut")
	from := 0
	tries := 0
	for len(mods) < vbaMaxModules {
		i := bytes.Index(data[from:], needle)
		if i < 0 {
			break
		}
		at := from + i // position of the flag byte
		from = at + 1
		if ctx.Err() != nil {
			break
		}
		if tries++; tries > vbaMaxCarve {
			b.LimitHit("vba-carve-attempts")
			break
		}
		if at < 3 || data[at-3] != 1 || (int(data[at-2])|int(data[at-1])<<8)&0x7000 != 0x3000 {
			continue
		}
		src := ovbaDecompress(data[at-3:])
		if s := string(src); strings.HasPrefix(s, "Attribute VB_") {
			mods = append(mods, s)
			// Skip past what this container covered so it is not carved twice.
			from = min(at+1+len(src)/2, len(data))
		}
	}
	if len(mods) >= vbaMaxModules {
		b.LimitHit("vba-modules")
	}
	return mods
}

var (
	vbaAutoExec = regexp.MustCompile(`(?im)^\s*(?:public\s+|private\s+)?(?:sub|function)\s+(auto_?open|auto_?exec|auto_?close|auto_?new|document_open|document_new|document_close|workbook_open|workbook_activate|workbook_beforeclose|worksheet_activate|worksheet_change|userform_initialize|app_?(?:documentopen))\b`)
	vbaShell    = regexp.MustCompile(`(?i)\bshell\s*\(?\s*["a-z(]|wscript\.shell|\.run\s*\(|\.exec\s*\(|shellexecute|\bcmd(?:\.exe)?\s*/c|powershell|mshta|rundll32|regsvr32`)
	vbaCreate   = regexp.MustCompile(`(?i)createobject\s*\(\s*"([^"]+)"`)
	vbaNetObj   = regexp.MustCompile(`(?i)(?:msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|adodb\.stream|microsoft\.xmlhttp)|urldownloadtofile`)
	vbaDeclare  = regexp.MustCompile(`(?i)\bdeclare\s+(?:ptrsafe\s+)?(?:function|sub)\s+(\w+)\s+lib\s+"([^"]+)"`)
	vbaShellAPI = regexp.MustCompile(`(?i)virtualalloc|rtlmovememory|createthread|writeprocessmemory|createremotethread|ntallocatevirtualmemory`)
	vbaChrCall  = regexp.MustCompile(`(?i)\bchrw?\$?\s*\(`)
	vbaStrRev   = regexp.MustCompile(`(?i)\bstrreverse\s*\(|\bxor\b.*\basc\b|\bmid\$?\(.*\bchr`)
	vbaURLRe    = regexp.MustCompile(`(?i)https?://[^\s"')]+`)
)

func analyzeVBAProject(ctx context.Context, data []byte, b *InspectBuilder) {
	hasVBA := bytes.Contains(data, utf16le("VBA")) || bytes.Contains(data, []byte("_VBA_PROJECT")) || bytes.Contains(data, utf16le("_VBA_PROJECT"))
	mods := carveVBAModules(ctx, data, b)
	// Plaintext fallback: some files carry uncompressed source.
	if len(mods) == 0 && bytes.Contains(data, []byte("Attribute VB_Name")) {
		mods = append(mods, string(data[:min(len(data), vbaMaxSource)]))
	}
	if len(mods) == 0 {
		if hasVBA {
			fileFinding(b, "vba-no-source", "VBA project present but no module source could be recovered (fragmented, mini-stream, p-code only or encrypted)", "info", "T1137.001", "", 0)
		}
		return
	}
	b.Meta("vba.modules_recovered", len(mods))
	var autos, shells, objs, decls, apis, urls []string
	chrCalls, concatOps, longLines := 0, 0, 0
	revOrXor := false
	var joined strings.Builder
	for _, m := range mods {
		for _, x := range vbaAutoExec.FindAllStringSubmatch(m, 10) {
			autos = append(autos, x[1])
		}
		for _, x := range vbaShell.FindAllString(m, 5) {
			shells = append(shells, strings.TrimSpace(x))
		}
		for _, x := range vbaCreate.FindAllStringSubmatch(m, 10) {
			objs = append(objs, x[1])
		}
		for _, x := range vbaNetObj.FindAllString(m, 5) {
			objs = append(objs, x)
		}
		for _, x := range vbaDeclare.FindAllStringSubmatch(m, 10) {
			decls = append(decls, x[1]+"@"+x[2])
		}
		for _, x := range vbaShellAPI.FindAllString(m, 5) {
			apis = append(apis, x)
		}
		for _, u := range vbaURLRe.FindAllString(m, 10) {
			urls = append(urls, strings.TrimRight(u, `".,;`))
			b.IOC("url", strings.TrimRight(u, `".,;`))
		}
		chrCalls += len(vbaChrCall.FindAllStringIndex(m, -1))
		concatOps += strings.Count(m, "&") + strings.Count(m, "\" + \"")
		revOrXor = revOrXor || vbaStrRev.MatchString(m)
		for _, ln := range strings.Split(m, "\n") {
			if len(ln) > vbaLongLineMin {
				longLines++
			}
		}
		if joined.Len() < 1<<20 {
			joined.WriteString(m)
			joined.WriteByte('\n')
		}
	}
	if len(autos) > 0 {
		fileFinding(b, "vba-autoexec", "Macro runs automatically when the document opens or closes", "medium", "T1137.001", fileJoinCap(uniqStrings(autos), 4), 15)
	}
	if len(shells) > 0 || len(objs) > 0 {
		ev := fileJoinCap(uniqStrings(append(shells, objs...)), 5)
		w := 14
		if len(autos) > 0 {
			w = 24
		}
		fileFinding(b, "vba-shell-object", "Macro starts processes or creates scripting/network objects (Shell, WScript.Shell, CreateObject, XMLHTTP)", "high", "T1059.005", ev, w)
	}
	if len(decls) > 0 || len(apis) > 0 {
		sev, w := "medium", 12
		if len(apis) > 1 {
			sev, w = "high", 26
		}
		fileFinding(b, "vba-winapi", "Macro declares Win32 API imports"+map[bool]string{true: " typical of shellcode loaders", false: ""}[len(apis) > 1], sev, "T1620", fileJoinCap(uniqStrings(append(decls, apis...)), 5), w)
	}
	if chrCalls >= vbaChrChainMin || revOrXor || longLines > 0 || concatOps >= vbaConcatMinOps {
		fileFinding(b, "vba-obfuscated-strings", "Macro builds strings from Chr()/concatenation/reversal or has very long lines", "medium", "T1027",
			fmt.Sprintf("chr_calls=%d concat_ops=%d long_lines=%d reverse_or_xor=%v", chrCalls, concatOps, longLines, revOrXor), 14)
	}
	// Feed the shared deobfuscation layer log with whatever the decoders recover.
	scriptDeobLayers(ctx, b, "vba", joined.String())
	if len(urls) > 0 && len(shells)+len(objs) > 0 {
		fileFinding(b, "vba-download-exec", "Macro references a URL and a process/network object (download-and-execute pattern)", "high", "T1105", fileJoinCap(uniqStrings(urls), 2), 20)
	}
}

func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(s)
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}
