// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"compress/zlib"
	"context"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func init() {
	registerFileAnalyzer("file-document", func(ctx context.Context, data []byte, b *InspectBuilder) {
		switch f := detectFileFormat(data); f {
		case "OOXML":
			analyzeOOXML(ctx, data, b)
		case "PDF":
			analyzePDF(ctx, data, b)
		case "OLE2":
			analyzeOLE2(ctx, data, b)
		}
	})
}

const (
	ooxmlEntryReadCap = 2 << 20
	ooxmlTotalRead    = 24 << 20
	ooxmlMaxXMLParts  = 60
)

var (
	reRelationship = regexp.MustCompile(`(?is)<Relationship\b[^>]*>`)
	reAttr         = regexp.MustCompile(`(?is)\b([A-Za-z]+)\s*=\s*"([^"]*)"`)
	reDDEXML       = regexp.MustCompile(`(?i)(?:instr\s*=\s*"|<w:instrText[^>]*>|<w:instrText>)\s*DDE(?:AUTO)?\b[^<"]{0,200}`)
)

func analyzeOOXML(ctx context.Context, data []byte, b *InspectBuilder) {
	zr, refused, _ := zipSafeReader(data)
	if zr == nil {
		if refused {
			b.LimitHit("zip-entry-count")
		}
		fileFinding(b, "file-ooxml-malformed", "OOXML container does not parse as a zip", "low", "T1027", "", 5)
		return
	}
	var (
		vba, embedded, activeX []string
		ctMacro                bool
		relExternal            []string
		templates              []string
		uncShares              []string
		ddeHits                []string
		read                   int64
		xmlParts               int
	)
	readEntry := func(f interface {
		Open() (io.ReadCloser, error)
	}) []byte {
		if read >= ooxmlTotalRead {
			b.LimitHit("ooxml-read-budget")
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		defer rc.Close()
		out, _ := io.ReadAll(io.LimitReader(rc, ooxmlEntryReadCap))
		read += int64(len(out))
		return out
	}
	for i, f := range zr.File {
		if i >= fileMaxZipEntries {
			b.LimitHit("ooxml-entries")
			break
		}
		if fileCtxDone(ctx) {
			return
		}
		ln := strings.ToLower(f.Name)
		switch {
		case strings.HasSuffix(ln, "vbaproject.bin"):
			vba = append(vba, f.Name)
		case strings.Contains(ln, "/embeddings/"):
			embedded = append(embedded, f.Name)
		case strings.Contains(ln, "/activex/"):
			activeX = append(activeX, f.Name)
		}
		switch {
		case ln == "[content_types].xml":
			if bytes.Contains(bytes.ToLower(readEntry(f)), []byte("macroenabled")) {
				ctMacro = true
			}
		case strings.HasSuffix(ln, ".rels"):
			for _, rel := range reRelationship.FindAll(readEntry(f), 400) {
				attrs := map[string]string{}
				for _, m := range reAttr.FindAllSubmatch(rel, -1) {
					attrs[strings.ToLower(string(m[1]))] = xmlUnescape(string(m[2]))
				}
				if !strings.EqualFold(attrs["targetmode"], "external") {
					continue
				}
				tgt, typ := attrs["target"], strings.ToLower(attrs["type"])
				if tgt == "" {
					continue
				}
				if u, err := url.Parse(tgt); err == nil && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "ftp") {
					b.IOC("url", tgt)
				}
				isLink := strings.HasSuffix(typ, "/hyperlink")
				if strings.HasPrefix(tgt, `\\`) || strings.HasPrefix(strings.ToLower(tgt), "file:") {
					uncShares = append(uncShares, tgt)
				}
				switch {
				case strings.HasSuffix(typ, "/attachedtemplate"):
					templates = append(templates, tgt)
				case !isLink:
					relExternal = append(relExternal, shortType(typ)+"->"+tgt)
				}
			}
		case xmlParts < ooxmlMaxXMLParts && strings.HasSuffix(ln, ".xml") && (strings.HasPrefix(ln, "word/") || strings.HasPrefix(ln, "xl/") || strings.HasPrefix(ln, "ppt/")) && f.UncompressedSize64 < 64<<20:
			xmlParts++
			body := readEntry(f)
			if bytes.Contains(body, []byte("DDEAUTO")) || reDDEXML.Match(body) || bytes.Contains(body, []byte("<ddeLink")) || bytes.Contains(body, []byte("ddeService=")) {
				ddeHits = append(ddeHits, f.Name)
			}
		}
	}
	b.Meta("ooxml.parts_scanned", xmlParts)
	if len(vba) > 0 || ctMacro {
		ev := fileJoinCap(vba, 3)
		if ctMacro {
			ev += " (macro-enabled content type)"
		}
		fileFinding(b, "file-ooxml-macro", "Document carries a VBA macro project", "medium", "T1137.001", ev, 20)
	}
	if len(templates) > 0 {
		fileFinding(b, "file-ooxml-template-injection", "Document loads an external attached template (remote template injection)", "high", "T1221", fileJoinCap(templates, 3), 30)
	}
	if len(relExternal) > 0 {
		fileFinding(b, "file-ooxml-external-rel", "Document has external relationship targets (OLE, frame, linked content)", "medium", "T1221", fileJoinCap(relExternal, 4), 10)
	}
	if len(uncShares) > 0 {
		fileFinding(b, "file-ooxml-unc-target", "Relationship points at a UNC or file: target (credential-leak pattern)", "medium", "T1187", fileJoinCap(uncShares, 3), 14)
	}
	if len(ddeHits) > 0 {
		fileFinding(b, "file-ooxml-dde", "Document contains DDE fields", "high", "T1559.002", fileJoinCap(ddeHits, 3), 25)
	}
	if len(embedded) > 0 {
		fileFinding(b, "file-ooxml-embedded", "Document embeds OLE objects or packages", "medium", "T1204.002", fileJoinCap(embedded, 4), 10)
	}
	if len(activeX) > 0 {
		fileFinding(b, "file-ooxml-activex", "Document contains ActiveX controls", "medium", "T1204.002", fileJoinCap(activeX, 3), 10)
	}
}

func shortType(t string) string {
	if i := strings.LastIndex(t, "/"); i >= 0 {
		return t[i+1:]
	}
	return t
}

func xmlUnescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'").Replace(s)
}

// ---- PDF ----

var (
	rePDFName = regexp.MustCompile(`/[A-Za-z0-9#_.\-]{1,40}`)
	rePDFURI  = regexp.MustCompile(`/URI\s*\(([^)\x00]{1,500})\)`)
)

type pdfTokenRule struct {
	name, title, tech, sev string
	weight                 int
}

var pdfRules = []pdfTokenRule{
	{"JavaScript", "PDF contains JavaScript (/JavaScript)", "T1059.007", "medium", 15},
	{"JS", "PDF contains JavaScript (/JS)", "T1059.007", "medium", 15},
	{"OpenAction", "PDF runs an action on open (/OpenAction)", "T1204.002", "low", 5},
	{"AA", "PDF has additional-actions (/AA)", "T1204.002", "low", 5},
	{"Launch", "PDF can launch an external program (/Launch)", "T1204.002", "high", 25},
	{"EmbeddedFile", "PDF embeds a file (/EmbeddedFile)", "T1027.009", "medium", 10},
	{"RichMedia", "PDF has rich-media content (/RichMedia)", "T1204.002", "low", 8},
	{"XFA", "PDF has XFA forms (/XFA)", "T1204.002", "low", 6},
	{"SubmitForm", "PDF can submit form data (/SubmitForm)", "T1041", "low", 5},
	{"GoToR", "PDF jumps to a remote document (/GoToR)", "T1187", "low", 8},
}

func pdfUnhex(tok string) (string, bool) {
	if !strings.Contains(tok, "#") {
		return tok, false
	}
	var sb strings.Builder
	for i := 0; i < len(tok); i++ {
		if tok[i] == '#' && i+3 <= len(tok) {
			if v, err := strconv.ParseUint(tok[i+1:i+3], 16, 8); err == nil {
				sb.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		sb.WriteByte(tok[i])
	}
	return sb.String(), true
}

// pdfScan counts name tokens and URIs in buf.
func pdfScan(buf []byte, counts map[string]int, obf map[string]bool, uris map[string]bool) {
	for _, m := range rePDFName.FindAll(buf, 100000) {
		name, hex := pdfUnhex(string(m[1:]))
		counts[name]++
		if hex {
			obf[name] = true
		}
	}
	for _, m := range rePDFURI.FindAllSubmatch(buf, 500) {
		uris[string(m[1])] = true
	}
}

func analyzePDF(ctx context.Context, data []byte, b *InspectBuilder) {
	counts := map[string]int{}
	obf := map[string]bool{}
	uris := map[string]bool{}
	pdfScan(data, counts, obf, uris)

	// Inflate Flate streams (bounded) so tokens inside object streams show up.
	var inflated int64
	const perStream, total = 1 << 20, 16 << 20
	pos, streams := 0, 0
	for streams < 4000 && inflated < total {
		if fileCtxDone(ctx) {
			return
		}
		i := bytes.Index(data[pos:], []byte("stream"))
		if i < 0 {
			break
		}
		start := pos + i + len("stream")
		pos = start
		if start >= 9 && string(data[start-9:start]) == "endstream" {
			continue
		}
		if start < len(data) && data[start] == '\r' {
			start++
		}
		if start < len(data) && data[start] == '\n' {
			start++
		}
		end := bytes.Index(data[start:], []byte("endstream"))
		if end < 0 {
			end = len(data) - start
		}
		seg := data[start : start+end]
		pos = start + end
		streams++
		if len(seg) < 3 || seg[0]&0x0f != 8 || (int(seg[0])<<8|int(seg[1]))%31 != 0 {
			continue
		}
		zr, err := zlib.NewReader(bytes.NewReader(seg))
		if err != nil {
			continue
		}
		out, _ := io.ReadAll(io.LimitReader(zr, perStream))
		zr.Close()
		inflated += int64(len(out))
		pdfScan(out, counts, obf, uris)
	}
	if inflated >= total {
		b.LimitHit("pdf-inflate")
	}
	b.Meta("pdf.streams_seen", streams)
	b.Meta("pdf.inflated_bytes", inflated)

	have := map[string]bool{}
	for _, r := range pdfRules {
		if counts[r.name] > 0 {
			have[r.name] = true
			fileFinding(b, "file-pdf-"+strings.ToLower(r.name), r.title, r.sev, r.tech, "occurrences: "+strconv.Itoa(counts[r.name]), r.weight)
		}
	}
	if (have["OpenAction"] || have["AA"]) && (have["JS"] || have["JavaScript"]) {
		fileFinding(b, "file-pdf-autorun-js", "PDF combines automatic actions with JavaScript", "high", "T1059.007", "", 22)
	}
	if have["Launch"] && (have["OpenAction"] || have["AA"]) {
		fileFinding(b, "file-pdf-autorun-launch", "PDF combines automatic actions with /Launch", "high", "T1204.002", "", 20)
	}
	var obfNames []string
	for n := range obf {
		for _, r := range pdfRules {
			if n == r.name {
				obfNames = append(obfNames, n)
			}
		}
	}
	if len(obfNames) > 0 {
		sort.Strings(obfNames)
		fileFinding(b, "file-pdf-name-obfuscation", "Risky PDF keywords written with #-escapes to dodge scanners", "high", "T1027", strings.Join(obfNames, ","), 14)
	}
	if counts["Encrypt"] > 0 {
		fileFinding(b, "file-pdf-encrypted", "PDF is encrypted; some content could not be inspected", "info", "T1027.013", "", 3)
	}
	if counts["ObjStm"] > 0 {
		b.Meta("pdf.object_streams", counts["ObjStm"])
	}
	n := 0
	for u := range uris {
		if n >= 100 {
			b.LimitHit("pdf-uris")
			break
		}
		n++
		lu := strings.ToLower(u)
		if strings.HasPrefix(lu, "http://") || strings.HasPrefix(lu, "https://") || strings.HasPrefix(lu, "ftp://") {
			b.IOC("url", u)
		}
	}
	b.Meta("pdf.uri_count", len(uris))
}

// ---- OLE2 (legacy Office) ----

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

func analyzeOLE2(ctx context.Context, data []byte, b *InspectBuilder) {
	has := func(s string) bool { return bytes.Contains(data, utf16le(s)) || bytes.Contains(data, []byte(s)) }
	kind := ""
	switch {
	case has("WordDocument"):
		kind = "Word"
	case has("Workbook") || has("Book"):
		kind = "Excel"
	case has("PowerPoint Document"):
		kind = "PowerPoint"
	}
	if kind != "" {
		b.Meta("ole2.app", kind)
	}
	if fileCtxDone(ctx) {
		return
	}
	if has("_VBA_PROJECT") || has("VBA") && has("Macros") {
		fileFinding(b, "file-ole-macro", "Legacy Office file carries a VBA macro project", "medium", "T1137.001", "VBA storage present", 20)
	}
	if has("\x01Ole10Native") || has("ObjectPool") {
		fileFinding(b, "file-ole-embedded", "Legacy Office file embeds OLE objects or packages", "medium", "T1204.002", "", 10)
	}
	if bytes.Contains(data, []byte("DDEAUTO")) || bytes.Contains(data, utf16le("DDEAUTO")) {
		fileFinding(b, "file-ole-dde", "Legacy Office file contains DDE fields", "high", "T1559.002", "", 22)
	}
	if has("EncryptedPackage") {
		fileFinding(b, "file-ole-encrypted", "Office file is password-protected (OOXML inside an OLE wrapper)", "low", "T1027.013", "", 4)
	}
}
