// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// OneNote (.one) triage for kind file. Parse-only: the file header GUID is
// checked, FileDataStoreObject records (the blobs OneNote uses for "attached"
// files) are carved by their header and footer GUIDs with bounds checks, and
// the carved bytes are only classified (magic bytes, script keywords). Nothing
// is opened, extracted to disk or executed. The revision-store object graph is
// NOT walked, so an attachment is not tied to the page, picture or hyperlink
// that presents it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	oneMaxEmbeds     = 128
	oneMaxEmbedBytes = 8 << 20
	oneMaxTextBytes  = 1 << 20 // per embed, for keyword scans
	oneMaxNames      = 64
	oneUTF16Scan     = 8 << 20
)

var (
	oneFileGUID   = []byte{0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3}
	oneHeaderGUID = []byte{0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC}
	oneFooterGUID = []byte{0x22, 0xA7, 0xFB, 0x71, 0x79, 0x0F, 0x0B, 0x4A, 0xBB, 0x13, 0x89, 0x92, 0x56, 0x42, 0x6B, 0x24}
)

var oneScriptExt = regexp.MustCompile(`(?i)[\w .\-()]{1,80}\.(?:hta|wsf|wsh|vbs|vbe|js|jse|bat|cmd|ps1|exe|scr|com|pif|dll|msi|chm|lnk|jar|cpl|hta)\b`)
var oneURLRe = regexp.MustCompile(`(?i)https?://[a-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{4,200}`)
var oneLure = regexp.MustCompile(`(?i)double[ -]?click|click (?:to|here)|open (?:the )?(?:attachment|document)|view (?:document|file)|protected|enable (?:content|editing)`)
var oneScriptBody = regexp.MustCompile(`(?i)<script|wscript\.shell|activexobject|createobject\s*\(|powershell|invoke-expression|\biex\b|downloadstring|mshta|cmd(?:\.exe)?\s+/c|@echo\s+off|frombase64string|urlmon|xmlhttp|certutil`)

func init() {
	registerFileAnalyzer("file-onenote", func(ctx context.Context, data []byte, b *InspectBuilder) {
		if len(data) >= 16 && bytes.Equal(data[:16], oneFileGUID) {
			analyzeOneNote(ctx, data, b)
		}
	})
}

type oneEmbed struct {
	off, size int
	kind      string
	sha       string
}

// oneClassify names the payload type by magic bytes and keywords.
func oneClassify(p []byte) string {
	switch {
	case len(p) >= 2 && p[0] == 'M' && p[1] == 'Z':
		return "pe"
	case len(p) >= 4 && string(p[:4]) == "\x7fELF":
		return "elf"
	case len(p) >= 8 && string(p[:8]) == "\x4c\x00\x00\x00\x01\x14\x02\x00":
		return "lnk"
	case len(p) >= 4 && string(p[:4]) == "ITSF":
		return "chm"
	case len(p) >= 4 && (string(p[:4]) == "PK\x03\x04"):
		return "zip"
	case len(p) >= 8 && string(p[:8]) == "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
		return "ole2"
	case len(p) >= 4 && string(p[:4]) == "%PDF":
		return "pdf"
	}
	head := p
	if len(head) > oneMaxTextBytes {
		head = head[:oneMaxTextBytes]
	}
	if len(head) > 0 && oneScriptBody.Match(head) {
		return "script"
	}
	return "data"
}

// oneUTF16Strings returns printable UTF-16LE runs of at least minRunes runes.
func oneUTF16Strings(data []byte, minRunes, max int) []string {
	if len(data) > oneUTF16Scan {
		data = data[:oneUTF16Scan]
	}
	var out []string
	for start := 0; start < 2 && len(out) < max; start++ {
		var run []uint16
		flush := func() {
			if len(run) >= minRunes && len(out) < max {
				out = append(out, string(utf16.Decode(run)))
			}
			run = run[:0]
		}
		for i := start; i+1 < len(data); i += 2 {
			c := uint16(data[i]) | uint16(data[i+1])<<8
			if c >= 0x20 && c < 0x7f {
				run = append(run, c)
			} else {
				flush()
			}
		}
		flush()
	}
	return out
}

func analyzeOneNote(ctx context.Context, data []byte, b *InspectBuilder) {
	b.Format("OneNote")
	var embeds []oneEmbed
	off := 0
	for len(embeds) < oneMaxEmbeds {
		if ctx.Err() != nil {
			return
		}
		i := bytes.Index(data[off:], oneHeaderGUID)
		if i < 0 {
			break
		}
		at := off + i
		off = at + 16
		if at+36 > len(data) {
			break
		}
		ln := binary.LittleEndian.Uint64(data[at+16:])
		body := at + 36
		if ln == 0 || ln > uint64(len(data)-body) {
			b.LimitHit("onenote-embed-range")
			continue
		}
		n := int(ln)
		if n > oneMaxEmbedBytes {
			n = oneMaxEmbedBytes
			b.LimitHit("onenote-embed-size")
		}
		p := data[body : body+n]
		sum := sha256.Sum256(p)
		e := oneEmbed{off: at, size: int(ln), kind: oneClassify(p), sha: hex.EncodeToString(sum[:])}
		embeds = append(embeds, e)
		off = body + int(ln)
		b.IOC("sha256", e.sha)
		switch e.kind {
		case "pe", "elf":
			fileFinding(b, "onenote-embedded-executable", "OneNote file embeds an executable", "high", "T1204.002", fmtEmbed(e), 35)
		case "script":
			fileFinding(b, "onenote-embedded-script", "OneNote file embeds a script", "high", "T1059", fmtEmbed(e), 30)
		case "lnk", "chm":
			fileFinding(b, "onenote-embedded-shortcut", "OneNote file embeds a shortcut or compiled help file", "high", "T1204.002", fmtEmbed(e), 28)
		case "zip", "ole2":
			fileFinding(b, "onenote-embedded-container", "OneNote file embeds an archive or Office container", "low", "T1027", fmtEmbed(e), 8)
		}
		if e.kind == "script" {
			q := p
			if len(q) > oneMaxTextBytes {
				q = q[:oneMaxTextBytes]
			}
			for _, u := range oneURLRe.FindAll(q, 20) {
				b.IOC("url", string(u))
			}
		}
	}
	if len(embeds) >= oneMaxEmbeds {
		b.LimitHit("onenote-embeds")
	}

	// Names, lures and URLs live in UTF-16 text records (and sometimes ASCII).
	u16 := oneUTF16Strings(data, 4, 4000)
	asc := fileASCIIRuns(data, 6, 4000)
	all := append(append([]string{}, u16...), asc...)
	var names []string
	seen := map[string]bool{}
	launcher, lure := "", ""
	urls := 0
	for _, s := range all {
		for _, m := range oneScriptExt.FindAllString(s, 3) {
			m = strings.TrimSpace(m)
			if !seen[m] && len(names) < oneMaxNames {
				seen[m] = true
				names = append(names, m)
			}
		}
		if lure == "" {
			if m := oneLure.FindString(s); m != "" {
				lure = m
			}
		}
		for _, u := range oneURLRe.FindAllString(s, 3) {
			if urls < 40 {
				b.IOC("url", u)
				urls++
			}
		}
	}
	for _, n := range names {
		ext := strings.ToLower(n[strings.LastIndexByte(n, '.')+1:])
		switch ext {
		case "hta", "wsf", "wsh", "vbs", "vbe", "js", "jse", "bat", "cmd", "ps1", "exe", "scr", "com", "pif", "msi", "chm", "lnk", "cpl", "jar", "dll":
			if launcher == "" {
				launcher = n
			}
		}
	}
	if launcher != "" && len(embeds) > 0 {
		fileFinding(b, "onenote-launcher-name", "Embedded file is named like a launcher (script/executable extension)", "high", "T1204.002", launcher, 22)
	}
	if lure != "" && len(embeds) > 0 {
		fileFinding(b, "onenote-lure-text", "Page text resembles a click-to-open lure next to an embedded file", "medium", "T1204.002", lure, 10)
	}
	if len(embeds) > 3 {
		fileFinding(b, "onenote-many-embeds", "Unusually many embedded files", "low", "T1027", strconv.Itoa(len(embeds))+" embedded file records", 6)
	}
	meta := map[string]any{"embeds": len(embeds), "names": names}
	var list []map[string]any
	for i, e := range embeds {
		if i >= 40 {
			break
		}
		list = append(list, map[string]any{"offset": e.off, "size": e.size, "kind": e.kind, "sha256": e.sha})
	}
	meta["embedded"] = list
	b.Meta("onenote", meta)
	if len(embeds) == 0 {
		fileFinding(b, "onenote-no-embeds", "OneNote file with no carved embedded files", "info", "", "no FileDataStoreObject records found (the revision store is not walked)", 0)
	}
}

func fmtEmbed(e oneEmbed) string {
	return e.kind + " " + strconv.Itoa(e.size) + " bytes at offset " + strconv.Itoa(e.off) + " sha256 " + e.sha
}

// fileASCIIRuns returns printable ASCII runs of at least minLen bytes.
func fileASCIIRuns(data []byte, minLen, max int) []string {
	if len(data) > oneUTF16Scan {
		data = data[:oneUTF16Scan]
	}
	var out []string
	st := -1
	for i := 0; i <= len(data) && len(out) < max; i++ {
		if i < len(data) && data[i] >= 0x20 && data[i] < 0x7f {
			if st < 0 {
				st = i
			}
			continue
		}
		if st >= 0 && i-st >= minLen {
			s := data[st:i]
			if len(s) > 512 {
				s = s[:512]
			}
			out = append(out, string(s))
		}
		st = -1
	}
	return out
}
