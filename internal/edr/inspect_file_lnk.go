// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// Windows shortcut (.lnk, MS-SHLLINK) analyzer for kind file. Parse-only: the
// header, LinkInfo and StringData are read with bounds checks; the shortcut is
// never resolved, opened or followed. Target IDLists (shell item trees) are not
// decoded; the target comes from LinkInfo's local base path or, failing that,
// from the RelativePath string.

import (
	"context"
	"encoding/binary"
	"regexp"
	"strings"
	"unicode/utf16"
)

const (
	lnkHeaderSize   = 0x4c
	lnkMaxString    = 1 << 15 // characters read per StringData field
	lnkLongArgs     = 1024
	lnkTrailingFlag = 4096
)

func init() {
	registerFileAnalyzer("file-lnk", func(ctx context.Context, data []byte, b *InspectBuilder) {
		if detectFileFormat(data) == "LNK" {
			analyzeLNK(ctx, data, b)
		}
	})
}

// lnkInfo is the decoded subset of a shortcut.
type lnkInfo struct {
	Flags      uint32
	ShowCmd    uint32
	IconIndex  int32
	Target     string
	Name       string
	RelPath    string
	WorkingDir string
	Args       string
	IconLoc    string
	End        int // offset just after the last parsed structure
}

var lnkLOLBins = map[string]string{
	"cmd.exe": "T1059.003", "powershell.exe": "T1059.001", "pwsh.exe": "T1059.001", "mshta.exe": "T1218.005",
	"wscript.exe": "T1059.005", "cscript.exe": "T1059.005", "rundll32.exe": "T1218.011", "regsvr32.exe": "T1218.010",
	"certutil.exe": "T1105", "bitsadmin.exe": "T1197", "msiexec.exe": "T1218.007", "forfiles.exe": "T1202",
	"msbuild.exe": "T1127.001", "installutil.exe": "T1218.004", "curl.exe": "T1105", "wmic.exe": "T1047", "conhost.exe": "T1202",
}

var lnkArgPatterns = []struct {
	id, title string
	re        *regexp.Regexp
	weight    int
}{
	{"lnk-args-encoded", "Shortcut arguments carry an encoded PowerShell command", regexp.MustCompile(`(?i)(?:^|\s)-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}`), 22},
	{"lnk-args-download", "Shortcut arguments download or fetch remote content", regexp.MustCompile(`(?i)https?://|downloadstring|downloadfile|invoke-webrequest|\biwr\b|urlcache|/transfer\b|bitstransfer`), 22},
	{"lnk-args-hidden", "Shortcut arguments hide the window or bypass policy", regexp.MustCompile(`(?i)-w(?:indowstyle)?\s+hidden|-nop\b|-noprofile|-ep\s+bypass|-executionpolicy\s+bypass`), 12},
	{"lnk-args-iex", "Shortcut arguments evaluate dynamic content (IEX/Invoke-Expression)", regexp.MustCompile(`(?i)\biex\b|invoke-expression|frombase64string`), 18},
	{"lnk-args-script-host", "Shortcut arguments launch a script or scriptlet", regexp.MustCompile(`(?i)\.(?:vbs|vbe|js|jse|wsf|hta|sct)\b|scrobj\.dll|javascript:|vbscript:`), 16},
	{"lnk-args-cmd-chain", "Shortcut runs a command chain through cmd /c", regexp.MustCompile(`(?i)/c\s+.*(?:&&|\|\||&|\|)`), 8},
}

// parseLNK decodes the header, LinkInfo and StringData. ok is false when the
// data is too short for even the header.
func parseLNK(data []byte) (li lnkInfo, ok bool) {
	if len(data) < lnkHeaderSize || binary.LittleEndian.Uint32(data) != lnkHeaderSize {
		return li, false
	}
	li.Flags = binary.LittleEndian.Uint32(data[0x14:])
	li.IconIndex = int32(binary.LittleEndian.Uint32(data[0x38:]))
	li.ShowCmd = binary.LittleEndian.Uint32(data[0x3c:])
	off := lnkHeaderSize
	if li.Flags&1 != 0 { // HasLinkTargetIDList
		if off+2 > len(data) {
			li.End = off
			return li, true
		}
		off += 2 + int(binary.LittleEndian.Uint16(data[off:]))
	}
	if li.Flags&2 != 0 { // HasLinkInfo
		if off+4 > len(data) {
			li.End = len(data)
			return li, true
		}
		size := int(binary.LittleEndian.Uint32(data[off:]))
		if size >= 28 && off+size <= len(data) {
			info := data[off : off+size]
			hdr := int(binary.LittleEndian.Uint32(info[4:]))
			flags := binary.LittleEndian.Uint32(info[8:])
			if flags&1 != 0 { // VolumeIDAndLocalBasePath
				if o := int(binary.LittleEndian.Uint32(info[16:])); o > 0 && o < len(info) {
					li.Target = cString(info[o:])
				}
				if sfx := int(binary.LittleEndian.Uint32(info[24:])); sfx > 0 && sfx < len(info) && hdr >= 28 {
					if s := cString(info[sfx:]); s != "" && li.Target != "" {
						li.Target += s
					}
				}
			} else if flags&2 != 0 { // CommonNetworkRelativeLinkAndPathSuffix
				if o := int(binary.LittleEndian.Uint32(info[20:])); o > 0 && o+24 <= len(info) {
					if n := int(binary.LittleEndian.Uint32(info[o+8:])); n > 0 && o+n < len(info) {
						li.Target = cString(info[o+n:])
					}
				}
			}
		}
		if size < 4 || off+size > len(data) {
			li.End = len(data)
			return li, true
		}
		off += size
	}
	uni := li.Flags&0x80 != 0
	read := func() (string, bool) {
		if off+2 > len(data) {
			return "", false
		}
		n := int(binary.LittleEndian.Uint16(data[off:]))
		off += 2
		if n > lnkMaxString {
			n = lnkMaxString
		}
		if uni {
			if off+2*n > len(data) {
				n = (len(data) - off) / 2
			}
			u := make([]uint16, n)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(data[off+2*i:])
			}
			off += 2 * n
			return string(utf16.Decode(u)), true
		}
		if off+n > len(data) {
			n = len(data) - off
		}
		s := string(data[off : off+n])
		off += n
		return s, true
	}
	fields := []struct {
		bit uint32
		dst *string
	}{{4, &li.Name}, {8, &li.RelPath}, {0x10, &li.WorkingDir}, {0x20, &li.Args}, {0x40, &li.IconLoc}}
	for _, f := range fields {
		if li.Flags&f.bit == 0 {
			continue
		}
		s, ok2 := read()
		if !ok2 {
			break
		}
		*f.dst = s
	}
	li.End = off
	return li, true
}

func cString(p []byte) string {
	for i, c := range p {
		if c == 0 {
			return string(p[:i])
		}
	}
	return string(p)
}

func lnkBase(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	return p[strings.LastIndex(p, "/")+1:]
}

func analyzeLNK(ctx context.Context, data []byte, b *InspectBuilder) {
	li, ok := parseLNK(data)
	if !ok {
		fileFinding(b, "lnk-malformed", "Shortcut header is truncated or invalid", "low", "T1027", "", 5)
		return
	}
	if ctx.Err() != nil {
		return
	}
	target := li.Target
	if target == "" {
		target = li.RelPath
	}
	b.Meta("lnk", map[string]any{
		"target": truncInspect(target), "relative_path": truncInspect(li.RelPath), "arguments": truncInspect(li.Args),
		"icon_location": truncInspect(li.IconLoc), "working_dir": truncInspect(li.WorkingDir), "name": truncInspect(li.Name),
		"show_command": li.ShowCmd, "arguments_length": len(li.Args),
	})
	// Arguments are what makes shortcut abuse; surface them for the analyst.
	if li.Args != "" {
		fileFinding(b, "lnk-arguments", "Shortcut passes command-line arguments", "info", "T1204.002", li.Args, 0)
		for _, m := range deobURLRe.FindAllString(li.Args, 20) {
			b.IOC("url", strings.TrimRight(m, ".,;:\"'"))
		}
	}
	if strings.HasPrefix(target, `\\`) {
		b.IOC("path", target)
		fileFinding(b, "lnk-unc-target", "Shortcut target is a UNC/network path (credential-leak or remote-payload pattern)", "medium", "T1187", target, 14)
	}
	base := lnkBase(target)
	tech, isBin := lnkLOLBins[base]
	if isBin {
		fileFinding(b, "lnk-lolbin-target", "Shortcut launches a living-off-the-land binary: "+base, "medium", tech, target+" "+li.Args, 14)
	}
	if li.Args != "" {
		seen := 0
		for _, p := range lnkArgPatterns {
			if loc := p.re.FindStringIndex(li.Args); loc != nil {
				w := p.weight
				if !isBin && w > 8 {
					w = w * 2 / 3
				}
				fileFinding(b, p.id, p.title, "high", tech, li.Args[loc[0]:loc[1]], w)
				seen++
			}
		}
		_ = seen
	}
	if len(li.Args) > lnkLongArgs || strings.HasPrefix(li.Args, strings.Repeat(" ", 64)) {
		fileFinding(b, "lnk-long-args", "Shortcut arguments are very long or padded with leading whitespace (hides the payload in the properties dialog)", "medium", "T1027.010", "", 12)
	}
	if li.ShowCmd == 7 || li.ShowCmd == 2 {
		fileFinding(b, "lnk-minimised", "Shortcut starts its target minimised", "low", "T1564.003", "", 4)
	}
	if li.IconLoc != "" && isBin {
		il := lnkBase(li.IconLoc)
		for _, docExt := range []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"} {
			if strings.HasSuffix(il, docExt) {
				fileFinding(b, "lnk-icon-mismatch", "Shortcut icon imitates a document while the target is a script host or shell", "medium", "T1036.008", li.IconLoc, 12)
				break
			}
		}
	}
	if len(data)-li.End > lnkTrailingFlag {
		fileFinding(b, "lnk-appended-data", "Large data block follows the shortcut structures (appended payload)", "medium", "T1027.009",
			"", 12)
	}
}
