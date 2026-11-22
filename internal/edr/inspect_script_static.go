// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// Static script analyzer for kind script: shell, Python, JavaScript/Node (and
// PHP/Perl idioms). Regex idioms only: download-and-exec, reverse shells, eval of
// a decoded blob, persistence writes. The text is never run, and nothing is
// fetched. Base64 literals that feed an eval/decode-and-run idiom are decoded
// in memory and logged as inspector layers (method "script:..."), then the
// decoded text is scanned with the same rules, so a hidden second stage is
// reported with the layer it came from. Language is a guess from the shebang
// and a few keywords; every rule runs on every script. Idiom matching is not
// data-flow analysis: split-up strings, variables and unusual syntax are missed.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const (
	scriptMaxScan   = 2 << 20
	scriptMaxBlobs  = 12
	scriptMaxDepth  = 3
	scriptBlobMax   = 1 << 20
	scriptMaxLayers = 6
)

func init() {
	RegisterAnalyzer("script-static", []string{InspectKindScript}, analyzeScriptStatic)
}

type scriptRule struct {
	id, title, sev, tech string
	weight               int
	re                   *regexp.Regexp
}

func sr(id, title, sev, tech string, w int, re string) scriptRule {
	return scriptRule{id, title, sev, tech, w, regexp.MustCompile(re)}
}

var scriptRules = []scriptRule{
	sr("scr-download-exec", "Downloads remote content and executes it", "high", "T1105", 25,
		`(?i)\b(?:curl|wget|fetch)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da|k|a)?sh\b`+
			`|\b(?:ba|z)?sh\s+-c\s+["']?\$\(\s*(?:curl|wget)`+
			`|\b(?:bash|sh|source|\.)\s+<\(\s*(?:curl|wget)`+
			`|\b(?:curl|wget)\b[^\n]*(?:-o|-O|>)\s*\S+[^\n]*(?:&&|;)\s*chmod\s+\+?[0-9x]+`+
			`|\b(?:exec|eval)\s*\(\s*(?:urllib\.request\.urlopen|requests\.get|urlopen)\s*\([^)]*\)\s*\.(?:read|text|content)`+
			`|os\.system\(\s*["'][^"'\n]*(?:curl|wget)[^"'\n]*\|\s*(?:ba)?sh`+
			`|eval\s*\(\s*(?:await\s+)?(?:fetch|axios\.get|http\.get)`+
			`|child_process[^\n]*(?:curl|wget)[^\n]*\|`+
			`|new\s+Function\(\s*await\s+fetch`),
	sr("scr-reverse-shell", "Reverse shell idiom", "critical", "T1059", 40,
		`(?i)/dev/(?:tcp|udp)/[^/\s"']+/\d+`+
			`|\b(?:nc|ncat|netcat)\b[^\n]*\s-[a-z]*e\s+\S*(?:sh|bash|cmd)`+
			`|mkfifo\s+\S+[^\n]*\b(?:nc|ncat|netcat|telnet)\b`+
			`|\bsocat\b[^\n]*exec:`+
			`|(?s)socket\.socket\(.{0,400}?(?:os\.dup2|pty\.spawn|/bin/(?:ba)?sh)`+
			`|(?s)use\s+Socket.{0,300}?exec\s*\(?\s*["']?/bin/(?:ba)?sh`+
			`|(?s)net\.Socket\(\).{0,300}?(?:spawn|exec)\(\s*["']/bin/(?:ba)?sh`+
			`|fsockopen\([^)]*\)[^\n]*(?:exec|shell_exec|proc_open|passthru)`+
			`|System\.Net\.Sockets\.TCPClient`),
	sr("scr-eval-decoded", "Evaluates a decoded or decompressed blob", "high", "T1027.010", 28,
		`(?i)\b(?:eval|exec)\s*\(\s*(?:base64\.b64decode|b64decode|zlib\.decompress|codecs\.decode|bytes\.fromhex|atob|unescape|Buffer\.from)\b`+
			`|new\s+Function\s*\(\s*atob`+
			`|\beval\s+["']?\$\(\s*echo[^)]*\|\s*(?:base64\s+(?:-d|--decode)|xxd\s+-r)`+
			`|\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b`+
			`|\|\s*xxd\s+-r\s+-p\s*\|\s*(?:ba)?sh`+
			`|\bexec\s*\(\s*compile\s*\(\s*(?:base64|zlib)`+
			`|__import__\(\s*['"]base64['"]\s*\)\s*\.b64decode`+
			`|\beval\s*\(\s*String\.fromCharCode`),
	sr("scr-persist-cron", "Writes a cron entry", "high", "T1053.003", 22,
		`(?im)\bcrontab\s+-\s*$|\(\s*crontab\s+-l[^\n]*\)\s*\|\s*crontab|>>?\s*/(?:etc/cron\.[a-z.]+/|etc/crontab|var/spool/cron)|\|\s*crontab\s+-`),
	sr("scr-persist-systemd", "Writes a systemd unit", "high", "T1543.002", 22,
		`(?i)(?:>>?|\btee\s+(?:-a\s+)?)\s*/(?:etc|usr/lib|lib)/systemd/system/\S+\.(?:service|timer)`),
	sr("scr-persist-shellrc", "Appends to a shell startup file", "medium", "T1546.004", 20,
		`(?i)>>\s*(?:~|\$HOME|/home/\w+|/root)/\.(?:bashrc|bash_profile|profile|zshrc)|>>?\s*/etc/(?:profile(?:\.d/\S+)?|rc\.local|bash\.bashrc)|open\(\s*["'][^"']*(?:\.bashrc|\.profile|rc\.local)["']\s*,\s*["']a`),
	sr("scr-persist-sshkey", "Adds an SSH authorized key", "high", "T1098.004", 25,
		`(?i)>>?\s*\S*\.ssh/authorized_keys|open\(\s*["'][^"']*authorized_keys["']\s*,\s*["']a`),
	sr("scr-persist-preload", "Uses LD_PRELOAD or ld.so.preload for persistence", "high", "T1574.006", 28,
		`(?i)/etc/ld\.so\.preload|LD_PRELOAD=\S+[^\n]*>>`),
	sr("scr-persist-launchd", "Writes or loads a launchd job", "medium", "T1543.001", 20,
		`(?i)(?:LaunchAgents|LaunchDaemons)/[^\s"']+\.plist|launchctl\s+(?:load|bootstrap)\b`),
	sr("scr-persist-wintask", "Creates a scheduled task, Run key or startup item", "medium", "T1053.005", 20,
		`(?i)schtasks(?:\.exe)?\s+/create|\breg(?:\.exe)?\s+add\s+[^\n]*\\CurrentVersion\\Run|\\Start Menu\\Programs\\Startup`),
}

var (
	scriptB64Lit = regexp.MustCompile(`(?i)(?:b64decode|atob|frombase64string)\s*\(\s*(?:b?["'])([A-Za-z0-9+/=_-]{16,})["']|echo\s+["']?([A-Za-z0-9+/=]{16,})["']?\s*\|\s*base64\s+(?:-d|--decode)`)
	scriptDevTCP = regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/([^/\s"']+)/(\d+)`)
)

func scriptLanguage(text string) string {
	head := text
	if len(head) > 4096 {
		head = head[:4096]
	}
	lower := strings.ToLower(head)
	switch {
	case strings.HasPrefix(head, "#!") && strings.Contains(lower[:min(len(lower), 80)], "python"):
		return "python"
	case strings.HasPrefix(head, "#!") && strings.Contains(lower[:min(len(lower), 80)], "node"):
		return "javascript"
	case strings.HasPrefix(head, "#!"):
		return "shell"
	case strings.Contains(head, "import ") && strings.Contains(head, "def "), strings.Contains(head, "__name__"):
		return "python"
	case strings.Contains(head, "require(") || strings.Contains(head, "const ") || strings.Contains(head, "function("), strings.Contains(head, "=>"):
		return "javascript"
	case strings.Contains(head, "<?php"):
		return "php"
	case strings.Contains(head, "echo ") || strings.Contains(head, "fi\n") || strings.Contains(head, "$("):
		return "shell"
	}
	return "unknown"
}

func analyzeScriptStatic(ctx context.Context, in InspectInput, b *InspectBuilder) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("script-static: recovered: %v", r)
		}
	}()
	text := in.Text
	if len(text) > scriptMaxScan {
		text = text[:scriptMaxScan]
		b.LimitHit("script-truncated")
	}
	lang := scriptLanguage(text)
	b.Meta("language", lang)
	if lang != "unknown" {
		b.Format("script/" + lang)
	}
	seen := map[string]bool{}
	blobs, layers := 0, 0
	var scan func(t string, depth int, from string)
	scan = func(t string, depth int, from string) {
		for _, r := range scriptRules {
			if ctx.Err() != nil {
				return
			}
			if seen[r.id] {
				continue
			}
			loc := r.re.FindStringIndex(t)
			if loc == nil {
				continue
			}
			seen[r.id] = true
			ev := t[loc[0]:loc[1]]
			if from != "" {
				ev = from + ": " + ev
			}
			b.Finding(InspectFinding{ID: r.id, Title: r.title, Severity: r.sev, Technique: r.tech, Evidence: previewOf(ev), Weight: r.weight})
		}
		for _, m := range scriptDevTCP.FindAllStringSubmatch(t, 10) {
			b.IOC("domain", m[1]+":"+m[2])
		}
		if depth >= scriptMaxDepth {
			if scriptB64Lit.MatchString(t) {
				b.LimitHit("script-decode-depth")
			}
			return
		}
		for _, m := range scriptB64Lit.FindAllStringSubmatch(t, scriptMaxBlobs+1) {
			if ctx.Err() != nil {
				return
			}
			if blobs >= scriptMaxBlobs {
				b.LimitHit("script-blobs")
				return
			}
			tok := m[1]
			if tok == "" {
				tok = m[2]
			}
			raw, ok := b64Decode(tok)
			if !ok || len(raw) > scriptBlobMax {
				continue
			}
			dec, ok := asText(raw)
			if !ok {
				continue
			}
			blobs++
			if layers < scriptMaxLayers {
				layers++
				b.Layer(InspectLayer{Depth: depth + 1, Method: "script:eval-b64-literal", Bytes: len(raw), Preview: previewOf(dec)})
			}
			deobIOCs(b, dec, map[string]bool{})
			scan(dec, depth+1, fmt.Sprintf("decoded layer %d", depth+1))
		}
	}
	scan(text, 0, "")
	if layers > 0 {
		b.Meta("decoded_blobs", blobs)
	}
	return nil
}

// scriptDeobLayers runs the shared decoder chain over text and records each
// layer in the report's layer log, plus IOCs and download cradles found in the
// decoded text. Used by analyzers that carry script-like content inside another
// format (VBA macros); script and cmdline inputs get this from the
// "deobfuscation" analyzer directly.
func scriptDeobLayers(ctx context.Context, b *InspectBuilder, label, text string) {
	if len(text) < 8 {
		return
	}
	res := deobRun(ctx, text)
	for _, l := range res.Limits {
		b.LimitHit(l)
	}
	seenHosts := map[string]bool{}
	cradleSeen := map[string]bool{}
	for _, l := range res.Layers {
		b.Layer(InspectLayer{Depth: l.Depth, Method: label + ":" + strings.Join(l.Methods, "+"), Bytes: len(l.Text), Preview: previewOf(l.Text)})
		deobIOCs(b, l.Text, seenHosts)
		for _, c := range deobCradles {
			if cradleSeen[c.id] {
				continue
			}
			if loc := c.re.FindStringIndex(l.Text); loc != nil {
				cradleSeen[c.id] = true
				b.Finding(InspectFinding{ID: c.id, Title: c.title + " (in decoded " + label + " text)", Severity: "medium", Technique: c.technique,
					Evidence: previewOf(l.Text[loc[0]:loc[1]]), Weight: c.weight})
			}
		}
	}
}
