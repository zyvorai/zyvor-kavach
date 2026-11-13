// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Hard benign templates: ordinary code that superficially resembles
// obfuscation (encoded config blobs, installers that pipe to a shell,
// minified code, escape sequences, format strings). They enter training and
// evaluation as benign "hard-benign" samples; the separate hand-written set in
// inspect_obf_train_test.go stays held out.

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func (g *obfGen) randB64(n int) string {
	b := make([]byte, n)
	g.r.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func obfMinify(src string) string {
	var parts []string
	for _, l := range strings.Split(src, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			parts = append(parts, l)
		}
	}
	s := strings.Join(parts, "")
	for _, p := range []string{" = ", " + ", " => ", ", ", " === ", " !== ", ": ", " { ", " } ", " && ", " || "} {
		s = strings.ReplaceAll(s, p, strings.TrimSpace(p))
	}
	s = strings.ReplaceAll(s, "const ", "var ")
	return strings.ReplaceAll(s, "let ", "var ")
}

func (g *obfGen) hardBenign(lang string) (string, bool) {
	switch lang {
	case obfLangPS:
		switch g.n(0, 4) {
		case 0:
			return fmt.Sprintf("$%s = \"%s\"\n$bytes = [Convert]::FromBase64String($%s)\n[IO.File]::WriteAllBytes(\"%s\\%s.pfx\", $bytes)", g.camel(), g.randB64(g.n(200, 700)), g.camel(), g.winPath(), g.word()), false
		case 1:
			return fmt.Sprintf("Write-Host (\"{0,-18} {1,8} {2:N1}%% {3}\" -f $name, $count, $pct, $path)\n$line = '{0}|{1}|{2}|{3}' -f $a, $b, $c, $d\n$msg = \"[{0:yyyy-MM-dd}] {1}: {2}\" -f (Get-Date), '%s', $text", g.word()), false
		case 2:
			// Deliberately NOT a legitimate -EncodedCommand: that form is
			// byte-identical to the "encoding" obfuscation class, so labelling it
			// benign would make the task contradictory (see the evaluation notes).
			return fmt.Sprintf("Get-ChildItem %s -Recurse | ForEach-Object { '{0}\\t{1}\\t{2:yyyy-MM-dd}' -f $_.Name, $_.Length, $_.LastWriteTime } | Out-File %s\\%s.tsv", g.winPath(), g.winPath(), g.word()), false
		case 3:
			return fmt.Sprintf("Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://%s/%s/install.ps1'))", g.host(), g.word()), true
		default:
			return "$names = @('alpha','beta','gamma')\n$joined = $names -join ', '\n$parts = $joined -split ', '\n$title = ('{0}-{1}' -f $parts[0], $parts[1]).ToUpper()", false
		}
	case obfLangCmd:
		switch g.n(0, 2) {
		case 0:
			return fmt.Sprintf("@echo off\nrobocopy %s %s ^\n  /MIR /R:2 /W:5 ^\n  /LOG:%s\\%s.log ^\n  /XD node_modules .git ^\n  /XF *.tmp *.bak\necho done", g.winPath(), g.winPath(), g.winPath(), g.word()), false
		case 1:
			return fmt.Sprintf("@echo off\nset STAMP=%%date:~-4%%%%date:~4,2%%%%date:~7,2%%_%%time:~0,2%%%%time:~3,2%%\nset NAME=%s_%%STAMP: =0%%\nmove \"%s\\%s.log\" \"%s\\%%NAME%%.log\"", g.word(), g.winPath(), g.word(), g.winPath()), false
		default:
			return fmt.Sprintf("cmd.exe /c \"set PATH=%%PATH%%;%s\\bin && %s --config %s\\%s.ini --verbose\"", g.winPath(), g.word(), g.winPath(), g.word()), true
		}
	case obfLangBash:
		switch g.n(0, 4) {
		case 0:
			return fmt.Sprintf("curl --proto '=https' --tlsv1.2 -sSf https://%s/%s/install.sh | sh -s -- -y", g.host(), g.word()), true
		case 1:
			return fmt.Sprintf("#!/bin/bash\ncat > %s/%s.b64 <<'EOF'\n%s\nEOF\nbase64 -d %s/%s.b64 > %s/%s.key\nchmod 600 %s/%s.key", g.unixPath(), g.word(), g.randB64(g.n(200, 500)), g.unixPath(), g.word(), g.unixPath(), g.word(), g.unixPath(), g.word()), false
		case 2:
			b := make([]byte, 32)
			g.r.Read(b)
			return fmt.Sprintf("EXPECTED=\"%x\"\nACTUAL=$(sha256sum %s/%s.tar.gz | cut -d' ' -f1)\n[ \"$EXPECTED\" = \"$ACTUAL\" ] || { echo mismatch; exit 1; }", b, g.unixPath(), g.word()), false
		case 3:
			return fmt.Sprintf("printf '\\033[1;31m%%s\\033[0m: %%s\\n' \"ERROR\" \"%s failed\"\nprintf '\\033[32m%%s\\033[0m\\n' \"ok\"", g.word()), false
		default:
			return fmt.Sprintf("docker run -d --name %s -p %d:80 -e DATABASE_URL=postgres://app:secret@%s:5432/%s?sslmode=require -v %s/data:/var/lib/%s:ro registry.%s/team/%s:%s", g.word(), g.n(1024, 9999), g.host(), g.word(), g.unixPath(), g.word(), g.host(), g.word(), g.version()), true
		}
	case obfLangJS:
		switch g.n(0, 3) {
		case 0:
			src, _ := g.benignSource(lang)
			return obfMinify(src), false
		case 1:
			return fmt.Sprintf("function letter(i) { return String.fromCharCode(%s + i); }\nconst labels = Array.from({ length: %d }, (_, i) => letter(i));\nconsole.log(labels.join(', '));", g.pick("65", "97"), g.n(5, 26)), false
		case 2:
			return fmt.Sprintf("const emailRe = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;\nconst slug = s => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');\nconst pad = n => ('0' + n).slice(-2);\nconsole.log(slug('%s %s'));", g.word(), g.word()), false
		default:
			return fmt.Sprintf("const %s = '%s';\nconst icon = 'data:image/png;base64,%s';\ndocument.querySelector('.%s').src = icon;", g.camel(), g.word(), g.randB64(g.n(150, 400)), g.word()), false
		}
	case obfLangPy:
		switch g.n(0, 3) {
		case 0:
			return fmt.Sprintf("print(\"\\x1b[31mERROR\\x1b[0m: %s failed on \\x1b[1m%s\\x1b[0m\")\nprint(\"\\x1b[32mOK\\x1b[0m\")", g.word(), g.unixPath()), false
		case 1:
			return fmt.Sprintf("import struct\nheader = b'\\x89PNG\\r\\n\\x1a\\n'\nmagic, length = struct.unpack('>4sI', data[:8])\nif data[:8] != header:\n    raise ValueError('not a %s')", g.word()), false
		case 2:
			return fmt.Sprintf("import base64\nCERT = \"%s\"\nraw = base64.b64decode(CERT)\nwith open(\"%s/%s.der\", \"wb\") as fh:\n    fh.write(raw)", g.randB64(g.n(200, 600)), g.unixPath(), g.word()), false
		default:
			return fmt.Sprintf("import re\npattern = re.compile(r\"^(?P<user>[\\w.+-]+)@(?P<host>[\\w-]+(\\.[\\w-]+)+)$\")\nletters = [chr(ord('a') + i) for i in range(%d)]\nprint(''.join(letters))", g.n(3, 26)), false
		}
	default:
		if g.chance(0.5) {
			return fmt.Sprintf("Sub Write%s()\n    Dim msg As String\n    msg = \"%s\" & Chr(13) & Chr(10) & \"%s\" & Chr(13) & Chr(10) & \"%s\"\n    Debug.Print msg\n    Debug.Print \"Tab\" & Chr(9) & \"%s\"\nEnd Sub", g.pascal(), g.word(), g.word(), g.word(), g.word()), false
		}
		return fmt.Sprintf("Function BuildQuery() As String\n    Dim sql As String\n    sql = \"SELECT %s, %s, %s \" & _\n          \"FROM %s \" & _\n          \"WHERE %s = '\" & Range(\"B2\").Value & \"' \" & _\n          \"ORDER BY %s\"\n    BuildQuery = sql\nEnd Function", g.word(), g.word(), g.word(), g.word(), g.word(), g.word()), false
	}
}
