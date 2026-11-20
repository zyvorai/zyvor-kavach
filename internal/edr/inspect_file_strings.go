// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"net/netip"
	"regexp"
	"strings"
)

const (
	stringsMinLen    = 6
	stringsMaxCount  = 60000
	stringsMaxTotal  = 4 << 20
	stringsScanBytes = 24 << 20
)

func init() {
	registerFileAnalyzer("file-strings", analyzeStrings)
}

// extractStrings returns printable ASCII and UTF-16LE runs, capped.
func extractStrings(ctx context.Context, data []byte) (out []string, limited bool) {
	if len(data) > stringsScanBytes {
		data = data[:stringsScanBytes]
		limited = true
	}
	total := 0
	add := func(s string) bool {
		if len(out) >= stringsMaxCount || total+len(s) > stringsMaxTotal {
			limited = true
			return false
		}
		if len(s) > 4096 {
			s = s[:4096]
		}
		out = append(out, s)
		total += len(s)
		return true
	}
	printable := func(c byte) bool { return c >= 0x20 && c < 0x7f || c == '\t' }
	// ASCII
	start := -1
	for i := 0; i <= len(data); i++ {
		if i&0xFFFFF == 0 && fileCtxDone(ctx) {
			return out, true
		}
		if i < len(data) && printable(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= stringsMinLen {
			if !add(string(data[start:i])) {
				return out, true
			}
		}
		start = -1
	}
	// UTF-16LE: printable byte followed by 0x00.
	var sb []byte
	flush := func() bool {
		ok := true
		if len(sb) >= stringsMinLen {
			ok = add(string(sb))
		}
		sb = sb[:0]
		return ok
	}
	for i := 0; i+1 < len(data); {
		if i&0xFFFFF == 0 && fileCtxDone(ctx) {
			return out, true
		}
		if printable(data[i]) && data[i+1] == 0 {
			sb = append(sb, data[i])
			i += 2
			continue
		}
		if !flush() {
			return out, true
		}
		i++
	}
	flush()
	return out, limited
}

var (
	refangReps = strings.NewReplacer(
		"hxxps://", "https://", "hxxp://", "http://", "hXXp://", "http://", "hXXps://", "https://", "fxp://", "ftp://",
		"[.]", ".", "(.)", ".", "{.}", ".", "[dot]", ".", "(dot)", ".", " dot ", ".", "[DOT]", ".", "(DOT)", ".",
		"[:]", ":", "[://]", "://", "[at]", "@", "(at)", "@", "[@]", "@", "(@)", "@",
	)
	reURL      = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>\x00-\x1f\\^|{}` + "`" + `]{4,300}`)
	reIPv4     = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	reIPv6     = regexp.MustCompile(`(?i)[0-9a-f:]{2,45}`)
	reDomain   = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,6}[a-z]{2,24}\b`)
	reEmail    = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
	reRegistry = regexp.MustCompile(`(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR)\\[A-Za-z0-9_\\ .{}\-]{4,200}`)
	reRegCut   = regexp.MustCompile(`\s{2,}|\s[A-Za-z]$|\s[A-Za-z]:\\|\s(?:https?|HK[A-Z_]+)\b`)
	reWinPath  = regexp.MustCompile(`(?i)\b[a-z]:\\(?:[^\\/:*?"<>|\r\n\x00]{1,64}\\){0,12}[^\\/:*?"<>|\r\n\x00\s]{1,64}`)
	reBTC      = regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)
	reBech32   = regexp.MustCompile(`\bbc1[ac-hj-np-z02-9]{11,71}\b`)
	reETH      = regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`)
	reXMR      = regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`)
)

// Plausible TLDs: common generic and country codes. Two-letter ccTLDs that are
// also everyday file extensions or language suffixes (sh, py, rs, pl, so, md,
// cc, ps, pm, js) are left out to cut noise from names like main.py or libc.so.
var filePlausibleTLD = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.Fields(`com net org edu gov mil int info biz name pro mobi asia tel xyz top site online store shop app dev io ai co me tv cc ws club live tech cloud link click work fun icu vip cn ru de uk fr jp br in it es nl au ca ch se no fi dk pl cz at be pt gr tr ua ir kr tw hk sg id my th vn mx ar cl za ng ke eg il ae sa pk bd kz ro hu bg rs hr sk si lt lv ee by su eu onion bit zip mov pw tk ml ga cf gq ly gl gd to la fm im is nu st vc xxx cam bid win loc kim men party review stream download racing`) {
		m[t] = true
	}
	return m
}()

// Namespace and schema hosts that appear in nearly every document or binary.
var fileBenignHosts = map[string]bool{
	"schemas.microsoft.com": true, "schemas.openxmlformats.org": true, "www.w3.org": true, "purl.org": true,
	"schemas.xmlsoap.org": true, "www.microsoft.com": true, "microsoft.com": true, "ns.adobe.com": true,
	"www.verisign.com": true, "crl.microsoft.com": true, "www.apple.com": true, "apple.com": true,
	"ocsp.digicert.com": true, "crl.verisign.com": true, "www.digicert.com": true, "go.microsoft.com": true,
	"xmlns.com": true, "www.iana.org": true, "www.openssl.org": true, "golang.org": true, "go.dev": true,
}

func filePlausibleDomain(d string) bool {
	d = strings.ToLower(strings.Trim(d, "."))
	i := strings.LastIndex(d, ".")
	if i < 0 || len(d) > 253 || !filePlausibleTLD[d[i+1:]] {
		return false
	}
	labels := strings.Split(d[:i], ".")
	digitsOnly := true
	for _, l := range labels {
		if strings.Trim(l, "0123456789") != "" {
			digitsOnly = false
		}
	}
	return !digitsOnly && !fileBenignHosts[d]
}

func filePublicIP(a netip.Addr) bool {
	return a.IsValid() && !a.IsPrivate() && !a.IsLoopback() && !a.IsUnspecified() && !a.IsLinkLocalUnicast() &&
		!a.IsMulticast() && !a.IsInterfaceLocalMulticast() && a.IsGlobalUnicast()
}

const fileB58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// fileBase58Check verifies a Bitcoin legacy address checksum (stdlib only).
func fileBase58Check(s string) bool {
	n := new(big.Int)
	for _, c := range s {
		i := strings.IndexRune(fileB58, c)
		if i < 0 {
			return false
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(i)))
	}
	raw := n.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	raw = append(make([]byte, zeros), raw...)
	if len(raw) != 25 {
		return false
	}
	h1 := sha256.Sum256(raw[:21])
	h2 := sha256.Sum256(h1[:])
	return bytes.Equal(h2[:4], raw[21:])
}

// IOCSet is what extractIOCs found, in encounter order.
type fileIOC struct{ Typ, Val string }

// extractIOCs finds indicators in text. refang additionally defangs-reverses
// hxxp, [.], (dot) and friends so defanged reports are not missed.
func extractIOCs(text string, max int) []fileIOC {
	var out []fileIOC
	seen := map[string]bool{}
	add := func(t, v string) {
		if len(out) >= max || v == "" {
			return
		}
		k := t + "\x00" + v
		if !seen[k] {
			seen[k] = true
			out = append(out, fileIOC{t, v})
		}
	}
	texts := []string{text}
	if rf := refangReps.Replace(text); rf != text {
		texts = append(texts, rf)
	}
	for _, tx := range texts {
		for _, u := range reURL.FindAllString(tx, 400) {
			u = strings.TrimRight(u, ".,;:)]'\"")
			add("url", u)
			rest := u[strings.Index(u, "://")+3:]
			host := rest
			if j := strings.IndexAny(host, "/?#"); j >= 0 {
				host = host[:j]
			}
			if j := strings.LastIndex(host, "@"); j >= 0 {
				host = host[j+1:]
			}
			if j := strings.LastIndex(host, ":"); j >= 0 && !strings.Contains(host[j:], "]") {
				host = host[:j]
			}
			if a, err := netip.ParseAddr(host); err == nil {
				if filePublicIP(a) {
					add("ipv4", a.String())
				}
			} else if filePlausibleDomain(host) {
				add("domain", strings.ToLower(host))
			}
		}
		for _, loc := range reIPv4.FindAllStringIndex(tx, 400) {
			// reject version-like neighbours such as 1.2.3.4.5 or 11.2.3.4
			if loc[0] > 0 && (tx[loc[0]-1] == '.' || tx[loc[0]-1] >= '0' && tx[loc[0]-1] <= '9') {
				continue
			}
			if loc[1] < len(tx) && (tx[loc[1]] >= '0' && tx[loc[1]] <= '9' || tx[loc[1]] == '.' && loc[1]+1 < len(tx) && tx[loc[1]+1] >= '0' && tx[loc[1]+1] <= '9') {
				continue
			}
			a, err := netip.ParseAddr(tx[loc[0]:loc[1]])
			if err == nil && a.Is4() && filePublicIP(a) && a.As4()[0] != 0 {
				add("ipv4", a.String())
			}
		}
		for _, m := range reIPv6.FindAllString(tx, 400) {
			if strings.Count(m, ":") < 2 {
				continue
			}
			a, err := netip.ParseAddr(m)
			if err == nil && a.Is6() && !a.Is4In6() && filePublicIP(a) && (strings.Contains(m, "::") || strings.Count(m, ":") >= 5) {
				add("ipv6", a.String())
			}
		}
		for _, m := range reEmail.FindAllString(tx, 200) {
			if d := m[strings.LastIndex(m, "@")+1:]; filePlausibleDomain(d) {
				add("email", strings.ToLower(m))
			}
		}
		for _, d := range reDomain.FindAllString(tx, 1000) {
			if filePlausibleDomain(d) {
				add("domain", strings.ToLower(d))
			}
		}
		for _, m := range reRegistry.FindAllString(tx, 200) {
			if loc := reRegCut.FindStringIndex(m); loc != nil {
				m = m[:loc[0]]
			}
			add("registry", strings.TrimRight(m, " \\."))
		}
		for _, m := range reWinPath.FindAllString(tx, 200) {
			if len(m) > 6 { // skip a bare drive root
				add("path", m)
			}
		}
		for _, m := range reBTC.FindAllString(tx, 100) {
			if fileBase58Check(m) {
				add("wallet", m)
			}
		}
		for _, m := range reBech32.FindAllString(tx, 100) {
			if len(m) >= 14 {
				add("wallet", m)
			}
		}
		for _, m := range reETH.FindAllString(tx, 100) {
			if h := strings.ToLower(m[2:]); strings.Trim(h, "0") != "" && strings.Trim(h, "f") != "" {
				add("wallet", m)
			}
		}
		for _, m := range reXMR.FindAllString(tx, 100) {
			add("wallet", m)
		}
	}
	return out
}

var suspiciousStrings = []struct {
	needle, id, title, tech, sev string
	weight                       int
}{
	{"sekurlsa::", "file-str-mimikatz", "Credential-dumping tool strings (mimikatz-style)", "T1003.001", "high", 18},
	{"mimikatz", "file-str-mimikatz-name", "References mimikatz", "T1003.001", "medium", 10},
	{"vssadmin delete shadows", "file-str-shadow-delete", "Shadow-copy deletion command", "T1490", "high", 18},
	{"wmic shadowcopy delete", "file-str-shadow-delete-wmic", "Shadow-copy deletion command", "T1490", "high", 18},
	{"bcdedit /set {default} recoveryenabled no", "file-str-recovery-off", "Disables Windows recovery", "T1490", "high", 15},
	{"-encodedcommand", "file-str-ps-enc", "PowerShell encoded-command switch", "T1059.001", "medium", 8},
	{"invoke-expression", "file-str-ps-iex", "PowerShell Invoke-Expression", "T1059.001", "low", 5},
	{"frombase64string", "file-str-b64", "Base64 decode call", "T1140", "low", 4},
	{"your files have been encrypted", "file-str-ransom-note", "Ransom-note wording", "T1486", "high", 20},
	{"all your files are encrypted", "file-str-ransom-note2", "Ransom-note wording", "T1486", "high", 20},
	{"currentversion\\run", "file-str-run-key", "References a Run persistence key", "T1547.001", "low", 6},
	{"/bin/sh -i", "file-str-revshell", "Interactive shell string (reverse-shell pattern)", "T1059.004", "medium", 8},
	{"bash -i >& /dev/tcp/", "file-str-revshell-tcp", "Bash reverse-shell string", "T1059.004", "high", 20},
}

func analyzeStrings(ctx context.Context, data []byte, b *InspectBuilder) {
	strs, limited := extractStrings(ctx, data)
	if limited {
		b.LimitHit("strings")
	}
	b.Meta("strings.count", len(strs))
	if fileCtxDone(ctx) {
		return
	}
	joined := strings.Join(strs, "\n")
	lower := strings.ToLower(joined)
	for _, s := range suspiciousStrings {
		if strings.Contains(lower, s.needle) {
			fileFinding(b, s.id, s.title, s.sev, s.tech, s.needle, s.weight)
		}
	}
	iocs := extractIOCs(joined, InspectMaxIOCs)
	counts := map[string]int{}
	for _, i := range iocs {
		b.IOC(i.Typ, i.Val)
		counts[i.Typ]++
	}
	b.Meta("strings.ioc_counts", counts)
	if counts["ipv4"]+counts["ipv6"] > 0 && counts["url"] > 0 {
		fileFinding(b, "file-str-network-iocs", "Embedded URLs and public IP addresses", "low", "T1071", "", 4)
	}
	if counts["wallet"] > 0 {
		fileFinding(b, "file-str-wallet", "Embedded cryptocurrency wallet address", "low", "T1657", "checksum-validated where the format allows", 6)
	}
	if counts["wallet"] > 0 && (strings.Contains(lower, "encrypted") || strings.Contains(lower, "decrypt")) {
		fileFinding(b, "file-str-wallet-ransom", "Wallet address alongside encrypt/decrypt wording", "medium", "T1486", "", 14)
	}
}
