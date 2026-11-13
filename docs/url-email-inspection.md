# URL and e-mail inspection

Two analyzers on the artifact inspector: kind `url` (`POST /v1/inspect/url`) and
kind `email` (`POST /v1/inspect/email`, raw `.eml` text). Both are parse-only:
they never fetch a link, resolve a name, follow a redirect or contact a mail
server, and Kavach stays observation-only. A test (`TestURLNeverFetches`) checks
that the source files reference no network or exec packages.

Code: `internal/edr/inspect_url_*.go`, `inspect_email_*.go`. Kinds are added to
`inspect_contract.go` as `InspectKindURL = "url"` and `InspectKindEmail = "email"`.

## URL analyzer

A tolerant parser (not `net/url`, which rejects or normalises the very tricks of
interest) splits scheme, userinfo, host, port, path, query and fragment, drops
tab/newline/control characters the way browsers do, and classifies IPv4 hosts
written as dotted decimal, one 32-bit decimal, hex, octal or mixed.

Findings (ids `url-*`; weights are transparent and modest; no lexical signal
alone reaches the 40-point "suspicious" line):

| id | weight | meaning |
|---|---|---|
| `url-scheme-script` | 60 | `javascript:` / `vbscript:` URL (embedded code is also run through the script analyzers: deobfuscation, byte rules) |
| `url-data-html-script` | 55 | `data:text/html` / SVG containing script |
| `url-data-html` | 25 | `data:` HTML without script |
| `url-userinfo-lookalike` | 28 | userinfo before `@` looks like a domain (`paypal.com@evil.example`) |
| `url-ip-obfuscated` | 25 | decimal/hex/octal/mixed IP host, canonical form reported |
| `url-host-percent-encoded` | 22 | `%xx` inside the host |
| `url-scheme-file` | 20 | `file:` |
| `url-unicode-dots` | 15 | U+3002/U+FF0E/U+FF61 as label separators |
| `url-ip-host` | 12 | raw dotted IP |
| `url-port-invalid` / `url-port-odd` | 12 / 6 | port 0, over 65535, non-numeric / non-default port |
| `url-nested-redirect` | 12 (8 if the parameter name is not redirect-like) | a query value is a URL to a different registrable domain; the inner URL is analysed too at half weight |
| `url-double-encoding`, `url-encoded-plain-chars`, `url-path-traversal` | 10 / 8 / 8 | `%25xx`, letters needlessly encoded, `../` |
| `url-path-keywords`, `url-shortener`, `url-query-blob` | 8 / 6 / 6 | 2+ credential keywords, known shortener (destination hidden), high-entropy query value |
| `url-long`, `url-many-subdomains`, `url-long-host`, `url-host-hyphens`, `url-plain-http-login`, `url-control-chars` | 4-8 | weak lexical features |
| `url-host-*` | as the domain analyzer | the host goes through the existing domain analyzer (punycode, mixed-script, typosquat, brand-in-subdomain, DGA shape, suspicious TLD), ids re-prefixed |

IOCs extracted: the URL, the host as `domain`/`ipv4`/`ipv6`. The contract then
cross-checks them against the IOC store (read-only) and adds 40 on a match.
Only the first line of the input is analysed.

## E-mail analyzer

Uses `net/mail`, `mime`, `mime/multipart`, `mime/quotedprintable`. Caps: input
4 MiB (contract), 64 MIME parts, nesting depth 6, 8 MiB per decoded part, 24 MiB
decoded in total, boundary over 200 chars not parsed, 25 URLs analysed, 50
attachments hashed, 8 sent through the file analyzers. Hitting a cap is
recorded in `limits_hit`; it is not silent.

Headers (`email-*`): Reply-To / Return-Path / Sender domain differs from From
(15 / 4 / 4; free-mail Reply-To +5), display name holding a different address
(30) or a well-known brand name on an unrelated sender domain (22), lookalike
sender domain via the domain analyzer (`email-from-*`), Message-ID domain
mismatch (3), missing From/Date/Message-ID, Received chain: timestamps going
backwards by over 5 minutes (12), private/loopback earliest hop (4, weak:
internal relays are normal), very many hops, Date far from the newest Received.

Authentication: `Authentication-Results` and `Received-SPF` are parsed for
spf/dkim/dmarc/arc/compauth results and reported (`dmarc=fail` 25, `spf=fail`
15, `softfail` 8, `dkim=fail` 12, `compauth=fail` 15, header.from mismatch 12).
**Only what the receiving server recorded is reported. DKIM is not recomputed**
(that needs DNS and the exact original bytes), and SPF/DMARC are not evaluated.
An `Authentication-Results` header added by the sender cannot be told apart from
the receiver's without knowing your own authserv-id (RFC 8601 says verifiers
should strip foreign ones at the trust boundary); the report says so in meta
`email.auth.note`. A weightless `email-dkim-not-recomputed` finding marks this.

Body: plain and HTML parts are decoded (base64 / quoted-printable), URLs
extracted and run through the URL analyzer; findings are folded once per id as
`email-url-*`, with weights under 30 halved because tracking links in real mail
are long and redirecting (a redirect back to the sender's own site is ignored).
HTML: anchor text naming a different site than the href (30), form posting to
another host (22) or a password field (20), `<script>` (20), meta refresh (15),
iframe/object/embed (12), `<base href>` (8), hidden text, `font-size:0`, `data:`
sources (3-4 each: legitimate preheaders look identical). Urgency wording counts
only as a 4-point weak signal when three or more phrases appear.

Attachments: decoded, sha256 added as an IOC (cross-checked against the store),
double extension (35), bidi override in the name (35), content type mismatch
(an executable named `.pdf`, 40), risky/container/macro/HTML types (8-20), then
`RunAnalyzers` is called with kind `file` on the bytes, reusing the archive,
OOXML/PDF/OLE, PE/ELF/Mach-O, strings/IOC, byte-rule and similarity analyzers.
Their findings are folded in as `email-att-<id>` titled with the attachment
name. Script-type attachments are also run as kind `script` (deobfuscation).
Nested `message/rfc822` parts are walked as mail. No new internal API was needed
in the other analyzers; the helpers are in this feature's own files.

## Evaluation (URL analyzer, SYNTHETIC)

`TestURLEvaluationSynthetic` generates 300 benign-style and 300 phishing-style
URLs from a fixed seed with generators written for this test
(`inspect_url_eval_test.go`). No real URL or real-brand page is involved.
Threshold: report score >= `URLPhishThreshold` (20).

| | value |
|---|---|
| TP / FN (phishing) | 214 / 86 |
| FP / TN (benign) | 0 / 300 |
| precision | 1.000 |
| recall | 0.713 |

Failing floors: precision >= 0.90, recall >= 0.60. The misses are the shapes
lexical features cannot see: raw-IP logins with brand paths (`/chase/verify/`
on a bare IP scores only 12+8), punycode with no confusable mix, and
compromised-site paths (`/wp-content/.../login.php` on an ordinary domain), which
by design score near zero.

**Caveat: synthetic data overstates real accuracy.** The same author wrote the
analyzer and the generators, the benign set contains none of the odd-but-legit
URLs of real traffic (SSO redirect chains, signed CDN links, long app deep links),
and real phishing is mostly the hard "ordinary-looking" case. Precision 1.000
reflects separable generators, not a measured false-positive rate. Do not quote
these numbers as expected field performance. The e-mail analyzer has fixtures
(each header and URL trick, a benign plain mail, a benign newsletter, hostile
MIME) but no corpus evaluation.

## Sources actually opened

Fetched during this work (summaries are my own words, from the fetch output;
fetched pages were long and in several cases only the first ~100k characters
were read):

- Sahoo, Liu, Hoi, "Malicious URL Detection using Machine Learning: A Survey",
  https://arxiv.org/abs/1701.07179 : abstract page only. States that blacklists
  cannot be exhaustive and miss new malicious URLs, motivating learned detectors
  over feature representations. **The PDF (https://arxiv.org/pdf/1701.07179) was
  fetched but returned unreadable compressed bytes, so its feature taxonomy was
  not read.**
- RFC 3986, https://www.rfc-editor.org/rfc/rfc3986.html : authority is
  `[userinfo "@"] host [":" port]`; clients should show userinfo distinctly
  because it can be crafted to look like a trusted host name (basis of
  `url-userinfo-*`).
- RFC 8601, https://www.rfc-editor.org/rfc/rfc8601.html (first 100k chars) :
  Authentication-Results carries an authserv-id then `method=result` pairs; SPF
  results none/pass/fail/softfail/policy/neutral/temperror/permerror, DKIM
  similar with header.d/i/a/s properties; the authserv-id lets a consumer decide
  whether to trust it, and MTAs should remove such fields bearing their own id
  that arrive from outside the trust boundary. The DMARC result table was in the
  unread remainder.
- RFC 7489, https://www.rfc-editor.org/rfc/rfc7489.html (first 100k chars) :
  DMARC passes when SPF or DKIM passes for a domain aligned (relaxed or strict)
  with RFC5322.From; policy p=none/quarantine/reject published at `_dmarc`; it
  does not address display-name abuse or lookalike domains (basis for checking
  those separately).
- RFC 7208, https://www.rfc-editor.org/rfc/rfc7208.html (first 100k chars) : SPF
  authorises a sending host for the HELO and MAIL FROM identities; results
  pass/fail/softfail/neutral/none/temperror/permerror.
- RFC 6376, https://www.rfc-editor.org/rfc/rfc6376.html (first 100k chars) :
  DKIM `d=` is the signing domain, `s=` the selector, `bh=` the body hash, `b=`
  the header signature; verification needs a DNS public-key lookup (why this
  analyzer does not recompute it).
- RFC 5322, https://www.rfc-editor.org/rfc/rfc5322.html (first 100k chars) :
  From = author mailbox(es), Sender = the transmitting agent, Reply-To =
  preferred reply addresses, Received = per-hop trace with a date-time,
  Message-ID = unique id; a mailbox is `display-name <addr-spec>` or bare addr-spec.
- Unicode UTS #39, https://www.unicode.org/reports/tr39/ (first 100k chars) :
  confusables map to prototype skeletons; mixed-script and whole-script
  confusables; restriction levels. Our homograph handling reuses the existing
  domain analyzer's Latin+Cyrillic/Greek mixed-script check; it does not
  implement the full UTS #39 skeleton comparison.
- OWASP Unvalidated Redirects and Forwards Cheat Sheet,
  https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html :
  untrusted parameters that choose a redirect target let attackers keep a
  trusted domain at the start of a phishing link (basis of `url-nested-redirect`).

## UNVERIFIED

- The specific lexical feature list (length, dot count, `@`, IP host, hex
  encoding, suspicious TLDs, brand in subdomain, path keywords, entropy) and its
  weights come from general practice and my own judgement, NOT from a paper I
  read; the survey's PDF could not be read. Weights are not fitted to data.
- The URL shortener list, free-mail list, credential keyword list, redirect
  parameter names and urgency phrases are hand-written lists from general
  knowledge, not cited.
- BEC/phishing indicators (display-name spoofing, Reply-To mismatch, lookalike
  domains, urgency as a weak signal) were not confirmed by an opened source in
  this run; the RFCs above only confirm what each header means.
- The 5-minute clock-skew tolerance, the 72-hour Date skew and the hop count are
  arbitrary.
- Character sets are not transcoded (bodies are treated as UTF-8/ASCII bytes), so
  non-UTF-8 HTML may hide anchors from the regex scanner. HTML is scanned with
  regular expressions, not a full HTML parser.
- Brand detection depends on the existing domain brand list.

## Limits

Static and offline: a clean report is not proof of safety, shortened and
redirecting links are not resolved, attachment analysis is only as good as the
file analyzers, encrypted archives are reported but not opened, and the
5-second per-analyzer budget bounds how many attachments are analysed.
