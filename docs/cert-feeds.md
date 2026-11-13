# Worldwide CERT advisory feeds

Kavach is observation-only. This optional feature pulls public advisories from national and regional CERTs, normalises them, and flags the ones that mention a CVE your software inventory is affected by. It never patches or changes anything.

Default off. Enable per feed with `KAVACH_CERT_FEEDS`, a comma list of feed ids (for example `KAVACH_CERT_FEEDS=cisa,cert-eu,jvn`). With the variable unset there is no network traffic and `GET /v1/advisories` returns an empty list. Unknown ids are reported in `feed_errors`.

## Feeds (verified live)

All URLs below were fetched on **2026-11-13** and returned HTTP 200 with parseable content. None needs authentication or an API key.

| id | Publisher | URL | Format |
|---|---|---|---|
| `cisa` | CISA, all advisories (incl. ICS) | https://www.cisa.gov/cybersecurity-advisories/all.xml | RSS 2.0 (about 6 MB) |
| `cisa-ics` | CISA, ICS advisories | https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml | RSS 2.0 (about 6 MB) |
| `ncsc-uk` | NCSC UK (reports, guidance, news) | https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml | RSS 2.0 |
| `cert-eu` | CERT-EU security advisories | https://cert.europa.eu/publications/security-advisories-rss | RSS 2.0 |
| `jpcert` | JPCERT/CC alerts and weekly reports (Japanese) | https://www.jpcert.or.jp/rss/jpcert.rdf | RSS 1.0 (RDF) |
| `jvn` | JVN, Japan Vulnerability Notes (English) | https://jvn.jp/en/rss/jvn.rdf | RSS 1.0 (RDF) |
| `cert-bund` | BSI WID / CERT-Bund security advisories (German) | https://wid.cert-bund.de/content/public/securityAdvisory/rss | RSS 2.0 |
| `cert-fr` | CERT-FR alerts (French) | https://cert.cyber.gouv.fr/alerte/feed/ (old host `www.cert.ssi.gouv.fr` redirects here) | RSS 2.0 |
| `cert-fr-avis` | CERT-FR security notices | https://cert.cyber.gouv.fr/avis/feed/ | RSS 2.0 |
| `cccs` | Canadian Centre for Cyber Security alerts and advisories | https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en (the `rss/v1` variant redirects to this Atom URL) | Atom |
| `singcert` | SingCERT / CSA Singapore alerts | https://www.csa.gov.sg/alerts-and-advisories/alerts/rss.xml | RSS 2.0 |
| `singcert-adv` | SingCERT / CSA Singapore advisories | https://www.csa.gov.sg/alerts-and-advisories/advisories/rss.xml | RSS 2.0 |
| `euvd` | ENISA European Vulnerability Database, latest | https://euvdservices.enisa.europa.eu/api/lastvulnerabilities | JSON |
| `euvd-exploited` | ENISA EUVD, exploited vulnerabilities | https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities | JSON |

Not wired up: the ENISA EUVD "critical" endpoint also responds (`/api/criticalvulnerabilities`) but overlaps `euvd`; a bulk JVN iPedia feed (`jvndb.jvn.jp/en/rss/jvndb_new.rdf`, 1.4 MB) also responds but was left out to keep the cache small.

## Could not verify (not included)

| Publisher | What was tried | Result on 2026-11-13 |
|---|---|---|
| ACSC (cyber.gov.au) | `/about-us/view-all-content/alerts-and-advisories/rss`, `/rss/alerts`, `/rss/advisories`, `/acsc/view-all-content/advisories/rss` | Every request timed out or the HTTP/2 stream was reset from the test machine. Third-party aggregators list `/rss/advisories` and `/rss/alerts`, but that is unconfirmed. ACSC also offers an email Alert Service. |
| CERT-In (cert-in.org.in) | Home page, `s2cMainServlet?pageid=RSSFEED`, `/RSS_FEED/rss.xml` | No feed found; those URLs return an HTML page (or an empty body). The site is a frameset with servlet pages only. |
| KrCERT/CC (KISA) | `krcert.or.kr/rss/rssAdvisory.do`, `knvd.krcert.or.kr/rss/securityNotice.do`, `krcert.or.kr/rss/rss.do` | 404 or an HTML error page. No machine-readable feed located. |
| BSI main site (bsi.bund.de) | Guessed RSS paths | 404. Use the WID feed (`cert-bund`) instead. |
| EUVD web UI docs | `euvd.enisa.europa.eu` | The UI is a client-rendered app; the API docs are reported by third parties at `euvd.enisa.europa.eu/apidoc` but were not readable. The JSON endpoints above do work without a key. |

Add a feed only after fetching its URL and checking the content.

## Terms and licence notes

Kavach only reads the public feeds and stores titles, ids, links, dates and CVE ids (no full advisory bodies). Check each publisher's terms for your own redistribution. Notes below are a plain-language reading of what the publishers say, not legal advice.

| Publisher | Source consulted (2026-11-13) | Note |
|---|---|---|
| CISA | https://www.cisa.gov/linking-policy ; https://cisa.gov/intellectual-property-policy (not fully readable) | CISA describes its site as public domain for linking; its own work is generally treated as public domain, but third-party material in advisories (vendor text, images) can carry rights. |
| NCSC UK | https://www.ncsc.gov.uk/section/about-this-website/terms-and-conditions | Crown copyright, reusable under the Open Government Licence v3.0 with attribution. Third-party content and logos are excluded. The page does not mention RSS. |
| CERT-EU | https://cert.europa.eu/legal-notice | Content generally reusable under CC BY 4.0 with attribution and change notice; third-party material and logos excluded. |
| CERT-FR (ANSSI) | https://cert.cyber.gouv.fr/mentions-legales/ | Generally reusable under Etalab Open Licence 2.0; the ANSSI logo needs permission; framing is not allowed. |
| JPCERT/CC and JVN | https://jvndb.jvn.jp/en/ (JVN iPedia FAQ), https://jvndb.jvn.jp/en/schema/jvnrss.html | JVN iPedia FAQ allows quoting but asks users to tell IPA/JPCERT (jvn@jvn.jp). The JVNRSS spec allows free use of the format. No separate RSS terms page was found; the jpcert.or.jp terms page was not located. |
| CCCS | https://www.cyber.gc.ca (terms pages not retrieved directly); related CSE terms found by search | Content is meant to be credited to the Cyber Centre; names, logos and graphics need written permission; commercial reproduction of CSE content needs permission. Treat as attribution required, confirm before redistribution. |
| SingCERT / CSA | https://www.csa.gov.sg/terms-of-use | Content is copyright; written permission is generally needed to copy or republish. Kavach shows titles and links only, locally; do not republish the feed content. |
| BSI WID / CERT-Bund | not located | No terms page found. Treat as unknown; link back to the advisory. |
| ENISA EUVD | not located (API docs not readable) | No terms found. Treat as unknown; the endpoints are public and unauthenticated. |

Kavach sets a `User-Agent: kavach-cert-feed` header and polls at most every 6 hours (and on explicit refresh), which keeps load low. ACSC-style rate limits are unknown; if a publisher asks you to stop, remove its id from `KAVACH_CERT_FEEDS`.

## What is sent

Nothing about your hosts. Every request is a plain `GET` to one of the fixed URLs above: no query parameters other than the fixed CCCS one, no request body, no cookies, no authorization header, only `User-Agent` and `Accept`. Hostnames, package names, versions and CVE ids from your inventory are never included. Correlation runs locally against the cached advisories. A test asserts this and also asserts that non-allowlisted hosts, plain `http`, and redirects to other hosts are refused.

Limits: https only; allowlisted hosts only (the hosts of the feeds above, redirects re-checked, at most 3); 30 s request timeout; 16 MiB response cap; at most 300 items per feed and 50 CVEs per advisory.

Parsing is defensive: the XML decoder never expands DTD entities or fetches external resources, feeds containing `<!DOCTYPE` or `<!ENTITY` are rejected, nesting depth is capped, non-http(s) links are dropped, and a malformed feed only produces an error entry while the previous cache is kept. RSS 2.0, RSS 1.0/RDF and Atom are read by element local name, so no per-publisher schema is needed.

## Normalised record

```json
{"source":"cisa","id":"icsa-26-316-02","title":"...","published":"2026-11-12T12:00:00Z",
 "url":"https://...","cves":["CVE-2026-111497"],"severity":"high",
 "matched":true,"matched_cves":["CVE-2026-111497"],"matched_hosts":["web-1"]}
```

CVE ids are found by pattern in the title, description and attributes. `severity` is set only when the feed gives it (BSI category, EUVD CVSS score). `matched*` fields are computed on read from the vulnerability findings of the current software inventory (the same findings as `/v1/vulns/findings`, so they follow `KAVACH_CVE_FILE` and `KAVACH_VULN_FEED`).

## Cache and refresh

Cached at `<store path>.certfeeds.json` (see `docs/persistence-files.md`). When any feed is enabled a background refresh runs at start and every 6 hours. Requests are served from cache and never block on the network. A feed that fails keeps its previous items. Items of feeds that are no longer enabled are hidden.

## API (all require auth)

- `GET /v1/advisories` filters: `source` (comma list), `cve`, `since` (RFC 3339 or YYYY-MM-DD), `q`, `matched=true`, `limit` (default 100, max 500). Newest first.
- `GET /v1/advisories/feeds/status`: enabled and available ids, per-feed counts and fetch times, last refresh, `feed_errors`.
- `POST /v1/advisories/feeds/refresh`: refresh now; 409 when `KAVACH_CERT_FEEDS` is unset.

CLI: `kavachctl advisories list [--source --cve --since --q --matched --limit --json] | status | refresh`. MCP (read-only): `advisories_list`, `advisories_feed_status`.
