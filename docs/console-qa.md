# Console QA

How the single-file console (`internal/edr/dashboard.html`) was checked, and what was not.

## Method

- Built `cmd/kavach` and ran it on `127.0.0.1` only, with a throwaway data dir, a generated random token, `KAVACH_RATE_LIMIT=0` (local only) and a loopback syslog UDP listener.
- Seeded synthetic data through the API: about 540 process events over 72 hours across 6 hosts, network events (including a periodic beacon), DNS and auth telemetry, an SBOM inventory for vulnerabilities, 4 syslog datagrams, feedback verdicts on 319 findings, an exception and a scheduled detection.
- Drove the console with headless Chrome via puppeteer: sign in through the login form, then for each page in the g-key table: load, collect page errors and 5xx, horizontal overflow, text contrast below 4.5:1, and click every visible button and tab except delete, clear, reset, download, remove, revoke, rebuild, replay, disable, rotate.
- Every g-key (including `, . ' \` \ ! @ # $ % ^ & *`) was pressed after `g` and the visible page compared with the table: all matched on desktop light.
- Models: the four new tabs (DNS tunneling, Users, Peers, Alert fatigue) plus the Priority factor reference were loaded, and host, user and rule drill-downs were exercised, including a nonexistent host and a model below its minimum samples.
- Inspector: file upload, script, command line, domain, config, lockfile, URL and email modes were each run end to end and appeared in Recent reports.

## Bugs found and fixed

- Inspector intro omitted config, lockfile, URL and email; the last three modes had no UI at all although the server supports them. Added.
- Contrast: light-theme `th`, captions, taglines and metric labels (`--text-tertiary` 3.6:1), high/critical/failed tags (red on pink 3.2:1), neutral tags (4.3:1). Tokens darkened and a `--danger-text` token added.
- New Models views initially printed "0 samples" for models that do not report a sample count; fixed.

## Expected console noise, not bugs

400 or 409 from clicking Run or Refresh with empty input or with feeds offline (no network), and 404 from the similar-submissions lookup for unindexed content.

## Not verified

- Dark theme and 390px for pages other than those listed under "Theme and phone-width pass" below; treat them as unverified.
- Real sensors, remote feeds, TLS syslog, mTLS agents, SSE streams under load and destructive actions were not exercised.
- Contrast is computed from computed styles with alpha blending; gradients and images are not measured.
- Models "ok" for DNS tunneling with flagged windows was not reached: the synthetic burst stayed below the 50-lookup minimum per host (shown honestly as not_enough_data).

`internal/edr/dashboard_smoke_test.go` gained static checks for Models tabs, Inspector modes and the light text-token contrast.

## Usability pass (palette, tables, views)

Checked with headless Chrome driving a copy of the page with a probe script (no server, synthetic rows): table tool row and view bar appear, numeric sort ascending and descending, column hide, palette CVE lookup entry, saved view written to localStorage. Dark theme, phone width and a real signed-in session against live data were not exercised in this pass; contrast relies on existing text tokens.

## Theme and phone-width pass

Real browser: headless Google Chrome (157) driven over the DevTools protocol by a throwaway Node script, with `prefers-color-scheme` emulated and the viewport set to 1280x900 and to 390x900 (mobile). Four combinations were run: light and dark, each at 1280 and 390. The page was served from a copy with a stubbed `fetch` returning small **synthetic** JSON (6 findings, 3 hosts, one incident, an Inspector report with findings, IOCs and a decoding layer, similar-submission matches, and a Competitive matrix with 3 products, 3 areas, a backlog row and a source). Unlisted endpoints returned `{}`. No real server, no credentials, no network.

Exercised in all four combinations, with a script that flags horizontal overflow past the viewport, text below 4.5:1 (3:1 for large text) with alpha blending, and unreachable tab buttons, plus screenshots that were looked at:
- Every page section loaded once (empty or stub data): overflow and contrast sweep.
- Command palette: opened with Ctrl+K, typed a query, checked it stays inside the viewport and scrolls.
- Table tool row on Detect (row count, Columns, CSV, JSON) and the saved views bar; the Columns disclosure opened.
- All 11 Models tabs: clicked, scrolled into view, contrast checked (empty state only; no real model data).
- Inspector: all 8 mode buttons, plus Analyze with stub text for script, command line, domain, URL, email and lockfile, and the rendered verdict, findings table, IOC list, layers and similar-submissions table; the Recent reports tab (empty).
- Competitive page with the stub matrix, backlog and sources.
- Theme: no stored choice follows the OS (and a live OS change), the toggle cycles system, light, dark, a stored explicit choice beats the OS after reload.

Defects found and fixed:
- Theme ignored the OS scheme; now system/light/dark with a stored choice (try/catch).
- The Browse menu (about 60 pages) sat inside the horizontally scrolling tab strip, so its dropdown was clipped and unreachable by mouse at every width. Moved out of the strip, and given a max height with scrolling.
- At 390px the section tabs were squeezed into about 80px beside the brand and buttons; they now wrap to their own row.
- Severity tags wrapped mid-word ("mediu m") in narrow table cells; now no-wrap.
- At 390px narrow table columns broke words per letter; cells now wrap at word boundaries and the table scrolls sideways.
- Textareas (Inspector, lab) had the pill radius and rendered as a blob.
- Dark theme contrast: high/critical text 4.2:1, low/open/out-of-scope tags 4.1:1, tertiary text and the palette key hints 3.9:1, placeholders about 3:1, the pressed range buttons (black on blue 4.47:1), the Advisories env-var code chip 4.0:1. Tokens or token usage adjusted.

Not verified in this pass:
- Any real server, session, login form or live data; every endpoint other than those listed above returned `{}` or empty, so most pages were checked only in their empty state.
- Models tabs with real model output (flagged windows, sparklines), Inspector file upload, the Inspector similarity result beyond the two stub rows, and config mode results.
- Popups and transient states after interaction (toasts, drawer, help overlay) in dark and at 390px, and the page-by-page g-key sweep in dark.
- Safari, Firefox, a physical phone (the 390px run is Chrome's mobile emulation), touch gestures, print.
- The Recent reports tab was flagged once at 3.3:1; the sample was taken mid colour transition and the settled colours were not re-measured separately.

## Automated checks that run in `go test`

These are static checks of `dashboard.html` and `docs/console.md`; none of them runs a browser.

| Test | What it guards |
|------|----------------|
| `TestDashboardEveryPageResolves` | Every page id has a section, a label and a loader guard, and the g-key table points at real pages (at least 60 pages) |
| `TestDashboardInlineScriptParses` | The inline script is syntactically valid |
| `TestDashboardModelsAndInspectorTabs` | Every Models tab and Inspector mode button has a pane and is listed in its handler |
| `TestDashboardLightTextTokensContrast` | Light-theme text tokens keep the contrast ratio after the fixes above |
| `TestDashboardUsabilityFeatures` | The table, saved-view and palette block keeps its safety rules: tokens only, no `innerHTML`, storage access inside try/catch, the user-facing hooks present |
| `TestDashboardThemeAndPhoneRules` | Theme is auto/light/dark with try/catch storage and an OS media query; the Browse menu is not inside the scrolling tab strip; phone nav wrap and no-wrap tags are present; dark tokens that were failing stay at the fixed values |
| `TestDocsConsoleListsMenuPages` | Every Browse-menu label appears in `docs/console.md` |

Run them with `go test ./internal/edr/ -run 'Docs|Dashboard'`.

## Coverage by feature

| Feature | Real browser, light, desktop | Dark theme | 390px phone width | Against live data |
|---------|------------------------------|------------|-------------------|-------------------|
| g-key navigation, login, page loads | yes (headless Chrome) | sweep only (stubbed data) | sweep only (stubbed data) | synthetic data, local server |
| Models tabs (original and four new) | yes | yes, empty state | yes, empty state | synthetic data |
| Inspector modes | yes | yes, stub results | yes, stub results | synthetic data |
| Palette, table tools, saved views | yes (stubbed fetch) | yes | yes | no (synthetic rows) |
| Pages added later (Posture trend, Executive digest, Auditor bundle, Syslog, Content versions, Reports and SLO, Automation, Attack chains, Feedback, Vulnerability priority, Sequence hunt, Coverage, Provenance, Ransomware behaviour, TTP similarity) | covered only by the g-key sweep where it ran; no per-page interaction record | no | no | no |
| Competitive | yes (stub matrix) | yes | yes | no |

"No" here means not exercised or not recorded, not that a defect was found. Treat every "no" as unverified.

## Not covered by the console at all

No console page exists for software exposure reports, cloud audit-log ingestion or the Sigma importer, so their QA is the API tests, not this document. The Inspector's SARIF export and report clustering are API only.
