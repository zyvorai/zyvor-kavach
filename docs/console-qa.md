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

- Dark theme, phone width (390px) and light/dark contrast after the fixes were scripted (`qa.js` in the scratch area) but the run had not finished when this was written; treat them as unverified.
- Real sensors, remote feeds, TLS syslog, mTLS agents, SSE streams under load and destructive actions were not exercised.
- Contrast is computed from computed styles with alpha blending; gradients and images are not measured.
- Models "ok" for DNS tunneling with flagged windows was not reached: the synthetic burst stayed below the 50-lookup minimum per host (shown honestly as not_enough_data).

`internal/edr/dashboard_smoke_test.go` gained static checks for Models tabs, Inspector modes and the light text-token contrast.
