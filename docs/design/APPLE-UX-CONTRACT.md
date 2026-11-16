# Kavach UX contract — apple.com

Kavach’s investigation console is the embedded surface in
`internal/edr/dashboard.html` (served by `internal/edr/dashboard.go`). The docs
site (`website/`) shares the same tokens. There is no separate Vite `web/` app.
The embed has grown to about 66 pages (9 primary tabs plus a Browse menu); see
[console.md](../console.md) for the page list, routes and shortcuts. Splitting it
into a separate app is still an open decision, not a plan.

Identity: security without compromise, observation-first, quiet until a finding
needs attention.

## Surface tiers

| Tier | Kavach surfaces | Density | Layout |
|---|---|---|---|
| **Story** | Login, Overview | Very low | Eyebrow, display, lede, one primary CTA; hairline metric band; chapter rows |
| **Browse** | Detect, Incidents, Fleet, and every Browse-menu page (Models, Inspector, Search, Competitive, ...) | Medium | Page hero + glass toolbar + hairline `table-wrap`; tool row (columns, CSV, JSON) above each table and a saved-views bar at the top of each page |
| **Work** | Incident transitions, fleet enroll/revoke, finding drawer and analyst verdicts, Models reset/rebuild, scheduled detections and reports, case workflow | High | Work panels + drawer; session may mutate Kavach's own records only |

## Tokens

| Token | Light (default) | Dark |
|---|---|---|
| `--bg-page` | `#ffffff` | `#000000` |
| `--surface-1` (card) | `#ffffff` + hairline | `#1d1d1f` |
| `--text-primary` | `#1d1d1f` | `#f5f5f7` |
| `--text-secondary` | `#636366` | `#a1a1a6` |
| `--text-tertiary` | `#6e6e73` | `#86868b` |
| `--text-faint` | `#767679` | `#6e6e73` |
| `--danger-text` (red text on tinted or white fills) | `#c9251b` | `#ff453a` |
| `--apple-blue` (CTA, focus) | `#0071e3` | `#0071e3` |
| `--apple-link` | `#0066cc` | `#2997ff` |

## Type scale

Values below are what `dashboard.html` defines today. An earlier version of this contract listed smaller values (h1 `clamp(24px, 2.6vw, 34px)`, body 15px); the embed is the source of truth, so check `:root` there before relying on this table.

| Token | Value | Used by |
|---|---|---|
| `--fs-h1` | `clamp(32px, 4vw, 48px)` | Page heroes, login display |
| `--fs-h2` | `clamp(24px, 2.4vw, 32px)` | Chapter / card headings |
| `--fs-h3` | `19px` | Empty-state titles, integration titles |
| `--fs-figure` | `clamp(24px, 2.2vw, 36px)` | Metric figures |
| `--fs-lede` | `19px` | Hero / page lede |
| `--fs-body` | `17px` | Body, buttons |
| `--fs-link` | `17px` | Text links |

Page heroes are compact titles, not posters: data starts within the first screen.

## Laws

1. **Elevation runs up.** Dark: page `#000` → panel `#1d1d1f`. Light: white page, white surface with a hairline. A grey panel on a white page is a bug.
2. **Color is deviation.** Nominal values are graphite. Blue means intent (CTA, link, focus). Red/amber/green only when a value really deviates or is confirmed good.
3. **One primary action per view.** Everything else is secondary, ghost, or text link.
4. **No hard-coded hex in markup.** Use tokens; define new ones next to the shared palette in `dashboard.html` / `website/src/css/custom.css`.
5. **Read-only surfaces stay read-only.** Observation views must not grow mutating controls without an explicit Work-tier redesign.

## Author checklist

1. Pick the tier first.
2. Story: one composition, hairline metric band (not a card grid), optional status pill.
3. Browse: glass toolbar + search + `table-wrap`; tertiary 12px headers.
4. Empty lists: title, sentence, next action; loading shows skeletons.
5. Motion: `fadeRise`, count-up, live-dot — gated by `prefers-reduced-motion`.
6. Check light and dark at 1440px and 390px; no horizontal scroll at 390px.

## Implementation status

What the console does today against this contract, and what has not been checked.

- **Laws 1 to 4** are enforced partly by tests: `TestDashboardLightTextTokensContrast` guards the light text tokens, and `TestDashboardUsabilityFeatures` requires tokens only (no hard-coded hex) and no `innerHTML` in the usability block.
- **Law 5** is applied per page: Browse pages are read-only; mutating controls live on Work-tier pages and only change Kavach's own records. Nothing in the console contains, kills, blocks or isolates.
- **Contrast fixes.** Light `--text-tertiary` was darkened (it measured 3.6:1) and `--danger-text` was added after a headless-Chrome audit; see [console-qa](../console-qa.md).
- **Shared behaviours** added across pages: command palette, `g` shortcuts, sortable tables with column toggle and CSV/JSON export, per-page saved views in `localStorage`; see [console.md](../console.md).
- **Theme.** Light by default; the toggle is stored in `localStorage`. The console does not follow `prefers-color-scheme`. Motion is gated by `prefers-reduced-motion`.
- **Unverified.** Checklist item 6 (light and dark at 1440px and 390px, no horizontal scroll at 390px) was not completed for the newer features: dark theme and phone width of the palette, table tools, saved views, the newer Models tabs and the Inspector url, email and lockfile modes have not been checked in a browser. A scripted run for dark and 390px existed but had not finished when the QA notes were written.
