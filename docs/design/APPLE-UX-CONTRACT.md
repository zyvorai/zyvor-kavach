# Kavach UX contract — apple.com

Kavach’s investigation console is the embedded surface in
`internal/edr/dashboard.html` (served by `internal/edr/dashboard.go`). The docs
site (`website/`) shares the same tokens. There is no separate Vite `web/` app
yet — deepen the embed until IA outgrows ~5 views.

Identity: security without compromise, observation-first, quiet until a finding
needs attention.

## Surface tiers

| Tier | Kavach surfaces | Density | Layout |
|---|---|---|---|
| **Story** | Login, Overview | Very low | Eyebrow, display, lede, one primary CTA; hairline metric band; chapter rows |
| **Browse** | Detect, Incidents, Fleet | Medium | Page hero + glass toolbar + hairline `table-wrap` |
| **Work** | Incident transitions, fleet enroll/revoke, finding drawer | High | Work panels + drawer; session may mutate |

## Tokens

| Token | Light (default) | Dark |
|---|---|---|
| `--bg-page` | `#ffffff` | `#000000` |
| `--surface-1` (card) | `#ffffff` + hairline | `#1d1d1f` |
| `--text-primary` | `#1d1d1f` | `#f5f5f7` |
| `--text-secondary` | `#6e6e73` | `#a1a1a6` |
| `--text-tertiary` | `#86868b` | `#86868b` |
| `--apple-blue` (CTA, focus) | `#0071e3` | `#0071e3` |
| `--apple-link` | `#0066cc` | `#2997ff` |

## Type scale

| Token | Value | Used by |
|---|---|---|
| `--fs-h1` | `clamp(24px, 2.6vw, 34px)` | Page heroes, login display |
| `--fs-h2` | `clamp(20px, 1.8vw, 24px)` | Chapter / card headings |
| `--fs-h3` | `17px` | Empty-state titles, integration titles |
| `--fs-figure` | `clamp(18px, 1.6vw, 24px)` | Metric figures |
| `--fs-lede` | `16px` | Hero / page lede |
| `--fs-body` | `15px` | Body, buttons |

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
