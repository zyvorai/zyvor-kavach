# Kavach UX contract — apple.com

Kavach's investigation console and docs site (`website/`) follow one
apple.com-style contract, adapted from Netra's `docs/design/APPLE-UX-CONTRACT.md`.
Kavach keeps its own identity: security without compromise, observation-first,
quiet until a finding needs attention.

Docs tokens live in `website/src/css/custom.css`. Console styles should reuse the
same values when a dedicated `web/` surface lands.

## Surface tiers

| Tier | Kavach surfaces | Density | Layout |
|---|---|---|---|
| **Story** | Login, Overview / summary | Very low | Eyebrow, display title, lede, one CTA; metric band instead of a tile grid |
| **Browse** | Findings, events, fleet, incidents | Medium | Page hero + toolbar + hairline table |
| **Work** | Incident transition, enroll/revoke, mTLS ops | High | Card panels, tokens only |

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
| `--fs-h1` | `clamp(24px, 2.6vw, 34px)` | Page heroes, login title |
| `--fs-h2` | `clamp(20px, 1.8vw, 24px)` | Section headings |
| `--fs-h3` | `17px` | Card titles |
| `--fs-figure` | `clamp(18px, 1.6vw, 24px)` | Metric figures |
| `--fs-lede` | `16px` | Hero / page lede |
| `--fs-body` | `15px` | Body, buttons |

Page heroes are compact titles, not posters: findings data starts within the
first screen.

## Laws

1. **Elevation runs up.** Dark: page `#000` → panel `#1d1d1f` → card lighter. Light: white page, white card with a hairline. A grey panel on a white page is a bug.
2. **Color is deviation.** Nominal values are graphite. Blue means intent (CTA, link, focus). Red/amber/green only when a value really deviates or is confirmed good.
3. **One primary action per view.** Everything else is secondary or ghost.
4. **No hard-coded hex in components.** Use tokens; define new ones next to the shared palette.
5. **Read-only surfaces stay read-only.** Observation views must not grow mutating controls without an explicit work-tier redesign.

## Author checklist

1. Pick the tier first.
2. Story: one composition, no card grid.
3. Browse: toolbar + table; search uses a shared input field.
4. Empty lists get a title, a sentence, and a next action; loading shows a skeleton.
5. Check light and dark at 1440px and 390px; no horizontal scroll at 390px.
