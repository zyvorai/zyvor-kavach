# Console

The Kavach web console is an Apple.com / Netra-sister SPA served from the controller (`internal/edr/dashboard.html`).

---

## Login

| Field | Demo value |
|-------|------------|
| Username | `admin` |
| Password | `Admin@321` |

Password **is** the server bearer (`KAVACH_TOKEN`). The form posts candidates to `POST /v1/session` and receives an HttpOnly `zyvor_session` cookie (1h, SameSite=Strict).

Wrong username or password → “Wrong username or password.”

Legacy lab tokens that used `Admin@321Admin@321` are still tried when the password is `Admin@321`, for smooth upgrades.

---

## Layout

- Shell max width **1800px** (Netra sister) — full use of wide displays.  
- Sticky translucent nav; primary tabs + **Browse** overflow menu.  
- Observation-only banner on every page.  
- Light / dark theme toggle.  
- Netra-matching button system: blue primary CTA, quiet secondary, danger only for destructive-looking ledgers.

---

## Pages (primary)

| Page | Purpose |
|------|---------|
| Overview | Story hero, live metrics, chapter links |
| Detect / Detections | Findings + Insight detections |
| Hunt | Query / KQL style hunts |
| Incidents | Workflow state |
| Hosts / Fleet | Inventory + enrollment |
| AI Hub | Chat, briefing, agents, NL hunt |
| World | Global vendor domain loader |

## Browse menu

Timeline, Prevent, Intel, Identity, Spotlight, OverWatch, Response, Ops, Observe, eBPF, Alerts, Risk, SOC, Posture, Finance, Sectors, Modules, Integrations, Detection lab, Intel feeds, Evidence, Fleet health, Prevalence, Canaries, Governance, Tuning, Identity threats, Vulnerabilities, Cases, Hunt packs, Ransomware, Content library, Adversaries, Rule health, Export, Search, CERT advisories, Regulatory clocks, Models, Inspector, Provenance, Ransomware behaviour, TTP similarity, Competitive, Syslog, Content versions, Reports and SLO, Automation, Attack chains, Feedback, Vulnerability priority, Sequence hunt, Coverage, Posture trend, Executive digest, Auditor bundle.

The menu is read from `internal/edr/dashboard.html`; `TestDocsConsoleListsMenuPages` fails when a page is missing here.

---

## Usability features

- **Command palette**: Ctrl/Cmd+K or `/` opens it. Type a page name to jump, or a lookup: `host web01`, `cve CVE-2024-1234`, `ioc <ip|domain|hash>`, `rule`, `case`, `technique` (a bare CVE id, IP, hash or domain is recognised too). Lookups open the Search page with the type preset. It also offers theme toggle, shortcuts help and CSV/JSON export of the first table on the page.
- **Keyboard help**: `?` lists every shortcut, including all `g` page keys.
- **Tables**: each table has a tool row with a row count (or "Loading…" / "No rows to show"), a **Columns** toggle, and **CSV** / **JSON** export of the rows already loaded in the browser (visible columns only; nothing is refetched). Click or press Enter on a header to sort ascending, again for descending, a third time to clear. Numbers, percentages and ISO dates sort naturally, and sort and hidden columns survive reloads of the table data. CSV cells that start with `=`, `+`, `-` or `@` are prefixed with `'` to stop spreadsheet formula injection.
- **Saved views**: a bar at the top of each page saves the current filter inputs, selects, sort and hidden columns under a name. Views live only in this browser's `localStorage` (`kavach-views-<page>`, up to 20 per page); they are never sent to the server and secret-like fields (token, password, key) are never captured. Applying a view fills the fields; press the page's own action to run it. If storage is blocked the bar says so and the page still works.
- Mobile and dark mode use the same tokens as the rest of the console; the tool rows wrap at phone width.

Not covered: pages that render lists as cards rather than tables get no sort or export; tables with expandable detail rows are not sortable.

---

## eBPF page

Health score, backend, event/lost counters, feature table, recent events. Data from `/v1/ebpf/status|health|features|events`.

---

## Finance page

Dalal Street band — modules, institutions, exchanges, insurance, events — plus tables for venues, payment rails, institutions, insurers, IRDAI posture, and recent finance events. Data from `/v1/finance/summary|exchanges|payment-rails|institutions|insurance|irdai|events`.

---

## Sectors page

Critical infrastructure band — modules, public fleets, city buses, ISRO, events — plus government vehicles, city buses, taxis, OEMs, manufacturing, ISRO centers, airports, flights, defence, railways, portals, and recent sector events. Data from `/v1/sectors/summary|gov-vehicles|city-buses|taxis-cabs|vehicle-oem|manufacturing|isro-centers|airports|flights|defence|railways|gov-portals|events`.

---

## Auth for APIs from the browser

Session cookie is enough for same-origin `fetch`. Automations should use:

```bash
Authorization: Bearer $KAVACH_TOKEN
```

Sign out calls `POST /v1/logout` and reloads.

---

## Related

- [Tutorial](tutorial.md)
- [Architecture](architecture.md)
- [kavachctl](kavachctl.md) for the CLI twin
- Design notes: [APPLE-UX-CONTRACT](https://github.com/zyvorai/zyvor-kavach/blob/main/docs/design/APPLE-UX-CONTRACT.md)
