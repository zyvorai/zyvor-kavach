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

Timeline, Prevent, Intel, Identity, Spotlight, OverWatch, Response, Ops, **eBPF**, **Finance**, **Sectors**, Modules, Integrations.

---

## eBPF page

Health score, backend, event/lost counters, feature table, recent events. Data from `/v1/ebpf/status|health|features|events`.

---

## Finance page

Dalal Street band — modules, institutions, exchanges, open fraud, events — plus tables for venues, payment rails, institutions, and recent finance events. Data from `/v1/finance/summary|exchanges|payment-rails|institutions|events`.

---

## Sectors page

Critical infrastructure band — modules, airports, flights, defence, events — plus airports, flights, defence enterprise IT, railways, portals, and recent sector events. Data from `/v1/sectors/summary|airports|flights|defence|railways|gov-portals|events`.

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
