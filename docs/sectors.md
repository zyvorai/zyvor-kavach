# Critical sectors — railways, government & more

Observation-only security for public infrastructure and citizen services. Kavach **never** stops trains, trips power breakers, takes portals offline, or mutates identity / PHI / election systems.

## Coverage

| Sector | What is observed |
|--------|------------------|
| Railways | FOIS, TMS, IRCTC, UTS, PRS, stations, signaling IT, freight |
| Metro | OCC / AFC (Delhi, Mumbai, Bengaluru, Hyderabad, …) |
| Airports | DEL/BOM/BLR/… AODB, CUTE, BHS, FIDS, ACS |
| Flights | AODB-style board observe — never cancels/diversions |
| Airlines | PSS / DCS / crew IT |
| ATC-adjacent IT | AAI enterprise only — no voice/radar control |
| Baggage / cargo / ground | BHS bridges, ICS, GSE IT |
| Airport security | CISF / screening IT — no access writes |
| DGCA / MoCA | Regulatory portal posture |
| Defence | MoD / service HQ enterprise IT — never weapons/C2 |
| Defence portals | Recruitment / SPARSH / public MoD sites |
| Border / Coast Guard / CAPF | ICP immigration, ICG shore IT, BSF/CRPF/CISF |
| DRDO / Cantonment | Lab campus & MES estate IT |
| Government | DigiLocker, UMANG, MyGov, Passport Seva, MCA21, ministries |
| e-Office / NIC | Workflow hosts, NICNET edge |
| Tax / Customs | GSTN, IT e-Filing, ICEGATE |
| Elections / Courts / Postal | ECI IT (not EVMs), eCourts, India Post |
| CERT-In | Directive posture checklist |
| Power / SCADA / Oil-gas | SLDC/DISCOM IT, OT bridges — no control writes |
| Telecom | BSS/OSS/NOC |
| Aviation / Ports | AODB, CUTE, TOS, PCS |
| Highways / RTO | FASTag, Vahan, Sarathi |
| Health / Pharma / Education | ABDM posture, HIMS, DIKSHA |
| Smart city / Water | ICC, CCTV VMS, utility IT |
| Space / Disaster | Ground-segment IT, NDMA |

## APIs

All under `/v1/sectors/*` (bearer / session auth). Key routes:

| Path | Purpose |
|------|---------|
| `GET /v1/sectors/summary` | Counts + `enforce: false` |
| `GET /v1/sectors/modules` | Capability map |
| `GET /v1/sectors/railways` | Rail systems |
| `GET /v1/sectors/gov-portals` | Citizen portals |
| `GET /v1/sectors/power` | Grid / DISCOM IT |
| `GET /v1/sectors/scada` | OT bridge hosts from fleet |
| `GET /v1/sectors/aviation` | Aviation domain overview |
| `GET /v1/sectors/airports` | Airport inventory |
| `GET /v1/sectors/flights` | Flight board observe |
| `GET /v1/sectors/airlines` | Airline PSS/DCS |
| `GET /v1/sectors/atc-it` | ATC-adjacent enterprise IT |
| `GET /v1/sectors/baggage` | BHS IT bridges |
| `GET /v1/sectors/defence` | Defence enterprise IT |
| `GET /v1/sectors/defence-portals` | Recruitment / pension portals |
| `GET /v1/sectors/border` | Immigration / ICP IT |
| `GET /v1/sectors/critical-sites` | Named critical locations |
| `GET /v1/sectors/events?type=&sector=` | Observe event ledger |
| `POST /v1/sectors/events` | Ingest `{ "events": [...] }` |

Full module list: `GET /v1/sectors/modules`.

## kavachctl

```bash
./bin/kavachctl sectors summary
./bin/kavachctl sectors railways
./bin/kavachctl sectors airports
./bin/kavachctl sectors flights
./bin/kavachctl sectors airlines
./bin/kavachctl sectors defence
./bin/kavachctl sectors border
./bin/kavachctl sectors gov-portals
./bin/kavachctl sectors power
./bin/kavachctl sectors critical-sites
./bin/kavachctl sectors events --sector aviation
```

Aliases: `sector`, `railways`, `govt`, `government` → sectors summary when used alone.

## Console

**Browse → Sectors** — metric band, airports, flights, defence, railways, government portals, recent events.

## Hard rule

`enforce: false` on summary and ingest. Detection and reporting only — never cancels flights, controls ATC, trips power, stops trains, or touches weapons/C2. Operational control stays with the owning agency / OT network / Netra for network XDR.
