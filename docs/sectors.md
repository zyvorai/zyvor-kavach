# Critical sectors — railways, government, industry & space

Observation-only security for public infrastructure and citizen services. Kavach **never** stops trains, trips power breakers, immobilizes vehicles, commands spacecraft, writes plant OT/MES, takes portals offline, or mutates identity / PHI / election systems.

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
| Gov vehicles | Central/state motor pools, police/ambulance/fire/traffic/VVIP fleets — never immobilizes |
| Public vehicles | City buses/STU, BRTS, taxis/cabs, autos/e-rickshaw, school buses, municipal fleets, intercity coaches, ferries |
| Automotive / EV / OEM / dealers | OEM plants, DMS, connected-car telematics, CPO backends, ARAI/MoHI posture |
| Manufacturing / parks / heavy | Discrete/process plants, SEZ IT, steel/cement, electronics, textiles — MES/OT observe only |
| Health / Pharma / Education | ABDM posture, HIMS, DIKSHA |
| Smart city / Water | ICC, CCTV VMS, utility IT |
| Space / ISRO / research | Center campus IT, launch-range support, TT&C ground stations, IIST/academia, NSIL/Antrix — never flight command |
| Disaster | NDMA / civil defence IT |

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
| `GET /v1/sectors/transport-reg` | Vahan / Sarathi |
| `GET /v1/sectors/gov-vehicles` | Government / emergency fleets |
| `GET /v1/sectors/public-vehicles` | Public mobility domain map |
| `GET /v1/sectors/city-buses` | DTC / BEST / BMTC / STU fleets |
| `GET /v1/sectors/brts` | BRTS corridors |
| `GET /v1/sectors/taxis-cabs` | Radio taxi / aggregator backends |
| `GET /v1/sectors/autos-rickshaw` | Auto / e-rickshaw fleets |
| `GET /v1/sectors/school-buses` | School / college transport |
| `GET /v1/sectors/municipal-fleet` | Sanitation / tankers / sweepers |
| `GET /v1/sectors/intercity-coaches` | State roadways / tourist coaches |
| `GET /v1/sectors/ferries` | Public ferry / water-bus IT |
| `GET /v1/sectors/automotive` | Automotive / cars / EV overview |
| `GET /v1/sectors/ev-charging` | CPO / charger backends |
| `GET /v1/sectors/vehicle-oem` | Named OEM plant IT |
| `GET /v1/sectors/dealers` | Dealer DMS / workshop IT |
| `GET /v1/sectors/manufacturing` | Plant MES/OT bridges |
| `GET /v1/sectors/industrial-parks` | SEZ / park IT |
| `GET /v1/sectors/steel-cement` | Heavy industry plant IT |
| `GET /v1/sectors/electronics-mfg` | Electronics / fab-adjacent IT |
| `GET /v1/sectors/textiles` | Textile / apparel plant IT |
| `GET /v1/sectors/space` | Space domain overview |
| `GET /v1/sectors/isro-centers` | VSSC / SAC / URSC / SHAR / … |
| `GET /v1/sectors/launch-range` | Range support IT (no flight command) |
| `GET /v1/sectors/ground-stations` | TT&C / ISTRAC-style ground IT |
| `GET /v1/sectors/space-research` | Academia / research lab IT |
| `GET /v1/sectors/nsil-antrix` | Commercial space enterprise IT |
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
./bin/kavachctl sectors gov-vehicles
./bin/kavachctl sectors public-vehicles
./bin/kavachctl sectors city-buses
./bin/kavachctl sectors taxis-cabs
./bin/kavachctl sectors school-buses
./bin/kavachctl sectors municipal-fleet
./bin/kavachctl sectors ferries
./bin/kavachctl sectors automotive
./bin/kavachctl sectors vehicle-oem
./bin/kavachctl sectors manufacturing
./bin/kavachctl sectors isro-centers
./bin/kavachctl sectors space
./bin/kavachctl sectors launch-range
./bin/kavachctl sectors gov-portals
./bin/kavachctl sectors power
./bin/kavachctl sectors critical-sites
./bin/kavachctl sectors events --sector city-buses
```

Aliases: `sector`, `railways`, `govt`, `government` → sectors summary when used alone.

## Console

**Browse → Sectors** — metric band (public fleets, city buses, ISRO), government vehicles, city buses, taxis, OEMs, manufacturing, ISRO centers, airports, flights, defence, railways, portals, recent events.

## Hard rule

`enforce: false` on summary and ingest. Detection and reporting only — never cancels flights, controls ATC, immobilizes vehicles, commands spacecraft, writes plant OT, trips power, stops trains, or touches weapons/C2. Operational control stays with the owning agency / OT network / Netra for network XDR.
