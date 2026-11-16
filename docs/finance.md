# Dalal Street Finance — banks, markets, payments & insurance

Observation-only security for financial institutions. Kavach **never** freezes accounts, blocks orders, kills algo strategies, cancels policies, or rewrites SWIFT / UPI / card messages.

## Places

| Place | Focus |
|-------|--------|
| Dalal Street | Exchanges, insider / MNPI watch |
| GIFT City | Algo / HFT observe |
| Mint Street | RBI posture, treasury, NEFT/RTGS |
| Bandra Kurla (BKC) | Trading desks, SEBI, mutual funds, PCI, motor insurance |
| Nariman Point | Banks, SWIFT |
| Lower Parel | Insurance / TPA / reinsurance |
| Hyderabad | UPI / NPCI |
| Connaught Place | Cards |
| Electronic City | Payment rails |
| Cuffe Parade | Fraud ledger |

## APIs

All under `/v1/finance/*` (bearer / session auth).

| Path | Purpose |
|------|---------|
| `GET /v1/finance/summary` | Module counts + enforce=false |
| `GET /v1/finance/modules` | Capability map |
| `GET /v1/finance/institutions` | Banks, NBFCs, brokers, insurers |
| `GET /v1/finance/exchanges` | BSE / NSE / MSEI / GIFT |
| `GET /v1/finance/markets` | Cash / F&O / currency sessions |
| `GET /v1/finance/trading-desks` | Desk inventory |
| `GET /v1/finance/workstations` | Dealer hosts from fleet |
| `GET /v1/finance/algo` | Algo/HFT hosts (observe) |
| `GET /v1/finance/market-data` | Feed lag signals |
| `GET /v1/finance/payment-rails` | UPI / IMPS / NEFT / RTGS / cards / SWIFT |
| `GET /v1/finance/upi` | PSP / app risk |
| `GET /v1/finance/cards` | BIN / channel fraud signals |
| `GET /v1/finance/swift` | Correspondent channel health |
| `GET /v1/finance/treasury` | Treasury systems |
| `GET /v1/finance/core-banking` | CBS hosts from fleet |
| `GET /v1/finance/branches` | Branch endpoints |
| `GET /v1/finance/atms` | ATM / CRM fleet |
| `GET /v1/finance/fraud` | Fraud cases (no freeze) |
| `GET /v1/finance/insider` | Insider-trading style IOA |
| `GET /v1/finance/sanctions` | Screening hits (advisory) |
| `GET /v1/finance/kyc` | KYC / AML anomalies |
| `GET /v1/finance/pci` | PCI-DSS posture |
| `GET /v1/finance/rbi` | RBI circular checklist |
| `GET /v1/finance/sebi` | SEBI integrity signals |
| `GET /v1/finance/nbfc` | NBFC portfolio |
| `GET /v1/finance/insurance` | Life / general / health / motor systems |
| `GET /v1/finance/insurance-lines` | Product line inventory |
| `GET /v1/finance/insurance-tpa` | TPA / claims processors |
| `GET /v1/finance/reinsurance` | Reinsurer connectors |
| `GET /v1/finance/irdai` | IRDAI circular / posture checklist |
| `GET /v1/finance/motor-insurance` | Motor policy systems (never cancels) |
| `GET /v1/finance/mutual-funds` | AMC / RTA inventory |
| `GET /v1/finance/events?type=` | Observe event ledger |
| `POST /v1/finance/events` | Ingest `{ "events": [...] }` |

## kavachctl

```bash
./bin/kavachctl finance summary
./bin/kavachctl finance exchanges
./bin/kavachctl finance upi
./bin/kavachctl finance markets
./bin/kavachctl finance fraud
./bin/kavachctl finance sebi
./bin/kavachctl finance rbi
./bin/kavachctl finance insurance
./bin/kavachctl finance insurance-lines
./bin/kavachctl finance insurance-tpa
./bin/kavachctl finance reinsurance
./bin/kavachctl finance irdai
./bin/kavachctl finance motor-insurance
./bin/kavachctl finance events --type claims_burst
```

Aliases: `fin`, `banking`.

## Console

**Browse -> Finance** (`#/finance`, no g-key; open it from the Browse menu, the palette, or the hash).

- Metric band: modules, institutions, exchanges, insurance, events.
- Tables: exchanges and markets (venue, place, segments, status), payment rails, institutions, insurers, IRDAI posture, and recent finance events.
- Data: `/v1/finance/summary|exchanges|payment-rails|institutions|insurance|irdai|events`. These are fetched with the console's main data load (at sign-in and on refresh), not when the page is opened, so a failed request shows in the main page error line rather than inside the page.
- Controls: read-only. Every table gets the standard tool row (column toggle, CSV and JSON export of loaded rows, click-to-sort) and the page gets the saved-views bar; see [console](console.md).
- Empty state: a table with no data shows an empty-state row; the event ledger also shows events posted to `POST /v1/finance/events`. Inventory domains are served as empty lists, never null.
- Not on the page: markets, trading desks, algo, UPI, cards, SWIFT, treasury, fraud, insider, sanctions, KYC, PCI, RBI, SEBI, NBFC and mutual-fund routes are API and `kavachctl` only.
- Known limit: the dark theme and the 390px phone width of this page are unverified in a browser; see [console-qa](console-qa.md).

## Hard rule

`enforce: false` on summary and ingest. Detection and reporting only — money movement and policy actions stay with bank/exchange/insurer rails and Netra for network XDR. Never freezes accounts or cancels policies.
