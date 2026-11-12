// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Finance domain — banks, NBFCs, exchanges, payments, markets.
// Observation / compliance posture only — never freezes accounts, blocks trades, or moves money.

type FinanceModule struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Place  string   `json:"place"`
	Status string   `json:"status"`
	APIs   []string `json:"apis"`
	Note   string   `json:"note"`
}

func FinanceModules() []FinanceModule {
	return []FinanceModule{
		{ID: "institutions", Name: "Institutions Registry", Place: "Nariman Point", APIs: []string{"/v1/finance/institutions"}, Status: "active", Note: "Banks, NBFCs, insurers, brokers"},
		{ID: "exchanges", Name: "Exchanges", Place: "Dalal Street", APIs: []string{"/v1/finance/exchanges"}, Status: "active", Note: "BSE / NSE / MSEI style venue inventory"},
		{ID: "markets", Name: "Market Sessions", Place: "Dalal Street", APIs: []string{"/v1/finance/markets"}, Status: "active", Note: "Cash / F&O / currency session health"},
		{ID: "desks", Name: "Trading Desks", Place: "Bandra Kurla", APIs: []string{"/v1/finance/trading-desks"}, Status: "active", Note: "Equity, F&O, FX, commodity desks"},
		{ID: "workstations", Name: "Trading Workstations", Place: "Fort", APIs: []string{"/v1/finance/workstations"}, Status: "active", Note: "Dealer terminals — observe hosts only"},
		{ID: "algo", Name: "Algo / HFT Observe", Place: "GIFT City", APIs: []string{"/v1/finance/algo"}, Status: "active", Note: "Algo strategy hosts — never throttle or kill"},
		{ID: "market-data", Name: "Market Data Feeds", Place: "Churchgate", APIs: []string{"/v1/finance/market-data"}, Status: "active", Note: "Feed lag / disconnect signals"},
		{ID: "payments", Name: "Payment Rails", Place: "Electronic City", APIs: []string{"/v1/finance/payment-rails"}, Status: "active", Note: "NEFT / RTGS / IMPS / cards / UPI"},
		{ID: "upi", Name: "UPI / NPCI", Place: "Hyderabad", APIs: []string{"/v1/finance/upi"}, Status: "active", Note: "UPI PSP / app risk observations"},
		{ID: "cards", Name: "Card Issuing / Acquiring", Place: "Connaught Place", APIs: []string{"/v1/finance/cards"}, Status: "active", Note: "BIN / POS / e-com fraud signals"},
		{ID: "swift", Name: "SWIFT / Correspondent", Place: "Nariman Point", APIs: []string{"/v1/finance/swift"}, Status: "active", Note: "Message channel health — no message rewrite"},
		{ID: "treasury", Name: "Treasury", Place: "Mint Street", APIs: []string{"/v1/finance/treasury"}, Status: "active", Note: "Treasury system inventory"},
		{ID: "core", Name: "Core Banking Hosts", Place: "Fort", APIs: []string{"/v1/finance/core-banking"}, Status: "active", Note: "CBS / mid-office hosts from fleet"},
		{ID: "branches", Name: "Branches", Place: "Chowringhee", APIs: []string{"/v1/finance/branches"}, Status: "active", Note: "Branch endpoint inventory"},
		{ID: "atms", Name: "ATM / CRM Fleet", Place: "MG Road", APIs: []string{"/v1/finance/atms"}, Status: "active", Note: "ATM host / network observe"},
		{ID: "fraud", Name: "Fraud Cases", Place: "Cuffe Parade", APIs: []string{"/v1/finance/fraud"}, Status: "active", Note: "Fraud case ledger — never freezes accounts"},
		{ID: "insider", Name: "Insider / MNPI Watch", Place: "Dalal Street", APIs: []string{"/v1/finance/insider"}, Status: "active", Note: "Insider-trading style IOA observe"},
		{ID: "sanctions", Name: "Sanctions Screening", Place: "Raisina", APIs: []string{"/v1/finance/sanctions"}, Status: "active", Note: "Screening hit ledger — advisory"},
		{ID: "kyc", Name: "KYC / AML Anomalies", Place: "Ballard Estate", APIs: []string{"/v1/finance/kyc"}, Status: "active", Note: "KYC refresh / mule-pattern signals"},
		{ID: "pci", Name: "PCI-DSS Posture", Place: "BKC", APIs: []string{"/v1/finance/pci"}, Status: "active", Note: "Cardholder-data environment posture"},
		{ID: "rbi", Name: "RBI Circular Posture", Place: "Mint Street", APIs: []string{"/v1/finance/rbi"}, Status: "active", Note: "Regulatory control checklist (observe)"},
		{ID: "sebi", Name: "SEBI Market Integrity", Place: "Bandra Kurla", APIs: []string{"/v1/finance/sebi"}, Status: "active", Note: "Broker / PMS / AIF integrity signals"},
		{ID: "nbfc", Name: "NBFC Portfolio", Place: "Andheri", APIs: []string{"/v1/finance/nbfc"}, Status: "active", Note: "NBFC app / API observe"},
		{ID: "insurance", Name: "Insurance Systems", Place: "Lower Parel", APIs: []string{"/v1/finance/insurance"}, Status: "active", Note: "Policy admin / claims hosts"},
		{ID: "mutual-funds", Name: "AMFI / Mutual Funds", Place: "Bandra Kurla", APIs: []string{"/v1/finance/mutual-funds"}, Status: "active", Note: "AMC / RTA connector inventory"},
	}
}

var (
	financeMu     sync.Mutex
	financeEvents []map[string]any
)

func init() {
	seedFinanceDemo()
}

func seedFinanceDemo() {
	host, _ := os.Hostname()
	if host == "" {
		host = "controller"
	}
	now := time.Now().UTC()
	financeMu.Lock()
	defer financeMu.Unlock()
	financeEvents = []map[string]any{
		{"id": "fin-evt-1", "type": "upi_anomaly", "severity": "medium", "place": "Hyderabad", "host": host, "detail": "Burst UPI collect requests from unusual PSP app", "time": now.Add(-15 * time.Minute)},
		{"id": "fin-evt-2", "type": "market_data_lag", "severity": "high", "place": "Churchgate", "host": host, "detail": "NSE cash feed lag > 250ms", "time": now.Add(-8 * time.Minute)},
		{"id": "fin-evt-3", "type": "insider_watch", "severity": "high", "place": "Dalal Street", "host": host, "detail": "Dealer workstation accessed restricted research share", "time": now.Add(-5 * time.Minute)},
		{"id": "fin-evt-4", "type": "swift_channel", "severity": "low", "place": "Nariman Point", "host": host, "detail": "SWIFT Alliance Access heartbeat delayed", "time": now.Add(-3 * time.Minute)},
		{"id": "fin-evt-5", "type": "atm_offline", "severity": "medium", "place": "MG Road", "host": "atm-blr-0142", "detail": "ATM host missed heartbeat 90s", "time": now.Add(-2 * time.Minute)},
	}
}

func financeInstitutions() []map[string]any {
	return []map[string]any{
		{"id": "fi-sbi", "name": "State Bank of India", "type": "bank", "place": "Nariman Point", "tier": "scheduled", "regulator": "RBI"},
		{"id": "fi-hdfc", "name": "HDFC Bank", "type": "bank", "place": "Lower Parel", "tier": "scheduled", "regulator": "RBI"},
		{"id": "fi-icici", "name": "ICICI Bank", "type": "bank", "place": "BKC", "tier": "scheduled", "regulator": "RBI"},
		{"id": "fi-zerodha", "name": "Zerodha Broking", "type": "broker", "place": "Bengaluru", "tier": "SEBI", "regulator": "SEBI"},
		{"id": "fi-groww", "name": "Groww", "type": "broker", "place": "Bengaluru", "tier": "SEBI", "regulator": "SEBI"},
		{"id": "fi-bajaj", "name": "Bajaj Finance", "type": "nbfc", "place": "Pune", "tier": "NBFC-ICC", "regulator": "RBI"},
		{"id": "fi-lic", "name": "LIC", "type": "insurer", "place": "Yogakshema", "tier": "life", "regulator": "IRDAI"},
		{"id": "fi-npci", "name": "NPCI", "type": "payment", "place": "Hyderabad", "tier": "UPI", "regulator": "RBI"},
	}
}

func financeExchanges() []map[string]any {
	return []map[string]any{
		{"id": "ex-bse", "name": "BSE", "place": "Dalal Street", "segments": []string{"equity", "equity_derivatives", "currency"}, "status": "open"},
		{"id": "ex-nse", "name": "NSE", "place": "Bandra Kurla", "segments": []string{"equity", "fno", "currency", "commodity"}, "status": "open"},
		{"id": "ex-mse", "name": "MSEI", "place": "Fort", "segments": []string{"currency"}, "status": "open"},
		{"id": "ex-gift", "name": "India INX / GIFT", "place": "GIFT City", "segments": []string{"international"}, "status": "open"},
	}
}

func financeMarkets() []map[string]any {
	return []map[string]any{
		{"segment": "equity_cash", "venue": "NSE/BSE", "place": "Dalal Street", "session": "continuous", "health": "ok"},
		{"segment": "equity_fno", "venue": "NSE", "place": "Bandra Kurla", "session": "continuous", "health": "ok"},
		{"segment": "currency", "venue": "NSE/MSEI", "place": "Fort", "session": "continuous", "health": "degraded", "note": "feed lag observe"},
		{"segment": "commodity", "venue": "MCX", "place": "Exchange Plaza", "session": "continuous", "health": "ok"},
	}
}

func financeDesks() []map[string]any {
	return []map[string]any{
		{"id": "desk-eq", "name": "Equity Cash", "place": "Bandra Kurla", "headcount": 12, "risk": "medium"},
		{"id": "desk-fno", "name": "Equity F&O", "place": "Bandra Kurla", "headcount": 18, "risk": "high"},
		{"id": "desk-fx", "name": "FX / Treasury", "place": "Mint Street", "headcount": 8, "risk": "high"},
		{"id": "desk-algo", "name": "Algo / Quant", "place": "GIFT City", "headcount": 6, "risk": "critical"},
	}
}

func financeWorkstations(store *Store, registry *CredentialRegistry) []map[string]any {
	out := []map[string]any{}
	if registry != nil {
		for _, a := range registry.Status(time.Now(), 90*time.Second) {
			role := "endpoint"
			low := strings.ToLower(a.Host)
			if strings.Contains(low, "dealer") || strings.Contains(low, "trader") || strings.Contains(low, "oms") {
				role = "trading_workstation"
			}
			out = append(out, map[string]any{"host": a.Host, "state": a.State, "role": role, "place": "Fort", "sensor": a.Sensor})
		}
	}
	if len(out) == 0 {
		out = append(out,
			map[string]any{"host": "dealer-bkc-01", "state": "online", "role": "trading_workstation", "place": "Bandra Kurla", "sensor": "derived"},
			map[string]any{"host": "oms-fort-02", "state": "online", "role": "oms", "place": "Fort", "sensor": "derived"},
			map[string]any{"host": "algo-gift-01", "state": "online", "role": "algo", "place": "GIFT City", "sensor": "derived"},
		)
	}
	return out
}

func financePaymentRails() []map[string]any {
	return []map[string]any{
		{"rail": "UPI", "place": "Hyderabad", "status": "active", "tps_observe": 12000},
		{"rail": "IMPS", "place": "Electronic City", "status": "active", "tps_observe": 800},
		{"rail": "NEFT", "place": "Mint Street", "status": "active", "tps_observe": 200},
		{"rail": "RTGS", "place": "Mint Street", "status": "active", "tps_observe": 40},
		{"rail": "Cards", "place": "Connaught Place", "status": "active", "tps_observe": 3500},
		{"rail": "SWIFT", "place": "Nariman Point", "status": "degraded", "tps_observe": 5},
	}
}

func financeUPI() []map[string]any {
	return []map[string]any{
		{"psp": "PhonePe", "place": "Bengaluru", "risk": "low"},
		{"psp": "Google Pay", "place": "Hyderabad", "risk": "low"},
		{"psp": "Paytm", "place": "Noida", "risk": "medium"},
		{"psp": "BHIM", "place": "Hyderabad", "risk": "low"},
		{"app": "merchant-qr-collector", "place": "Electronic City", "risk": "high", "note": "unusual collect burst (observe)"},
	}
}

func financeCards() []map[string]any {
	return []map[string]any{
		{"bin": "4xxxxx", "scheme": "Visa", "place": "Connaught Place", "fraud_score": 12},
		{"bin": "5xxxxx", "scheme": "Mastercard", "place": "Connaught Place", "fraud_score": 18},
		{"bin": "6xxxxx", "scheme": "RuPay", "place": "Hyderabad", "fraud_score": 9},
		{"channel": "ecom", "place": "BKC", "anomaly": "velocity", "severity": "medium"},
	}
}

func financeSWIFT() []map[string]any {
	return []map[string]any{
		{"channel": "FIN", "place": "Nariman Point", "status": "up", "latency_ms": 120},
		{"channel": "FileAct", "place": "Nariman Point", "status": "up", "latency_ms": 400},
		{"channel": "Alliance Access", "place": "Fort", "status": "degraded", "latency_ms": 2400},
	}
}

func financeTreasury() []map[string]any {
	return []map[string]any{
		{"system": "treasury-front", "place": "Mint Street", "host": "trs-front-01", "status": "online"},
		{"system": "treasury-mid", "place": "Mint Street", "host": "trs-mid-01", "status": "online"},
		{"system": "alm", "place": "Nariman Point", "host": "alm-01", "status": "online"},
	}
}

func financeCore(store *Store, registry *CredentialRegistry) []map[string]any {
	out := []map[string]any{}
	for _, h := range financeWorkstations(store, registry) {
		role, _ := h["role"].(string)
		if role == "oms" || role == "endpoint" {
			out = append(out, map[string]any{"host": h["host"], "tier": "mid-office", "place": "Fort", "state": h["state"]})
		}
	}
	out = append(out,
		map[string]any{"host": "cbs-primary", "tier": "core", "place": "Fort", "state": "online"},
		map[string]any{"host": "cbs-dr", "tier": "core-dr", "place": "Chennai", "state": "online"},
	)
	return out
}

func financeBranches() []map[string]any {
	return []map[string]any{
		{"id": "br-mum-001", "name": "Fort Main", "place": "Fort", "city": "Mumbai", "endpoints": 24},
		{"id": "br-del-014", "name": "Connaught Place", "place": "Connaught Place", "city": "Delhi", "endpoints": 18},
		{"id": "br-blr-022", "name": "MG Road", "place": "MG Road", "city": "Bengaluru", "endpoints": 16},
		{"id": "br-kol-007", "name": "Chowringhee", "place": "Chowringhee", "city": "Kolkata", "endpoints": 14},
	}
}

func financeATMs() []map[string]any {
	return []map[string]any{
		{"id": "atm-mum-1001", "place": "Nariman Point", "host": "atm-mum-1001", "status": "online"},
		{"id": "atm-blr-0142", "place": "MG Road", "host": "atm-blr-0142", "status": "stale"},
		{"id": "atm-del-220", "place": "Connaught Place", "host": "atm-del-220", "status": "online"},
	}
}

func financeFraud() []map[string]any {
	financeMu.Lock()
	defer financeMu.Unlock()
	out := []map[string]any{}
	for _, e := range financeEvents {
		t, _ := e["type"].(string)
		if strings.Contains(t, "fraud") || strings.Contains(t, "upi") || strings.Contains(t, "card") {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		out = append(out, map[string]any{
			"id": "fraud-ledger-1", "status": "open", "place": "Cuffe Parade",
			"type": "account_takeover_suspect", "note": "Ledger only — no account freeze from Kavach",
		})
	}
	return out
}

func financeInsider() []map[string]any {
	return []map[string]any{
		{"id": "ins-1", "place": "Dalal Street", "host": "dealer-bkc-01", "signal": "restricted_research_access", "severity": "high"},
		{"id": "ins-2", "place": "Bandra Kurla", "host": "oms-fort-02", "signal": "after_hours_order_blotter", "severity": "medium"},
	}
}

func financeSanctions() []map[string]any {
	return []map[string]any{
		{"id": "san-1", "list": "UN", "place": "Raisina", "match": "weak", "action": "review", "note": "Advisory — no auto-block"},
		{"id": "san-2", "list": "OFAC-style", "place": "Nariman Point", "match": "none", "action": "clear"},
	}
}

func financeKYC() []map[string]any {
	return []map[string]any{
		{"id": "kyc-1", "place": "Ballard Estate", "signal": "mule_pattern", "severity": "high"},
		{"id": "kyc-2", "place": "Ballard Estate", "signal": "kyc_stale_gt_2y", "severity": "medium"},
	}
}

func financePCI() map[string]any {
	return map[string]any{
		"place": "BKC",
		"score": 78,
		"controls": []map[string]any{
			{"id": "pci-1", "name": "CDE network segment inventory", "status": "pass"},
			{"id": "pci-2", "name": "PAN storage observe", "status": "warn"},
			{"id": "pci-3", "name": "POS endpoint sensor coverage", "status": "pass"},
		},
		"note": "Posture only — Kavach does not reconfigure payment switches",
	}
}

func financeRBI() []map[string]any {
	return []map[string]any{
		{"circular": "IT Framework", "place": "Mint Street", "control": "SOC monitoring", "status": "mapped"},
		{"circular": "Digital Payment Security", "place": "Mint Street", "control": "UPI anomaly observe", "status": "mapped"},
		{"circular": "Cyber Security", "place": "Mint Street", "control": "Endpoint EDR coverage", "status": "mapped"},
		{"circular": "Outsourcing", "place": "Mint Street", "control": "Vendor connector inventory", "status": "partial"},
	}
}

func financeSEBI() []map[string]any {
	return []map[string]any{
		{"theme": "market_integrity", "place": "Bandra Kurla", "signal": "wash_trade_pattern_observe", "severity": "medium"},
		{"theme": "algo_governance", "place": "GIFT City", "signal": "unregistered_algo_host", "severity": "high"},
		{"theme": "client_order", "place": "Dalal Street", "signal": "blotter_access_anomaly", "severity": "low"},
	}
}

func financeNBFC() []map[string]any {
	return []map[string]any{
		{"name": "Bajaj Finance apps", "place": "Pune", "risk": "medium"},
		{"name": "Gold loan origination API", "place": "Andheri", "risk": "high"},
	}
}

func financeInsurance() []map[string]any {
	return []map[string]any{
		{"system": "policy-admin", "place": "Lower Parel", "status": "online"},
		{"system": "claims", "place": "Lower Parel", "status": "online"},
	}
}

func financeMutualFunds() []map[string]any {
	return []map[string]any{
		{"amc": "SBI MF", "place": "Bandra Kurla", "rta": "CAMS"},
		{"amc": "HDFC MF", "place": "BKC", "rta": "CAMS"},
		{"amc": "ICICI Pru MF", "place": "BKC", "rta": "KFin"},
	}
}

func financeAlgo() []map[string]any {
	return []map[string]any{
		{"id": "algo-1", "place": "GIFT City", "host": "algo-gift-01", "strategy": "market_making", "status": "observed"},
		{"id": "algo-2", "place": "GIFT City", "host": "algo-gift-02", "strategy": "stat_arb", "status": "observed"},
		{"note": "Observe only — Kavach never pauses or kills strategies"},
	}
}

func financeMarketData() []map[string]any {
	return []map[string]any{
		{"feed": "NSE_CM", "place": "Churchgate", "lag_ms": 12, "status": "ok"},
		{"feed": "NSE_FO", "place": "Churchgate", "lag_ms": 18, "status": "ok"},
		{"feed": "BSE_CM", "place": "Dalal Street", "lag_ms": 280, "status": "lag"},
		{"feed": "MCX", "place": "Exchange Plaza", "lag_ms": 40, "status": "ok"},
	}
}

func financeSummary(store *Store, registry *CredentialRegistry) map[string]any {
	return map[string]any{
		"product":       "kavach-finance",
		"mode":          "observe-only",
		"enforce":       false,
		"modules":       len(FinanceModules()),
		"institutions":  len(financeInstitutions()),
		"exchanges":     len(financeExchanges()),
		"workstations":  len(financeWorkstations(store, registry)),
		"payment_rails": len(financePaymentRails()),
		"open_fraud":    len(financeFraud()),
		"events":        len(listFinanceEvents("")),
		"places":        []string{"Dalal Street", "GIFT City", "Mint Street", "Bandra Kurla", "Nariman Point", "Hyderabad"},
		"note":          "Banking & markets security observe — never freezes accounts, blocks orders, or drops payment messages",
	}
}

func listFinanceEvents(typ string) []map[string]any {
	financeMu.Lock()
	defer financeMu.Unlock()
	out := make([]map[string]any, 0, len(financeEvents))
	for _, e := range financeEvents {
		if typ != "" {
			t, _ := e["type"].(string)
			if !strings.EqualFold(t, typ) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

func ingestFinanceEvents(events []map[string]any) int {
	financeMu.Lock()
	defer financeMu.Unlock()
	n := 0
	for _, e := range events {
		if e == nil {
			continue
		}
		if e["id"] == nil {
			e["id"] = "fin-" + time.Now().UTC().Format("150405.000")
		}
		if e["time"] == nil {
			e["time"] = time.Now().UTC()
		}
		financeEvents = append(financeEvents, e)
		n++
	}
	if len(financeEvents) > 2000 {
		financeEvents = financeEvents[len(financeEvents)-2000:]
	}
	return n
}

// RegisterFinancePlatform wires banking / markets observe APIs.
func RegisterFinancePlatform(mux *http.ServeMux, token string, store *Store, registry *CredentialRegistry) {
	get := func(path string, fn func() any) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			if !requireAuth(w, r, token) {
				return
			}
			writeJSON(w, fn())
		})
	}

	get("/v1/finance/modules", func() any { return FinanceModules() })
	get("/v1/finance/summary", func() any { return financeSummary(store, registry) })
	get("/v1/finance/institutions", func() any { return financeInstitutions() })
	get("/v1/finance/exchanges", func() any { return financeExchanges() })
	get("/v1/finance/markets", func() any { return financeMarkets() })
	get("/v1/finance/trading-desks", func() any { return financeDesks() })
	get("/v1/finance/workstations", func() any { return financeWorkstations(store, registry) })
	get("/v1/finance/algo", func() any { return financeAlgo() })
	get("/v1/finance/market-data", func() any { return financeMarketData() })
	get("/v1/finance/payment-rails", func() any { return financePaymentRails() })
	get("/v1/finance/upi", func() any { return financeUPI() })
	get("/v1/finance/cards", func() any { return financeCards() })
	get("/v1/finance/swift", func() any { return financeSWIFT() })
	get("/v1/finance/treasury", func() any { return financeTreasury() })
	get("/v1/finance/core-banking", func() any { return financeCore(store, registry) })
	get("/v1/finance/branches", func() any { return financeBranches() })
	get("/v1/finance/atms", func() any { return financeATMs() })
	get("/v1/finance/fraud", func() any { return financeFraud() })
	get("/v1/finance/insider", func() any { return financeInsider() })
	get("/v1/finance/sanctions", func() any { return financeSanctions() })
	get("/v1/finance/kyc", func() any { return financeKYC() })
	get("/v1/finance/pci", func() any { return financePCI() })
	get("/v1/finance/rbi", func() any { return financeRBI() })
	get("/v1/finance/sebi", func() any { return financeSEBI() })
	get("/v1/finance/nbfc", func() any { return financeNBFC() })
	get("/v1/finance/insurance", func() any { return financeInsurance() })
	get("/v1/finance/mutual-funds", func() any { return financeMutualFunds() })

	mux.HandleFunc("GET /v1/finance/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		writeJSON(w, listFinanceEvents(r.URL.Query().Get("type")))
	})
	mux.HandleFunc("POST /v1/finance/events", func(w http.ResponseWriter, r *http.Request) {
		if !requireAuth(w, r, token) {
			return
		}
		var body struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		writeJSON(w, map[string]any{"ingested": ingestFinanceEvents(body.Events), "enforce": false})
	})
}
