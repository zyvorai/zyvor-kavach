// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"encoding/csv"
	"regexp"
	"strings"
	"time"
)

// Firewall log parsers for a documented subset (see docs/network-detection.md): FortiGate
// key=value syslog, Palo Alto PAN-OS TRAFFIC / THREAT / CONFIG / SYSTEM CSV syslog, and a short list
// of Cisco ASA / FTD message ids. Everything else is counted as rejected. The subsets were written
// from vendor field documentation, not validated against captures from real devices.

func netParseFirewall(text string, p *netParsed, format string) error {
	lines, err := netLines(text)
	if err != nil {
		return err
	}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p.Received++
		if len(line) > webLineMax {
			p.reject(i, "line too long")
			continue
		}
		var ev NetEvent
		var why string
		switch format {
		case "fortigate":
			ev, why = fortiEvent(line)
		case "panos":
			ev, why = panEvent(line)
		default:
			ev, why = asaEvent(line)
		}
		if why != "" {
			p.reject(i, why)
			continue
		}
		p.add(ev)
	}
	return nil
}

// fortiKV scans key=value pairs; values may be double-quoted. At most 256 pairs are read.
func fortiKV(line string) map[string]string {
	m := map[string]string{}
	i, n := 0, len(line)
	for i < n && len(m) < 256 {
		for i < n && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		j := i
		for j < n && line[j] != '=' && line[j] != ' ' {
			j++
		}
		if j >= n || line[j] != '=' {
			i = j + 1
			continue
		}
		key := strings.ToLower(line[i:j])
		j++
		var val string
		if j < n && line[j] == '"' {
			k := j + 1
			for k < n && !(line[k] == '"' && line[k-1] != '\\') {
				k++
			}
			val = line[j+1 : min(k, n)]
			j = k + 1
		} else {
			k := j
			for k < n && line[k] != ' ' {
				k++
			}
			val = line[j:k]
			j = k
		}
		if len(key) <= 40 {
			m[key] = val
		}
		i = j
	}
	return m
}

func fortiEvent(line string) (NetEvent, string) {
	var e NetEvent
	f := fortiKV(line)
	if f["logid"] == "" && f["type"] == "" {
		return e, "not a FortiGate key=value line"
	}
	var t time.Time
	var ok bool
	if v := f["eventtime"]; v != "" {
		t, ok = parseWebTime(v) // epoch seconds, ms, us or ns
	}
	if !ok && f["date"] != "" && f["time"] != "" {
		t, ok = parseWebTime(f["date"] + " " + f["time"])
	}
	if !ok {
		return e, "no parseable timestamp"
	}
	e.T, e.Kind, e.Source, e.TTL, e.AuthOK = t, "fw", "fortigate", -1, -1
	_ = netSetTuple(&e, f["srcip"], f["srcport"], f["dstip"], f["dstport"])
	e.Proto = netProto(f["proto"])
	e.OrigBytes, e.RespBytes = netInt64(f["sentbyte"]), netInt64(f["rcvdbyte"])
	e.Category = "traffic"
	typ, sub := strings.ToLower(f["type"]), strings.ToLower(f["subtype"])
	switch strings.ToLower(f["action"]) {
	case "accept", "close", "timeout", "start", "client-rst", "server-rst", "allow", "pass", "ip-conn", "detected", "passthrough", "monitored", "logged":
		e.Action = "allow"
	case "deny", "block", "blocked", "drop", "dropped", "reset", "reject":
		e.Action = "deny"
	}
	e.Start = typ == "traffic" && e.Src != ""
	desc := f["logdesc"]
	e.Sig = netRedact(desc)
	low := strings.ToLower(desc + " " + f["msg"] + " " + f["status"])
	switch {
	case typ == "event" && (strings.Contains(low, "login failed") || strings.Contains(low, "authentication failed") || (strings.EqualFold(f["action"], "login") && strings.EqualFold(f["status"], "failed"))):
		e.Category = "admin-login-failed"
		e.User = webTruncate(webSanitise(f["user"]), 64)
		if e.Src == "" {
			_ = netSetTuple(&e, webPick(f, "srcip", "remip", "ui"), "", "", "")
		}
	case typ == "event" && (f["cfgpath"] != "" || strings.Contains(low, "configuration changed") || strings.Contains(low, "attribute configured") || strings.Contains(low, "object configured") || strings.Contains(low, "object deleted") || strings.Contains(low, "object attribute")):
		e.Category = "config-change"
		e.User = webTruncate(webSanitise(f["user"]), 64)
		e.Msg = netRedact("cfgpath=" + f["cfgpath"] + " " + f["msg"]) // cfgattr values are not read
	case typ == "utm" || sub == "ips" || sub == "virus" || sub == "webfilter" || sub == "anomaly":
		e.Category = "threat"
		e.Msg = netRedact(webPick(f, "attack", "msg", "virus", "hostname"))
		e.Sig = e.Msg
	}
	if e.Src == "" && e.Category == "traffic" {
		return e, "no source address"
	}
	return e, ""
}

var panTypeRe = regexp.MustCompile(`,(TRAFFIC|THREAT|CONFIG|SYSTEM),`)

// panEvent reads PAN-OS CSV syslog. Index positions follow the documented TRAFFIC log field order
// (the threat/config/system positions beyond the common prefix are from memory and unverified).
func panEvent(line string) (NetEvent, string) {
	var e NetEvent
	loc := panTypeRe.FindStringIndex(line)
	if loc == nil {
		return e, "not a PAN-OS TRAFFIC/THREAT/CONFIG/SYSTEM line"
	}
	// the syslog header (if any) is folded into field 0, which is never read
	r := csv.NewReader(strings.NewReader(line))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	c, err := r.Read()
	if err != nil || len(c) < 14 {
		return e, "too few CSV fields"
	}
	typ := strings.ToUpper(c[3])
	t, perr := time.Parse("2006/01/02 15:04:05", c[6])
	if perr != nil {
		var ok2 bool
		t, ok2 = parseWebTime(c[6])
		if !ok2 {
			return e, "no parseable generated time"
		}
	}
	e.T, e.Source, e.TTL, e.AuthOK = t.UTC(), "panos", -1, -1
	at := func(i int) string {
		if i < len(c) {
			return strings.TrimSpace(c[i])
		}
		return ""
	}
	switch typ {
	case "TRAFFIC", "THREAT":
		if !netSetTuple(&e, at(7), at(24), at(8), at(25)) {
			return e, "no valid address"
		}
		e.Proto = netProto(at(29))
		e.Category = "traffic"
		e.Start = true
		e.Sig = webTruncate(webSanitise(at(11)), 80) // rule name
		a := strings.ToLower(at(30))
		switch {
		case a == "allow" || a == "alert":
			e.Action = "allow"
		case strings.HasPrefix(a, "deny") || strings.HasPrefix(a, "drop") || strings.HasPrefix(a, "reset") || a == "block-url" || a == "block-ip":
			e.Action = "deny"
		}
		if typ == "TRAFFIC" {
			e.OrigBytes, e.RespBytes = netInt64(at(32)), netInt64(at(33))
			e.Dur = netFloat(at(36))
		} else {
			e.Category = "threat"
			e.Msg = netRedact(at(32))
		}
	case "CONFIG":
		e.Category = "config-change"
		e.Msg = netRedact("cmd=" + at(9) + " result=" + at(12))
		e.User = webTruncate(webSanitise(at(10)), 64)
		_ = netSetTuple(&e, at(11), "", "", "")
		if strings.EqualFold(at(12), "failed") || strings.EqualFold(at(12), "unauthorized") {
			e.Category = "admin-login-failed"
		}
	case "SYSTEM":
		joined := strings.ToLower(strings.Join(c[7:], " "))
		if !(strings.Contains(joined, "fail") && (strings.Contains(joined, "login") || strings.Contains(joined, "auth"))) {
			return e, "system log is not an admin login failure (ignored)"
		}
		e.Category = "admin-login-failed"
		e.Msg = netRedact(c[len(c)-1])
	default:
		return e, "unsupported PAN-OS log type"
	}
	e.Kind = "fw"
	return e, ""
}

var (
	asaHdrRe    = regexp.MustCompile(`%(?:ASA|FTD)-(\d)-(\d{6}): (.*)$`)
	asaTimeRe   = regexp.MustCompile(`([A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d\d:\d\d:\d\d)`)
	asaISORe    = regexp.MustCompile(`(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)`)
	asa106023Re = regexp.MustCompile(`^Deny (\w+) src [^:\s]+:([0-9a-fA-F:.]+)(?:/(\d+))? dst [^:\s]+:([0-9a-fA-F:.]+)(?:/(\d+))?`)
	asa106100Re = regexp.MustCompile(`^access-list (\S+) (permitted|denied|est-allowed) (\w+) [^/\s]+/([0-9a-fA-F:.]+)\((\d+)\) -> [^/\s]+/([0-9a-fA-F:.]+)\((\d+)\)`)
	asaBuiltRe  = regexp.MustCompile(`^Built (?:inbound|outbound) (TCP|UDP) connection \d+ for [^:\s]+:([0-9a-fA-F:.]+)/(\d+) \([^)]*\) to [^:\s]+:([0-9a-fA-F:.]+)/(\d+)`)
	asa710003Re = regexp.MustCompile(`^(TCP|UDP) access denied by ACL from ([0-9a-fA-F:.]+)/(\d+) to [^:\s]+:([0-9a-fA-F:.]+)/(\d+)`)
	asaIPRe     = regexp.MustCompile(`(?:from|src)\s+([0-9a-fA-F:.]{3,45})`)
	asaUserRe   = regexp.MustCompile(`[Uu]ser\W+'?([A-Za-z0-9_.@\\-]{1,64})`)
)

func asaEvent(line string) (NetEvent, string) {
	var e NetEvent
	m := asaHdrRe.FindStringSubmatch(line)
	if m == nil {
		return e, "not an ASA/FTD syslog line"
	}
	id, body := m[2], m[3]
	var t time.Time
	var ok bool
	if h := asaTimeRe.FindStringSubmatch(line[:strings.Index(line, "%")]); h != nil {
		t, ok = parseWebTime(strings.Join(strings.Fields(h[1]), " "))
	}
	if !ok {
		if h := asaISORe.FindStringSubmatch(line[:strings.Index(line, "%")]); h != nil {
			t, ok = parseWebTime(h[1])
		}
	}
	if !ok {
		return e, "no timestamp with a year in the syslog header"
	}
	e.T, e.Kind, e.Source, e.TTL, e.AuthOK, e.Category = t, "fw", "asa", -1, -1, "traffic"
	e.SigID = id
	switch id {
	case "106023":
		g := asa106023Re.FindStringSubmatch(body)
		if g == nil || !netSetTuple(&e, g[2], g[3], g[4], g[5]) {
			return e, "unparseable 106023"
		}
		e.Proto, e.Action, e.Start = netProto(g[1]), "deny", true
	case "106100":
		g := asa106100Re.FindStringSubmatch(body)
		if g == nil || !netSetTuple(&e, g[4], g[5], g[6], g[7]) {
			return e, "unparseable 106100"
		}
		e.Proto, e.Start = netProto(g[3]), true
		e.Sig = webTruncate(webSanitise(g[1]), 80)
		if g[2] == "denied" {
			e.Action = "deny"
		} else {
			e.Action = "allow"
		}
	case "302013", "302015":
		g := asaBuiltRe.FindStringSubmatch(body)
		if g == nil || !netSetTuple(&e, g[2], g[3], g[4], g[5]) {
			return e, "unparseable " + id
		}
		e.Proto, e.Action, e.Start = netProto(g[1]), "allow", true
	case "710003":
		g := asa710003Re.FindStringSubmatch(body)
		if g == nil || !netSetTuple(&e, g[2], g[3], g[4], g[5]) {
			return e, "unparseable 710003"
		}
		e.Proto, e.Action, e.Start = netProto(g[1]), "deny", true
		e.Sig = "access to the device itself denied"
	case "113005", "611102", "605004":
		e.Category = "admin-login-failed"
		if g := asaIPRe.FindStringSubmatch(body); g != nil {
			_ = netSetTuple(&e, strings.TrimRight(g[1], ":"), "", "", "")
		}
		if g := asaUserRe.FindStringSubmatch(body); g != nil {
			e.User = g[1]
		}
		e.Msg = netRedact(body)
	case "111008", "111010", "502103":
		e.Category = "config-change"
		if g := asaIPRe.FindStringSubmatch(body); g != nil {
			_ = netSetTuple(&e, strings.TrimRight(g[1], ":"), "", "", "")
		}
		if g := asaUserRe.FindStringSubmatch(body); g != nil {
			e.User = g[1]
		}
		// the command text is never kept: it can contain keys and passwords
		e.Msg = "configuration or privilege change message " + id
	default:
		return e, "unsupported ASA message id " + id
	}
	return e, ""
}
