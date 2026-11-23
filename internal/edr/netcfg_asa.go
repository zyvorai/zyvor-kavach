// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Cisco ASA / FTD-style running-config text. Commands read: access-list NAME [line N] [extended]
// permit|deny PROTO SRC [PORT] DST [PORT] [log [disable]] [inactive] [time-range X], access-list
// NAME remark TEXT, access-group NAME in|out|global [interface IF], object network (host, subnet,
// range, fqdn), object service (service PROTO ... destination eq|range), object-group network
// (network-object host|ADDR MASK|object, group-object), object-group service (port-object eq|range,
// service-object, group-object), object-group protocol, name ADDR NAME, interface + nameif +
// security-level, ssh|telnet|http ADDR MASK IF, ssh version, ssh key-exchange, ssl server-version,
// snmp-server community|host, username ... password, enable password, passwd, logging enable|host,
// crypto ikev1|ikev2|isakmp policy (encryption, hash, integrity, group). Syntax follows the public
// command reference and common configurations; see docs/netcfg-posture.md for what is unverified.

var asaPorts = map[string]int{"www": 80, "http": 80, "https": 443, "ssh": 22, "telnet": 23, "ftp": 21, "ftp-data": 20, "domain": 53, "smtp": 25,
	"pop3": 110, "imap4": 143, "snmp": 161, "snmptrap": 162, "ldap": 389, "ldaps": 636, "sqlnet": 1521, "netbios-ssn": 139, "netbios-ns": 137,
	"netbios-dgm": 138, "pptp": 1723, "ntp": 123, "tftp": 69, "syslog": 514, "sip": 5060, "rdp": 3389, "echo": 7, "bgp": 179, "nfs": 2049, "kerberos": 750}

type asaGroup struct {
	Kind string // network, service, protocol
	Net  ncSet
	Svc  ncSvc
	Line int
	OK   bool
}

type asaCtx struct {
	kind, name string
	line       int
}

func asaPort(proto, tok string) (int, bool) {
	if n, err := strconv.Atoi(tok); err == nil && n >= 0 && n <= 65535 {
		return n, true
	}
	n, ok := asaPorts[strings.ToLower(tok)]
	return n, ok
}

func ncParseASA(text string) (*ncModel, error) {
	m := newNcModel("cisco-asa")
	m.DescSupported = true
	lines := ncSplitLines(text, m)
	aliases := map[string]string{} // name command
	objNet := map[string]*ncSet{}
	objSvc := map[string]*ncSvc{}
	groups := map[string]*asaGroup{}
	ifLevel := map[string]int{}
	ifName := map[string]string{} // interface id -> nameif
	type bind struct {
		dir, iface string
	}
	binds := map[string][]bind{}
	remarks := map[string]string{}
	type pending struct {
		rule *ncRule
		acl  string
	}
	var pend []pending
	var ctx *asaCtx
	curIf := ""
	recognised := 0
	sawLogEnable, sawNoLog := false, false

	// pass 1: definitions that ACEs refer to (objects appear before ACLs, but do not rely on it)
	for i, raw := range lines {
		if raw == "" {
			continue
		}
		indented := raw[0] == ' '
		l := strings.TrimSpace(raw)
		if l == "" || l[0] == '!' {
			if !indented {
				ctx = nil
			}
			continue
		}
		t := ncTokens(l)
		if !indented {
			ctx = nil
			switch {
			case len(t) >= 3 && t[0] == "object" && (t[1] == "network" || t[1] == "service"):
				ctx = &asaCtx{kind: "object-" + t[1], name: t[2], line: i + 1}
				if t[1] == "network" {
					objNet[strings.ToLower(t[2])] = &ncSet{}
				} else {
					objSvc[strings.ToLower(t[2])] = &ncSvc{}
				}
				m.addObj(map[string]string{"network": "address", "service": "service"}[t[1]], t[2], ncLine(i+1)+" (object "+t[1]+")", "")
			case len(t) >= 3 && t[0] == "object-group" && (t[1] == "network" || t[1] == "service" || t[1] == "protocol"):
				ctx = &asaCtx{kind: "group-" + t[1], name: t[2], line: i + 1}
				g := &asaGroup{Kind: t[1], Line: i + 1, OK: true}
				if t[1] == "service" && len(t) >= 4 {
					g.Svc = ncSvc{}
				}
				groups[strings.ToLower(t[2])] = g
				k := "address"
				if t[1] != "network" {
					k = "service"
				}
				m.addObj(k, t[2], ncLine(i+1)+" (object-group "+t[1]+")", "")
			case len(t) >= 3 && t[0] == "name":
				aliases[strings.ToLower(t[2])] = t[1]
			case len(t) >= 2 && t[0] == "interface":
				curIf = t[1]
				ctx = &asaCtx{kind: "interface", name: t[1], line: i + 1}
			case len(t) >= 2 && (t[0] == "crypto") && len(t) >= 4 && (t[1] == "ikev1" || t[1] == "ikev2" || t[1] == "isakmp") && t[2] == "policy":
				ctx = &asaCtx{kind: "ike", name: strings.Join(t[1:], " "), line: i + 1}
			}
			continue
		}
		if ctx == nil {
			continue
		}
		g := groups[strings.ToLower(ctx.name)]
		switch ctx.kind {
		case "object-network":
			s := objNet[strings.ToLower(ctx.name)]
			switch {
			case len(t) >= 2 && t[0] == "host":
				if p, _, ok := ncParseAddrTok(asaAlias(aliases, t[1])); ok {
					s.addPrefix(p)
				} else {
					s.addOpq("val:" + strings.ToLower(t[1]))
				}
			case len(t) >= 3 && t[0] == "subnet":
				if p, ok := ncMaskPrefix(t[1], t[2]); ok {
					if p.Bits() == 0 {
						s.Any = true
					} else {
						s.addPrefix(p)
					}
				} else {
					s.addOpq("val:" + strings.ToLower(t[1]+" "+t[2]))
				}
			case len(t) >= 2 && t[0] == "subnet":
				if p, _, ok := ncParseAddrTok(t[1]); ok {
					s.addPrefix(p)
				}
			case len(t) >= 3 && t[0] == "range":
				s.addOpq("range:" + strings.ToLower(t[1]+"-"+t[2]))
			case len(t) >= 2 && t[0] == "fqdn":
				s.addOpq("fqdn:" + strings.ToLower(t[len(t)-1]))
			}
			m.Objs["address:"+strings.ToLower(ctx.name)].Sig = s.sig()
		case "object-service":
			s := objSvc[strings.ToLower(ctx.name)]
			if t[0] == "service" && len(t) >= 2 {
				asaServiceSpec(t[1:], s)
			}
			m.Objs["service:"+strings.ToLower(ctx.name)].Sig = s.sig()
		case "group-network":
			if g == nil {
				break
			}
			switch {
			case len(t) >= 3 && t[0] == "network-object" && t[1] == "host":
				if p, _, ok := ncParseAddrTok(asaAlias(aliases, t[2])); ok {
					g.Net.addPrefix(p)
				} else {
					g.Net.addOpq("val:" + strings.ToLower(t[2]))
				}
			case len(t) >= 3 && t[0] == "network-object" && t[1] == "object":
				g.Net.addOpq("grpref:o:" + strings.ToLower(t[2]))
			case len(t) >= 3 && t[0] == "network-object":
				if p, ok := ncMaskPrefix(t[1], t[2]); ok {
					if p.Bits() == 0 {
						g.Net.Any = true
					} else {
						g.Net.addPrefix(p)
					}
				} else if p, _, ok := ncParseAddrTok(t[1]); ok {
					g.Net.addPrefix(p)
				} else {
					g.Net.addOpq("val:" + strings.ToLower(t[1]))
				}
			case len(t) >= 2 && t[0] == "network-object":
				if p, _, ok := ncParseAddrTok(t[1]); ok {
					g.Net.addPrefix(p)
				}
			case len(t) >= 2 && t[0] == "group-object":
				g.Net.addOpq("grpref:g:" + strings.ToLower(t[1]))
			}
		case "group-service", "group-protocol":
			if g == nil {
				break
			}
			switch {
			case len(t) >= 3 && t[0] == "port-object" && t[1] == "eq":
				if n, ok := asaPort("tcp", t[2]); ok {
					g.Svc.addRange(ncRange{"tcp-udp", n, n})
				} else {
					g.Svc.addOpq("port:" + strings.ToLower(t[2]))
				}
			case len(t) >= 4 && t[0] == "port-object" && t[1] == "range":
				a, ok1 := asaPort("tcp", t[2])
				b, ok2 := asaPort("tcp", t[3])
				if ok1 && ok2 && a <= b {
					g.Svc.addRange(ncRange{"tcp-udp", a, b})
				} else {
					g.Svc.addOpq("port:" + strings.ToLower(t[2]+"-"+t[3]))
				}
			case len(t) >= 2 && t[0] == "service-object":
				if t[1] == "object" && len(t) >= 3 {
					g.Svc.addOpq("grpref:o:" + strings.ToLower(t[2]))
				} else {
					asaServiceSpec(t[1:], &g.Svc)
				}
			case len(t) >= 2 && t[0] == "protocol-object":
				asaServiceSpec(t[1:], &g.Svc)
			case len(t) >= 2 && t[0] == "group-object":
				g.Svc.addOpq("grpref:g:" + strings.ToLower(t[1]))
			}
		case "interface":
			if t[0] == "nameif" && len(t) >= 2 {
				ifName[curIf] = t[1]
			}
			if t[0] == "security-level" && len(t) >= 2 {
				if n, err := strconv.Atoi(t[1]); err == nil {
					if nm := ifName[curIf]; nm != "" {
						ifLevel[strings.ToLower(nm)] = n
					} else {
						ifLevel["\x00"+curIf] = n
					}
				}
			}
		case "ike":
			if len(t) >= 2 {
				v := strings.ToLower(t[len(t)-1])
				switch {
				case (t[0] == "encryption") && (v == "des" || v == "3des" || strings.Contains(v, "des") && !strings.Contains(v, "aes")):
					m.issue("netcfg-weak-crypto", ncLine(i+1)+" ("+ctx.name+")", "IKE policy encryption "+ncClean(v))
				case (t[0] == "hash" || t[0] == "integrity") && (v == "md5" || strings.Contains(strings.ToLower(l), "md5")):
					m.issue("netcfg-weak-crypto", ncLine(i+1)+" ("+ctx.name+")", "IKE policy "+t[0]+" md5")
				case t[0] == "group":
					for _, g := range t[1:] {
						if g == "1" || g == "2" || g == "5" {
							m.issue("netcfg-weak-crypto", ncLine(i+1)+" ("+ctx.name+")", "IKE policy DH group "+g+" is small")
						}
					}
				}
			}
		}
	}
	// nameif may follow security-level on odd exports: resolve leftovers
	for k, v := range ifLevel {
		if strings.HasPrefix(k, "\x00") {
			if nm := ifName[k[1:]]; nm != "" {
				ifLevel[strings.ToLower(nm)] = v
			}
			delete(ifLevel, k)
		}
	}
	untrustedIf := func(n string) bool {
		if lv, ok := ifLevel[strings.ToLower(n)]; ok && lv == 0 {
			return true
		}
		return ncUntrustedName(n)
	}

	// resolution helpers
	var resNet func(name string, depth int, out *ncSet) bool
	resNet = func(name string, depth int, out *ncSet) bool {
		l := strings.ToLower(name)
		if o, ok := objNet[l]; ok {
			m.use("address", name)
			out.merge(*o)
			return true
		}
		g, ok := groups[l]
		if !ok || g.Kind != "network" || depth >= ncExpandDepth {
			out.addOpq("name:" + l)
			return false
		}
		m.use("address", name)
		good := true
		out.merge(ncSet{Any: g.Net.Any, Pfx: g.Net.Pfx})
		for k := range g.Net.Opq {
			switch {
			case strings.HasPrefix(k, "grpref:o:"):
				good = resNet(k[9:], depth+1, out) && good
			case strings.HasPrefix(k, "grpref:g:"):
				good = resNet(k[9:], depth+1, out) && good
			default:
				out.addOpq(k)
			}
		}
		return good && out.size() <= ncExpandMax
	}
	var resSvc func(name string, depth int, out *ncSvc) bool
	resSvc = func(name string, depth int, out *ncSvc) bool {
		l := strings.ToLower(name)
		if o, ok := objSvc[l]; ok {
			m.use("service", name)
			out.merge(*o)
			return true
		}
		g, ok := groups[l]
		if !ok || g.Kind == "network" || depth >= ncExpandDepth {
			out.addOpq("name:" + l)
			return false
		}
		m.use("service", name)
		good := true
		out.merge(ncSvc{Any: g.Svc.Any, R: g.Svc.R})
		for k := range g.Svc.Opq {
			if strings.HasPrefix(k, "grpref:") {
				good = resSvc(k[9:], depth+1, out) && good
			} else {
				out.addOpq(k)
			}
		}
		return good && out.size() <= ncExpandMax
	}
	// address operand: returns next index
	addr := func(t []string, i int, out *ncSet) (int, bool) {
		if i >= len(t) {
			return i, false
		}
		switch strings.ToLower(t[i]) {
		case "any", "any4", "any6":
			out.Any = true
			return i + 1, true
		case "host":
			if i+1 < len(t) {
				if p, _, ok := ncParseAddrTok(asaAlias(aliases, t[i+1])); ok {
					out.addPrefix(p)
				} else {
					out.addOpq("val:" + strings.ToLower(t[i+1]))
				}
				return i + 2, true
			}
		case "object":
			if i+1 < len(t) {
				return i + 2, resNet(t[i+1], 0, out)
			}
		case "object-group":
			if i+1 < len(t) {
				return i + 2, resNet(t[i+1], 0, out)
			}
		case "interface":
			if i+1 < len(t) {
				out.addOpq("if:" + strings.ToLower(t[i+1]))
				return i + 2, true
			}
		}
		a := asaAlias(aliases, t[i])
		if p, isAny, ok := ncParseAddrTok(a); ok && strings.Contains(a, "/") {
			if isAny {
				out.Any = true
			} else {
				out.addPrefix(p)
			}
			return i + 1, true
		}
		if i+1 < len(t) {
			if p, ok := ncMaskPrefix(a, t[i+1]); ok {
				if p.Bits() == 0 {
					out.Any = true
				} else {
					out.addPrefix(p)
				}
				return i + 2, true
			}
		}
		if p, _, ok := ncParseAddrTok(a); ok { // lone address
			out.addPrefix(p)
			return i + 1, true
		}
		if _, ok := aliases[strings.ToLower(t[i])]; ok {
			return i + 1, true
		}
		out.addOpq("name:" + strings.ToLower(t[i]))
		return i + 1, false
	}
	// port operand for tcp/udp
	portOp := func(proto string, t []string, i int, out *ncSvc, allowGroup bool) (int, bool, bool) { // next, consumed, ok
		if i >= len(t) {
			return i, false, true
		}
		switch strings.ToLower(t[i]) {
		case "eq", "gt", "lt", "neq":
			if i+1 >= len(t) {
				return i, false, false
			}
			n, ok := asaPort(proto, t[i+1])
			if !ok {
				out.addOpq("port:" + strings.ToLower(t[i+1]))
				return i + 2, true, false
			}
			switch strings.ToLower(t[i]) {
			case "eq":
				out.addRange(ncRange{proto, n, n})
			case "gt":
				out.addRange(ncRange{proto, n + 1, 65535})
			case "lt":
				out.addRange(ncRange{proto, 0, n - 1})
			default:
				out.addOpq("neq:" + strconv.Itoa(n))
				return i + 2, true, false
			}
			return i + 2, true, true
		case "range":
			if i+2 >= len(t) {
				return i, false, false
			}
			a, ok1 := asaPort(proto, t[i+1])
			b, ok2 := asaPort(proto, t[i+2])
			if !ok1 || !ok2 || a > b {
				out.addOpq("port:" + strings.ToLower(t[i+1]+"-"+t[i+2]))
				return i + 3, true, false
			}
			out.addRange(ncRange{proto, a, b})
			return i + 3, true, true
		case "object-group":
			if allowGroup && i+1 < len(t) {
				if g, ok := groups[strings.ToLower(t[i+1])]; ok && g.Kind == "service" {
					var s ncSvc
					good := resSvc(t[i+1], 0, &s)
					for _, r := range s.R {
						if r.Proto == "tcp-udp" {
							out.addRange(ncRange{proto, r.Lo, r.Hi})
						} else {
							out.addRange(r)
						}
					}
					for k := range s.Opq {
						out.addOpq(k)
					}
					return i + 2, true, good
				}
			}
		}
		return i, false, true
	}

	// pass 2: access lists, bindings, management and device settings
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if l == "" || raw[0] == ' ' || l[0] == '!' {
			continue
		}
		t := ncTokens(l)
		if len(t) == 0 {
			continue
		}
		loc := ncLine(i + 1)
		switch t[0] {
		case "access-list":
			recognised++
			if len(t) < 4 {
				continue
			}
			acl := t[1]
			j := 2
			if t[j] == "line" && j+1 < len(t) {
				j += 2
			}
			if t[j] == "remark" {
				remarks[acl] = strings.Join(t[j+1:], " ")
				continue
			}
			if t[j] == "extended" || t[j] == "standard" || t[j] == "webtype" || t[j] == "ethertype" {
				if t[j] != "extended" {
					m.note("access-list kind " + t[j] + " is not analysed")
					continue
				}
				j++
			}
			if j >= len(t) || (t[j] != "permit" && t[j] != "deny") {
				continue
			}
			r := &ncRule{Scope: "acl:" + acl, Loc: loc + " (access-list " + ncClean(acl) + ")", Terminal: true, Allow: t[j] == "permit", Log: "unknown", Inspect: "unknown"}
			r.Name = acl
			r.Desc = remarks[acl]
			r.App.Any = true
			r.SrcZ.Any, r.DstZ.Any = true, true
			j++
			ok := true
			var extra []string
			proto := ""
			if j >= len(t) {
				continue
			}
			p := strings.ToLower(t[j])
			j++
			switch p {
			case "object", "object-group":
				if j < len(t) {
					var s ncSvc
					ok = resSvc(t[j], 0, &s) && ok
					for _, rg := range s.R {
						r.Svc.addRange(rg)
					}
					r.Svc.Any = r.Svc.Any || s.Any
					for k := range s.Opq {
						r.Svc.addOpq(k)
					}
					j++
				}
			case "ip":
				r.Svc.Any = true
			case "tcp", "udp", "icmp", "icmp6", "sctp", "gre", "esp", "ah", "ospf", "eigrp":
				proto = p
			case "tcp-udp":
				proto = "tcp-udp"
			default:
				if n, err := strconv.Atoi(p); err == nil && n == 0 {
					r.Svc.Any = true
				} else {
					r.Svc.addRange(ncRange{p, 0, 0})
				}
			}
			var good bool
			j, good = addr(t, j, &r.Src)
			ok = ok && good
			var sport, dport ncSvc
			pr := proto
			if pr == "tcp-udp" {
				pr = "tcp"
			}
			if proto == "tcp" || proto == "udp" || proto == "tcp-udp" {
				var c, g2 bool
				j, c, g2 = portOp(pr, t, j, &sport, true)
				_ = c
				ok = ok && g2
			}
			j, good = addr(t, j, &r.Dst)
			ok = ok && good
			if proto == "tcp" || proto == "udp" || proto == "tcp-udp" {
				var c, g2 bool
				j, c, g2 = portOp(pr, t, j, &dport, true)
				_ = c
				ok = ok && g2
				if proto == "tcp-udp" {
					for _, rg := range dport.R {
						r.Svc.addRange(ncRange{"udp", rg.Lo, rg.Hi})
					}
				}
				if dport.size() == 0 && !dport.Any {
					r.Svc.addRange(ncRange{pr, 0, 65535})
					if proto == "tcp-udp" {
						r.Svc.addRange(ncRange{"udp", 0, 65535})
					}
				} else {
					r.Svc.merge(dport)
				}
				if sport.size() > 0 {
					extra = append(extra, "sport="+sport.sig())
				}
			} else if proto == "icmp" || proto == "icmp6" {
				r.Svc.addRange(ncRange{"icmp", 0, 0})
				if j < len(t) && t[j] != "log" && t[j] != "inactive" && t[j] != "time-range" {
					if t[j] == "object-group" && j+1 < len(t) {
						extra = append(extra, "icmp="+strings.ToLower(t[j+1]))
						j += 2
					} else {
						extra = append(extra, "icmp="+strings.ToLower(t[j]))
						j++
					}
				}
			} else if proto != "" {
				r.Svc.addRange(ncRange{proto, 0, 0})
			}
			for ; j < len(t); j++ {
				switch t[j] {
				case "log":
					r.Log = "on"
					if j+1 < len(t) && t[j+1] == "disable" {
						r.Log = "off"
						j++
					}
				case "inactive":
					r.Disabled = true
				case "time-range":
					if j+1 < len(t) {
						extra = append(extra, "time-range="+strings.ToLower(t[j+1]))
						j++
					}
				}
			}
			r.Extra = strings.Join(extra, ";")
			r.Complex = !ok
			if r.Svc.size() > ncExpandMax || r.Src.size() > ncExpandMax || r.Dst.size() > ncExpandMax {
				r.Complex = true
			}
			if m.addRule(r) {
				pend = append(pend, pending{r, acl})
			}
		case "access-group":
			recognised++
			if len(t) >= 3 {
				switch {
				case t[2] == "global":
					binds[t[1]] = append(binds[t[1]], bind{"global", ""})
				case len(t) >= 5 && t[3] == "interface":
					binds[t[1]] = append(binds[t[1]], bind{t[2], t[4]})
				}
			}
		case "ssh", "telnet", "http":
			recognised++
			asaMgmt(m, t, loc, untrustedIf)
		case "snmp-server":
			recognised++
			for k := 1; k+1 < len(t); k++ {
				if t[k] == "community" {
					c := strings.ToLower(t[k+1])
					if fgWeakComm[c] {
						m.issue("netcfg-weak-snmp", loc, fmt.Sprintf("snmp-server uses a default or well-known community (value not shown, %d characters)", len(c)))
					}
				}
			}
		case "ssl":
			recognised++
			asaSSL(m, t, loc)
		case "username":
			recognised++
			if len(t) >= 3 {
				enc := false
				for _, w := range t[3:] {
					lw := strings.ToLower(w)
					if lw == "encrypted" || lw == "nt-encrypted" || lw == "pbkdf2" {
						enc = true
					}
				}
				switch {
				case t[2] == "nopassword":
					m.issue("netcfg-default-credentials", loc, "user "+ncClean(t[1])+" has no password")
				case t[2] == "password" && !enc && len(t) >= 4:
					m.issue("netcfg-default-credentials", loc, "user "+ncClean(t[1])+" password is not marked encrypted, so it may be in clear text (value not shown)")
				}
			}
		case "enable", "passwd", "password":
			recognised++
			if (t[0] == "enable" && len(t) >= 3 && t[1] == "password") || (t[0] == "passwd" && len(t) >= 2) {
				enc := false
				for _, w := range t {
					if strings.EqualFold(w, "encrypted") || strings.EqualFold(w, "pbkdf2") {
						enc = true
					}
				}
				if !enc {
					m.issue("netcfg-default-credentials", loc, t[0]+" password is not marked encrypted, so it may be in clear text (value not shown)")
				}
			}
		case "logging":
			recognised++
			if len(t) >= 2 && t[1] == "enable" {
				sawLogEnable = true
			}
		case "no":
			if len(t) >= 3 && t[1] == "logging" && t[2] == "enable" {
				sawNoLog = true
				m.issueSev("netcfg-logging-disabled", "medium", loc, "logging is explicitly disabled (no logging enable)")
			}
		}
	}
	if recognised == 0 || (len(m.Rules) == 0 && len(m.Objs) == 0 && len(m.Issues) == 0) {
		return nil, fmt.Errorf("not a readable Cisco ASA configuration (no access-list, object or management lines)")
	}
	if !sawLogEnable && !sawNoLog && m.Lines >= 15 {
		m.issueSev("netcfg-logging-disabled", "low", "configuration", "no 'logging enable' line was found; the export may omit it or logging may be configured elsewhere")
	}
	// objects named in lines this parser does not model (nat, route-map, crypto maps ...) count as used
	elsewhere := map[string]bool{}
	for _, raw := range lines {
		t := strings.Fields(raw)
		if len(t) > 0 && raw[0] != ' ' && (t[0] == "access-list" || t[0] == "object" || t[0] == "object-group") {
			continue
		}
		for _, w := range t {
			elsewhere[strings.ToLower(w)] = true
		}
	}
	for _, o := range m.Objs {
		if !o.Used && elsewhere[strings.ToLower(o.Name)] {
			o.Used = true
		}
	}
	for _, p := range pend {
		for _, b := range binds[p.acl] {
			switch b.dir {
			case "in":
				p.rule.SrcZ = ncStrSet{}
				p.rule.SrcZ.add(b.iface)
				if untrustedIf(b.iface) {
					p.rule.UntrustedSrc = true
				}
			case "out":
				p.rule.DstZ = ncStrSet{}
				p.rule.DstZ.add(b.iface)
			}
		}
		if len(binds[p.acl]) == 0 {
			p.rule.Scope += " (not bound by access-group in this export)"
		}
		if len(binds[p.acl]) > 1 {
			p.rule.Complex = true // bound to several interfaces: zone comparison is ambiguous
		}
	}
	m.note("ASA: access lists are analysed per list; neq, source ports and time ranges make a rule skip shadow comparison against rules without the same condition; NAT and inter-interface security-level defaults are not modelled")
	return m, nil
}

func asaAlias(al map[string]string, s string) string {
	if v, ok := al[strings.ToLower(s)]; ok {
		return v
	}
	return s
}

func asaServiceSpec(t []string, out *ncSvc) {
	if len(t) == 0 {
		return
	}
	p := strings.ToLower(t[0])
	switch p {
	case "ip":
		out.Any = true
	case "icmp", "icmp6":
		out.addRange(ncRange{"icmp", 0, 0})
	case "tcp", "udp":
		k := 1
		for k < len(t) && strings.ToLower(t[k]) != "destination" {
			k++
		}
		if k >= len(t) {
			out.addRange(ncRange{p, 0, 65535})
			return
		}
		var tmp ncSvc
		d := t[k+1:]
		if len(d) >= 2 && (d[0] == "eq" || d[0] == "gt" || d[0] == "lt") {
			if n, ok := asaPort(p, d[1]); ok {
				switch d[0] {
				case "eq":
					tmp.addRange(ncRange{p, n, n})
				case "gt":
					tmp.addRange(ncRange{p, n + 1, 65535})
				case "lt":
					tmp.addRange(ncRange{p, 0, n - 1})
				}
			} else {
				tmp.addOpq("port:" + strings.ToLower(d[1]))
			}
		} else if len(d) >= 3 && d[0] == "range" {
			a, ok1 := asaPort(p, d[1])
			b, ok2 := asaPort(p, d[2])
			if ok1 && ok2 && a <= b {
				tmp.addRange(ncRange{p, a, b})
			} else {
				tmp.addOpq("port:" + strings.ToLower(d[1]+"-"+d[2]))
			}
		} else {
			tmp.addRange(ncRange{p, 0, 65535})
		}
		out.merge(tmp)
	default:
		if n, err := strconv.Atoi(p); err == nil && n == 0 {
			out.Any = true
		} else {
			out.addRange(ncRange{p, 0, 0})
		}
	}
}

// asaMgmt handles "ssh|telnet|http ADDR MASK IF" and the ssh option lines.
func asaMgmt(m *ncModel, t []string, loc string, untrusted func(string) bool) {
	cmd := t[0]
	if len(t) >= 3 && cmd == "ssh" {
		switch t[1] {
		case "version":
			if t[2] == "1" {
				m.issue("netcfg-weak-crypto", loc, "SSH protocol version 1 is allowed")
			}
			return
		case "key-exchange":
			if strings.Contains(strings.Join(t[2:], " "), "dh-group1") {
				m.issue("netcfg-weak-crypto", loc, "SSH key exchange allows a 1024-bit Diffie-Hellman group")
			}
			return
		case "cipher":
			if strings.Contains(strings.Join(t[2:], " "), " low") || strings.HasSuffix(strings.Join(t[2:], " "), "low") {
				m.issue("netcfg-weak-crypto", loc, "SSH cipher level is low")
			}
			return
		case "timeout", "scopy", "stricthostkeycheck", "pubkey-chain", "authentication", "key-exchange-group":
			return
		}
	}
	if cmd == "http" && len(t) >= 2 && t[1] == "server" {
		return
	}
	if len(t) < 3 {
		return
	}
	var pfx netip.Prefix
	anyAddr := false
	if a := t[1]; strings.Contains(a, "/") || strings.Contains(a, ":") {
		p, isAny, ok := ncParseAddrTok(a)
		if !ok {
			return
		}
		pfx, anyAddr = p, isAny
		if len(t) < 3 {
			return
		}
	} else {
		if len(t) < 4 {
			return
		}
		p, ok := ncMaskPrefix(t[1], t[2])
		if !ok {
			if a == "0" && t[2] == "0" {
				anyAddr = true
			} else {
				return
			}
		} else {
			pfx = p
			anyAddr = p.Bits() == 0
		}
	}
	iface := t[3]
	if strings.Contains(t[1], "/") || strings.Contains(t[1], ":") {
		iface = t[2]
	}
	bits := 32
	if pfx.IsValid() {
		bits = pfx.Bits()
	}
	if cmd == "telnet" {
		m.issue("netcfg-mgmt-weak-protocol", loc, fmt.Sprintf("telnet management is allowed from %s on interface %s", asaPfxLabel(pfx, anyAddr), ncClean(iface)))
	}
	if cmd == "http" {
		m.note("ASA 'http' lines enable the ASDM HTTPS server; they are treated as HTTPS management")
	}
	switch {
	case anyAddr && untrusted(iface):
		m.issue("netcfg-mgmt-exposed-untrusted", loc, fmt.Sprintf("%s management is allowed from any address on interface %s (looks untrusted)", cmd, ncClean(iface)))
	case !anyAddr && untrusted(iface) && bits < 16:
		m.issue("netcfg-mgmt-exposed-untrusted", loc, fmt.Sprintf("%s management is allowed from %s on interface %s (looks untrusted)", cmd, pfx, ncClean(iface)))
	case anyAddr:
		m.issue("netcfg-admin-unrestricted", loc, fmt.Sprintf("%s management is allowed from any address on interface %s", cmd, ncClean(iface)))
	}
}

func asaPfxLabel(p netip.Prefix, anyAddr bool) string {
	if anyAddr || !p.IsValid() {
		return "any address"
	}
	return p.String()
}

func asaSSL(m *ncModel, t []string, loc string) {
	j := strings.ToLower(strings.Join(t[1:], " "))
	switch {
	case strings.HasPrefix(j, "server-version") || strings.HasPrefix(j, "client-version"):
		for _, w := range t[2:] {
			lw := strings.ToLower(w)
			if lw == "sslv3" || lw == "tlsv1" || lw == "tlsv1.1" || lw == "sslv3-only-or-greater" {
				m.issue("netcfg-weak-crypto", loc, "ssl "+t[1]+" allows "+lw)
			}
		}
	case strings.HasPrefix(j, "cipher") || strings.HasPrefix(j, "encryption"):
		for _, k := range []string{"rc4", "3des", "des-", "md5", "null", " low", "export"} {
			if strings.Contains(" "+j, k) {
				m.issue("netcfg-weak-crypto", loc, "ssl cipher setting mentions "+strings.TrimSpace(k))
				break
			}
		}
	}
}
