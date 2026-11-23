// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// FortiGate `show` / `show full-configuration` text. Sections read: firewall policy (name, srcintf,
// dstintf, srcaddr, dstaddr, service, action, status, logtraffic, comments, schedule, ssl-ssh-profile,
// utm-status, av-profile, ips-sensor, webfilter-profile, application-list, profile-group,
// internet-service, *-negate, users, groups), firewall address (type, subnet, start-ip, end-ip,
// fqdn), firewall addrgrp (member), firewall service custom (tcp-portrange, udp-portrange,
// protocol), firewall service group (member), system interface (allowaccess, role, type),
// system admin (trusthost1..10, password), system global (admin-telnet, admin-ssh-v1,
// admin-https-ssl-versions, strong-crypto, ssl-min-proto-version), system snmp community (name),
// system snmp user (security-level), vpn ipsec phase1-interface / phase1 / phase2 (proposal,
// dhgrp, mode, psksecret), vpn ssl settings (ssl-min-proto-ver), log targets (status).
// Field names come from the public CLI reference pages and community articles; the ones marked
// [U] in docs/netcfg-posture.md (defaults, newer security options) are not verified.

type fgEdit struct {
	Path, Name string
	Line       int
	Vdom       string
	Set        map[string][]string
	Order      []string
}

func (e *fgEdit) get(k string) []string { return e.Set[k] }
func (e *fgEdit) one(k string) string {
	if v := e.Set[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}
func (e *fgEdit) loc() string {
	n := e.Name
	if n != "" {
		n = " / edit " + ncClean(n)
	}
	return fmt.Sprintf("line %d (config %s%s)", e.Line, e.Path, n)
}

type fgFrame struct {
	isEdit bool
	edit   *fgEdit
	path   string
}

var fgWeakComm = map[string]bool{"public": true, "private": true, "community": true, "cisco": true, "admin": true, "snmp": true, "default": true, "test": true, "manager": true, "secret": true, "read": true, "write": true, "password": true, "123456": true, "1234": true, "monitor": true}

func ncParseForti(text string) (*ncModel, error) {
	m := newNcModel("fortigate")
	m.DescSupported = true
	lines := ncSplitLines(text, m)
	var edits []*fgEdit
	var stack []fgFrame
	vdom := ""
	sawConfig := false
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		t := ncTokens(l)
		if len(t) == 0 {
			continue
		}
		switch strings.ToLower(t[0]) {
		case "config":
			sawConfig = true
			if len(t) < 2 {
				continue
			}
			path := strings.ToLower(strings.Join(t[1:], " "))
			if len(stack) > 0 && stack[len(stack)-1].isEdit && stack[len(stack)-1].path != "vdom" {
				path = stack[len(stack)-1].path + " / " + path
			}
			if len(stack) >= 16 {
				m.note("configuration nesting deeper than 16 was not followed")
				continue
			}
			stack = append(stack, fgFrame{path: path})
		case "edit":
			if len(stack) == 0 || len(t) < 2 {
				continue
			}
			top := stack[len(stack)-1]
			if top.isEdit {
				continue
			}
			if top.path == "vdom" {
				vdom = t[1]
			}
			e := &fgEdit{Path: top.path, Name: t[1], Line: i + 1, Vdom: vdom, Set: map[string][]string{}}
			if len(edits) < ncMaxRules*5 {
				edits = append(edits, e)
			} else {
				m.truncated = true
			}
			stack = append(stack, fgFrame{isEdit: true, edit: e, path: top.path})
		case "next":
			if len(stack) > 0 && stack[len(stack)-1].isEdit {
				stack = stack[:len(stack)-1]
			}
		case "end":
			if len(stack) > 0 && !stack[len(stack)-1].isEdit {
				if stack[len(stack)-1].path == "vdom" {
					vdom = ""
				}
				stack = stack[:len(stack)-1]
			} else if len(stack) > 1 && stack[len(stack)-1].isEdit { // end without next
				stack = stack[:len(stack)-2]
			}
		case "set", "append":
			if len(stack) == 0 || len(t) < 2 {
				continue
			}
			top := stack[len(stack)-1]
			e := top.edit
			if !top.isEdit {
				if e == nil { // sets directly under a config block (system global, vpn ssl settings, ...)
					e = &fgEdit{Path: top.path, Line: i + 1, Vdom: vdom, Set: map[string][]string{}}
					stack[len(stack)-1].edit = e
					if len(edits) < ncMaxRules*5 {
						edits = append(edits, e)
					}
				}
			}
			k := strings.ToLower(t[1])
			if strings.ToLower(t[0]) == "append" {
				e.Set[k] = append(e.Set[k], t[2:]...)
			} else {
				e.Set[k] = t[2:]
			}
			if _, seen := e.Set["\x00line:"+k]; !seen {
				e.Set["\x00line:"+k] = []string{fmt.Sprint(i + 1)}
			}
		case "unset":
			if len(stack) > 0 && len(t) > 1 {
				if e := stack[len(stack)-1].edit; e != nil {
					delete(e.Set, strings.ToLower(t[1]))
				}
			}
		}
	}
	if !sawConfig || len(edits) == 0 {
		return nil, fmt.Errorf("not a readable FortiGate configuration (no config/edit blocks)")
	}

	addrs := map[string]*ncSet{}
	groups := map[string][]string{}
	svcs := map[string]*ncSvc{}
	sgroups := map[string][]string{}
	for _, e := range edits {
		switch e.Path {
		case "firewall address":
			s := &ncSet{}
			sig := ""
			switch strings.ToLower(e.one("type")) {
			case "iprange":
				s.addOpq("range:" + strings.ToLower(e.one("start-ip")) + "-" + strings.ToLower(e.one("end-ip")))
				sig = "range " + e.one("start-ip") + "-" + e.one("end-ip")
			case "fqdn":
				s.addOpq("fqdn:" + strings.ToLower(e.one("fqdn")))
				sig = "fqdn " + e.one("fqdn")
			case "", "ipmask":
				sub := e.get("subnet")
				if len(sub) >= 2 {
					if p, ok := ncMaskPrefix(sub[0], sub[1]); ok {
						if p.Bits() == 0 {
							s.Any = true
						} else {
							s.addPrefix(p)
						}
						sig = p.String()
					} else if p, err := netip.ParsePrefix(sub[1]); err == nil {
						s.addPrefix(p)
						sig = p.String()
					} else {
						s.addOpq("val:" + strings.ToLower(strings.Join(sub, " ")))
					}
				} else if len(sub) == 1 {
					if p, _, ok := ncParseAddrTok(sub[0]); ok {
						s.addPrefix(p)
						sig = p.String()
					}
				} else {
					s.addOpq("name:" + strings.ToLower(e.Name))
				}
			default:
				s.addOpq("name:" + strings.ToLower(e.Name)) // geography, mac, dynamic: compared by name only
			}
			addrs[strings.ToLower(e.Name)] = s
			m.addObj("address", e.Name, e.loc(), strings.ToLower(sig))
		case "firewall addrgrp":
			groups[strings.ToLower(e.Name)] = e.get("member")
			m.addObj("address", e.Name, e.loc(), "")
		case "firewall service custom":
			s := &ncSvc{}
			ok := true
			if v := e.get("tcp-portrange"); len(v) > 0 {
				rs, good := ncParsePorts("tcp", strings.Join(v, " "))
				ok = ok && good
				for _, r := range rs {
					s.addRange(r)
				}
			}
			if v := e.get("udp-portrange"); len(v) > 0 {
				rs, good := ncParsePorts("udp", strings.Join(v, " "))
				ok = ok && good
				for _, r := range rs {
					s.addRange(r)
				}
			}
			switch strings.ToUpper(e.one("protocol")) {
			case "ICMP":
				s.addRange(ncRange{"icmp", 0, 0})
			case "IP", "":
				if s.size() == 0 && strings.ToUpper(e.one("protocol")) == "IP" {
					s.addOpq("ip:" + e.one("protocol-number"))
				}
			}
			if !ok || s.size() == 0 {
				s.addOpq("name:" + strings.ToLower(e.Name))
			}
			svcs[strings.ToLower(e.Name)] = s
			m.addObj("service", e.Name, e.loc(), s.sig())
		case "firewall service group":
			sgroups[strings.ToLower(e.Name)] = e.get("member")
			m.addObj("service", e.Name, e.loc(), "")
		}
	}

	var resAddr func(names []string, depth int, out *ncSet) bool
	resAddr = func(names []string, depth int, out *ncSet) bool {
		ok := true
		for _, nm := range names {
			l := strings.ToLower(nm)
			if l == "all" || l == "any" {
				out.Any = true
				continue
			}
			m.use("address", nm)
			if s, f := addrs[l]; f {
				out.merge(*s)
			} else if g, f := groups[l]; f && depth < ncExpandDepth {
				if !resAddr(g, depth+1, out) {
					ok = false
				}
			} else {
				out.addOpq("name:" + l)
				ok = false
			}
		}
		return ok && out.size() <= ncExpandMax
	}
	var resSvc func(names []string, depth int, out *ncSvc) bool
	resSvc = func(names []string, depth int, out *ncSvc) bool {
		ok := true
		for _, nm := range names {
			l := strings.ToLower(nm)
			switch l {
			case "all", "any":
				out.Any = true
				continue
			case "all_tcp":
				out.addRange(ncRange{"tcp", 1, 65535})
				continue
			case "all_udp":
				out.addRange(ncRange{"udp", 1, 65535})
				continue
			case "all_icmp":
				out.addRange(ncRange{"icmp", 0, 0})
				continue
			}
			m.use("service", nm)
			if s, f := svcs[l]; f {
				out.merge(*s)
			} else if g, f := sgroups[l]; f && depth < ncExpandDepth {
				if !resSvc(g, depth+1, out) {
					ok = false
				}
			} else if wk, f := ncWellKnown[l]; f {
				for _, r := range wk {
					out.addRange(r)
				}
			} else {
				out.addOpq("name:" + l)
				ok = false
			}
		}
		return ok && out.size() <= ncExpandMax
	}

	logTarget, sawGlobal := false, false
	for _, e := range edits {
		switch e.Path {
		case "firewall policy":
			r := &ncRule{Scope: "policy:" + e.Vdom, Loc: e.loc(), Terminal: true, Log: "unknown", Inspect: "unknown"}
			r.Name = e.one("name")
			if r.Name == "" {
				r.Name = "policy " + e.Name
			}
			r.Desc = strings.Join(e.get("comments"), " ")
			r.Allow = strings.EqualFold(e.one("action"), "accept")
			r.Disabled = strings.EqualFold(e.one("status"), "disable")
			for _, z := range e.get("srcintf") {
				r.SrcZ.add(z)
			}
			for _, z := range e.get("dstintf") {
				r.DstZ.add(z)
			}
			ok1 := resAddr(e.get("srcaddr"), 0, &r.Src)
			ok2 := resAddr(e.get("dstaddr"), 0, &r.Dst)
			ok3 := resSvc(e.get("service"), 0, &r.Svc)
			r.Complex = !(ok1 && ok2 && ok3)
			r.App.Any = true
			var extra []string
			if strings.EqualFold(e.one("internet-service"), "enable") || strings.EqualFold(e.one("internet-service-src"), "enable") {
				r.Complex = true
				extra = append(extra, "internet-service")
			}
			for _, k := range []string{"srcaddr-negate", "dstaddr-negate", "service-negate"} {
				if strings.EqualFold(e.one(k), "enable") {
					r.Complex = true
					extra = append(extra, k)
				}
			}
			if s := e.get("schedule"); len(s) > 0 && !strings.EqualFold(s[0], "always") {
				extra = append(extra, "schedule="+strings.ToLower(s[0]))
			}
			for _, k := range []string{"users", "groups", "fsso-groups", "srcaddr6", "dstaddr6"} {
				if v := e.get(k); len(v) > 0 {
					extra = append(extra, k+"="+strings.ToLower(strings.Join(v, "+")))
				}
			}
			sort.Strings(extra)
			r.Extra = strings.Join(extra, ";")
			switch strings.ToLower(e.one("logtraffic")) {
			case "disable":
				r.Log = "off"
			case "all", "utm":
				r.Log = "on"
			}
			hasProf := false
			for _, k := range []string{"av-profile", "ips-sensor", "webfilter-profile", "application-list", "profile-group", "dnsfilter-profile", "emailfilter-profile"} {
				if e.one(k) != "" {
					hasProf = true
				}
			}
			ssl := strings.ToLower(e.one("ssl-ssh-profile"))
			switch {
			case hasProf && ssl != "no-inspection":
				r.Inspect = "yes"
			case hasProf:
				r.Inspect = "yes"
			default:
				r.Inspect = "no"
			}
			if strings.EqualFold(e.one("utm-status"), "disable") {
				r.Inspect = "no"
			}
			m.addRule(r)
		case "system interface":
			var on []string
			for _, a := range e.get("allowaccess") {
				on = append(on, strings.ToLower(a))
			}
			role := strings.ToLower(e.one("role"))
			untrusted := role == "wan" || ncUntrustedName(e.Name)
			for _, w := range on {
				if w == "telnet" || w == "http" {
					m.issue("netcfg-mgmt-weak-protocol", e.loc(), fmt.Sprintf("interface %s allowaccess includes %s", ncClean(e.Name), w))
				}
			}
			if untrusted {
				var mg []string
				for _, w := range on {
					if w == "https" || w == "ssh" || w == "http" || w == "telnet" || w == "snmp" {
						mg = append(mg, w)
					}
				}
				if len(mg) > 0 {
					m.issue("netcfg-mgmt-exposed-untrusted", e.loc(), fmt.Sprintf("interface %s (role %s, name or role looks untrusted) allowaccess includes %s", ncClean(e.Name), ncClean(role), strings.Join(mg, ", ")))
				}
			}
		case "system admin":
			restricted := false
			for i := 1; i <= 10; i++ {
				th := e.get(fmt.Sprintf("trusthost%d", i))
				if len(th) >= 2 && !(th[0] == "0.0.0.0" && th[1] == "0.0.0.0") {
					restricted = true
				}
			}
			if !restricted {
				m.issue("netcfg-admin-unrestricted", e.loc(), fmt.Sprintf("administrator %s has no trusted host restriction", ncClean(e.Name)))
			}
		case "system global":
			sawGlobal = true
			if strings.EqualFold(e.one("admin-telnet"), "enable") {
				m.issue("netcfg-mgmt-weak-protocol", e.loc(), "system global admin-telnet is enabled")
			}
			if strings.EqualFold(e.one("admin-ssh-v1"), "enable") {
				m.issue("netcfg-weak-crypto", e.loc(), "SSH protocol version 1 is enabled for administration")
			}
			for _, v := range e.get("admin-https-ssl-versions") {
				if lv := strings.ToLower(v); lv == "sslv3" || lv == "tlsv1-0" || lv == "tlsv1-1" {
					m.issue("netcfg-weak-crypto", e.loc(), "administrative HTTPS allows "+lv)
				}
			}
			if strings.EqualFold(e.one("strong-crypto"), "disable") {
				m.issue("netcfg-weak-crypto", e.loc(), "strong-crypto is disabled")
			}
			if v := strings.ToLower(e.one("ssl-min-proto-version")); v == "sslv3" || v == "tlsv1" || v == "tlsv1-1" {
				m.issue("netcfg-weak-crypto", e.loc(), "ssl-min-proto-version allows "+v)
			}
		case "system snmp community":
			if n := strings.ToLower(e.one("name")); n != "" && fgWeakComm[n] {
				m.issue("netcfg-weak-snmp", e.loc(), fmt.Sprintf("SNMP community entry %s uses a default or well-known community (value not shown, %d characters)", ncClean(e.Name), len(n)))
			}
		case "system snmp user":
			if strings.EqualFold(e.one("security-level"), "no-auth-no-priv") {
				m.issue("netcfg-weak-snmp", e.loc(), "SNMPv3 user "+ncClean(e.Name)+" uses no-auth-no-priv")
			}
		case "vpn ipsec phase1-interface", "vpn ipsec phase1", "vpn ipsec phase2-interface", "vpn ipsec phase2":
			for _, p := range e.get("proposal") {
				lp := strings.ToLower(p)
				if strings.HasPrefix(lp, "des-") || strings.HasPrefix(lp, "3des-") || strings.HasSuffix(lp, "-md5") || strings.HasSuffix(lp, "-null") {
					m.issue("netcfg-weak-crypto", e.loc(), "IPsec proposal "+ncClean(p)+" uses DES, 3DES, MD5 or null")
				}
			}
			for _, g := range e.get("dhgrp") {
				if g == "1" || g == "2" || g == "5" {
					m.issue("netcfg-weak-crypto", e.loc(), "IPsec dhgrp "+g+" is a small Diffie-Hellman group")
				}
			}
			if strings.EqualFold(e.one("mode"), "aggressive") {
				m.issue("netcfg-weak-crypto", e.loc(), "IKE aggressive mode is configured")
			}
		case "vpn ssl settings":
			if v := strings.ToLower(e.one("ssl-min-proto-ver")); v == "sslv3" || v == "tlsv1" || v == "tlsv1-1" {
				m.issue("netcfg-weak-crypto", e.loc(), "SSL VPN ssl-min-proto-ver allows "+v)
			}
			for _, k := range []string{"tlsv1-0", "tlsv1-1", "sslv3"} {
				if strings.EqualFold(e.one(k), "enable") {
					m.issue("netcfg-weak-crypto", e.loc(), "SSL VPN "+k+" is enabled")
				}
			}
		}
		if strings.HasPrefix(e.Path, "log ") && strings.HasSuffix(e.Path, " setting") && strings.EqualFold(e.one("status"), "enable") {
			logTarget = true
		}
		for _, k := range []string{"password", "passwd", "psksecret", "secret", "auth-pwd", "priv-pwd"} {
			if v := e.get(k); len(v) > 0 {
				first := strings.ToLower(v[0])
				switch {
				case first == "enc" || first == "*":
				case first == "":
					m.issue("netcfg-default-credentials", fmt.Sprintf("line %s (config %s)", e.Set["\x00line:"+k][0], e.Path), "empty value for "+k+" (value not shown)")
				default:
					m.issue("netcfg-default-credentials", fmt.Sprintf("line %s (config %s)", e.Set["\x00line:"+k][0], e.Path), "value for "+k+" is not ENC-prefixed, so it may be stored in clear text (value not shown)")
				}
			}
		}
	}
	if sawGlobal && !logTarget {
		m.issueSev("netcfg-logging-disabled", "low", "config log ... setting", "no enabled log target section (syslogd, fortianalyzer, disk) was found in the export; sections may be omitted from a partial export")
	}
	m.note("FortiGate: logtraffic absent is treated as unknown; policy profile groups are not resolved; internet-service and negated policies are skipped by shadow analysis")
	return m, nil
}
