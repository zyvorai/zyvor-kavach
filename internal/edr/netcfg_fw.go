// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"fmt"
	"strconv"
	"strings"
)

// iptables-save / ip6tables-save output (filter table only) and `nft list ruleset` output.
//
// iptables: *filter, :CHAIN POLICY, -A CHAIN with -s -d -p -i -o --sport --dport (and the
// multiport --sports/--dports), -m state/conntrack (--state/--ctstate), -m comment (--comment),
// -j ACCEPT|DROP|REJECT. Other modules and options are kept as an opaque condition. Negated
// matches mark the rule complex. Rules that jump to a user chain, LOG, RETURN and the like are not
// terminal and are left out of shadow analysis. Other tables are ignored.
//
// nft: table FAMILY NAME { chain NAME { type ... hook H priority P; policy V; RULES } } with
// iif/iifname/oif/oifname, ip|ip6 saddr|daddr, ip protocol / meta l4proto, tcp|udp dport|sport,
// ct state, sets in braces, counter, log, comment and the verdicts accept, drop, reject.

func ncPortSpec(proto, v string) ([]ncRange, bool) {
	v = strings.ReplaceAll(v, ":", "-")
	return ncParsePorts(proto, v)
}

func ncFWFinish(m *ncModel, r *ncRule, terminal, allow bool, extra []string) {
	r.Terminal, r.Allow = terminal, allow
	sortStrings(extra)
	r.Extra = strings.Join(extra, ";")
	r.App.Any = true
	if r.Src.size() == 0 {
		r.Src.Any = true // no -s / saddr match means any source
	}
	if r.Dst.size() == 0 {
		r.Dst.Any = true
	}
	if r.Svc.size() > ncExpandMax || r.Src.size() > ncExpandMax || r.Dst.size() > ncExpandMax {
		r.Complex = true
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func ncParseIptables(text string) (*ncModel, error) {
	m := newNcModel("iptables")
	lines := ncSplitLines(text, m)
	table := ""
	sawFilter := false
	type chainInfo struct {
		policy string
		line   int
		last   *ncRule
	}
	chains := map[string]*chainInfo{}
	for i, raw := range lines {
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		switch {
		case l[0] == '*':
			table = l[1:]
			if table == "filter" {
				sawFilter = true
			} else {
				m.note("iptables table " + ncClean(table) + " is not analysed")
			}
			continue
		case l == "COMMIT":
			table = ""
			continue
		case l[0] == ':' && table == "filter":
			f := strings.Fields(l[1:])
			if len(f) >= 2 {
				chains[f[0]] = &chainInfo{policy: f[1], line: i + 1}
			}
			continue
		}
		if table != "filter" || !strings.HasPrefix(l, "-A ") {
			continue
		}
		t := ncTokens(l)
		if len(t) < 2 {
			continue
		}
		chain := t[1]
		r := &ncRule{Scope: "filter/" + chain, Loc: ncLine(i+1) + " (chain " + ncClean(chain) + ")", Log: "unknown", Inspect: "unknown"}
		r.Name = chain
		r.SrcZ.Any, r.DstZ.Any = true, true
		r.Egress = chain == "OUTPUT"
		proto := ""
		var extra []string
		var dports, sports []ncRange
		hasDport, hasSport := false, false
		target := ""
		neg := false
		ok := true
		for j := 2; j < len(t); j++ {
			w := t[j]
			if w == "!" {
				neg = true
				continue
			}
			next := func() string {
				if j+1 < len(t) {
					j++
					return t[j]
				}
				return ""
			}
			switch w {
			case "-s", "--source", "--src":
				for _, a := range strings.Split(next(), ",") {
					if p, isAny, good := ncParseAddrTok(a); good {
						if isAny {
							r.Src.Any = true
						} else {
							r.Src.addPrefix(p)
						}
					} else {
						r.Src.addOpq("name:" + strings.ToLower(a))
						ok = false
					}
				}
			case "-d", "--destination", "--dst":
				for _, a := range strings.Split(next(), ",") {
					if p, isAny, good := ncParseAddrTok(a); good {
						if isAny {
							r.Dst.Any = true
						} else {
							r.Dst.addPrefix(p)
						}
					} else {
						r.Dst.addOpq("name:" + strings.ToLower(a))
						ok = false
					}
				}
			case "-p", "--protocol":
				proto = strings.ToLower(next())
			case "-i", "--in-interface":
				r.SrcZ = ncStrSet{}
				r.SrcZ.add(next())
			case "-o", "--out-interface":
				r.DstZ = ncStrSet{}
				r.DstZ.add(next())
			case "--dport", "--destination-port", "--dports", "--destination-ports":
				rs, good := ncPortSpec(proto, next())
				dports, hasDport = rs, true
				ok = ok && good
			case "--sport", "--source-port", "--sports", "--source-ports":
				rs, good := ncPortSpec(proto, next())
				sports, hasSport = rs, true
				ok = ok && good
			case "--state", "--ctstate":
				extra = append(extra, "state="+strings.ToLower(next()))
			case "--comment":
				r.Desc = next()
			case "-m", "--match":
				mod := strings.ToLower(next())
				switch mod {
				case "tcp", "udp", "multiport", "comment", "state", "conntrack":
				default:
					extra = append(extra, "m:"+mod)
				}
			case "-j", "--jump":
				target = next()
			case "-g", "--goto":
				target = next()
				extra = append(extra, "goto")
			default:
				if strings.HasPrefix(w, "-") {
					extra = append(extra, "opt:"+strings.TrimLeft(w, "-"))
					if j+1 < len(t) && !strings.HasPrefix(t[j+1], "-") {
						j++
					}
				}
			}
			if neg && w != "!" {
				if w != "--comment" {
					ok = false
				}
				neg = false
			}
		}
		switch proto {
		case "", "all":
			r.Svc.Any = true
		case "tcp", "udp":
			rs := dports
			if !hasDport {
				rs = []ncRange{{proto, 0, 65535}}
			}
			for _, x := range rs {
				r.Svc.addRange(x)
			}
			if hasSport {
				extra = append(extra, "sport="+fmt.Sprint(len(sports))+":"+portSig(sports))
			}
		case "icmp", "icmpv6", "ipv6-icmp":
			r.Svc.addRange(ncRange{"icmp", 0, 0})
		default:
			r.Svc.addRange(ncRange{proto, 0, 0})
		}
		r.Complex = !ok
		terminal, allow := false, false
		switch strings.ToUpper(target) {
		case "ACCEPT":
			terminal, allow = true, true
		case "DROP", "REJECT":
			terminal = true
		}
		ncFWFinish(m, r, terminal, allow, extra)
		if r.SrcZ.M["lo"] && len(r.SrcZ.M) == 1 {
			r.Egress = true // loopback input: breadth checks do not apply
		}
		if terminal {
			if ci := chains[chain]; ci != nil {
				ci.last = r
			}
		}
		m.addRule(r)
	}
	if !sawFilter {
		return nil, fmt.Errorf("not a readable iptables-save output (no *filter table)")
	}
	for name, ci := range chains {
		if (name == "INPUT" || name == "FORWARD") && strings.EqualFold(ci.policy, "ACCEPT") {
			if ci.last != nil && !ci.last.Allow && ci.last.Src.Any && ci.last.Dst.Any && ci.last.Svc.Any && ci.last.Extra == "" && ci.last.SrcZ.Any {
				continue // an unconditional final deny makes the accept policy unreachable
			}
			m.issue("netcfg-default-policy-accept", ncLine(ci.line)+" (chain "+name+")", "chain "+name+" has policy ACCEPT and no unconditional final deny rule")
		}
	}
	m.note("iptables: only the filter table is read; user-chain jumps are not followed; set matches and other modules are treated as unknown conditions")
	return m, nil
}

func portSig(rs []ncRange) string {
	var s []string
	for _, r := range rs {
		s = append(s, strconv.Itoa(r.Lo)+"-"+strconv.Itoa(r.Hi))
	}
	sortStrings(s)
	return strings.Join(s, ",")
}

// nft tokenizer: braces, commas and semicolons are their own tokens; quotes are honoured.
func nftTokens(s string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s) && len(out) < 600; i++ {
		c := s[i]
		switch {
		case c == '"':
			inQ = !inQ
			b.WriteByte(c)
		case inQ:
			b.WriteByte(c)
		case c == ' ' || c == '\t':
			flush()
		case c == '{' || c == '}' || c == ',' || c == ';':
			flush()
			out = append(out, string(c))
		case c == '#':
			flush()
			return out
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return out
}

func ncParseNft(text string) (*ncModel, error) {
	m := newNcModel("nftables")
	lines := ncSplitLines(text, m)
	var table, chain, hook, family string
	depth := 0
	sawChain := false
	type ci struct {
		policy string
		line   int
		last   *ncRule
	}
	chains := map[string]*ci{}
	for i, raw := range lines {
		t := nftTokens(strings.TrimSpace(raw))
		if len(t) == 0 {
			continue
		}
		switch {
		case t[0] == "table" && len(t) >= 4 && t[len(t)-1] == "{":
			family, table = t[1], t[2]
			depth = 1
			continue
		case t[0] == "chain" && len(t) >= 3 && t[len(t)-1] == "{" && depth >= 1:
			chain, hook = t[1], ""
			depth = 2
			sawChain = true
			continue
		case t[0] == "}":
			if depth > 0 {
				depth--
			}
			if depth < 2 {
				chain = ""
			}
			continue
		}
		if depth != 2 || chain == "" {
			continue
		}
		key := family + " " + table + "/" + chain
		if t[0] == "type" {
			for k := 0; k+1 < len(t); k++ {
				if t[k] == "hook" {
					hook = t[k+1]
				}
				if t[k] == "policy" {
					c := &ci{policy: t[k+1], line: i + 1}
					chains[key] = c
				}
			}
			continue
		}
		r := &ncRule{Scope: key, Loc: ncLine(i+1) + " (" + ncClean(key) + ")", Log: "unknown", Inspect: "unknown"}
		r.Name = chain
		r.SrcZ.Any, r.DstZ.Any = true, true
		r.Egress = hook == "output"
		proto := ""
		var extra []string
		var dports []ncRange
		hasDport := false
		ok := true
		verdict := ""
		readVal := func(j *int) ([]string, bool) { // value or {set}; returns negated
			neg := false
			if *j+1 < len(t) && (t[*j+1] == "!=" || t[*j+1] == "==") {
				neg = t[*j+1] == "!="
				*j++
			}
			var vals []string
			if *j+1 < len(t) && t[*j+1] == "{" {
				*j += 2
				for *j < len(t) && t[*j] != "}" {
					if t[*j] != "," {
						vals = append(vals, t[*j])
					}
					*j++
				}
			} else if *j+1 < len(t) {
				*j++
				vals = []string{t[*j]}
			}
			return vals, neg
		}
		for j := 0; j < len(t); j++ {
			w := strings.ToLower(t[j])
			switch w {
			case "iif", "iifname":
				v, ng := readVal(&j)
				r.SrcZ = ncStrSet{}
				for _, x := range v {
					r.SrcZ.add(strings.Trim(x, `"`))
				}
				ok = ok && !ng
			case "oif", "oifname":
				v, ng := readVal(&j)
				r.DstZ = ncStrSet{}
				for _, x := range v {
					r.DstZ.add(strings.Trim(x, `"`))
				}
				ok = ok && !ng
			case "ip", "ip6":
				if j+1 < len(t) && (t[j+1] == "saddr" || t[j+1] == "daddr") {
					side := t[j+1]
					j++
					v, ng := readVal(&j)
					ok = ok && !ng
					dst := &r.Src
					if side == "daddr" {
						dst = &r.Dst
					}
					for _, a := range v {
						if strings.HasPrefix(a, "@") {
							dst.addOpq("set:" + strings.ToLower(a))
							ok = false
						} else if p, isAny, good := ncParseAddrTok(a); good {
							if isAny {
								dst.Any = true
							} else {
								dst.addPrefix(p)
							}
						} else {
							dst.addOpq("val:" + strings.ToLower(a))
							ok = false
						}
					}
				} else if j+1 < len(t) && (t[j+1] == "protocol" || t[j+1] == "nexthdr") {
					j++
					v, _ := readVal(&j)
					if len(v) == 1 {
						proto = strings.ToLower(v[0])
					} else {
						ok = false
					}
				}
			case "meta":
				if j+1 < len(t) && t[j+1] == "l4proto" {
					j++
					v, _ := readVal(&j)
					if len(v) == 1 {
						proto = strings.ToLower(v[0])
					} else {
						ok = false
					}
				} else {
					extra = append(extra, "meta")
					if j+1 < len(t) {
						j++
					}
				}
			case "tcp", "udp":
				proto = w
				if j+1 < len(t) && (t[j+1] == "dport" || t[j+1] == "sport") {
					side := t[j+1]
					j++
					v, ng := readVal(&j)
					ok = ok && !ng
					var rs []ncRange
					for _, p := range v {
						x, good := ncPortSpec(w, p)
						ok = ok && good
						rs = append(rs, x...)
					}
					if side == "dport" {
						dports, hasDport = rs, true
					} else {
						extra = append(extra, "sport="+portSig(rs))
					}
				}
			case "ct":
				if j+1 < len(t) && t[j+1] == "state" {
					j++
					v, _ := readVal(&j)
					extra = append(extra, "state="+strings.ToLower(strings.Join(v, "+")))
				} else {
					extra = append(extra, "ct")
					if j+1 < len(t) {
						j++
					}
				}
			case "comment":
				if j+1 < len(t) {
					j++
					r.Desc = strings.Trim(t[j], `"`)
				}
			case "accept", "drop", "reject":
				verdict = w
				if w == "reject" && j+1 < len(t) && t[j+1] == "with" {
					j += 2
				}
			case "jump", "goto", "return", "queue", "continue":
				verdict = "other"
				if j+1 < len(t) && w != "return" {
					j++
				}
			case "counter", "log", "limit", "notrack", ";":
				if w == "log" {
					r.Log = "on"
				}
				if w == "limit" {
					extra = append(extra, "limit")
				}
			case "icmp", "icmpv6":
				proto = "icmp"
				if j+1 < len(t) && t[j+1] == "type" {
					j++
					v, _ := readVal(&j)
					extra = append(extra, "icmp="+strings.ToLower(strings.Join(v, "+")))
				}
			default:
				extra = append(extra, "tok:"+w)
				ok = false
			}
		}
		switch proto {
		case "":
			r.Svc.Any = true
		case "tcp", "udp":
			rs := dports
			if !hasDport {
				rs = []ncRange{{proto, 0, 65535}}
			}
			for _, x := range rs {
				r.Svc.addRange(x)
			}
		case "icmp", "icmpv6", "ipv6-icmp":
			r.Svc.addRange(ncRange{"icmp", 0, 0})
		default:
			r.Svc.addRange(ncRange{proto, 0, 0})
		}
		r.Complex = !ok
		terminal := verdict == "accept" || verdict == "drop" || verdict == "reject"
		ncFWFinish(m, r, terminal, verdict == "accept", extra)
		if r.SrcZ.M["lo"] && len(r.SrcZ.M) == 1 {
			r.Egress = true
		}
		if verdict == "" {
			continue
		}
		if terminal {
			if c := chains[key]; c != nil {
				c.last = r
			}
		}
		m.addRule(r)
	}
	if !sawChain {
		return nil, fmt.Errorf("not a readable nft ruleset (no table/chain blocks)")
	}
	for key, c := range chains {
		if strings.EqualFold(c.policy, "accept") && (strings.HasSuffix(key, "/input") || strings.HasSuffix(key, "/forward") || strings.HasSuffix(key, "/INPUT") || strings.HasSuffix(key, "/FORWARD")) {
			if c.last != nil && !c.last.Allow && c.last.Src.Any && c.last.Dst.Any && c.last.Svc.Any && c.last.Extra == "" && c.last.SrcZ.Any {
				continue
			}
			m.issue("netcfg-default-policy-accept", ncLine(c.line)+" ("+ncClean(key)+")", "chain "+ncClean(key)+" has policy accept and no unconditional final deny rule")
		}
	}
	m.note("nftables: sets by name (@set) and maps are opaque; only chain names input and forward are checked for the default policy rule")
	return m, nil
}
