// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// F5 BIG-IP configuration parser (bigip.conf, bigip_base.conf, or the output of
// `tmsh list` / a qkview's config files, submitted as text). tmsh stanzas are
// brace-structured; this parser is bounded (depth, node and token caps), never
// follows `include`-like references and never evaluates iRule (Tcl) bodies.
//
// Setting keys (lower-case):
//
//	<class>.<kind>.<prop>      for a stanza `class kind [name] { prop value }`, e.g. sys.httpd.allow
//	<class>.<kind>.<blk>.<p>   one nested level, e.g. sys.snmp.communities.community-name
//	bigip.version              from the `#TMSH-VERSION:` header comment
//	bigip.objects              number of top-level stanzas
//	risk.bigip-*               object-level findings computed here (value = object name)

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	bigipMaxNodes = 60000
	bigipMaxDepth = 24
)

type bigipNode struct {
	words []string
	kids  []*bigipNode
	line  int
}

var bigipVersionRe = regexp.MustCompile(`(?m)^#TMSH-VERSION:\s*([0-9][0-9A-Za-z._-]{0,31})`)

// bigipParse builds a statement tree: a newline ends a statement, '{' opens a
// child block and '}' closes it. Quoted strings keep their quotes stripped.
func bigipParse(text string) (roots []*bigipNode, notes []string) {
	root := &bigipNode{}
	stack := []*bigipNode{root}
	var cur *bigipNode
	nodes := 0
	line := 1
	flush := func() { cur = nil }
	push := func(w string) {
		if cur == nil {
			cur = &bigipNode{line: line}
			top := stack[len(stack)-1]
			top.kids = append(top.kids, cur)
			nodes++
		}
		cur.words = append(cur.words, w)
	}
	for i := 0; i < len(text) && nodes < bigipMaxNodes; {
		c := text[i]
		switch {
		case c == '\n':
			line++
			flush()
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == ';':
			i++
		case c == '#' && cur == nil:
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case c == '{':
			if cur == nil {
				// A bare block: attach to a synthetic node so depth stays consistent.
				push("")
			}
			if len(stack) >= bigipMaxDepth {
				notes = append(notes, "nesting deeper than "+strconv.Itoa(bigipMaxDepth)+" ignored")
				i = len(text)
				break
			}
			stack = append(stack, cur)
			cur = nil
			i++
		case c == '}':
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			cur = nil
			i++
		case c == '"':
			j := i + 1
			for j < len(text) && text[j] != '"' && j-i < 4096 {
				if text[j] == '\\' {
					j++
				}
				if j < len(text) && text[j] == '\n' {
					line++
				}
				j++
			}
			if j > len(text) {
				j = len(text)
			}
			push(text[i+1 : min(j, len(text))])
			i = j + 1
		default:
			j := i
			for j < len(text) && !strings.ContainsRune(" \t\r\n{};\"", rune(text[j])) && j-i < 4096 {
				j++
			}
			if j == i {
				j = i + 1
			}
			push(text[i:j])
			i = j
		}
	}
	if nodes >= bigipMaxNodes {
		notes = append(notes, "configuration truncated at "+strconv.Itoa(bigipMaxNodes)+" statements")
	}
	if len(stack) > 1 {
		notes = append(notes, "unbalanced braces: some stanzas were not closed")
	}
	return root.kids, notes
}

func bigipJoin(ns []*bigipNode) string {
	var parts []string
	for _, n := range ns {
		parts = append(parts, strings.Join(n.words, " "))
	}
	return strings.Join(parts, " ")
}

func parseBigIP(d *cfgDoc, text string) {
	if m := bigipVersionRe.FindStringSubmatch(text); m != nil {
		d.add("bigip.version", m[1], 1)
	}
	roots, notes := bigipParse(text)
	d.Notes = append(d.Notes, notes...)
	objs := 0
	for _, n := range roots {
		if len(n.words) < 2 || d.full() {
			continue
		}
		objs++
		class := strings.ToLower(n.words[0]) + "." + strings.ToLower(n.words[1])
		name := ""
		if len(n.words) >= 4 && !strings.HasPrefix(n.words[2], "/") {
			// `ltm profile client-ssl /Common/x`: the third word is a type, not a name.
			class += "." + strings.ToLower(n.words[2])
			name = n.words[3]
		} else if len(n.words) > 2 {
			name = n.words[2]
		}
		d.add("obj."+class, name, n.line)
		for _, c := range n.kids {
			if len(c.words) == 0 {
				continue
			}
			prop := strings.ToLower(c.words[0])
			if len(c.kids) == 0 {
				d.add(class+"."+prop, strings.Join(c.words[1:], " "), c.line)
				continue
			}
			d.add(class+"."+prop, strings.TrimSpace(strings.Join(c.words[1:], " ")+" "+bigipJoin(c.kids)), c.line)
			for _, g := range c.kids {
				if len(g.words) == 0 {
					continue
				}
				d.add(class+"."+prop+"."+strings.ToLower(g.words[0]), strings.TrimSpace(strings.Join(g.words[1:], " ")+" "+bigipJoin(g.kids)), g.line)
			}
		}
		bigipRisks(d, class, name, n)
	}
	if objs > 0 {
		d.add("bigip.objects", strconv.Itoa(objs), 0)
	}
}

var (
	bigipWeakCipherRe = regexp.MustCompile(`(?i)(^|[:!+ ])(RC4|3DES|DES|MD5|EXPORT|NULL|aNULL|eNULL|LOW|SSLv3)([:! ]|$)`)
)

func bigipProp(n *bigipNode, key string) string {
	for _, c := range n.kids {
		if len(c.words) > 0 && strings.EqualFold(c.words[0], key) {
			return strings.TrimSpace(strings.Join(c.words[1:], " ") + " " + bigipJoin(c.kids))
		}
	}
	return ""
}

func bigipRisks(d *cfgDoc, class, name string, n *bigipNode) {
	risk := func(k string) { d.add("risk.bigip-"+k, name, n.line) }
	switch class {
	case "net.self":
		svc := " " + strings.ToLower(bigipProp(n, "allow-service")) + " "
		if strings.Contains(svc, " all ") {
			risk("selfip-allow-all")
		} else if strings.Contains(svc, " default ") {
			risk("selfip-allow-default")
		}
	case "ltm.profile.client-ssl", "ltm.profile.server-ssl":
		if bigipWeakCipherRe.MatchString(bigipProp(n, "ciphers")) {
			risk("ssl-weak-ciphers")
		}
	case "ltm.virtual":
		dst := bigipProp(n, "destination")
		src := bigipProp(n, "source")
		if (strings.HasSuffix(dst, ":any") || strings.HasSuffix(dst, ":0")) && (src == "" || src == "0.0.0.0/0") &&
			bigipProp(n, "ip-forward") == "" && bigipProp(n, "ip-protocol") != "" {
			risk("virtual-wildcard-port")
		}
	case "sys.snmp":
		for _, c := range n.kids {
			if len(c.words) == 0 || !strings.EqualFold(c.words[0], "communities") {
				continue
			}
			for _, g := range c.kids {
				for _, h := range g.kids {
					if len(h.words) >= 2 && strings.EqualFold(h.words[0], "community-name") {
						if v := strings.ToLower(h.words[1]); v == "public" || v == "private" {
							risk("snmp-default-community")
						}
					}
				}
			}
		}
	}
}
