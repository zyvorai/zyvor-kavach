// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package edr

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// PAN-OS XML configuration (a running-config export). Element names read: under
// devices/entry/vsys/entry (or shared): rulebase/security/rules/entry (also pre-rulebase and
// post-rulebase on Panorama) with from, to, source, destination, application, service, action,
// disabled, log-start, log-end, log-setting, description, profile-setting, negate-source,
// negate-destination, source-user, category; address/entry (ip-netmask, ip-range, fqdn),
// address-group/entry (static/member), service/entry (protocol/tcp|udp/port),
// service-group/entry (members/member), zone/entry (network/layer3|layer2|virtual-wire|tap/member),
// network/profiles/interface-management-profile/entry (ssh, telnet, http, https, snmp, ping,
// permitted-ip/entry) and the interface-management-profile binding under interface entries.
// Element names come from the XML API documentation and public examples; the interface-management
// and binding paths are NOT verified against a real export (see docs/netcfg-posture.md).

type xn struct {
	Name, Attr, Text string
	Kids             []*xn
	Off              int64
	Parent           *xn
}

func (n *xn) kid(name string) *xn {
	for _, k := range n.Kids {
		if k.Name == name {
			return k
		}
	}
	return nil
}
func (n *xn) members(name string) []string {
	var out []string
	if c := n.kid(name); c != nil {
		for _, k := range c.Kids {
			v := k.Text
			if k.Name == "entry" && k.Attr != "" {
				v = k.Attr
			}
			if v != "" {
				out = append(out, v)
			}
		}
		if len(out) == 0 && c.Text != "" {
			out = append(out, c.Text)
		}
	}
	return out
}
func (n *xn) yes(name string) (bool, bool) { // value, present
	if c := n.kid(name); c != nil {
		return strings.EqualFold(c.Text, "yes"), true
	}
	return false, false
}

var errNcXML = errors.New("not a readable PAN-OS XML configuration")

// ncParseXML builds a bounded tree. DOCTYPE and entity declarations are refused outright; the Go
// decoder never fetches external entities, and with no Entity map it cannot expand custom ones.
func ncParseXML(raw []byte) (*xn, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.Strict = true
	d.Entity = nil
	d.CharsetReader = func(cs string, in io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("charset %q is not accepted", webTruncate(webSanitise(cs), 20))
	}
	root := &xn{}
	cur := root
	depth, nodes := 0, 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s", errNcXML, webTruncate(webSanitise(err.Error()), 100))
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, fmt.Errorf("%w: DOCTYPE and entity declarations are not accepted", errNcXML)
		case xml.StartElement:
			depth++
			nodes++
			if depth > ncXMLDepth || nodes > ncXMLNodes {
				return nil, fmt.Errorf("%w: nesting or element count over the limit", errNcXML)
			}
			n := &xn{Name: t.Name.Local, Off: d.InputOffset(), Parent: cur}
			for _, a := range t.Attr {
				if a.Name.Local == "name" {
					n.Attr = webTruncate(a.Value, 200)
				}
			}
			cur.Kids = append(cur.Kids, n)
			cur = n
		case xml.EndElement:
			if cur.Parent == nil {
				return nil, errNcXML
			}
			cur = cur.Parent
			depth--
		case xml.CharData:
			if len(cur.Text) < ncXMLText {
				cur.Text += strings.TrimSpace(string(t))
			}
		}
	}
	if depth != 0 || len(root.Kids) == 0 {
		return nil, errNcXML
	}
	return root, nil
}

func ncPath(n *xn) string {
	var p []string
	for x := n; x != nil && x.Name != ""; x = x.Parent {
		s := x.Name
		if x.Attr != "" {
			s += "[" + x.Attr + "]"
		}
		p = append(p, s)
	}
	for i, j := 0, len(p)-1; i < j; i, j = i+1, j-1 {
		p[i], p[j] = p[j], p[i]
	}
	return strings.Join(p, "/")
}

func ncOffLine(raw []byte, off int64) int {
	if off > int64(len(raw)) {
		off = int64(len(raw))
	}
	return 1 + bytes.Count(raw[:off], []byte{'\n'})
}

func ncWalk(n *xn, fn func(*xn)) {
	stack := []*xn{n}
	for len(stack) > 0 {
		x := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		fn(x)
		for i := len(x.Kids) - 1; i >= 0; i-- {
			stack = append(stack, x.Kids[i])
		}
	}
}

type panCtx struct {
	m      *ncModel
	raw    []byte
	addr   map[string]*ncSet // scope-less: names are resolved globally (first definition wins)
	svc    map[string]*ncSvc
	agroup map[string][]string
	sgroup map[string][]string
}

func (c *panCtx) loc(n *xn) string {
	return fmt.Sprintf("line %d (%s)", ncOffLine(c.raw, n.Off), webTruncate(ncClean(ncPath(n)), 140))
}

func (c *panCtx) resolveAddr(names []string, depth int, out *ncSet) bool {
	ok := true
	for _, nm := range names {
		l := strings.ToLower(nm)
		if l == "any" {
			out.Any = true
			continue
		}
		if p, isAny, good := ncParseAddrTok(nm); good { // literal addresses are allowed in rules
			if isAny {
				out.Any = true
			} else {
				out.addPrefix(p)
			}
			continue
		}
		c.m.use("address", nm)
		if s, found := c.addr[l]; found {
			out.merge(*s)
			continue
		}
		if g, found := c.agroup[l]; found && depth < ncExpandDepth {
			if !c.resolveAddr(g, depth+1, out) {
				ok = false
			}
			continue
		}
		out.addOpq("name:" + l)
		ok = false
		if out.size() > ncExpandMax {
			return false
		}
	}
	if out.size() > ncExpandMax {
		return false
	}
	return ok
}

func (c *panCtx) resolveSvc(names []string, depth int, out *ncSvc) bool {
	ok := true
	for _, nm := range names {
		l := strings.ToLower(nm)
		switch l {
		case "any":
			out.Any = true
			continue
		case "application-default":
			out.addOpq("application-default")
			continue
		case "service-http":
			out.addRange(ncRange{"tcp", 80, 80})
			out.addRange(ncRange{"tcp", 8080, 8080})
			continue
		case "service-https":
			out.addRange(ncRange{"tcp", 443, 443})
			continue
		}
		c.m.use("service", nm)
		if s, found := c.svc[l]; found {
			out.merge(*s)
			continue
		}
		if g, found := c.sgroup[l]; found && depth < ncExpandDepth {
			if !c.resolveSvc(g, depth+1, out) {
				ok = false
			}
			continue
		}
		out.addOpq("name:" + l)
		ok = false
	}
	if out.size() > ncExpandMax {
		return false
	}
	return ok
}

// ParsePANXML parses a PAN-OS XML configuration into the model.
func ncParsePAN(raw []byte) (*ncModel, error) {
	root, err := ncParseXML(raw)
	if err != nil {
		return nil, err
	}
	m := newNcModel("pan-os")
	m.DescSupported = true
	m.Lines = ncOffLine(raw, int64(len(raw)))
	c := &panCtx{m: m, raw: raw, addr: map[string]*ncSet{}, svc: map[string]*ncSvc{}, agroup: map[string][]string{}, sgroup: map[string][]string{}}

	var rulesNodes []*xn
	var zones, profiles, ifaces []*xn
	zoneOf := map[string]string{} // interface -> zone
	ncWalk(root, func(n *xn) {
		p := n.Parent
		switch {
		case n.Name == "entry" && p != nil && p.Name == "address" && p.Parent != nil && (p.Parent.Name == "shared" || p.Parent.Name == "entry"):
			s := &ncSet{}
			sig := ""
			if v := n.kid("ip-netmask"); v != nil {
				if pf, isAny, ok := ncParseAddrTok(v.Text); ok {
					if isAny {
						s.Any = true
					} else {
						s.addPrefix(pf)
					}
				} else {
					s.addOpq("val:" + strings.ToLower(v.Text))
				}
				sig = v.Text
			} else if v := n.kid("ip-range"); v != nil {
				s.addOpq("range:" + strings.ToLower(v.Text))
				sig = "range " + v.Text
			} else if v := n.kid("fqdn"); v != nil {
				s.addOpq("fqdn:" + strings.ToLower(v.Text))
				sig = "fqdn " + v.Text
			} else {
				return
			}
			c.addr[strings.ToLower(n.Attr)] = s
			m.addObj("address", n.Attr, c.loc(n), strings.ToLower(sig))
		case n.Name == "entry" && p != nil && p.Name == "address-group" && p.Parent != nil && (p.Parent.Name == "shared" || p.Parent.Name == "entry"):
			mem := n.members("static")
			if st := n.kid("static"); st != nil || n.kid("dynamic") != nil {
				c.agroup[strings.ToLower(n.Attr)] = mem
				m.addObj("address", n.Attr, c.loc(n), "")
				if n.kid("dynamic") != nil {
					c.addr[strings.ToLower(n.Attr)] = &ncSet{Opq: map[string]bool{"dyn:" + strings.ToLower(n.Attr): true}}
				}
			}
		case n.Name == "entry" && p != nil && p.Name == "service" && p.Parent != nil && (p.Parent.Name == "shared" || p.Parent.Name == "entry"):
			s := &ncSvc{}
			pr := n.kid("protocol")
			if pr == nil {
				return
			}
			for _, k := range pr.Kids {
				if k.Name != "tcp" && k.Name != "udp" {
					continue
				}
				if pt := k.kid("port"); pt != nil {
					rs, ok := ncParsePorts(k.Name, pt.Text)
					if !ok {
						s.addOpq("name:" + strings.ToLower(n.Attr))
						continue
					}
					for _, r := range rs {
						s.addRange(r)
					}
				}
			}
			c.svc[strings.ToLower(n.Attr)] = s
			m.addObj("service", n.Attr, c.loc(n), s.sig())
		case n.Name == "entry" && p != nil && p.Name == "service-group" && p.Parent != nil && (p.Parent.Name == "shared" || p.Parent.Name == "entry"):
			c.sgroup[strings.ToLower(n.Attr)] = n.members("members")
			m.addObj("service", n.Attr, c.loc(n), "")
		case n.Name == "rules" && p != nil && p.Name == "security" && p.Parent != nil && strings.HasSuffix(p.Parent.Name, "rulebase"):
			rulesNodes = append(rulesNodes, n)
		case n.Name == "entry" && p != nil && p.Name == "zone":
			zones = append(zones, n)
		case n.Name == "entry" && p != nil && p.Name == "interface-management-profile":
			profiles = append(profiles, n)
		case n.Name == "interface-management-profile" && n.Text != "" && len(n.Kids) == 0:
			ifaces = append(ifaces, n)
		}
	})
	if len(rulesNodes) == 0 && len(profiles) == 0 {
		return nil, fmt.Errorf("%w: no security rulebase or management profile was found", errNcXML)
	}

	for _, z := range zones {
		if net := z.kid("network"); net != nil {
			for _, k := range net.Kids {
				for _, mem := range k.members("") {
					zoneOf[strings.ToLower(mem)] = z.Attr
				}
				for _, kk := range k.Kids {
					if kk.Name == "member" && kk.Text != "" {
						zoneOf[strings.ToLower(kk.Text)] = z.Attr
					}
				}
			}
		}
	}

	for _, rn := range rulesNodes {
		scope := ncPath(rn.Parent.Parent) + "/" + rn.Parent.Name // owner path + rulebase name
		for _, e := range rn.Kids {
			if e.Name != "entry" {
				continue
			}
			r := &ncRule{Scope: scope, Name: e.Attr, Loc: c.loc(e), Terminal: true, Log: "unknown", Inspect: "unknown"}
			if d := e.kid("description"); d != nil {
				r.Desc = d.Text
			}
			act := ""
			if a := e.kid("action"); a != nil {
				act = strings.ToLower(a.Text)
			}
			r.Allow = act == "allow"
			if dis, _ := e.yes("disabled"); dis {
				r.Disabled = true
			}
			for _, z := range e.members("from") {
				r.SrcZ.add(z)
			}
			for _, z := range e.members("to") {
				r.DstZ.add(z)
			}
			if len(e.members("from")) == 0 {
				r.SrcZ.Any = true
			}
			if len(e.members("to")) == 0 {
				r.DstZ.Any = true
			}
			ok := c.resolveAddr(orAny(e.members("source")), 0, &r.Src)
			ok2 := c.resolveAddr(orAny(e.members("destination")), 0, &r.Dst)
			ok3 := c.resolveSvc(orAny(e.members("service")), 0, &r.Svc)
			r.Complex = !(ok && ok2 && ok3)
			apps := e.members("application")
			if len(apps) == 0 {
				r.App.Any = true
			}
			for _, a := range apps {
				r.App.add(a)
				r.Apps = append(r.Apps, a)
			}
			var extra []string
			for _, nm := range []string{"negate-source", "negate-destination"} {
				if v, _ := e.yes(nm); v {
					r.Complex = true
					extra = append(extra, nm)
				}
			}
			for _, nm := range []string{"source-user", "category", "source-hip", "destination-hip", "schedule"} {
				if v := e.members(nm); len(v) > 0 && !(len(v) == 1 && strings.EqualFold(v[0], "any")) {
					extra = append(extra, nm+"="+strings.Join(v, "+"))
				}
			}
			sort.Strings(extra)
			r.Extra = strings.Join(extra, ";")
			if ls, has := e.yes("log-start"); has && ls {
				r.Log = "on"
			}
			if le, has := e.yes("log-end"); has {
				if le {
					r.Log = "on"
				} else if r.Log != "on" {
					r.Log = "off"
				}
			}
			if e.kid("profile-setting") != nil {
				r.Inspect = "yes"
			} else if e.kid("log-setting") != nil || e.kid("action") != nil {
				r.Inspect = "no"
			}
			m.addRule(r)
		}
	}

	// management profiles bound to interfaces
	prof := map[string]*xn{}
	for _, p := range profiles {
		prof[strings.ToLower(p.Attr)] = p
	}
	for _, b := range ifaces {
		pn := prof[strings.ToLower(b.Text)]
		if pn == nil {
			continue
		}
		// nearest ancestor entry is the interface (or sub-interface unit)
		ifn := ""
		for x := b.Parent; x != nil; x = x.Parent {
			if x.Name == "entry" && x.Attr != "" {
				ifn = x.Attr
				break
			}
		}
		var on []string
		for _, k := range []string{"ssh", "telnet", "http", "https", "snmp", "http-ocsp", "response-pages", "userid-service"} {
			if v, _ := pn.yes(k); v {
				on = append(on, k)
			}
		}
		restricted := pn.kid("permitted-ip") != nil && len(pn.kid("permitted-ip").Kids) > 0
		zone := zoneOf[strings.ToLower(ifn)]
		untrusted := ncUntrustedName(zone) || (zone == "" && ncUntrustedName(ifn))
		loc := c.loc(b)
		for _, w := range on {
			if w == "telnet" || w == "http" {
				m.issue("netcfg-mgmt-weak-protocol", loc, fmt.Sprintf("interface %s (zone %s) management profile %s allows %s", ncClean(ifn), ncClean(zone), ncClean(pn.Attr), w))
			}
		}
		if untrusted && !restricted {
			var mg []string
			for _, w := range on {
				if w == "ssh" || w == "telnet" || w == "http" || w == "https" || w == "snmp" {
					mg = append(mg, w)
				}
			}
			if len(mg) > 0 {
				m.issue("netcfg-mgmt-exposed-untrusted", loc, fmt.Sprintf("interface %s in zone %s (name looks untrusted) allows %s with no permitted-ip list", ncClean(ifn), ncClean(zone), strings.Join(mg, ", ")))
			}
		}
	}
	m.note("PAN-OS: log-end absent is treated as unknown (the default is not assumed); profile-setting groups are not resolved")
	return m, nil
}

func orAny(v []string) []string {
	if len(v) == 0 {
		return []string{"any"}
	}
	return v
}
