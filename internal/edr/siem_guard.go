// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"
)

// SIEM push-sink SSRF policy. Loopback, link-local (includes the cloud
// metadata address 169.254.169.254), unspecified and multicast destinations are
// always refused. RFC1918 and ULA ranges are refused unless the operator sets
// KAVACH_SIEM_ALLOW_PRIVATE=1. Tests use SIEMConfig.allowLoopback, which is
// unexported and never set from the environment.

func siemAllowPrivate() bool { return os.Getenv("KAVACH_SIEM_ALLOW_PRIVATE") == "1" }

// siemIPBlocked reports why ip may not be dialled ("" when it may).
func siemIPBlocked(ip net.IP, allowPrivate, allowLoopback bool) string {
	switch {
	case ip.IsLoopback():
		if allowLoopback {
			return ""
		}
		return "loopback address"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return "link-local or metadata address"
	case ip.IsUnspecified():
		return "unspecified address"
	case ip.IsMulticast() || ip.IsInterfaceLocalMulticast():
		return "multicast address"
	case ip.IsPrivate():
		if allowPrivate {
			return ""
		}
		return "private address (set KAVACH_SIEM_ALLOW_PRIVATE=1 to allow)"
	}
	return ""
}

// validateSIEMURL checks scheme, host and the addresses the host resolves to.
// A host that does not resolve yet is accepted; the dial guard still applies.
func validateSIEMURL(raw string, allowPrivate, allowLoopback bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("invalid webhook url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("webhook url scheme must be http or https")
	}
	host := u.Hostname()
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if addrs, err := net.LookupIP(host); err == nil {
		ips = addrs
	}
	for _, ip := range ips {
		if why := siemIPBlocked(ip, allowPrivate, allowLoopback); why != "" {
			return nil, fmt.Errorf("webhook host %s resolves to a blocked %s", host, why)
		}
	}
	return u, nil
}

// siemDialControl re-checks the concrete IP at connect time, so DNS rebinding
// and redirects cannot reach a blocked address.
func siemDialControl(allowPrivate, allowLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return errors.New("siem: non-IP dial address")
		}
		if why := siemIPBlocked(ip, allowPrivate, allowLoopback); why != "" {
			return fmt.Errorf("siem: destination refused: %s", why)
		}
		return nil
	}
}

// newSIEMHTTPClient returns a client whose dialer enforces the policy. It does
// not use proxy environment variables (a proxy would make the dial check see
// the proxy, not the target).
func newSIEMHTTPClient(allowPrivate, allowLoopback bool) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: siemDialControl(allowPrivate, allowLoopback)}
	tr := &http.Transport{DialContext: d.DialContext, Proxy: nil, TLSHandshakeTimeout: 5 * time.Second}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			_, err := validateSIEMURL(req.URL.String(), allowPrivate, allowLoopback)
			return err
		},
	}
}
