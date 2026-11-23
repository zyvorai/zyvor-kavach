// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package edr

// Versioned advisory matching for configuration text (kind "config"). When the
// submitted text carries a product version string (a BIG-IP "#TMSH-VERSION:"
// header, "nginx version: nginx/x.y.z" output of `nginx -V`, or a
// "Server: nginx/x.y.z" line), the version is compared with a user-updatable
// table of vendor advisories. Offline and parse-only: no lookup is made.
//
// Honest limits: only the version string is compared. Vendor advisories often
// depend on a module being provisioned or a feature being configured, and
// distribution packages backport fixes without changing the version string, so
// "in range" means "worth checking", not "exploitable". Findings carry weight 0
// like every other config finding.

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed configadvisories/*.json
var cfgAdvisoryFS embed.FS

// CfgAdvisoryEnv names an optional file that replaces the embedded sample.
const CfgAdvisoryEnv = "KAVACH_CONFIG_ADVISORIES"

const (
	cfgAdvMaxFile  = 2 << 20
	cfgAdvMaxItems = 5000
	cfgAdvFormat   = "kavach-config-advisories/1"
)

// CfgAdvRange is a half-open affected range: introduced <= v < fixed, or
// introduced <= v <= last_affected when there is no fix.
type CfgAdvRange struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// CfgAdvisory is one entry of the advisory table.
type CfgAdvisory struct {
	ID             string        `json:"id"`
	Aliases        []string      `json:"aliases,omitempty"`
	Product        string        `json:"product"` // nginx | bigip
	Severity       string        `json:"severity"`
	Summary        string        `json:"summary"`
	Ranges         []CfgAdvRange `json:"ranges"`
	KEV            bool          `json:"kev,omitempty"`
	Source         string        `json:"source,omitempty"`
	SourceVerified bool          `json:"source_verified"`
	SourceNote     string        `json:"source_note,omitempty"`
}

type cfgAdvFile struct {
	Format     string        `json:"format"`
	Source     string        `json:"source"`
	Note       string        `json:"note"`
	Advisories []CfgAdvisory `json:"advisories"`
}

var (
	cfgAdvOnce sync.Once
	cfgAdvSet  []CfgAdvisory
	cfgAdvSrc  string
	cfgAdvErr  error
)

var cfgAdvIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)

// ParseCfgAdvisories validates an advisory table. It is exported for tests and
// for the CLI; it never fetches anything.
func ParseCfgAdvisories(b []byte) (*cfgAdvFile, error) {
	if len(b) > cfgAdvMaxFile {
		return nil, fmt.Errorf("advisory file larger than %d bytes", cfgAdvMaxFile)
	}
	var f cfgAdvFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("advisory file: %v", err)
	}
	if f.Format != cfgAdvFormat {
		return nil, fmt.Errorf("advisory file: format must be %q", cfgAdvFormat)
	}
	if len(f.Advisories) > cfgAdvMaxItems {
		return nil, fmt.Errorf("advisory file: more than %d advisories", cfgAdvMaxItems)
	}
	seen := map[string]bool{}
	for i := range f.Advisories {
		a := &f.Advisories[i]
		if !cfgAdvIDRe.MatchString(a.ID) {
			return nil, fmt.Errorf("advisory %d: bad id", i)
		}
		if seen[a.ID+"|"+a.Product] {
			return nil, fmt.Errorf("advisory %s: duplicate", a.ID)
		}
		seen[a.ID+"|"+a.Product] = true
		if a.Product != "nginx" && a.Product != "bigip" {
			return nil, fmt.Errorf("advisory %s: product must be nginx or bigip", a.ID)
		}
		switch a.Severity {
		case "low", "medium", "high", "critical":
		default:
			return nil, fmt.Errorf("advisory %s: bad severity", a.ID)
		}
		if len(a.Ranges) == 0 || len(a.Ranges) > 64 {
			return nil, fmt.Errorf("advisory %s: needs 1..64 ranges", a.ID)
		}
		for _, r := range a.Ranges {
			if _, ok := cfgVerParse(r.Introduced); !ok {
				return nil, fmt.Errorf("advisory %s: bad introduced %q", a.ID, r.Introduced)
			}
			if r.Fixed == "" && r.LastAffected == "" {
				return nil, fmt.Errorf("advisory %s: a range needs fixed or last_affected", a.ID)
			}
			for _, v := range []string{r.Fixed, r.LastAffected} {
				if v != "" {
					if _, ok := cfgVerParse(v); !ok {
						return nil, fmt.Errorf("advisory %s: bad version %q", a.ID, v)
					}
				}
			}
		}
		a.Summary = cfgAdvClip(a.Summary, 300)
		a.SourceNote = cfgAdvClip(a.SourceNote, 400)
	}
	return &f, nil
}

func cfgAdvClip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// CfgAdvisories returns the active table and a label of where it came from.
func CfgAdvisories() ([]CfgAdvisory, string, error) {
	cfgAdvOnce.Do(func() {
		if p := os.Getenv(CfgAdvisoryEnv); p != "" {
			b, err := os.ReadFile(p)
			if err == nil {
				f, perr := ParseCfgAdvisories(b)
				if perr == nil {
					cfgAdvSet, cfgAdvSrc = f.Advisories, "operator file "+p
					return
				}
				err = perr
			}
			cfgAdvErr = fmt.Errorf("%s: %v (falling back to the embedded sample)", CfgAdvisoryEnv, err)
		}
		b, err := cfgAdvisoryFS.ReadFile("configadvisories/sample.json")
		if err != nil {
			cfgAdvErr = err
			return
		}
		f, err := ParseCfgAdvisories(b)
		if err != nil {
			cfgAdvErr = err
			return
		}
		cfgAdvSet, cfgAdvSrc = f.Advisories, "embedded SAMPLE (not a complete or current feed)"
	})
	return cfgAdvSet, cfgAdvSrc, cfgAdvErr
}

// cfgVerParse reads dotted numeric versions ("1.25.3", "15.1.5.1"). A
// trailing non-numeric suffix on a part ("5.1-hf2") is ignored; anything that
// does not start with a digit is rejected.
func cfgVerParse(s string) ([]int, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "v"))
	if s == "" || len(s) > 40 {
		return nil, false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 6 {
		return nil, false
	}
	out := make([]int, 0, len(parts))
	for i, p := range parts {
		j := 0
		for j < len(p) && p[j] >= '0' && p[j] <= '9' {
			j++
		}
		if j == 0 || j > 9 {
			return nil, false
		}
		n, _ := strconv.Atoi(p[:j])
		out = append(out, n)
		if j < len(p) && i != len(parts)-1 {
			return nil, false
		}
	}
	return out, true
}

func cfgVerCmp(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// CfgAdvAffected reports whether version v is inside any range of a.
func CfgAdvAffected(a CfgAdvisory, v []int) bool {
	for _, r := range a.Ranges {
		lo, _ := cfgVerParse(r.Introduced)
		if cfgVerCmp(v, lo) < 0 {
			continue
		}
		if r.Fixed != "" {
			hi, _ := cfgVerParse(r.Fixed)
			if cfgVerCmp(v, hi) < 0 {
				return true
			}
			continue
		}
		hi, _ := cfgVerParse(r.LastAffected)
		if cfgVerCmp(v, hi) <= 0 {
			return true
		}
	}
	return false
}

func cfgAdvFixedIn(a CfgAdvisory, v []int) string {
	for _, r := range a.Ranges {
		lo, _ := cfgVerParse(r.Introduced)
		if cfgVerCmp(v, lo) >= 0 && r.Fixed != "" {
			hi, _ := cfgVerParse(r.Fixed)
			if cfgVerCmp(v, hi) < 0 {
				return r.Fixed
			}
		}
	}
	return "no fixed version listed for this branch"
}

var (
	cfgVerNginxRe = regexp.MustCompile(`(?i)\bnginx/(\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	cfgVerBigIPRe = regexp.MustCompile(`(?m)^#TMSH-VERSION:\s*([0-9]{1,3}(?:\.[0-9]{1,4}){1,4})`)
)

// CfgDetectVersions finds product versions in submitted text (first 2 MiB).
func CfgDetectVersions(text string) map[string]string {
	if len(text) > 2<<20 {
		text = text[:2<<20]
	}
	out := map[string]string{}
	if m := cfgVerBigIPRe.FindStringSubmatch(text); m != nil {
		out["bigip"] = m[1]
	}
	if m := cfgVerNginxRe.FindStringSubmatch(text); m != nil {
		out["nginx"] = m[1]
	}
	return out
}

func init() {
	RegisterAnalyzer("config-advisory", []string{InspectKindConfig}, configAdvisoryAnalyzer)
}

func configAdvisoryAnalyzer(ctx context.Context, in InspectInput, b *InspectBuilder) error {
	vers := CfgDetectVersions(in.Text)
	if len(vers) == 0 {
		return nil
	}
	advs, src, err := CfgAdvisories()
	if err != nil && len(advs) == 0 {
		return err
	}
	products := make([]string, 0, len(vers))
	for p := range vers {
		products = append(products, p)
	}
	sort.Strings(products)
	matched := 0
	for _, p := range products {
		v, ok := cfgVerParse(vers[p])
		if !ok {
			continue
		}
		for _, a := range advs {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if a.Product != p || !CfgAdvAffected(a, v) {
				continue
			}
			matched++
			sev := a.Severity
			ev := fmt.Sprintf("%s %s is in the affected range; fixed in %s. %s", p, vers[p], cfgAdvFixedIn(a, v), a.Summary)
			if !a.SourceVerified {
				ev += " (advisory data not verified against the vendor page)"
			}
			b.Finding(InspectFinding{ID: "cfg-advisory-" + strings.ToLower(a.ID), Title: "[fail] Version string in range of " + a.ID + " (" + p + ")",
				Severity: sev, Technique: "T1190", Evidence: previewOf(ev)})
		}
	}
	meta := map[string]any{"versions": vers, "advisory_source": src, "matched": matched, "advisories_loaded": len(advs),
		"note": "Only the version string in the submitted text is compared. Advisories can depend on provisioned modules or configured features, and distribution packages backport fixes without changing the version, so a match means check the vendor advisory, not proof of exposure."}
	if err != nil {
		meta["advisory_warning"] = err.Error()
	}
	b.Meta("summary", meta)
	return nil
}
