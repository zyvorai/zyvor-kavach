// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"runtime/debug"
	"sort"
	"strings"
)

// Content versioning: stable hashes of every embedded content pack so operators can see what
// changed between builds. Hashes are computed over canonical JSON (sorted keys) and items are
// sorted by id, so neither key order nor item order affects any hash. Observation only.

// ContentRuleSnap is one item (rule, profile, scenario, ...) inside a pack.
type ContentRuleSnap struct {
	ID    string            `json:"id"`
	Hash  string            `json:"hash"`
	Field map[string]string `json:"fields,omitempty"` // top-level field -> short hash, for field-level diffs
}

// ContentPackSnap is the hash and item list of one pack file.
type ContentPackSnap struct {
	Name     string            `json:"name"` // e.g. detection/content/windows.json
	Kind     string            `json:"kind"` // detection | bytes | adversary | scenario | hunt | compliance
	Hash     string            `json:"hash"`
	Count    int               `json:"count"`
	Items    []ContentRuleSnap `json:"items"`
	Metadata string            `json:"meta_hash,omitempty"` // hash of non-item top-level keys
}

// ContentSnapshot is the state of all embedded content at one point in time.
type ContentSnapshot struct {
	Seq    int               `json:"seq"`
	Time   string            `json:"time"`
	Build  string            `json:"build"`
	Hash   string            `json:"hash"`
	Packs  []ContentPackSnap `json:"packs"`
	Total  int               `json:"total_items"`
	ByKind map[string]int    `json:"items_by_kind"`
}

func shortHash(b []byte, n int) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])[:n]
}

// canonJSON re-marshals a decoded value; encoding/json sorts map keys, so the output is stable.
func canonJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// hashPack parses one JSON pack (object with arrays of {id,...} items, or a top-level array) and
// returns its snapshot. Items without an id get a content-derived id. Order-independent.
func hashPack(name, kind string, raw []byte) (ContentPackSnap, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ContentPackSnap{}, fmt.Errorf("%s: %w", name, err)
	}
	ps := ContentPackSnap{Name: name, Kind: kind}
	meta := map[string]any{}
	add := func(prefix string, arr []any) {
		for _, it := range arr {
			m, ok := it.(map[string]any)
			if !ok {
				meta[prefix+"#"+shortHash(canonJSON(it), 8)] = it
				continue
			}
			id, _ := m["id"].(string)
			full := canonJSON(m)
			if id == "" {
				id = "anon-" + shortHash(full, 10)
			}
			if prefix != "" {
				id = prefix + "/" + id
			}
			fields := make(map[string]string, len(m))
			for k, v := range m {
				fields[k] = shortHash(canonJSON(v), 6)
			}
			ps.Items = append(ps.Items, ContentRuleSnap{ID: id, Hash: shortHash(full, 16), Field: fields})
		}
	}
	switch d := doc.(type) {
	case []any:
		add("", d)
	case map[string]any:
		arrKeys := []string{}
		for k, v := range d {
			if a, ok := v.([]any); ok && len(a) > 0 {
				if _, isObj := a[0].(map[string]any); isObj {
					arrKeys = append(arrKeys, k)
					continue
				}
			}
			meta[k] = v
		}
		sort.Strings(arrKeys)
		for _, k := range arrKeys {
			p := ""
			if len(arrKeys) > 1 { // a single array key keeps ids unprefixed
				p = k
			}
			add(p, d[k].([]any))
		}
	}
	sort.Slice(ps.Items, func(i, j int) bool { return ps.Items[i].ID < ps.Items[j].ID })
	ps.Count = len(ps.Items)
	var sb strings.Builder
	for _, it := range ps.Items {
		sb.WriteString(it.ID + ":" + it.Hash + "\n")
	}
	if len(meta) > 0 {
		ps.Metadata = shortHash(canonJSON(meta), 12)
		sb.WriteString("meta:" + ps.Metadata + "\n")
	}
	ps.Hash = shortHash([]byte(sb.String()), 16)
	return ps, nil
}

// combineSnapshot fills the derived fields (overall hash, totals) of a snapshot from its packs.
func combineSnapshot(packs []ContentPackSnap) ContentSnapshot {
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	s := ContentSnapshot{Packs: packs, ByKind: map[string]int{}}
	var sb strings.Builder
	for _, p := range packs {
		s.Total += p.Count
		s.ByKind[p.Kind] += p.Count
		sb.WriteString(p.Name + ":" + p.Hash + "\n")
	}
	s.Hash = shortHash([]byte(sb.String()), 16)
	return s
}

func packsFromFS(fsys fs.FS, dir, kind string, out *[]ContentPackSnap, errs *[]error) {
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		*errs = append(*errs, err)
		return
	}
	for _, e := range ents {
		if e.IsDir() || path.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			*errs = append(*errs, err)
			continue
		}
		p, err := hashPack(kind+"/"+dir+"/"+e.Name(), kind, raw)
		if err != nil {
			*errs = append(*errs, err)
			continue
		}
		*out = append(*out, p)
	}
}

// buildContentSnapshot hashes every embedded pack (detection, byte patterns, adversaries,
// validation scenarios, hunt examples, regulatory catalog). Custom customer rules are excluded:
// they are operator state, not shipped content.
func buildContentSnapshot() (ContentSnapshot, []error) {
	var packs []ContentPackSnap
	var errs []error
	packsFromFS(contentFS, "content", "detection", &packs, &errs)
	packsFromFS(byteContentFS, "bytecontent", "bytes", &packs, &errs)
	packsFromFS(adversaryFS, "adversaries", "adversary", &packs, &errs)
	packsFromFS(scenarioFS, "scenarios", "scenario", &packs, &errs)
	for _, f := range []struct {
		file, kind string
		raw        []byte
	}{{"hunt_eql_examples.json", "hunt", seqExamplesJSON}, {"regulatory_regimes.json", "compliance", regulatoryCatalogJSON}} {
		p, err := hashPack(f.kind+"/"+f.file, f.kind, f.raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		packs = append(packs, p)
	}
	return combineSnapshot(packs), errs
}

// contentBuildString returns the VCS revision when the binary carries one, else "dev".
func contentBuildString() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	rev, mod := "", ""
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				mod = "+dirty"
			}
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev + mod
}
