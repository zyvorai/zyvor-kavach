// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

const ccUsage = `usage: kavachctl content custom <command>
  list [--json]                         customer-authored rules
  put FILE|-                            create/update one rule from JSON (harness-validated)
  rm ID                                 delete a custom rule
  dryrun ID FILE|-                      evaluate a rule against {"events":[...]} (nothing is recorded)
  export [--source custom|embedded|all] [--tactic T] [--technique T] [--os O] [--batch B] [--ids a,b] [--out FILE]
  import FILE|- [--validate-only] [--format sigma]   import a JSON pack (or Sigma YAML/JSON)`

func ccReadInput(name string) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("missing FILE (use - for stdin)")
	}
	if name == "-" {
		return io.ReadAll(io.LimitReader(omStdin, 4<<20))
	}
	return os.ReadFile(name)
}

// ccRaw sends a raw body and prints the response as indented JSON. Validation failures (HTTP 400)
// carry a useful JSON body, so it is printed before the error is returned.
func ccRaw(out io.Writer, method, path string, body []byte, compact bool) error {
	b, code, err := doRequest(method, path, body, nil)
	if err != nil {
		return err
	}
	text := strings.TrimSpace(string(b))
	if !compact {
		var buf bytes.Buffer
		if json.Indent(&buf, b, "", "  ") == nil {
			text = buf.String()
		}
	}
	if text != "" {
		fmt.Fprintln(out, text)
	}
	if code >= 300 {
		return fmt.Errorf("HTTP %d", code)
	}
	return nil
}

// ccDispatch handles `kavachctl content custom ...`; other commands fall through.
func ccDispatch(args []string, out io.Writer) (bool, error) {
	if len(args) < 2 || args[0] != "content" || args[1] != "custom" {
		return false, nil
	}
	if len(args) < 3 {
		return true, fmt.Errorf("%s", ccUsage)
	}
	sub := args[2]
	pos, f, b := omParse(args[3:], "source", "tactic", "technique", "os", "batch", "ids", "out", "format")
	j := b["json"]
	switch sub {
	case "list":
		return true, omDo(out, "GET", "/v1/content/custom", nil, j)
	case "put":
		if len(pos) != 1 {
			return true, fmt.Errorf("usage: kavachctl content custom put FILE|-")
		}
		data, err := ccReadInput(pos[0])
		if err != nil {
			return true, err
		}
		return true, ccRaw(out, "POST", "/v1/content/custom", data, j)
	case "rm", "delete":
		if len(pos) != 1 {
			return true, fmt.Errorf("usage: kavachctl content custom rm ID")
		}
		return true, omDo(out, "DELETE", "/v1/content/custom/"+url.PathEscape(pos[0]), nil, j)
	case "dryrun":
		if len(pos) != 2 {
			return true, fmt.Errorf("usage: kavachctl content custom dryrun ID FILE|-")
		}
		data, err := ccReadInput(pos[1])
		if err != nil {
			return true, err
		}
		return true, ccRaw(out, "POST", "/v1/content/custom/"+url.PathEscape(pos[0])+"/dryrun", data, j)
	case "export":
		filter := map[string]any{}
		for _, k := range []string{"source", "tactic", "technique", "os", "batch"} {
			if f[k] != "" {
				filter[k] = f[k]
			}
		}
		if f["ids"] != "" {
			filter["ids"] = strings.Split(f["ids"], ",")
		}
		payload, _ := json.Marshal(filter)
		if f["out"] == "" {
			return true, ccRaw(out, "POST", "/v1/content/export", payload, j)
		}
		resp, code, err := doRequest("POST", "/v1/content/export", payload, nil)
		if err != nil {
			return true, err
		}
		if code >= 300 {
			return true, fmt.Errorf("HTTP %d: %s", code, truncate(strings.TrimSpace(string(resp)), 400))
		}
		if err := os.WriteFile(f["out"], resp, 0600); err != nil {
			return true, err
		}
		fmt.Fprintf(out, "wrote %s\n", f["out"])
		return true, nil
	case "import":
		if len(pos) != 1 {
			return true, fmt.Errorf("usage: kavachctl content custom import FILE|- [--validate-only] [--format sigma]")
		}
		data, err := ccReadInput(pos[0])
		if err != nil {
			return true, err
		}
		q := url.Values{}
		if b["validate-only"] {
			q.Set("validate_only", "true")
		}
		if f["format"] != "" {
			q.Set("format", f["format"])
		}
		path := "/v1/content/import"
		if e := q.Encode(); e != "" {
			path += "?" + e
		}
		return true, ccRaw(out, "POST", path, data, j)
	}
	return true, fmt.Errorf("%s", ccUsage)
}
