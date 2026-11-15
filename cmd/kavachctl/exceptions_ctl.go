// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"fmt"
	"io"
)

const excUsage = `usage: kavachctl exceptions <command>
  list [--status active|expired] [--json]   exceptions and hash-chain integrity
  create --file F [--yes]                   admin; F: rule, reason, owner, expires (RFC3339), optional host, path
  update ID --file F [--yes]                admin
  expire ID [--yes]                         admin; reporting resumes immediately
  delete ID [--yes]                         admin; suppressed findings are kept
  suppressed [--exception ID] [--json]      findings whose REPORTING was suppressed
  history [--json]                          hash-chained change history
An exception suppresses reporting only; nothing is blocked.`

func excChain(out io.Writer, ok any, at any, entries any) {
	if ok == true {
		fmt.Fprintf(out, "Chain integrity: OK (%v entries)\n", entries)
		return
	}
	fmt.Fprintf(out, "Chain integrity: BROKEN at seq %v (history was altered or truncated)\n", at)
}

func excRun(out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", excUsage)
	}
	pos, f, b := omParse(args[1:], "file", "status", "exception")
	j := b["json"]
	switch args[0] {
	case "list":
		raw, err := schedCall("GET", omQuery("/v1/exceptions", f, "status"), nil)
		if err != nil {
			return err
		}
		if j {
			schedShow(out, raw, true)
			return nil
		}
		m, err := schedObj(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-8s %-10s %-24s %-16s %-22s %-10s %s\n", "ID", "STATUS", "RULE", "HOST", "EXPIRES", "SUPPRESSED", "OWNER / REASON")
		for _, e := range listOf(m, "exceptions") {
			fmt.Fprintf(out, "%-8s %-10s %-24s %-16s %-22s %-10s %s / %s\n", strFrom(e, "id"), strFrom(e, "status"), truncate(strFrom(e, "rule"), 24), truncate(strFrom(e, "host"), 16), truncate(strFrom(e, "expires"), 22), num(e, "suppressed_count"), strFrom(e, "owner"), truncate(strFrom(e, "reason"), 40))
		}
		fmt.Fprintf(out, "%s exceptions. These suppress reporting only; nothing is blocked.\n", num(m, "count"))
		if c, ok := m["chain"].(map[string]any); ok {
			excChain(out, c["ok"], c["broken_at_seq"], c["entries"])
		}
		return nil
	case "history":
		raw, err := schedCall("GET", "/v1/exceptions/history", nil)
		if err != nil {
			return err
		}
		if j {
			schedShow(out, raw, true)
			return nil
		}
		m, err := schedObj(raw)
		if err != nil {
			return err
		}
		hs := listOf(m, "history")
		for _, h := range hs {
			fmt.Fprintf(out, "#%s %s %-8s %-8s %s  %s\n", num(h, "seq"), strFrom(h, "time"), strFrom(h, "action"), strFrom(h, "target"), strFrom(h, "actor"), truncate(strFrom(h, "detail"), 60))
		}
		excChain(out, m["chain_ok"], m["broken_at_seq"], len(hs))
		return nil
	case "suppressed":
		raw, err := schedCall("GET", omQuery("/v1/exceptions/suppressed", f, "exception"), nil)
		if err != nil {
			return err
		}
		if j {
			schedShow(out, raw, true)
			return nil
		}
		m, err := schedObj(raw)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%-8s %-26s %-26s %s\n", "EXC", "SUPPRESSED AT", "FINDING", "RULE / HOST")
		for _, s := range listOf(m, "suppressed") {
			fd, _ := s["finding"].(map[string]any)
			fmt.Fprintf(out, "%-8s %-26s %-26s %s / %s\n", strFrom(s, "exception_id"), strFrom(s, "suppressed_at"), truncate(strFrom(fd, "id"), 26), strFrom(fd, "rule"), strFrom(fd, "host"))
		}
		fmt.Fprintf(out, "Total suppressed: %s (retained %s of max %s). Reporting was suppressed; nothing was blocked.\n", num(m, "total_suppressed"), num(m, "retained"), num(m, "retained_max"))
		return nil
	case "create":
		if len(pos) != 0 {
			return fmt.Errorf("usage: kavachctl exceptions create --file F [--yes]")
		}
		return schedWrite(out, "exceptions create", "POST", "/v1/exceptions", f["file"], b["yes"], j, "This creates an exception that suppresses REPORTING of matching findings (nothing is blocked).")
	case "update":
		id, err := schedID(pos, "usage: kavachctl exceptions update ID --file F [--yes]")
		if err != nil {
			return err
		}
		return schedWrite(out, "exceptions update", "PUT", "/v1/exceptions/"+id, f["file"], b["yes"], j, "This updates exception "+id+" (suppresses reporting only).")
	case "expire":
		id, err := schedID(pos, "usage: kavachctl exceptions expire ID [--yes]")
		if err != nil {
			return err
		}
		return schedSimple(out, "exceptions expire", "PUT", "/v1/exceptions/"+id, []byte(`{"expire_now":true}`), b["yes"], j, "This expires exception "+id+" now; reporting resumes.")
	case "delete":
		id, err := schedID(pos, "usage: kavachctl exceptions delete ID [--yes]")
		if err != nil {
			return err
		}
		return schedSimple(out, "exceptions delete", "DELETE", "/v1/exceptions/"+id, nil, b["yes"], j, "This deletes exception "+id+" (suppressed findings are kept).")
	}
	return fmt.Errorf("unknown exceptions command %q\n%s", args[0], excUsage)
}
