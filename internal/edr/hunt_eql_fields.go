// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// kavach-seq field catalogue. Every field below exists in data Kavach really
// stores; every "absent" entry documents a field analysts commonly expect but
// that is NOT collected, so a query that uses it is rejected with a reason
// instead of silently matching nothing.

type seqFType string

const (
	ftString seqFType = "string"
	ftInt    seqFType = "int"
	ftBool   seqFType = "bool"
)

// SeqCategories is the ordered list of event categories.
var SeqCategories = []string{"process", "network", "file", "registry", "dns", "auth", "module"}

// SeqField describes one queryable field.
type SeqField struct {
	Name     string   `json:"name"`
	Type     seqFType `json:"type"`
	Note     string   `json:"note,omitempty"`
	Optional bool     `json:"optional,omitempty"` // may be empty/0 when the source did not supply it
	Joinable bool     `json:"joinable,omitempty"` // usable in `sequence by`
}

// SeqAbsent documents a field that does not exist for a category.
type SeqAbsent struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type seqCatalog struct {
	Category string      `json:"category"`
	Source   string      `json:"source"`
	Fields   []SeqField  `json:"fields"`
	Absent   []SeqAbsent `json:"absent"`
}

var seqHost = SeqField{Name: "host", Type: ftString, Joinable: true}
var seqPIDReq = SeqField{Name: "pid", Type: ftInt, Joinable: true, Note: "OS process id; pids repeat across hosts, so use `by host, pid`"}
var seqPIDOpt = SeqField{Name: "pid", Type: ftInt, Joinable: true, Optional: true, Note: "0/unknown when the source gave no attribution; such events never join in a `by pid` sequence"}

var seqCatalogue = []seqCatalog{
	{"process", "process ledger (/proc scan or agent ingest)", []SeqField{
		seqHost, seqPIDReq,
		{Name: "ppid", Type: ftInt}, {Name: "uid", Type: ftInt, Note: "numeric uid only; no user name is stored"},
		{Name: "executable", Type: ftString, Note: "full image path"},
		{Name: "parent_exe", Type: ftString, Optional: true},
		{Name: "command", Type: ftString, Note: "full command line"},
		{Name: "process_start", Type: ftString, Optional: true, Note: "start-time token used to disambiguate pid reuse"},
	}, []SeqAbsent{
		{"user", "process events store a numeric uid, not a user name; use uid"},
		{"hash", "no binary hash is recorded on process events"},
		{"cwd", "working directory is not collected"},
		{"parent_command", "only the parent image path (parent_exe) is stored"},
		{"name", "no basename field; use executable with like/endswith"},
	}},
	{"network", "Netra adapter network ledger", []SeqField{
		seqHost, seqPIDReq,
		{Name: "destination", Type: ftString, Note: "destination string as reported by the adapter (typically host or ip[:port])"},
		{Name: "verdict", Type: ftString, Optional: true}, {Name: "source", Type: ftString, Optional: true, Note: "which adapter/sensor reported it"},
		{Name: "process_start", Type: ftString, Optional: true},
	}, []SeqAbsent{
		{"executable", "network events carry no process image; join on pid (sequence by host, pid) and match the image in the process step"},
		{"command", "network events carry no command line"},
		{"port", "no separate port field; match with destination like \"*:443\""},
		{"protocol", "protocol is not recorded"}, {"bytes", "byte counts are not recorded"},
		{"direction", "direction is not recorded"}, {"source_ip", "local address is not recorded on network events"},
	}},
	{"file", "file ledger (file scanner / agent ingest)", []SeqField{
		seqHost, seqPIDOpt,
		{Name: "path", Type: ftString}, {Name: "operation", Type: ftString, Note: "operation name as reported by the scanner"},
		{Name: "size", Type: ftInt, Optional: true},
	}, []SeqAbsent{
		{"executable", "the file scanner cannot identify the writer; pid is optional and there is no image"},
		{"hash", "file content hashes are not stored on file events"},
		{"user", "no owner is recorded on file events"}, {"extension", "no extension field; use path with like/endswith"},
	}},
	{"registry", "telemetry ring (type registry)", []SeqField{
		seqHost, seqPIDOpt, {Name: "user", Type: ftString, Optional: true},
		{Name: "key", Type: ftString}, {Name: "value_name", Type: ftString, Optional: true},
		{Name: "value_data", Type: ftString, Optional: true, Note: "truncated at ingest"},
		{Name: "operation", Type: ftString, Note: "set|create|delete|rename"},
	}, []SeqAbsent{{"executable", "registry events carry no process image; join on pid"}, {"command", "no command line on registry events"}}},
	{"dns", "telemetry ring (type dns)", []SeqField{
		seqHost, seqPIDOpt, {Name: "user", Type: ftString, Optional: true},
		{Name: "query", Type: ftString}, {Name: "qtype", Type: ftString, Optional: true},
		{Name: "answers", Type: ftString, Optional: true, Note: "answers joined with a comma; use :/like with wildcards"},
		{Name: "resolver", Type: ftString, Optional: true},
	}, []SeqAbsent{{"executable", "dns events carry no process image; join on pid"}, {"ttl", "TTL is not recorded"}}},
	{"auth", "telemetry ring (type auth)", []SeqField{
		seqHost, seqPIDOpt, {Name: "user", Type: ftString, Optional: true},
		{Name: "source_ip", Type: ftString, Optional: true},
		{Name: "method", Type: ftString, Note: "ssh|sudo|rdp|console|kerberos|ntlm|oauth"},
		{Name: "outcome", Type: ftString, Note: "success|failure"},
	}, []SeqAbsent{{"target_user", "only the authenticating user is recorded"}, {"logon_type", "no Windows logon type; use method"}}},
	{"module", "telemetry ring (type module)", []SeqField{
		seqHost, seqPIDOpt, {Name: "user", Type: ftString, Optional: true},
		{Name: "module_path", Type: ftString}, {Name: "hash", Type: ftString, Optional: true},
		{Name: "signed", Type: ftBool}, {Name: "signer", Type: ftString, Optional: true},
		{Name: "kind", Type: ftString, Note: "dll|so|kext|driver"},
	}, []SeqAbsent{{"executable", "module events carry no loading image; join on pid"}}},
}

func seqLookupCat(cat string) (*seqCatalog, bool) {
	for i := range seqCatalogue {
		if seqCatalogue[i].Category == cat {
			return &seqCatalogue[i], true
		}
	}
	return nil, false
}

func (c *seqCatalog) field(name string) (SeqField, bool) {
	for _, f := range c.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return SeqField{}, false
}

func (c *seqCatalog) absentReason(name string) string {
	for _, a := range c.Absent {
		if a.Name == name {
			return a.Reason
		}
	}
	return ""
}
