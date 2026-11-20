// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Built-in benign fixtures: ordinary files and scripts that no rule at medium
// severity or above may match. The loader enforces this at load time, so a rule
// that is too broad fails the build rather than shipping.

import "encoding/binary"

type byteBenign struct {
	name  string
	kinds []string
	data  []byte
}

var (
	benignBoth   = []string{InspectKindFile, InspectKindScript}
	benignFileOn = []string{InspectKindFile}
)

// benignPEStub is a minimal, ordinary executable header: DOS stub, PE
// signature, conventional section names and a few common imports.
func benignPEStub() []byte {
	b := make([]byte, 0x600)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x4e:], "This program cannot be run in DOS mode.\r\r\n$")
	copy(b[0x80:], "PE\x00\x00")
	copy(b[0x180:], ".text\x00\x00\x00.rdata\x00\x00.data\x00\x00\x00.rsrc\x00\x00\x00.reloc\x00\x00")
	copy(b[0x300:], "KERNEL32.dll\x00GetModuleHandleW\x00GetProcAddress\x00CreateFileW\x00ReadFile\x00CloseHandle\x00ExitProcess\x00USER32.dll\x00MessageBoxW\x00")
	copy(b[0x500:], "Hello, world\x00")
	return b
}

func benignELFStub() []byte {
	b := make([]byte, 0x400)
	copy(b, "\x7fELF\x02\x01\x01")
	copy(b[0x200:], ".text\x00.data\x00.bss\x00libc.so.6\x00printf\x00malloc\x00free\x00puts\x00")
	return b
}

func benignMachOStub() []byte {
	b := make([]byte, 0x400)
	copy(b, "\xcf\xfa\xed\xfe")
	copy(b[0x100:], "__TEXT\x00__text\x00__DATA\x00/usr/lib/libSystem.B.dylib\x00_printf\x00_malloc\x00")
	return b
}

func byteBenignFixtures() []byteBenign {
	t := func(name, text string) byteBenign {
		return byteBenign{name: name, kinds: benignBoth, data: []byte(text)}
	}
	return []byteBenign{
		t("readme", "# Widget\n\nWidget is a small library for parsing config files.\n\n## Install\n\n    go get example.com/widget\n\n## Usage\n\nCall `widget.Parse(path)` and read the result. Pull requests welcome. Licensed under MIT.\nSee the wiki for the download page, the password reset flow documentation and the encryption design notes.\n"),
		t("json", `{"name":"app","version":"1.2.3","dependencies":{"left-pad":"^1.3.0"},"scripts":{"build":"tsc -p .","test":"jest"},"files":["dist"],"keywords":["eval","exec","shell"]}`),
		t("go-source", "package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"os/exec\"\n\t\"encoding/base64\"\n)\n\nfunc main() {\n\tout, err := exec.Command(\"ls\", \"-l\").Output()\n\tif err != nil {\n\t\tfmt.Println(err)\n\t\tos.Exit(1)\n\t}\n\tfmt.Println(base64.StdEncoding.EncodeToString(out))\n}\n"),
		t("shell-backup", "#!/bin/bash\nset -euo pipefail\nSRC=/var/www\nDEST=/backup/$(date +%F)\nmkdir -p \"$DEST\"\ntar czf \"$DEST/www.tgz\" \"$SRC\"\nrsync -a \"$DEST\" backup@nas:/volume1/\necho \"done\"\ncrontab -l | head -5\n"),
		t("shell-installer", "#!/bin/sh\n# install the tool\nset -e\nVERSION=1.4.0\ncurl -fsSL -o /tmp/tool.tgz https://releases.example.com/tool-$VERSION.tgz\ntar -xzf /tmp/tool.tgz -C /usr/local/bin\nchmod +x /usr/local/bin/tool\ntool --version\n"),
		t("html", "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>Home</title><script src=\"/app.js\"></script></head><body><h1>Welcome</h1><form action=\"/login\" method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\"><button>Sign in</button></form><script>document.title = atob('SG9tZQ==');</script></body></html>\n"),
		t("nginx-conf", "worker_processes auto;\nevents { worker_connections 1024; }\nhttp {\n  server {\n    listen 80;\n    server_name example.com;\n    location / { proxy_pass http://127.0.0.1:8080; }\n    location ~ \\.php$ { fastcgi_pass unix:/run/php/php-fpm.sock; include fastcgi_params; }\n  }\n}\n"),
		t("yaml-config", "version: \"3\"\nservices:\n  web:\n    image: nginx:1.25\n    ports:\n      - \"8080:80\"\n    environment:\n      - LOG_LEVEL=info\n  db:\n    image: postgres:16\n    volumes:\n      - data:/var/lib/postgresql/data\nvolumes:\n  data: {}\n"),
		t("ini-config", "[core]\nrepositoryformatversion = 0\nfilemode = true\n[remote \"origin\"]\n\turl = https://example.com/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[user]\n\tname = Dev\n\temail = dev@example.com\n"),
		t("python-source", "import json\nimport subprocess\nimport base64\n\ndef run(cmd):\n    r = subprocess.run(cmd, capture_output=True, text=True)\n    return r.stdout\n\nif __name__ == '__main__':\n    print(json.dumps({'out': run(['uname', '-a']), 'b': base64.b64encode(b'hi').decode()}))\n"),
		t("php-page", "<?php\nrequire_once 'config.php';\n$name = htmlspecialchars($_GET['name'] ?? 'guest');\necho \"<h1>Hello, $name</h1>\";\n$rows = $db->query('SELECT id, title FROM posts LIMIT 10');\nforeach ($rows as $row) { echo '<li>' . htmlspecialchars($row['title']) . '</li>'; }\n"),
		t("powershell-admin", "Param([string]$Path = 'C:\\Logs')\n$files = Get-ChildItem -Path $Path -Filter *.log | Where-Object { $_.Length -gt 1MB }\nforeach ($f in $files) { Compress-Archive -Path $f.FullName -DestinationPath ($f.FullName + '.zip') }\nWrite-Output \"Compressed $($files.Count) files\"\nGet-Service | Where-Object Status -eq 'Running' | Select-Object -First 5\n"),
		t("javascript", "const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.json({ ok: true, buf: Buffer.from('abc').toString('base64') }));\napp.listen(3000, () => console.log('listening'));\n"),
		t("ransom-like-prose", "Dear customer, your invoice is attached. Your files are available in the shared folder; please pay the invoice in bitcoin or by bank transfer within 30 days. To decrypt the archive use the password in the email. Contact support for help.\n"),
		t("config-miner-prose", "The pool section of the benchmark report describes thread pools and connection pools. The stratum layer of the rock is shown in figure 3. Wallet and user fields are covered in the billing chapter.\n"),
		{name: "csv", kinds: benignBoth, data: []byte("id,name,email\n1,Ann,ann@example.com\n2,Bob,bob@example.com\n")},
		{name: "pe-stub", kinds: benignFileOn, data: benignPEStub()},
		{name: "elf-stub", kinds: benignFileOn, data: benignELFStub()},
		{name: "macho-stub", kinds: benignFileOn, data: benignMachOStub()},
		{name: "png-header", kinds: benignFileOn, data: append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), make([]byte, 64)...)},
		{name: "zeros", kinds: benignFileOn, data: make([]byte, 4096)},
	}
}
