// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

import (
	"sort"
	"strings"
	"testing"
)

// Benign test set: typical hardened and typical default configurations. It
// keeps false-fail claims honest. Hardened samples must produce no failures.
// Default samples must fail only on the listed policies, each of which is a
// real, explainable gap in a stock install (not a parser or policy mistake).

type benignCase struct {
	name string
	file string
	text string
	want []string // expected failing policy ids (sorted); nil for hardened
}

const hexDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var benignCases = []benignCase{
	{"sshd hardened", "sshd_config", `# hardened
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LogLevel VERBOSE
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
StrictModes yes
AllowGroups sshusers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Subsystem sftp /usr/lib/openssh/sftp-server
`, nil},
	{"sshd stock distro", "sshd_config", `# stock-style file, mostly defaults
Include /etc/ssh/sshd_config.d/*.conf
#Port 22
#PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem	sftp	/usr/lib/openssh/sftp-server
`, []string{"ssh-access-allowlist", "ssh-idle-timeout", "ssh-login-grace-time", "ssh-max-auth-tries", "ssh-password-auth", "ssh-x11-forwarding"}},
	{"sysctl hardened", "sysctl.conf", `net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_ra = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
`, nil},
	{"sysctl stock", "sysctl.conf", "# stock\nnet.ipv4.ip_forward=1\nvm.swappiness = 10\nkernel.sysrq = 176\n", []string{"sys-ip-forward"}},
	{"login.defs hardened", "login.defs", "PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD YESCRYPT\nLOGIN_RETRIES 3\nUMASK 027\n", nil},
	{"login.defs stock", "login.defs", "MAIL_DIR /var/mail\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t7\nUMASK 022\nENCRYPT_METHOD SHA512\n",
		[]string{"login-pass-max-days", "login-pass-min-days", "login-umask"}},
	{"sudoers stock", "sudoers", `Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults	use_pty
root	ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo	ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
`, nil},
	{"auditd hardened", "audit.rules", `-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/audit/ -p wa -k auditconfig
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -k delete
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -S chown -S fchown -k perm_mod
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access
-e 2
`, nil},
	{"pam common-auth stock", "common-auth", `# Debian-style
auth	[success=1 default=ignore]	pam_unix.so nullok_secure
auth	requisite			pam_deny.so
auth	required			pam_permit.so
auth	optional			pam_cap.so
`, []string{"pam-faillock", "pam-nullok"}}, // lockout is often configured via another included file; the policy says so
	{"pam hardened", "sshd", `auth required pam_faillock.so preauth
auth [success=1 default=ignore] pam_unix.so
auth [default=die] pam_faillock.so authfail
auth requisite pam_deny.so
auth required pam_permit.so
password required pam_unix.so sha512 shadow
`, nil},
	{"nginx hardened", "nginx.conf", `user www-data;
worker_processes auto;
events { worker_connections 1024; }
http {
  server_tokens off;
  client_max_body_size 10m;
  server {
    listen 443 ssl;
    server_name example.test;
    ssl_certificate /etc/ssl/a.pem;
    ssl_certificate_key /etc/ssl/a.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Content-Security-Policy "default-src 'self'" always;
    location / { proxy_pass http://127.0.0.1:8080; }
  }
}
`, nil},
	{"nginx stock", "nginx.conf", `user www-data;
worker_processes auto;
events { worker_connections 768; }
http {
  sendfile on;
  include /etc/nginx/mime.types;
  server {
    listen 80 default_server;
    root /var/www/html;
    location / { try_files $uri $uri/ =404; }
  }
}
`, []string{"web-csp", "web-framing", "web-nginx-server-tokens", "web-nosniff"}},
	{"apache hardened", "httpd.conf", `ServerTokens Prod
TraceEnable off
<VirtualHost *:443>
  SSLEngine on
  SSLProtocol -all +TLSv1.2 +TLSv1.3
  SSLCipherSuite HIGH:!aNULL:!MD5
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options nosniff
  Header always set X-Frame-Options DENY
  Header always set Content-Security-Policy "default-src 'self'"
</VirtualHost>
<Directory /var/www/html>
  Options -Indexes +FollowSymLinks
</Directory>
`, nil},
	{"k8s hardened", "", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: web
        image: reg.example/web@sha256:` + hexDigest + `
        ports:
        - containerPort: 8080
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 256Mi
`, nil},
	{"k8s typical default", "", `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.27
        ports:
        - containerPort: 80
`, []string{"k8s-cpu-limit", "k8s-drop-all-capabilities", "k8s-image-digest", "k8s-memory-limit", "k8s-privilege-escalation",
		"k8s-read-only-rootfs", "k8s-run-as-non-root", "k8s-sa-token", "k8s-seccomp"}},
	{"dockerfile hardened", "Dockerfile", `FROM python:3.12-slim@sha256:` + hexDigest + `
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app /app
RUN adduser --disabled-password --uid 10001 app
USER 10001
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/health')"
CMD ["python", "main.py"]
`, nil},
	{"dockerfile typical default", "Dockerfile", `FROM python:3.12
WORKDIR /app
COPY . .
RUN apt-get update && apt-get install -y gcc && pip install -r requirements.txt
EXPOSE 8000
CMD ["python", "main.py"]
`, []string{"dockerfile-apt-recommends", "dockerfile-base-digest", "dockerfile-healthcheck", "dockerfile-user-root"}},
	{"compose hardened", "docker-compose.yml", `services:
  web:
    image: app:1.4.2
    user: "10001:10001"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      - APP_ENV=prod
`, nil},
	{"compose typical default", "docker-compose.yml", `services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/pw
    volumes:
      - dbdata:/var/lib/postgresql/data
`, []string{"compose-cap-drop", "compose-read-only"}},
	{"terraform hardened", "main.tf", `provider "aws" {
  region = var.region
}
resource "aws_s3_bucket" "b" {
  bucket = "logs-example"
  acl = "private"
}
resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_security_group" "web" {
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
resource "aws_db_instance" "d" {
  storage_encrypted = true
  publicly_accessible = false
  password = var.db_password
}
`, nil},
}

func TestConfigBenignSet(t *testing.T) {
	for _, c := range benignCases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			a := assess(t, c.file, c.text)
			if a.Format == "" || a.ParseError != "" {
				t.Fatalf("format %q parse error %q", a.Format, a.ParseError)
			}
			got := failIDs(a)
			sort.Strings(got)
			want := append([]string(nil), c.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("fails\n got  %v\n want %v", got, want)
			}
			if a.Evaluated == 0 || a.Counts[CfgPass]+a.Counts[CfgFail]+a.Counts[CfgUnknown]+a.Counts[CfgNotApplicable] != a.Evaluated {
				t.Errorf("counts do not add up: %+v", a.Counts)
			}
		})
	}
}
