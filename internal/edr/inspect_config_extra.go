// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package edr

// Supplementary configuration checks for kind config: CI pipeline YAML (GitHub
// Actions, GitLab CI) plus a few Kubernetes and Dockerfile checks that the
// embedded policy set ("config-assess") does not cover. Line/regex based and
// parse-only: nothing is executed, expanded, fetched or applied. All findings
// carry weight 0 and the report is "not_scored"; they are policy observations,
// not a maliciousness verdict. Because this is text matching rather than a YAML
// evaluation, anchors, includes, templates, matrix expansion and reusable
// workflows are not resolved, and a check can miss or over-match accordingly.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const cfgxMaxScan = 2 << 20

func init() {
	RegisterAnalyzer("config-extra", []string{InspectKindConfig}, analyzeConfigExtra)
}

type cfgxRule struct {
	id, title, sev, tech string
	re                   *regexp.Regexp
}

func cx(id, title, sev, tech, re string) cfgxRule {
	return cfgxRule{id, title, sev, tech, regexp.MustCompile(re)}
}

const cfgxInjCtx = `\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|pages)[a-z_.\[\]0-9*]*?\.(?:title|body|name|label|ref|message|email|default_branch|head_ref)|github\.head_ref|github\.event\.workflow_run\.head_branch)\s*\}\}`

var cfgxGitHub = []cfgxRule{
	cx("cfgx-gha-pwn-request", "pull_request_target workflow checks out the pull request head (untrusted code with a privileged token)", "critical", "T1195.002",
		`(?is)pull_request_target.*?ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)`),
	cx("cfgx-gha-script-injection", "Untrusted event field expanded inside a run step (script injection)", "high", "T1059",
		`(?m)^\s*(?:-\s+)?run:.*`+cfgxInjCtx),
	cx("cfgx-gha-write-all", "Workflow grants permissions: write-all", "high", "T1078", `(?im)^\s*permissions:\s*write-all\b`),
	cx("cfgx-gha-unpinned-action", "Third-party action pinned to a branch or tag instead of a commit SHA", "low", "T1195.002",
		`(?m)^\s*-?\s*uses:\s*[\w.-]+/[\w./-]+@(?:main|master|latest|v?\d[\w.]*)\s*$`),
	cx("cfgx-gha-curl-pipe", "Step downloads a script and pipes it to a shell", "high", "T1105",
		`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b`),
	cx("cfgx-gha-unsecure-commands", "ACTIONS_ALLOW_UNSECURE_COMMANDS re-enables deprecated workflow commands", "medium", "T1562", `ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*['"]?true`),
	cx("cfgx-gha-self-hosted-pr", "Self-hosted runner used by a workflow triggered by pull requests", "medium", "T1021",
		`(?is)pull_request(?:_target)?\b.*?runs-on:\s*\[?\s*['"]?self-hosted`),
	cx("cfgx-gha-secret-echo", "Secret value is printed or passed on a command line", "medium", "T1552.001",
		`(?im)^\s*(?:-\s+)?run:.*(?:echo|printf)\b[^\n]*\$\{\{\s*secrets\.`),
}

var cfgxGitLab = []cfgxRule{
	cx("cfgx-gl-curl-pipe", "Job downloads a script and pipes it to a shell", "high", "T1105", `(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b`),
	cx("cfgx-gl-latest-image", "Job image uses the latest tag or no tag", "low", "T1195.002", `(?im)^\s*image:\s*['"]?[\w./-]+(?::latest)?['"]?\s*$`),
	cx("cfgx-gl-literal-secret", "Variable holds a literal secret-looking value", "high", "T1552.001",
		`(?im)^\s*[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY)[A-Z0-9_]*:\s*['"]?[A-Za-z0-9/+_=.-]{8,}['"]?\s*$`),
	cx("cfgx-gl-dind-notls", "docker:dind without TLS (DOCKER_TLS_CERTDIR empty)", "medium", "T1610", `(?im)DOCKER_TLS_CERTDIR:\s*['"]{2}`),
	cx("cfgx-gl-job-token-echo", "CI job token is echoed or placed in a URL", "medium", "T1552.001", `(?i)(?:echo|printf)\b[^\n]*\$\{?CI_JOB_TOKEN|https?://[^\s@/]*:\$\{?CI_JOB_TOKEN`),
}

var cfgxK8s = []cfgxRule{
	cx("cfgx-k8s-anonymous-binding", "RBAC binding grants access to system:anonymous or system:unauthenticated", "critical", "T1078",
		`(?i)name:\s*system:(?:anonymous|unauthenticated)\b`),
	cx("cfgx-k8s-lb-open", "Service is exposed to 0.0.0.0/0 through loadBalancerSourceRanges", "medium", "T1133", `(?i)loadBalancerSourceRanges:[\s\S]{0,200}?0\.0\.0\.0/0`),
	cx("cfgx-k8s-inline-secret", "Secret manifest embeds data in the file (store secrets outside source control)", "medium", "T1552.007",
		`(?is)\bkind:\s*Secret\b.*?\b(?:data|stringData):\s*\n\s+\S+:\s*\S+`),
	cx("cfgx-k8s-command-fetch-exec", "Container command downloads and runs code", "high", "T1105", `(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z)?sh\b|/dev/tcp/|\bnc\s+-[a-z]*e\b`),
}

var cfgxDocker = []cfgxRule{
	cx("cfgx-df-reverse-shell", "RUN/CMD contains a reverse shell or netcat exec idiom", "critical", "T1059", `(?i)/dev/tcp/|\b(?:nc|ncat|netcat)\b[^\n]*\s-[a-z]*e\s|mkfifo\s+\S+[^\n]*\bnc\b|\bsocat\b[^\n]*exec:`),
	cx("cfgx-df-decode-exec", "RUN decodes a blob and executes it", "high", "T1027.010", `(?i)base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba)?sh\b|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64`),
	cx("cfgx-df-miner", "Build step references a cryptominer", "high", "T1496", `(?i)\b(?:xmrig|minerd|cpuminer|stratum\+tcp://|nicehash)\b`),
	cx("cfgx-df-chmod-fetched", "Build step downloads a file and makes it executable", "medium", "T1105", `(?i)\b(?:curl|wget)\b[^\n]*(?:-o|-O|>)\s*\S+[^\n]*(?:&&|;)\s*chmod\s+\+?[0-9x]+`),
}

var (
	cfgxGHRe = regexp.MustCompile(`(?m)^on:|^"on":|^true:`)
	cfgxJobs = regexp.MustCompile(`(?m)^jobs:\s*$`)
	cfgxGLRe = regexp.MustCompile(`(?m)^(?:stages:|[.\w-]+:\s*\n\s+(?:script|image|stage):)`)
)

func cfgxFormat(name, text string) (string, []cfgxRule) {
	base := strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
	head := text
	switch {
	case strings.Contains(base, ".github/workflows/") || cfgxGHRe.MatchString(head) && cfgxJobs.MatchString(head) && strings.Contains(head, "runs-on"):
		return "github-actions", cfgxGitHub
	case strings.HasSuffix(base, ".gitlab-ci.yml") || (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) && cfgxGLRe.MatchString(head) && !cfgxJobs.MatchString(head) && !strings.Contains(head, "apiVersion:"):
		return "gitlab-ci", cfgxGitLab
	}
	switch SniffConfigFormat(name, text) {
	case CfgK8s:
		return "k8s", cfgxK8s
	case CfgDockerfile:
		return "dockerfile", cfgxDocker
	}
	return "", nil
}

func analyzeConfigExtra(ctx context.Context, in InspectInput, b *InspectBuilder) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("config-extra: recovered: %v", r)
		}
	}()
	text := in.Text
	if len(text) > cfgxMaxScan {
		text = text[:cfgxMaxScan]
		b.LimitHit("config-truncated")
	}
	format, rules := cfgxFormat(in.Name, text)
	if format == "" {
		return nil
	}
	if format == "github-actions" || format == "gitlab-ci" {
		b.Format("config/" + format)
	}
	fails := 0
	for _, r := range rules {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		loc := r.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		fails++
		b.Finding(InspectFinding{ID: r.id, Title: "[fail] " + r.title, Severity: r.sev, Technique: r.tech, Evidence: previewOf(text[loc[0]:min(loc[1], loc[0]+300)])})
	}
	b.Meta("summary", map[string]any{"format": format, "checks": len(rules), "failed": fails,
		"note": "text-pattern checks on the submitted file only; includes, anchors, templates and reusable workflows are not resolved"})
	return nil
}
