#!/usr/bin/env sh
# Local smoke: unit tests, vet, and build of Kavach module paths.
# Prefers ./cmd/kavach; falls back to ./cmd/zyvor-edr until the rename lands.
set -eu
cd "$(dirname "$0")/.."

go test ./...
go vet ./...

MAIN_PKG=./cmd/kavach
if [ ! -d cmd/kavach ]; then
  if [ -d cmd/zyvor-edr ]; then
    printf '%s\n' 'cmd/kavach missing — building ./cmd/zyvor-edr'
    MAIN_PKG=./cmd/zyvor-edr
  else
    printf '%s\n' 'error: neither cmd/kavach nor cmd/zyvor-edr found' >&2
    exit 1
  fi
fi

go build -o /dev/null "$MAIN_PKG"
if [ -d cmd/netra-bridge ]; then
  go build -o /dev/null ./cmd/netra-bridge
fi
if [ -d cmd/kavach-agent ]; then
  go build -o /dev/null ./cmd/kavach-agent
fi

go test -race ./internal/edr/ -run 'Health|RateLimiter|TokenBucket|ATTACK|Stream' >/dev/null
printf '%s\n' 'Build, unit and integration checks passed.'
