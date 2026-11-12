# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /kavach ./cmd/kavach

FROM alpine:3.20
RUN addgroup -S kavach && adduser -S -G kavach kavach \
 && mkdir -p /app/data && chown -R kavach:kavach /app
USER kavach
WORKDIR /app
COPY --from=builder /kavach /usr/local/bin/kavach
EXPOSE 8099
ENTRYPOINT ["/usr/local/bin/kavach"]
CMD ["-mode", "server", "-listen", "0.0.0.0:8099", "-state", "/app/data/findings.jsonl", "-credentials", "/app/data/agents.json", "-tls-cert", "/run/tls/tls.crt", "-tls-key", "/run/tls/tls.key"]
