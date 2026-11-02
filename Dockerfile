# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test .` runs the suite in this image.
# The demo image below does not run it.
# trust_chain_test.go runs scripts/trust_chain.py and the install script with
# this image's python3 and openssl.
FROM golang:1.27-bookworm AS test
WORKDIR /src
# Only what the build and the suite read, so a new trust chain in demo/
# generated does not retest anything.
COPY go.mod ./
COPY *.go ./
COPY scripts scripts
COPY demo/main.go demo/oidc.json demo/
COPY demo/public demo/public
RUN go test ./...

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY demo/main.go demo/main.go
COPY demo/public demo/public
RUN go build -o /out/oidc-caep-risc-demo ./demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/oidc-caep-risc-demo /app/oidc-caep-risc-demo
COPY scripts scripts
COPY LICENSE README.md VERSION ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
# demo/ comes after the compile, so a new chain does not rebuild the binary.
# .dockerignore admits one file of demo/generated: idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py writes where tlsCa
# names it. When it exists, this COPY puts it at
# /app/demo/generated/idp-ca.pem and the image trusts that iya-sts with no
# bind mount and no fetch; rebuild after running the install script against
# a different iya-sts. When it does not (a fresh clone, CI), the build still
# succeeds: a COPY of the demo DIRECTORY always has a source, where naming the
# file or a glob that matches nothing fails in both builders. The client
# secret never enters the image.
COPY demo demo
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:$PORT/healthz" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/oidc-caep-risc-demo"]
