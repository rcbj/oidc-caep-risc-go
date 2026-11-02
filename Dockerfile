# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY demo demo
RUN go build -o /out/oidc-caep-risc-demo ./demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/oidc-caep-risc-demo /app/oidc-caep-risc-demo
COPY demo demo
COPY scripts scripts
COPY LICENSE README.md VERSION ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:$$PORT/healthz" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/oidc-caep-risc-demo"]
