# oidc-caep-risc-go

A confidential OpenID Connect relying party for a traditional Go application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied. The shipped demo omits `signals`, so they stay on.

The license is the MIT License in `LICENSE`. Publishing is not set up. `develop` and `main` are the branches the test workflow runs.

Go 1.27. Cryptography is the standard library.

## Layout

| Path | What it is |
|---|---|
| package `oidc` | The library. `FromFile`, `Authorize`, `Complete`. |
| `*_test.go` | `go test ./...`. A stub provider and a stub transmitter. No live iya-sts. `trust_chain_test.go`: the install script writes the whole chain to `tlsCa`'s path; the library trusts an HTTPS provider through that file, checks the host name, and refuses a forged leaf before the real CAs. |
| `demo` | `demo/main.go` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client and writes the listener CA trust chain to the file `tlsCa` names. `trust_chain.py` holds `save_trust_chain()` and refreshes that file. `live_iya_sts.py` is the live sign-in, separate from the unit suite. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Usage

```go
rp, err := oidc.FromFile("oidc.json")
request, err := rp.Authorize()
who, err := rp.Complete(query, request)
```

Keep the transaction (`State`, nonce, code verifier) until the browser returns. Tokens stay in this process.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `go test ./...` in `golang:1.27-bookworm`. GitHub Actions uses that command. Do not run the Go toolchain on the host. The demo image does not run the suite.

The stub tests do not start iya-sts. `python3 scripts/live_iya_sts.py` does. It starts iya-sts when `IYA_STS_URL` is unset, copies this checkout to a scratch build context without `demo/generated`, builds the demo image from it as a fresh clone would be, runs the install script against that copy (which writes the `tlsCa` chain), builds the image again (which bakes the chain in), checks the image's `/app/demo/generated/idp-ca.pem` equals the saved chain, starts the demo with no CA mount and `TLS_CA_REFRESH=0` (only the client secret is mounted), signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000 or 8081. Secrets reach `docker run` as `-e NAME`, never `-e NAME=value`. The nightly workflow runs the unit suite and this script. `.github/workflows/nightly.yml` runs at 07:18 UTC (`18 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18559 and `LIVE_DEMO_PORT` to 18659; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never Go. Always use a fresh iya-sts: a second registration of the same client fails.

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library adds every certificate in it to the system trust store (`x509.CertPool.AppendCertsFromPEM` reads every PEM block, so the whole chain works and the root alone does too), keeps Go's normal chain verification, and checks the host name against the certificate's SANs (DNS name or IP literal). There is no pin shortcut: a forged leaf sent in front of the real CA certificates is refused.

`scripts/configure_iya_sts.py`, the install script, writes that file on every run. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`; the client secret and a generated test-user password stay out of the image. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` in the final stage, after the Go binary is built, plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, both BuildKit and the classic builder fail. A directory COPY of `demo/` (which always exists) succeeds in both. A new chain changes only that last layer; the binary is not rebuilt.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/oidc.json` refreshes it by hand.

When the install script creates the test user and iya-sts generates its password, the password is written to `demo/generated/<user>.password` (created 0600), not printed; only that path is. No script prints the client secret, the path of the file that holds it, or a plan built from it: `--dry-run` shows `<client secret>`, and the client-secret file is created 0600.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:$PORT/healthz` (not `$$PORT`, which the shell expands to its process ID).

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. `GET /live-status` reports the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 or 8081 while another demo or iya-sts is already using them.
