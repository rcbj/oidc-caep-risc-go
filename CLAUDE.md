# oidc-caep-risc-go

A confidential OpenID Connect relying party for a traditional Go application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`none`) is refused.

`signals` defaults to on. `signals: false` turns CAEP and RISC off: the receiver does not start, transmitter metadata is not required, and the authorization request does not include `ssf.read` or `ssf.manage`. `DEFAULT_SCOPES` still names those two scopes. They are removed after that default is applied. The shipped demo omits `signals`, so they stay on.

The license is the MIT License in `LICENSE`. Publishing is not set up. `develop` and `main` are the branches the test workflow runs.

Go 1.27. Cryptography is the standard library.

## Layout

| Path | What it is |
|---|---|
| package `oidc` | The library. `FromFile`, `Authorize`, `Complete`. |
| `*_test.go` | `go test ./...`. A stub provider and a stub transmitter. No live iya-sts. |
| `demo` | `demo/main.go` and `demo/public/`. Config is `demo/oidc.json`. |
| `scripts` | `configure_iya_sts.py` registers the confidential client. `trust_chain.py` refreshes the listener CA file named by `tlsCa`. `live_iya_sts.py` is the live sign-in, separate from the unit suite. |
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

The stub tests do not start iya-sts. `python3 scripts/live_iya_sts.py` does, unless `IYA_STS_URL` names one that is already running. It signs the demo in and checks two Shared Signals events on `GET /live-status`. The nightly workflow runs both. `.github/workflows/nightly.yml` runs at 07:18 UTC (`18 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18520 and `LIVE_DEMO_PORT` to 18620; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never Go. Always use a fresh iya-sts: a second registration of the same client fails.

## Demo

`docker-compose.yml` sets `network_mode: host`. The process binds `PORT`, default 3000. `ENV PORT=3000` in the image keeps an unset value on 3000, and the health check calls `http://127.0.0.1:${PORT}/healthz`.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` redirects to the provider. `GET /callback` completes the sign-in. `POST /logout` ends the local session. `GET /live-status` reports the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

A loopback redirect follows `PORT` in the running server and in `scripts/configure_iya_sts.py`. Any other host is left as written. An explicit `--public-url` or a non-empty `PUBLIC_URL` replaces the origin and keeps the path. The running container's `PORT` wins over the shell's when the script registers the application. `pollIntervalMs` is a millisecond pause, not a port.

Open `http://127.0.0.1:$PORT` after the provider is up. Do not bind port 3000 or 8081 while another demo or iya-sts is already using them.
