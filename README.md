# oidc-caep-risc-go

A confidential OpenID Connect relying party for a traditional Go application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. The library uses the Go standard library for HTTP, JSON, and RSA signatures.

JSON configuration keys match the Python library `oidc-caep-risc`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. Publishing is not set up.

## Usage

```go
package main

import "github.com/rcbj/oidc-caep-risc-go"

func main() {
    rp, err := oidc.FromFile("oidc.json")
    if err != nil {
        panic(err)
    }
    request, err := rp.Authorize()
    if err != nil {
        panic(err)
    }
    // redirect the browser to request.URL; keep State, Nonce, and CodeVerifier
    who, err := rp.Complete(query, request)
    _ = who
}
```

Tokens stay in this process. Keep the transaction until the browser returns.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts.

`python3 scripts/live_iya_sts.py` is the live half. It builds this demo image, starts iya-sts when `IYA_STS_URL` is unset, registers the demo, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000 or 8081. The nightly workflow runs the unit suite and this script. `.github/workflows/nightly.yml` runs at 07:18 UTC (`18 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18520 and `LIVE_DEMO_PORT` to 18620; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never Go. Always use a fresh iya-sts: a second registration of the same client fails.

## Layout

| Path | What it is |
|---|---|
| `*.go` | The library, package `oidc`. Module `github.com/rcbj/oidc-caep-risc-go`. |
| `*_test.go` | `go test` ports of the Python relying-party and Shared Signals tests. |
| `demo` | `demo/main.go`. Config is `demo/oidc.json`. |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `scripts/live_iya_sts.py` | The live sign-in against iya-sts, separate from the unit suite. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page. `GET /login` starts `Authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:${PORT}/healthz`. The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
