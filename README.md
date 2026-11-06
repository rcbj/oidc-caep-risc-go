# oidc-caep-risc-go

A confidential OpenID Connect relying party for a traditional Go application, and a CAEP and RISC receiver on one Shared Signals poll stream. Authorization Code with PKCE (S256) is required. Client authentication is `client_secret_basic`, `client_secret_post`, or `private_key_jwt`. A public client (`tokenEndpointAuthMethod` `"none"`) is refused. The library uses the Go standard library for HTTP, JSON, and RSA signatures.

JSON configuration keys match the Python library `oidc-caep-risc`. `signals` omitted or `true` keeps CAEP and RISC on. `signals: false` does not start the receiver, does not require transmitter metadata, and drops `ssf.read` and `ssf.manage` from the scope list after the default scopes are applied. `DEFAULT_SCOPES` still names those two scopes. The shipped demo leaves `signals` on (the key is omitted).

The license is MIT. A release happens when the library's files changed since the last release's tag: `release.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

The defaults follow one client profile, shared with the other six libraries: PKCE S256, `state`, `nonce`, RFC 9207 `iss`, PAR when the provider offers it, DPoP when the provider offers ES256, RS256 ID tokens, a required `typ` and `at_hash`, `acr` enforced when requested, and a per-session token cache. See *Settings and defaults*.

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

Tokens stay in this process. Keep the transaction until the browser returns (`State`, `Nonce`, `CodeVerifier`, `RedirectURI`, `ACRValues`).

## Settings and defaults

The same defaults and rules apply whether the client is loaded with `FromFile` / `ResolveConfig` or created directly with `Create`. `Create` works on a copy of the map it is given.

| Key | Default | Meaning |
|---|---|---|
| `par` | `auto` | `auto` pushes the authorization request when the provider has a PAR endpoint; `always` fails at creation without one; `never` does not push. When the provider's metadata says `require_pushed_authorization_requests: true`, `never` fails at creation and `auto` always pushes. |
| `dpop` | `auto` | DPoP (RFC 9449). `auto` uses it when the provider's `dpop_signing_alg_values_supported` lists ES256; `always` fails at creation when it does not; `never` sends no proofs. |
| `dpopKey` | none | A PEM ES256 (P-256) private key (inline, `file:`, `env:`, or a path in a configuration file). Without it the client generates a key when it is created and holds it in memory only. Name one when several processes share sign-ins. |
| `idTokenSigningAlgs` | `["RS256"]` | The ID token algorithm allow-list. Each algorithm must also be advertised by the provider (the others are dropped; none left fails at creation). `none` is never accepted. A symmetric algorithm (`HS256`...) is accepted only when it is named here. |
| `idTokenSignedResponseAlg` | none | One pinned algorithm; it replaces the allow-list and must be advertised. |
| `requireIdTokenTypAndAtHash` | `true` | The ID token header must carry `typ` `JWT` or `application/jwt` (any case), and when the token response carries an access token the ID token must carry a matching `at_hash`. `false` checks each only when present. |
| `acrValues` | none | A list (or a space-separated string). When set, or when `AuthorizeOptions.ACRValues` is given, the request carries `acr_values`, the transaction keeps them (`Transaction.ACRValues`), and the ID token from the code exchange must carry an `acr` that is one of them. A refresh does not re-check `acr`. |
| `clockToleranceSec` | `30` | Clock skew allowed on `exp`, `nbf`, `iat` and `auth_time`. An `iat` more than this in the future is refused. |
| `maxIdTokenAgeSec` | `600` | The oldest `iat` accepted. |
| `redirectUri`, `postLogoutRedirectUri` | | `https`, or `http` on a loopback host (`localhost`, `127.0.0.1`, `[::1]`). `allowInsecure` does not relax this. `AuthorizeOptions.RedirectURI` is held to the same rule. |

### DPoP

With DPoP on, a proof (`typ` `dpop+jwt`, the public key as `jwk`, `jti`, `htm`, `htu` without query or fragment, `iat`) goes on every request to the PAR endpoint and the token endpoint (code, refresh and client-credentials grants), and `dpop_jkt` goes on the authorization request (in the PAR body when PAR is used). The token response's `token_type` must then be `DPoP` (any case); without a proof it must be `Bearer`. A mismatch is refused.

`UserInfo`, `ResourceRequest(method, url, accessToken, tokenType, headers, body)` and every call the Shared Signals receiver makes to the transmitter (with `ReceiverOptions.Client`) send a DPoP-bound token as `Authorization: DPoP <token>` with a proof carrying `ath`. A 400 `use_dpop_nonce` from the authorization server, or a 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` from a resource server, is retried once with the `DPoP-Nonce` the response gave; the latest nonce is kept per server origin and sent on the next proof. `DPoPEnabled()` and `DPoPThumbprint()` report the state.

### The session token cache

```go
login, err := rp.CompleteSession(query, request, sessionID) // "" makes a handle: login.Session
access, err := rp.SessionAccessToken(sessionID)             // Access{AccessToken, TokenType, ...}
err = rp.RemoveSession(sessionID)                           // sign-out
```

`CompleteSession` is `Complete` that also keeps the sign-in's tokens under a session identifier the application chooses. `SessionAccessToken` returns the cached access token while it has more than 30 seconds left; otherwise it refreshes (with a DPoP proof when DPoP is on), stores the new tokens and returns them. A failed refresh removes the entry and returns an `OidcError` with `Code` `session`. `RemoveSession` clears an entry; a receiver created with `ReceiverOptions{Client: rp}` clears the entry of every session an event ends (a CAEP `session-revoked`). The default store is `MemorySessionStore`; `rp.SetSessionStore(store)` replaces it with any `SessionStore` (`Get`, `Set`, `Delete`), for example one shared across processes.

### The Shared Signals receiver

`ReceiverOptions{Client: rp, Scope: "ssf.manage"}` makes every transmitter call with `rp`'s client-credentials token for that scope, as a DPoP-bound token with proofs when DPoP is on. `Headers` still works when `Client` is nil.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

The tests build an in-process stub provider and a stub transmitter. They do not need a live iya-sts. `trust_chain_test.go` runs the install script and `scripts/trust_chain.py` against an HTTPS stub on a four-certificate chain shaped like iya-sts's, and checks the library trusts it through the saved file, verifies the host name, and refuses a forged leaf.

`python3 scripts/live_iya_sts.py` is the live half. It starts iya-sts when `IYA_STS_URL` is unset, copies this checkout to a scratch build context without `demo/generated`, builds the demo image from it as a fresh clone would be, runs the install script against that copy (which writes the `tlsCa` chain), builds the image again (which bakes the chain in), checks the image's `/app/demo/generated/idp-ca.pem` equals the saved chain, starts the demo with no CA mount and `TLS_CA_REFRESH=0` (only the client secret is mounted), signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It never binds port 3000 or 8081. Secrets reach `docker run` as `-e NAME`, never `-e NAME=value`. The nightly workflow runs the unit suite and this script. `.github/workflows/nightly.yml` runs at 07:18 UTC (`18 7 * * *`) and on `workflow_dispatch`. `IYA_STS_IMAGE` starts a fresh container from an image already built; without it or `IYA_STS_URL` the script clones and builds iya-sts `main`. `LIVE_STS_PORT` defaults to 18559 and `LIVE_DEMO_PORT` to 18659; the script refuses 3000, 8081, and 18481 through 18495. Registration runs `scripts/configure_iya_sts.py` with the host's stdlib python3, never Go. Always use a fresh iya-sts: a second registration of the same client fails.

## Layout

| Path | What it is |
|---|---|
| `*.go` | The library, package `oidc`. Module `github.com/rcbj/oidc-caep-risc-go`. |
| `*_test.go` | `go test` ports of the Python relying-party and Shared Signals tests. |
| `demo` | `demo/main.go`. Config is `demo/oidc.json`. Its message pages are drawn with `html/template` (`demo/main_test.go`). |
| `scripts/configure_iya_sts.py` | Registers the confidential client on iya-sts (with `id_token_signed_response_alg` RS256, the library's default allow-list) and writes the listener CA trust chain to the file `tlsCa` names. Loopback redirects follow the running container's `PORT`, then the shell `PORT`. |
| `scripts/live_iya_sts.py` | The live sign-in against iya-sts, separate from the unit suite. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose uses host networking. |

## The iya-sts trust chain (`tlsCa`)

`tlsCa` in `demo/oidc.json` names the iya-sts TLS listener CA trust chain the library trusts. The default is `generated/idp-ca.pem`, relative to `demo/`. The value may also be `file:<path>`, `env:<NAME>`, or the PEM itself. The library adds every certificate in it to the system trust store (`x509.CertPool.AppendCertsFromPEM` reads every PEM block, so the whole chain works and the root alone does too), keeps Go's normal chain verification, and checks the host name against the certificate's SANs (DNS name or IP literal). There is no pin shortcut: a forged leaf sent in front of the real CA certificates is refused.

`scripts/configure_iya_sts.py`, the install script, writes that file on every run. It saves the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain from the TLS handshake when that path does not answer. It prints the path, the trust anchor's subject and its SHA-256 fingerprint. Compare the anchor with the Root CA on iya-sts's PKI page.

The demo image build copies that file into the image at `/app/demo/generated/idp-ca.pem`, so the image trusts that iya-sts with no bind mount and no fetch. Run the install script before you build the image. Rebuild the image after running the install script against a different iya-sts. `.dockerignore` admits only that file from `demo/generated`; the client secret and a generated test-user password stay out of the image. A build with no chain file yet (a fresh clone, CI) still succeeds; the image then has no `tlsCa` file.

The mechanism is `COPY demo demo` in the final stage, after the Go binary is built, plus `.dockerignore`'s `demo/generated/*` and `!demo/generated/idp-ca.pem`. Do not replace it with a COPY that names the file or globs for it: when the file is absent, both BuildKit and the classic builder fail. A directory COPY of `demo/` (which always exists) succeeds in both. A new chain changes only that last layer; the binary is not rebuilt.

The container entrypoint also refreshes the file from the provider at start, because a development iya-sts makes a new CA when it restarts. A failed refresh keeps the file from the build. `TLS_CA_REFRESH=0` turns the refresh off. `python3 scripts/trust_chain.py --config demo/oidc.json` refreshes it by hand.

When the install script creates the test user and iya-sts generates its password, the password is written to `demo/generated/<user>.password` (created 0600), not printed; only that path is. No script prints the client secret, the path of the file that holds it, or a plan built from it: `--dry-run` shows `<client secret>`, and the client-secret file is created 0600.

## Demo

`PORT` defaults to 3000. A loopback redirect and post-logout URL follow `PORT`. Any other host is left as written. An explicit `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL.

```sh
docker compose up --build
```

`GET /healthz` returns `ok`. `GET /` is the page; it asks the library's session cache for the session's access token (`SessionAccessToken`, refreshing it when needed) and ends the session when that is refused. `GET /login` starts `Authorize` and redirects. `GET /callback` completes the code exchange. `POST /logout` signs the local session out. `GET /live-status` is JSON for the sign-in and the Shared Signals events this process has accepted. It does not include tokens.

`docker-compose.yml` sets `network_mode: host`. The image sets `ENV PORT=3000`. The health check calls `http://127.0.0.1:$PORT/healthz` (it said `$$PORT` until 2026-11-02, which the shell expands to its process ID). The running container's `PORT` wins over the shell's when `scripts/configure_iya_sts.py` registers the application.

Demo JSON uses `file:` and the configuration's own placeholders. It does not contain a generated secret or key.
