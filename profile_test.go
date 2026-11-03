// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

// Tests for issue #17: DPoP, acr, PAR required by the provider, the ID token
// algorithm allow-list, typ and at_hash, the same rules on every way of
// creating a client, and the per-session token cache.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustCreate(t *testing.T, cfg map[string]any) *RelyingParty {
	t.Helper()
	rp, err := Create(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

func wantErr(t *testing.T, err error, fragment string) *OidcError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q", fragment)
	}
	if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("expected %q in %q", fragment, err.Error())
	}
	return oidcErr(t, err)
}

func tryComplete(t *testing.T, rp *RelyingParty, opts AuthorizeOptions) (*Login, *Transaction, error) {
	t.Helper()
	request, err := rp.AuthorizeOptions(opts)
	if err != nil {
		return nil, nil, err
	}
	_, location := manual(t, request.URL)
	if location == "" {
		t.Fatalf("the provider did not redirect: %s", request.URL)
	}
	login, err := rp.Complete(queryOf(location), request)
	return login, request, err
}

func (s *providerStub) proofsAt(path string) []seenProof {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []seenProof
	for _, p := range s.proofs {
		if p.path == path {
			out = append(out, p)
		}
	}
	return out
}

func ecPEM(t *testing.T, curve elliptic.Curve) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), key
}

// 1. DPoP

func TestDPoPAutoProofsEveryRequestAndBindsTokens(t *testing.T) {
	stub := startProvider(t)
	stub.par = true
	stub.dpopAlgs = []string{"ES256", "PS256"}
	rp := mustCreate(t, stub.config(nil))
	if !rp.DPoPEnabled() || rp.DPoPThumbprint() == "" {
		t.Fatal("dpop auto did not turn DPoP on against a provider that advertises ES256")
	}
	signed := signIn(t, rp)
	login := signed.login
	if !strings.EqualFold(login.TokenType, "DPoP") {
		t.Fatalf("token_type %s", login.TokenType)
	}
	if strings.Contains(signed.request.URL, "dpop_jkt") {
		t.Fatalf("dpop_jkt belongs in the PAR body, not the URL: %s", signed.request.URL)
	}
	stub.mu.Lock()
	jkt := stub.authParams.Get("dpop_jkt")
	stub.mu.Unlock()
	if jkt != rp.DPoPThumbprint() {
		t.Fatalf("dpop_jkt %q, thumbprint %q", jkt, rp.DPoPThumbprint())
	}
	if len(stub.proofsAt("/par")) != 1 || len(stub.proofsAt("/token")) != 1 {
		t.Fatalf("proofs par %d token %d", len(stub.proofsAt("/par")), len(stub.proofsAt("/token")))
	}
	tokenProof := stub.proofsAt("/token")[0]
	if tokenProof.header["typ"] != "dpop+jwt" || tokenProof.claims["htm"] != "POST" || tokenProof.claims["htu"] != stub.url+"/token" || tokenProof.claims["ath"] != nil {
		t.Fatalf("token proof %#v %#v", tokenProof.header, tokenProof.claims)
	}
	info, err := rp.UserInfo(login.AccessToken, login.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if info["sub"] != "user-1" {
		t.Fatalf("userinfo %#v", info)
	}
	userinfoProof := stub.proofsAt("/userinfo")
	sum := sha256.Sum256([]byte(login.AccessToken))
	if len(userinfoProof) != 1 || userinfoProof[0].claims["ath"] != base64.RawURLEncoding.EncodeToString(sum[:]) || userinfoProof[0].claims["htm"] != "GET" {
		t.Fatalf("userinfo proof %#v", userinfoProof)
	}
	refreshed, err := rp.Refresh(login.RefreshToken, "", login)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(refreshed.TokenType, "DPoP") || len(stub.proofsAt("/token")) != 2 {
		t.Fatalf("refresh %s, token proofs %d", refreshed.TokenType, len(stub.proofsAt("/token")))
	}
	cc, err := rp.ClientCredentials("ssf.manage")
	if err != nil {
		t.Fatal(err)
	}
	if cc.TokenType != "DPoP" || len(stub.proofsAt("/token")) != 3 {
		t.Fatalf("client credentials %s, token proofs %d", cc.TokenType, len(stub.proofsAt("/token")))
	}
	status, _, _, err := rp.ResourceRequest("GET", stub.url+"/userinfo?x=1#y", login.AccessToken, login.TokenType, nil, nil)
	if err != nil || status != 200 {
		t.Fatalf("resource request %d %v", status, err)
	}
	last := stub.proofsAt("/userinfo")
	if got := last[len(last)-1].claims["htu"]; got != stub.url+"/userinfo" {
		t.Fatalf("htu keeps no query or fragment: %v", got)
	}
}

func TestDPoPModes(t *testing.T) {
	stub := startProvider(t)
	stub.dpopAlgs = []string{"ES256"}
	never := mustCreate(t, stub.config(map[string]any{"dpop": "never"}))
	if never.DPoPEnabled() {
		t.Fatal("dpop never sent proofs")
	}
	signed := signIn(t, never)
	if signed.login.TokenType != "Bearer" || len(stub.proofsAt("/token")) != 0 || strings.Contains(signed.request.URL, "dpop_jkt") {
		t.Fatalf("never: %s %d %s", signed.login.TokenType, len(stub.proofsAt("/token")), signed.request.URL)
	}
	auto := mustCreate(t, stub.config(nil))
	request, err := auto.Authorize()
	if err != nil {
		t.Fatal(err)
	}
	if query := queryOf(request.URL); query["dpop_jkt"] != auto.DPoPThumbprint() || query["dpop_jkt"] == "" {
		t.Fatalf("without PAR dpop_jkt is on the authorization request: %s", request.URL)
	}
	always := mustCreate(t, stub.config(map[string]any{"dpop": "always"}))
	if !always.DPoPEnabled() {
		t.Fatal("always")
	}

	plain := startProvider(t)
	if mustCreate(t, plain.config(nil)).DPoPEnabled() {
		t.Fatal("auto used DPoP with a provider that advertises none")
	}
	_, err = Create(plain.config(map[string]any{"dpop": "always"}))
	wantErr(t, err, "dpop_signing_alg_values_supported")

	noES := startProvider(t)
	noES.dpopAlgs = []string{"PS256", "EdDSA"}
	if mustCreate(t, noES.config(nil)).DPoPEnabled() {
		t.Fatal("auto used DPoP without ES256 advertised")
	}
	_, err = Create(noES.config(map[string]any{"dpop": "always"}))
	wantErr(t, err, "ES256")

	_, err = Create(stub.config(map[string]any{"dpop": "sometimes"}))
	wantErr(t, err, "dpop must be auto, always, or never")
}

func TestDPoPKeyFromPEM(t *testing.T) {
	stub := startProvider(t)
	stub.dpopAlgs = []string{"ES256"}
	pemText, key := ecPEM(t, elliptic.P256())
	rp := mustCreate(t, stub.config(map[string]any{"dpopKey": pemText}))
	point, _ := key.PublicKey.ECDH()
	raw := point.Bytes()
	canonical := `{"crv":"P-256","kty":"EC","x":"` + B64URLEncode(raw[1:33]) + `","y":"` + B64URLEncode(raw[33:]) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	if rp.DPoPThumbprint() != B64URLEncode(sum[:]) {
		t.Fatal("the configured DPoP key is not the one used")
	}
	again := mustCreate(t, stub.config(map[string]any{"dpopKey": pemText}))
	if again.DPoPThumbprint() != rp.DPoPThumbprint() {
		t.Fatal("two processes with one dpopKey disagree")
	}
	if fresh := mustCreate(t, stub.config(nil)); fresh.DPoPThumbprint() == rp.DPoPThumbprint() {
		t.Fatal("a generated key repeated")
	}
	p384, _ := ecPEM(t, elliptic.P384())
	_, err := Create(stub.config(map[string]any{"dpopKey": p384}))
	wantErr(t, err, "P-256")
	_, err = Create(stub.config(map[string]any{"dpopKey": clientPEM}))
	wantErr(t, err, "P-256")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dpop.pem"), []byte(pemText), 0o600); err != nil {
		t.Fatal(err)
	}
	file := map[string]any{
		"metadataUrl":  "https://localhost:8081/.well-known/openid-configuration",
		"clientId":     testClient,
		"clientSecret": "secret",
		"redirectUri":  "http://localhost:3000/callback",
		"dpopKey":      "file:dpop.pem",
	}
	resolved, err := ResolveConfig(file, dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolved["dpopKey"] != strings.TrimSpace(pemText) || resolved["dpop"] != "auto" {
		t.Fatalf("dpopKey %v dpop %v", resolved["dpopKey"], resolved["dpop"])
	}
}

func TestDPoPNonceRetries(t *testing.T) {
	stub := startProvider(t)
	stub.par = true
	stub.dpopAlgs = []string{"ES256"}
	stub.asNonce = "as-nonce-1"
	stub.rsNonce = "rs-nonce-1"
	rp := mustCreate(t, stub.config(nil))
	login := signIn(t, rp).login
	stub.mu.Lock()
	asks := stub.nonceAsks
	stub.mu.Unlock()
	// The PAR endpoint asked once; the token endpoint is the same origin, so
	// the remembered nonce went on its first proof.
	if asks != 1 {
		t.Fatalf("nonce asked %d times", asks)
	}
	par := stub.proofsAt("/par")
	if len(par) != 2 || par[0].claims["nonce"] != nil || par[1].claims["nonce"] != "as-nonce-1" {
		t.Fatalf("par proofs %#v", par)
	}
	token := stub.proofsAt("/token")
	if len(token) != 1 || token[0].claims["nonce"] != "as-nonce-1" {
		t.Fatalf("token proofs %#v", token)
	}
	// A new nonce: the token endpoint answers 400 use_dpop_nonce once more.
	stub.mu.Lock()
	stub.asNonce = "as-nonce-2"
	stub.mu.Unlock()
	if _, err := rp.Refresh(login.RefreshToken, "", login); err != nil {
		t.Fatal(err)
	}
	if token = stub.proofsAt("/token"); len(token) != 3 || token[2].claims["nonce"] != "as-nonce-2" {
		t.Fatalf("refresh proofs %#v", token)
	}
	// UserInfo with the token the refresh did not replace in the stub.
	fresh := signIn(t, rp).login
	before := len(stub.proofsAt("/userinfo"))
	if _, err := rp.UserInfo(fresh.AccessToken, fresh.Subject); err != nil {
		t.Fatal(err)
	}
	userinfo := stub.proofsAt("/userinfo")[before:]
	if len(userinfo) != 2 || userinfo[0].claims["nonce"] == "rs-nonce-1" || userinfo[1].claims["nonce"] != "rs-nonce-1" {
		t.Fatalf("userinfo proofs %#v", userinfo)
	}
	// A resource server that changes its nonce is answered with one retry.
	stub.mu.Lock()
	stub.rsNonce = "rs-nonce-2"
	stub.mu.Unlock()
	answerStatus, _, _, err := rp.ResourceRequest("GET", stub.url+"/userinfo", fresh.AccessToken, "DPoP", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if answerStatus != 200 {
		t.Fatalf("status %d after the nonce changed once", answerStatus)
	}
}

func TestTokenTypeMustMatchTheProof(t *testing.T) {
	stub := startProvider(t)
	stub.dpopAlgs = []string{"ES256"}
	stub.forceType = "Bearer"
	rp := mustCreate(t, stub.config(nil))
	_, _, err := tryComplete(t, rp, AuthorizeOptions{})
	wantErr(t, err, "not DPoP")

	plain := startProvider(t)
	plain.forceType = "DPoP"
	bearer := mustCreate(t, plain.config(nil))
	_, _, err = tryComplete(t, bearer, AuthorizeOptions{})
	wantErr(t, err, "not Bearer")

	lower := startProvider(t)
	lower.dpopAlgs = []string{"ES256"}
	lower.forceType = "dpop"
	if _, _, err := tryComplete(t, mustCreate(t, lower.config(nil)), AuthorizeOptions{}); err != nil {
		t.Fatalf("token_type is case-insensitive: %v", err)
	}
}

// 2. acr

func TestACRIsEnforced(t *testing.T) {
	stub := startProvider(t)
	stub.acr = "urn:acr:two"
	rp := mustCreate(t, stub.config(map[string]any{"acrValues": []any{"urn:acr:one", "urn:acr:two"}}))
	login, request, err := tryComplete(t, rp, AuthorizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if request.ACRValues != "urn:acr:one urn:acr:two" || queryOf(request.URL)["acr_values"] != "urn:acr:one urn:acr:two" {
		t.Fatalf("transaction %q url %s", request.ACRValues, request.URL)
	}
	stub.mu.Lock()
	stub.acr = "urn:acr:three"
	stub.mu.Unlock()
	_, _, err = tryComplete(t, rp, AuthorizeOptions{})
	wantErr(t, err, "not one of the requested acr_values")
	// The per-request option replaces the setting.
	if _, _, err := tryComplete(t, rp, AuthorizeOptions{ACRValues: "urn:acr:three"}); err != nil {
		t.Fatal(err)
	}
	stub.mu.Lock()
	stub.acr = ""
	stub.mu.Unlock()
	_, _, err = tryComplete(t, rp, AuthorizeOptions{})
	wantErr(t, err, "has no acr")
	// Not requested: not checked.
	unasked := mustCreate(t, stub.config(nil))
	if _, _, err := tryComplete(t, unasked, AuthorizeOptions{}); err != nil {
		t.Fatal(err)
	}
	// The refresh path does not re-check acr.
	stub.mu.Lock()
	stub.acr = "urn:acr:elsewhere"
	stub.mu.Unlock()
	if _, err := rp.Refresh(login.RefreshToken, "", login); err != nil {
		t.Fatalf("refresh re-checked acr: %v", err)
	}
	// The transaction carries the values: a stored transaction without them
	// is not held to them, and one with them is.
	stub.mu.Lock()
	stub.acr = "urn:acr:one"
	stub.mu.Unlock()
	request, err = rp.AuthorizeOptions(AuthorizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, location := manual(t, request.URL)
	kept := *request
	kept.ACRValues = "urn:acr:two"
	_, err = rp.Complete(queryOf(location), &kept)
	wantErr(t, err, "not one of the requested acr_values")
}

// 3. PAR required by the provider

func TestPARRequiredByTheProvider(t *testing.T) {
	stub := startProvider(t)
	stub.par = true
	stub.requirePAR = true
	_, err := Create(stub.config(map[string]any{"par": "never"}))
	wantErr(t, err, "requires pushed authorization requests")
	rp := mustCreate(t, stub.config(nil))
	if !isExactTrue(rp.Metadata()["require_pushed_authorization_requests"]) {
		t.Fatal("discovery dropped require_pushed_authorization_requests")
	}
	signed := signIn(t, rp)
	if !strings.Contains(signed.request.URL, "request_uri=") {
		t.Fatalf("auto did not push: %s", signed.request.URL)
	}
	missing := startProvider(t)
	missing.requirePAR = true
	_, err = Create(missing.config(nil))
	wantErr(t, err, "no pushed authorization endpoint")
}

// 4. ID token algorithms

func TestIDTokenAlgorithmAllowList(t *testing.T) {
	stub := startProvider(t)
	stub.idAlgs = []string{"ES256", "RS256", "PS256", "HS256"}
	rp := mustCreate(t, stub.config(nil))
	if strings.Join(rp.algs, ",") != "RS256" {
		t.Fatalf("default allow-list %v", rp.algs)
	}
	if got := rp.Config()["idTokenSigningAlgs"]; strings.Join(stringList(got), ",") != "RS256" {
		t.Fatalf("idTokenSigningAlgs default %v", got)
	}
	wide := mustCreate(t, stub.config(map[string]any{"idTokenSigningAlgs": []any{"PS256", "RS256", "ES384"}}))
	if strings.Join(wide.algs, ",") != "PS256,RS256" {
		t.Fatalf("widened %v (ES384 is not advertised and is dropped)", wide.algs)
	}
	hs := mustCreate(t, stub.config(map[string]any{"idTokenSigningAlgs": []any{"HS256"}}))
	if strings.Join(hs.algs, ",") != "HS256" {
		t.Fatalf("named symmetric %v", hs.algs)
	}
	_, err := Create(stub.config(map[string]any{"idTokenSigningAlgs": []any{"none"}}))
	wantErr(t, err, "none")
	_, err = Create(stub.config(map[string]any{"idTokenSigningAlgs": []any{"ES384"}}))
	wantErr(t, err, "advertises none of the allowed")
	pinned := mustCreate(t, stub.config(map[string]any{"idTokenSignedResponseAlg": "PS256"}))
	if strings.Join(pinned.algs, ",") != "PS256" {
		t.Fatalf("pinned %v", pinned.algs)
	}
	_, err = Create(stub.config(map[string]any{"idTokenSignedResponseAlg": "ES512"}))
	wantErr(t, err, "does not advertise id_token alg ES512")
	_, err = Create(stub.config(map[string]any{"idTokenSignedResponseAlg": "none"}))
	wantErr(t, err, "none")

	esOnly := startProvider(t)
	esOnly.idAlgs = []string{"ES256"}
	_, err = Create(esOnly.config(nil))
	wantErr(t, err, "advertises none of the allowed")

	// An RS256 sign-in with the RS256-only default; a PS256-only allow-list
	// refuses the same RS256 ID token.
	if _, _, err := tryComplete(t, rp, AuthorizeOptions{}); err != nil {
		t.Fatal(err)
	}
	psOnly := mustCreate(t, stub.config(map[string]any{"idTokenSigningAlgs": []any{"PS256"}}))
	_, _, err = tryComplete(t, psOnly, AuthorizeOptions{})
	wantErr(t, err, "does not accept")
}

// 5. typ and at_hash

func TestTypAndAtHashAreRequired(t *testing.T) {
	stub := startProvider(t)
	rp := mustCreate(t, stub.config(nil))
	if rp.Config()["requireIdTokenTypAndAtHash"] != true {
		t.Fatal("requireIdTokenTypAndAtHash default")
	}
	stub.noTyp = true
	_, _, err := tryComplete(t, rp, AuthorizeOptions{})
	wantErr(t, err, "no typ")
	stub.mu.Lock()
	stub.noTyp = false
	stub.noAtHash = true
	stub.mu.Unlock()
	_, _, err = tryComplete(t, rp, AuthorizeOptions{})
	wantErr(t, err, "no at_hash")
	relaxed := mustCreate(t, stub.config(map[string]any{"requireIdTokenTypAndAtHash": false}))
	stub.mu.Lock()
	stub.noTyp = true
	stub.mu.Unlock()
	if _, _, err := tryComplete(t, relaxed, AuthorizeOptions{}); err != nil {
		t.Fatalf("relaxed: %v", err)
	}
	// Relaxed still checks them when present.
	stub.mu.Lock()
	stub.noTyp = false
	stub.noAtHash = false
	stub.badAtHash = true
	stub.mu.Unlock()
	_, _, err = tryComplete(t, relaxed, AuthorizeOptions{})
	wantErr(t, err, "at_hash")
	_, err = Create(stub.config(map[string]any{"requireIdTokenTypAndAtHash": "no"}))
	wantErr(t, err, "requireIdTokenTypAndAtHash must be true or false")

	// typ: JWT and application/jwt, in any case; anything else is refused.
	now := time.Now().Unix()
	payload := map[string]any{"iss": "https://op", "sub": "s", "aud": testClient, "exp": now + 60, "iat": now}
	checks := tokenChecks{Issuer: "https://op", ClientID: testClient, Algorithms: []string{"RS256"}, JWKS: []map[string]any{providerJWK}, RequireTyp: true}
	for typ, ok := range map[string]bool{"JWT": true, "jwt": true, "application/JWT": true, "at+jwt": false, "JOSE": false} {
		token := signIDTokenHeader(map[string]any{"alg": "RS256", "kid": "op", "typ": typ}, payload, false)
		_, err := ValidateIDToken(token, checks)
		if (err == nil) != ok {
			t.Fatalf("typ %s: %v", typ, err)
		}
	}
}

// 6. The same rules on every way of creating a client

func TestCreateAppliesTheDefaultsAndRules(t *testing.T) {
	stub := startProvider(t)
	minimal := map[string]any{
		"metadata":     stub.metadata(),
		"clientId":     testClient,
		"clientSecret": testSecret,
		"redirectUri":  "http://127.0.0.1/callback",
		// The stub provider is plain http.
		"allowInsecure": true,
	}
	rp := mustCreate(t, minimal)
	cfg := rp.Config()
	if cfg["par"] != "auto" || cfg["dpop"] != "auto" || cfg["clockToleranceSec"] != float64(30) || cfg["maxIdTokenAgeSec"] != float64(600) ||
		cfg["requireIdTokenTypAndAtHash"] != true || strings.Join(stringList(cfg["idTokenSigningAlgs"]), ",") != "RS256" ||
		cfg["tokenEndpointAuthMethod"] != "client_secret_basic" || cfg["scopes"] != testScopes {
		t.Fatalf("defaults %#v", cfg)
	}
	if _, ok := minimal["dpop"]; ok {
		t.Fatal("Create changed the caller's map")
	}
	for _, good := range []string{"https://app.example/cb", "http://localhost:3000/cb", "http://127.0.0.1/cb", "http://[::1]:3000/cb"} {
		if _, err := Create(merge(minimal, map[string]any{"redirectUri": good})); err != nil {
			t.Fatalf("%s: %v", good, err)
		}
	}
	for _, bad := range []string{"http://app.example/cb", "http://10.0.0.1/cb", "ftp://localhost/cb", "https://app.example/cb#frag"} {
		_, err := Create(merge(minimal, map[string]any{"redirectUri": bad, "allowInsecure": true}))
		if err == nil {
			t.Fatalf("Create accepted %s", bad)
		}
	}
	_, err := Create(merge(minimal, map[string]any{"postLogoutRedirectUri": "http://app.example/"}))
	wantErr(t, err, "postLogoutRedirectUri must use https")
	_, err = ResolveConfig(map[string]any{
		"metadataUrl": "https://localhost:8081/.well-known/openid-configuration",
		"clientId":    testClient, "clientSecret": "s", "redirectUri": "http://app.example/cb", "allowInsecure": true,
	}, t.TempDir())
	wantErr(t, err, "redirectUri must use https")
	_, err = Create(merge(minimal, map[string]any{"par": "maybe"}))
	wantErr(t, err, "par must be auto, always, or never")
	_, err = Create(merge(minimal, map[string]any{"clockToleranceSec": -1}))
	wantErr(t, err, "clockToleranceSec")
	_, err = Create(merge(minimal, map[string]any{"tokenEndpointAuthMethod": "none"}))
	wantErr(t, err, "public client")

	// A per-request redirect URI override is held to the same rule.
	_, err = rp.AuthorizeOptions(AuthorizeOptions{RedirectURI: "http://evil.example/cb"})
	wantErr(t, err, "must use https")
	request, err := rp.AuthorizeOptions(AuthorizeOptions{RedirectURI: "http://localhost:4000/cb"})
	if err != nil || request.RedirectURI != "http://localhost:4000/cb" {
		t.Fatalf("loopback override %v", err)
	}
	// maxIdTokenAgeSec 600 applies to a client created directly.
	stub.mu.Lock()
	stub.iatAhead = -700
	stub.mu.Unlock()
	_, _, err = tryComplete(t, rp, AuthorizeOptions{})
	wantErr(t, err, "iat is too old")
	// An iat more than the tolerance in the future is refused; within it, not.
	stub.mu.Lock()
	stub.iatAhead = 120
	stub.mu.Unlock()
	_, _, err = tryComplete(t, rp, AuthorizeOptions{})
	wantErr(t, err, "iat is in the future")
	stub.mu.Lock()
	stub.iatAhead = 10
	stub.mu.Unlock()
	if _, _, err := tryComplete(t, rp, AuthorizeOptions{}); err != nil {
		t.Fatal(err)
	}
}

// 7. The per-session token cache

type recordingStore struct {
	*MemorySessionStore
	mu   sync.Mutex
	sets []string
	dels []string
}

func (r *recordingStore) Set(id string, login *Login) error {
	r.mu.Lock()
	r.sets = append(r.sets, id)
	r.mu.Unlock()
	return r.MemorySessionStore.Set(id, login)
}

func (r *recordingStore) Delete(id string) error {
	r.mu.Lock()
	r.dels = append(r.dels, id)
	r.mu.Unlock()
	return r.MemorySessionStore.Delete(id)
}

func completeSession(t *testing.T, rp *RelyingParty, sid string) *Login {
	t.Helper()
	request, err := rp.Authorize()
	if err != nil {
		t.Fatal(err)
	}
	_, location := manual(t, request.URL)
	login, err := rp.CompleteSession(queryOf(location), request, sid)
	if err != nil {
		t.Fatal(err)
	}
	return login
}

func TestSessionCache(t *testing.T) {
	stub := startProvider(t)
	stub.dpopAlgs = []string{"ES256"}
	rp := mustCreate(t, stub.config(nil))
	store := &recordingStore{MemorySessionStore: NewMemorySessionStore()}
	rp.SetSessionStore(store)
	login := completeSession(t, rp, "app-session-1")
	if login.Session != "app-session-1" {
		t.Fatal(login.Session)
	}
	access, err := rp.SessionAccessToken("app-session-1")
	if err != nil {
		t.Fatal(err)
	}
	if access.AccessToken != login.AccessToken || access.TokenType != "DPoP" {
		t.Fatalf("cached %+v", access)
	}
	// A token with 30 seconds or less left is refreshed, with a DPoP proof.
	stub.mu.Lock()
	stub.expiresIn = 20
	stub.mu.Unlock()
	short := completeSession(t, rp, "")
	if short.Session == "" {
		t.Fatal("no handle was made")
	}
	tokenProofs := len(stub.proofsAt("/token"))
	stub.mu.Lock()
	stub.expiresIn = 300
	stub.mu.Unlock()
	renewed, err := rp.SessionAccessToken(short.Session)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.AccessToken == short.AccessToken || len(stub.proofsAt("/token")) != tokenProofs+1 {
		t.Fatalf("not refreshed with a proof: %+v", renewed)
	}
	held, _ := rp.Session(short.Session)
	if held == nil || held.AccessToken != renewed.AccessToken || held.Session != short.Session {
		t.Fatalf("the cache was not updated: %+v", held)
	}
	again, err := rp.SessionAccessToken(short.Session)
	if err != nil || again.AccessToken != renewed.AccessToken {
		t.Fatalf("the refreshed token was not cached: %v", err)
	}
	// A failed refresh removes the entry and is refused.
	stub.mu.Lock()
	stub.expiresIn = 5
	stub.mu.Unlock()
	failing := completeSession(t, rp, "app-session-3")
	stub.mu.Lock()
	stub.refreshFails = true
	stub.mu.Unlock()
	_, err = rp.SessionAccessToken("app-session-3")
	oe := wantErr(t, err, "refresh was refused")
	if oe.Code != "session" || oe.OAuthError != "invalid_grant" {
		t.Fatalf("refusal %+v", oe)
	}
	if held, _ := rp.Session(failing.Session); held != nil {
		t.Fatal("a failed refresh kept the entry")
	}
	_, err = rp.SessionAccessToken("app-session-3")
	wantErr(t, err, "no such session")
	// Sign-out clears the entry.
	if err := rp.RemoveSession("app-session-1"); err != nil {
		t.Fatal(err)
	}
	_, err = rp.SessionAccessToken("app-session-1")
	wantErr(t, err, "no such session")
	store.mu.Lock()
	sets := strings.Join(store.sets, ",")
	dels := strings.Join(store.dels, ",")
	store.mu.Unlock()
	if !strings.HasPrefix(sets, "app-session-1,") || !strings.Contains(dels, "app-session-3") || !strings.Contains(dels, "app-session-1") {
		t.Fatalf("the replaced store was not used: sets %s dels %s", sets, dels)
	}
}

func TestReceiverCallsTheTransmitterWithDPoPAndClearsEndedSessions(t *testing.T) {
	provider := startProvider(t)
	provider.dpopAlgs = []string{"ES256"}
	rp := mustCreate(t, provider.config(nil))
	tx := startTransmitter(t)
	tx.dpopToken = "cc-token"
	tx.nonce = "tx-nonce"
	login := completeSession(t, rp, "L-1")
	receiver, err := NewSignalsReceiver(tx.url, func([]string, SignalEvent) {}, ReceiverOptions{
		Client:         rp,
		PollIntervalMs: 60000,
		Log:            quietLog{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	receiver.Stop()
	tx.mu.Lock()
	asks, proofs, created := tx.nonceAsks, tx.proofs, tx.created
	tx.mu.Unlock()
	if created != 1 || asks != 1 || proofs < 2 {
		t.Fatalf("created %d nonce asks %d proofs %d", created, asks, proofs)
	}
	receiver.Track(TrackedFromLogin("L-1", login, nil))
	tx.deliver(Event["sessionRevoked"], map[string]any{
		"format":  "complex",
		"user":    map[string]any{"format": "iss_sub", "iss": tx.url, "sub": "user-1"},
		"session": map[string]any{"format": "opaque", "id": "sid-1"},
	}, nil, nil, "", "")
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if held, _ := rp.Session("L-1"); held != nil {
		t.Fatal("session-revoked left the session cache entry")
	}
	tx.mu.Lock()
	asksAfter := tx.nonceAsks
	tx.mu.Unlock()
	if asksAfter != 1 {
		t.Fatalf("the remembered nonce was not reused: %d asks", asksAfter)
	}
}
