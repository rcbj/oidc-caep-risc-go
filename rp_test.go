// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testClient = "oidc-caep-risc-demo"
	testSecret = "test-secret"
	testScopes = "openid profile email offline_access ssf.read ssf.manage"
)

var (
	providerKey *rsa.PrivateKey
	clientKey   *rsa.PrivateKey
	clientPEM   string
	providerJWK map[string]any
)

func TestMain(m *testing.M) {
	var err error
	providerKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	clientKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		panic(err)
	}
	clientPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	providerJWK = publicJWK(&providerKey.PublicKey, "op")
	os.Exit(m.Run())
}

func publicJWK(key *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   b64uint(key.N),
		"e":   b64uint(big.NewInt(int64(key.E))),
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
	}
}

func b64uint(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func signIDToken(payload map[string]any, corrupt bool) string {
	return signIDTokenHeader(map[string]any{"alg": "RS256", "kid": "op", "typ": "JWT"}, payload, corrupt)
}

func signIDTokenHeader(header map[string]any, payload map[string]any, corrupt bool) string {
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, providerKey, cryptoSHA256, sum[:])
	if err != nil {
		panic(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(sig)
	if corrupt && encoded != "" {
		flip := "A"
		if encoded[0] == 'A' {
			flip = "B"
		}
		encoded = flip + encoded[1:]
	}
	return h + "." + p + "." + encoded
}

const cryptoSHA256 = 5 // crypto.SHA256, kept local to avoid an import cycle in the test file's hash constant

func clientAssertionOK(assertion, audience string) bool {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return false
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	var header map[string]any
	var payload map[string]any
	if json.Unmarshal(hb, &header) != nil || json.Unmarshal(pb, &payload) != nil {
		return false
	}
	if header["alg"] != "RS256" {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&clientKey.PublicKey, cryptoSHA256, sum[:], sig) != nil {
		return false
	}
	if payload["iss"] != testClient || payload["sub"] != testClient {
		return false
	}
	switch aud := payload["aud"].(type) {
	case string:
		return aud == audience
	case []any:
		for _, item := range aud {
			if item == audience {
				return true
			}
		}
	}
	return false
}

type providerStub struct {
	mu        sync.Mutex
	server    *httptest.Server
	url       string
	par       bool
	corrupt   bool
	aud       string
	exp       *int64
	badAtHash bool
	codes     map[string]map[string]string
	refresh   map[string]map[string]string
	access    map[string]map[string]any
	pushed    map[string]url.Values

	// Issue #17 knobs. Each stays set for the stub's life.
	dpopAlgs     []string // dpop_signing_alg_values_supported; nil leaves it out
	requirePAR   bool
	idAlgs       []string // id_token_signing_alg_values_supported; nil is RS256
	asNonce      string   // PAR and token proofs must carry it
	rsNonce      string   // UserInfo proofs must carry it
	acr          string
	noTyp        bool
	noAtHash     bool
	iatAhead     int64
	expiresIn    int
	forceType    string
	refreshFails bool
	proofs       []seenProof
	nonceAsks    int
	authParams   url.Values
	bound        map[string]string // access token -> jkt
}

type seenProof struct {
	path   string
	header map[string]any
	claims map[string]any
}

func startProvider(t *testing.T) *providerStub {
	t.Helper()
	stub := &providerStub{
		aud:     testClient,
		codes:   map[string]map[string]string{},
		refresh: map[string]map[string]string{},
		access:  map[string]map[string]any{},
		pushed:  map[string]url.Values{},
		bound:   map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", stub.serve)
	stub.server = httptest.NewServer(mux)
	stub.url = stub.server.URL
	t.Cleanup(stub.server.Close)
	return stub
}

func (s *providerStub) metadata() map[string]any {
	doc := map[string]any{
		"issuer":                                         s.url,
		"authorization_endpoint":                         s.url + "/authorize",
		"token_endpoint":                                 s.url + "/token",
		"jwks_uri":                                       s.url + "/jwks",
		"userinfo_endpoint":                              s.url + "/userinfo",
		"end_session_endpoint":                           s.url + "/end-session",
		"response_types_supported":                       []string{"code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          s.idAlgsOr(),
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
		"scopes_supported":                               strings.Split(testScopes, " "),
	}
	s.mu.Lock()
	par := s.par
	dpopAlgs := s.dpopAlgs
	requirePAR := s.requirePAR
	s.mu.Unlock()
	if par {
		doc["pushed_authorization_request_endpoint"] = s.url + "/par"
	}
	if dpopAlgs != nil {
		doc["dpop_signing_alg_values_supported"] = dpopAlgs
	}
	if requirePAR {
		doc["require_pushed_authorization_requests"] = true
	}
	return doc
}

func (s *providerStub) idAlgsOr() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.idAlgs == nil {
		return []string{"RS256"}
	}
	return s.idAlgs
}

// checkProof verifies a DPoP proof the way an authorization or resource
// server does. It answers the key's thumbprint, or "" and a reason.
func (s *providerStub) checkProof(r *http.Request, accessToken, nonce string) (string, string) {
	proof := r.Header.Get("DPoP")
	if proof == "" {
		return "", "no proof"
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return "", "not a JWS"
	}
	header, err := decodePart(proof, 0, "header")
	if err != nil {
		return "", "header"
	}
	claims, err := decodePart(proof, 1, "payload")
	if err != nil {
		return "", "payload"
	}
	s.mu.Lock()
	s.proofs = append(s.proofs, seenProof{path: r.URL.Path, header: header, claims: claims})
	s.mu.Unlock()
	jwk, _ := asMap(header["jwk"])
	if header["typ"] != "dpop+jwt" || header["alg"] != "ES256" || jwk == nil || jwk["d"] != nil {
		return "", "header fields"
	}
	key, err := PublicKeyFromJWK(jwk)
	if err != nil {
		return "", "jwk"
	}
	sig, err := B64URLDecode(parts[2], "sig")
	if err != nil || !VerifySignature(key, "ES256", []byte(parts[0]+"."+parts[1]), sig) {
		return "", "signature"
	}
	if claims["htm"] != r.Method || claims["htu"] != s.url+r.URL.Path || sprint(claims["jti"]) == "" {
		return "", "htm/htu/jti"
	}
	iat, ok := asFloat(claims["iat"])
	if !ok || iat < float64(time.Now().Unix()-60) || iat > float64(time.Now().Unix()+60) {
		return "", "iat"
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		if claims["ath"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return "", "ath"
		}
	} else if claims["ath"] != nil {
		return "", "ath on a token request"
	}
	if nonce != "" && claims["nonce"] != nonce {
		return "", "use_dpop_nonce"
	}
	canonical := `{"crv":"` + sprint(jwk["crv"]) + `","kty":"EC","x":"` + sprint(jwk["x"]) + `","y":"` + sprint(jwk["y"]) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), ""
}

// asProof answers a PAR or token request's DPoP header: the thumbprint (""
// when there is no proof), or false after writing the refusal.
func (s *providerStub) asProof(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Header.Get("DPoP") == "" {
		return "", true
	}
	s.mu.Lock()
	nonce := s.asNonce
	s.mu.Unlock()
	jkt, problem := s.checkProof(r, "", nonce)
	if problem == "use_dpop_nonce" {
		s.mu.Lock()
		s.nonceAsks++
		s.mu.Unlock()
		w.Header().Set("DPoP-Nonce", nonce)
		writeJSON(w, 400, map[string]any{"error": "use_dpop_nonce", "error_description": "a nonce is required"})
		return "", false
	}
	if problem != "" {
		writeJSON(w, 400, map[string]any{"error": "invalid_dpop_proof", "error_description": problem})
		return "", false
	}
	if nonce != "" {
		w.Header().Set("DPoP-Nonce", nonce)
	}
	return jkt, true
}

func (s *providerStub) tokenFor(row map[string]string, jkt string) map[string]any {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	accessToken := base64.RawURLEncoding.EncodeToString(buf)
	_, _ = rand.Read(buf)
	refreshToken := base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now().Unix()
	s.mu.Lock()
	aud := s.aud
	exp := now + 300
	iat := now
	if s.exp != nil {
		exp = *s.exp
		iat = *s.exp
	}
	bad := s.badAtHash
	corrupt := s.corrupt
	acr := s.acr
	noTyp := s.noTyp
	noAtHash := s.noAtHash
	iat += s.iatAhead
	expiresIn := s.expiresIn
	if expiresIn == 0 {
		expiresIn = 300
	}
	tokenType := "Bearer"
	if jkt != "" {
		tokenType = "DPoP"
	}
	if s.forceType != "" {
		tokenType = s.forceType
	}
	s.aud = testClient
	s.corrupt = false
	s.badAtHash = false
	s.exp = nil
	s.mu.Unlock()
	atHash := "aaaa"
	if !bad {
		atHash = HashClaim(accessToken, "RS256")
	}
	payload := map[string]any{
		"iss": s.url, "sub": row["sub"], "aud": aud, "exp": exp, "iat": iat, "nonce": row["nonce"],
		"email": row["email"], "name": "Demo User", "preferred_username": row["sub"], "sid": row["sid"],
		"at_hash": atHash,
	}
	if acr != "" {
		payload["acr"] = acr
	}
	if noAtHash {
		delete(payload, "at_hash")
	}
	header := map[string]any{"alg": "RS256", "kid": "op", "typ": "JWT"}
	if noTyp {
		delete(header, "typ")
	}
	token := signIDTokenHeader(header, payload, corrupt)
	s.mu.Lock()
	s.refresh[refreshToken] = row
	stored := map[string]any{}
	for k, v := range payload {
		stored[k] = v
	}
	s.access[accessToken] = stored
	if jkt != "" {
		s.bound[accessToken] = jkt
	}
	s.mu.Unlock()
	return map[string]any{
		"access_token": accessToken, "token_type": tokenType, "expires_in": expiresIn,
		"refresh_token": refreshToken, "id_token": token, "scope": testScopes,
	}
}

func (s *providerStub) authorized(r *http.Request, body string) bool {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
		if err != nil {
			return false
		}
		return string(decoded) == testClient+":"+testSecret
	}
	values, _ := url.ParseQuery(body)
	if values.Get("client_secret") != "" {
		return values.Get("client_id") == testClient && values.Get("client_secret") == testSecret
	}
	assertion := values.Get("client_assertion")
	if assertion == "" {
		return false
	}
	return clientAssertionOK(assertion, s.url)
}

func (s *providerStub) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	text := string(body)
	path := r.URL.Path
	if path == "/.well-known/openid-configuration" {
		writeJSON(w, 200, s.metadata())
		return
	}
	if path == "/jwks" {
		writeJSON(w, 200, map[string]any{"keys": []any{providerJWK}})
		return
	}
	if path == "/userinfo" {
		authz := r.Header.Get("Authorization")
		scheme, token, _ := strings.Cut(authz, " ")
		token = strings.TrimSpace(token)
		s.mu.Lock()
		claims := s.access[token]
		jkt := s.bound[token]
		nonce := s.rsNonce
		s.mu.Unlock()
		if jkt != "" {
			if scheme != "DPoP" {
				writeJSON(w, 401, map[string]any{"error": "invalid_token", "error_description": "a DPoP-bound token sent as " + scheme})
				return
			}
			got, problem := s.checkProof(r, token, nonce)
			if problem == "use_dpop_nonce" {
				s.mu.Lock()
				s.nonceAsks++
				s.mu.Unlock()
				w.Header().Set("DPoP-Nonce", nonce)
				w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="a nonce is required"`)
				writeJSON(w, 401, map[string]any{"error": "use_dpop_nonce"})
				return
			}
			if problem != "" || got != jkt {
				writeJSON(w, 401, map[string]any{"error": "invalid_dpop_proof", "error_description": problem})
				return
			}
		} else if scheme != "Bearer" {
			claims = nil
		}
		if claims == nil {
			writeJSON(w, 401, map[string]any{"error": "invalid_token"})
			return
		}
		writeJSON(w, 200, claims)
		return
	}
	if path == "/par" && r.Method == http.MethodPost {
		if !s.authorized(r, text) {
			writeJSON(w, 401, map[string]any{"error": "invalid_client"})
			return
		}
		if _, ok := s.asProof(w, r); !ok {
			return
		}
		values, _ := url.ParseQuery(text)
		buf := make([]byte, 8)
		_, _ = rand.Read(buf)
		requestURI := "urn:par:" + base64.RawURLEncoding.EncodeToString(buf)
		s.mu.Lock()
		s.pushed[requestURI] = values
		s.mu.Unlock()
		writeJSON(w, 201, map[string]any{"request_uri": requestURI, "expires_in": 60})
		return
	}
	if path == "/authorize" {
		values := r.URL.Query()
		stored := values.Get("request_uri")
		params := values
		if stored != "" {
			s.mu.Lock()
			got, ok := s.pushed[stored]
			s.mu.Unlock()
			if !ok {
				writeJSON(w, 400, map[string]any{"error": "invalid_request"})
				return
			}
			params = got
		}
		s.mu.Lock()
		s.authParams = params
		s.mu.Unlock()
		redirect := params.Get("redirect_uri")
		state := params.Get("state")
		challenge := params.Get("code_challenge")
		if params.Get("code_challenge_method") != "S256" || challenge == "" {
			writeJSON(w, 400, map[string]any{"error": "invalid_request"})
			return
		}
		row := map[string]string{"sub": "user-1", "email": "user-1@example.com", "sid": "sid-1", "nonce": params.Get("nonce")}
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		code := base64.RawURLEncoding.EncodeToString(buf)
		s.mu.Lock()
		s.codes[code] = map[string]string{"sub": row["sub"], "email": row["email"], "sid": row["sid"], "nonce": row["nonce"], "redirect": redirect, "challenge": challenge}
		s.mu.Unlock()
		q := url.Values{}
		q.Set("code", code)
		q.Set("state", state)
		q.Set("iss", s.url)
		dest, _ := url.Parse(redirect)
		dest.RawQuery = q.Encode()
		w.Header().Set("Location", dest.String())
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(302)
		return
	}
	if path == "/token" && r.Method == http.MethodPost {
		if !s.authorized(r, text) {
			writeJSON(w, 401, map[string]any{"error": "invalid_client", "error_description": "client authentication failed"})
			return
		}
		jkt, ok := s.asProof(w, r)
		if !ok {
			return
		}
		params, _ := url.ParseQuery(text)
		switch params.Get("grant_type") {
		case "client_credentials":
			tokenType := "Bearer"
			if jkt != "" {
				tokenType = "DPoP"
				s.mu.Lock()
				s.bound["cc-token"] = jkt
				s.mu.Unlock()
			}
			writeJSON(w, 200, map[string]any{"access_token": "cc-token", "token_type": tokenType, "expires_in": 120, "scope": params.Get("scope")})
			return
		case "refresh_token":
			s.mu.Lock()
			row := s.refresh[params.Get("refresh_token")]
			fails := s.refreshFails
			s.mu.Unlock()
			if row == nil || fails {
				writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
				return
			}
			minted := s.tokenFor(row, jkt)
			s.mu.Lock()
			claims := map[string]any{}
			for k, v := range s.access[minted["access_token"].(string)] {
				claims[k] = v
			}
			s.mu.Unlock()
			delete(claims, "nonce")
			minted["id_token"] = signIDToken(claims, false)
			writeJSON(w, 200, minted)
			return
		}
		code := params.Get("code")
		s.mu.Lock()
		row := s.codes[code]
		s.mu.Unlock()
		if row == nil {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
		if params.Get("redirect_uri") != row["redirect"] {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
		verifier := params.Get("code_verifier")
		sum := sha256.Sum256([]byte(verifier))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != row["challenge"] {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant", "error_description": "pkce"})
			return
		}
		s.mu.Lock()
		delete(s.codes, code)
		s.mu.Unlock()
		writeJSON(w, 200, s.tokenFor(row, jkt))
		return
	}
	writeJSON(w, 404, map[string]any{"error": "not_found"})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	raw, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconvItoa(len(raw)))
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func strconvItoa(n int) string {
	return jsonNumber(float64(n))
}

func (s *providerStub) config(over map[string]any) map[string]any {
	doc := map[string]any{
		"metadataUrl":             s.url + "/.well-known/openid-configuration",
		"clientId":                testClient,
		"clientSecret":            testSecret,
		"tokenEndpointAuthMethod": "client_secret_basic",
		"redirectUri":             "http://127.0.0.1/callback",
		"postLogoutRedirectUri":   "http://127.0.0.1/",
		"scopes":                  testScopes,
		"privateKeyAlg":           "RS256",
		"par":                     "auto",
		"clockToleranceSec":       30,
		"maxIdTokenAgeSec":        600,
		"allowInsecure":           true,
	}
	for k, v := range over {
		if v == nil {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	return doc
}

func manual(t *testing.T, rawURL string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := (&http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{Proxy: nil},
	}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode, res.Header.Get("Location")
}

func queryOf(location string) map[string]string {
	u, err := url.Parse(location)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for k, v := range u.Query() {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func signIn(t *testing.T, rp *RelyingParty) *signedIn {
	t.Helper()
	return signInOpts(t, rp, AuthorizeOptions{})
}

type signedIn struct {
	request *Transaction
	query   map[string]string
	login   *Login
}

func signInOpts(t *testing.T, rp *RelyingParty, opts AuthorizeOptions) *signedIn {
	t.Helper()
	request, err := rp.AuthorizeOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	status, location := manual(t, request.URL)
	if location == "" {
		t.Fatalf("the provider did not redirect (%d)", status)
	}
	query := queryOf(location)
	login, err := rp.Complete(query, request)
	if err != nil {
		t.Fatal(err)
	}
	return &signedIn{request: request, query: query, login: login}
}

func oidcErr(t *testing.T, err error) *OidcError {
	t.Helper()
	var oe *OidcError
	if !errors.As(err, &oe) {
		t.Fatalf("expected OidcError, got %v", err)
	}
	return oe
}

func TestDefaultScopesAndAtHash(t *testing.T) {
	sum := sha256.Sum256([]byte("abc"))
	if DefaultScopes != testScopes {
		t.Fatalf("scopes %q", DefaultScopes)
	}
	if HashClaim("abc", "RS256") != B64URLEncode(sum[:len(sum)/2]) {
		t.Fatalf("at_hash %s", HashClaim("abc", "RS256"))
	}
}

func TestSignsInWithPKCE(t *testing.T) {
	stub := startProvider(t)
	rp, err := Create(stub.config(nil))
	if err != nil {
		t.Fatal(err)
	}
	signed := signIn(t, rp)
	login := signed.login
	if login.Subject != "user-1" || login.Email != "user-1@example.com" || login.SID != "sid-1" || login.Issuer != stub.url || login.PreferredUsername != "user-1" || login.RefreshToken == "" {
		t.Fatalf("login %+v", login)
	}
	if !strings.Contains(signed.request.URL, "code_challenge=") || !strings.Contains(signed.request.URL, "code_challenge_method=S256") || strings.Contains(signed.request.URL, "client_secret") {
		t.Fatalf("url %s", signed.request.URL)
	}
	info, err := rp.UserInfo(login.AccessToken, login.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if info["sub"] != "user-1" {
		t.Fatalf("userinfo %#v", info["sub"])
	}
	end := rp.EndSessionURL(EndSessionOptions{IDToken: login.IDToken, State: "bye"})
	if !strings.Contains(end, "/end-session") || !strings.Contains(end, "id_token_hint=") || !strings.Contains(end, "client_id=") {
		t.Fatalf("end %s", end)
	}
}

func TestRefusesACallbackThatIsNotThisSignIn(t *testing.T) {
	stub := startProvider(t)
	rp, err := Create(stub.config(nil))
	if err != nil {
		t.Fatal(err)
	}
	request, err := rp.Authorize()
	if err != nil {
		t.Fatal(err)
	}
	_, location := manual(t, request.URL)
	query := queryOf(location)
	badState := *request
	badState.State = "nope"
	_, err = rp.Complete(query, &badState)
	if err == nil || !regexp.MustCompile("state").MatchString(err.Error()) {
		t.Fatalf("state: %v", err)
	}
	badNonce := *request
	badNonce.Nonce = "nope"
	_, err = rp.Complete(query, &badNonce)
	if err == nil || !regexp.MustCompile("nonce").MatchString(err.Error()) {
		t.Fatalf("nonce: %v", err)
	}
	query["iss"] = "https://elsewhere.example"
	_, err = rp.Complete(query, request)
	if err == nil || !regexp.MustCompile("iss mismatch").MatchString(err.Error()) {
		t.Fatalf("iss: %v", err)
	}
	query["iss"] = stub.url
	query["access_token"] = "should-not-be-here"
	_, err = rp.Complete(query, request)
	if err == nil || !regexp.MustCompile("access_token").MatchString(err.Error()) {
		t.Fatalf("front: %v", err)
	}
}

func TestAcceptsACodeOnce(t *testing.T) {
	stub := startProvider(t)
	rp, err := Create(stub.config(nil))
	if err != nil {
		t.Fatal(err)
	}
	signed := signIn(t, rp)
	if signed.login.Subject != "user-1" {
		t.Fatal(signed.login.Subject)
	}
	_, err = rp.Complete(signed.query, signed.request)
	if err == nil || !regexp.MustCompile("already used").MatchString(err.Error()) {
		t.Fatalf("reuse: %v", err)
	}
}

func TestRefusesBadTokens(t *testing.T) {
	stub := startProvider(t)
	rp, err := Create(stub.config(nil))
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := Create(stub.config(map[string]any{"clientSecret": "nope"}))
	if err != nil {
		t.Fatal(err)
	}
	request, err := wrong.Authorize()
	if err != nil {
		t.Fatal(err)
	}
	_, location := manual(t, request.URL)
	query := queryOf(location)
	_, err = wrong.Complete(query, request)
	oe := oidcErr(t, err)
	if oe.OAuthError != "invalid_client" {
		t.Fatalf("oauth %q %v", oe.OAuthError, err)
	}
	stub.mu.Lock()
	stub.corrupt = true
	stub.mu.Unlock()
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatal(recovered)
			}
		}()
		request, err := rp.Authorize()
		if err != nil {
			t.Fatal(err)
		}
		_, location := manual(t, request.URL)
		_, err = rp.Complete(queryOf(location), request)
		if err == nil || !regexp.MustCompile("signature").MatchString(err.Error()) {
			t.Fatalf("signature: %v", err)
		}
	}()
	stub.mu.Lock()
	stub.aud = "other-client"
	stub.mu.Unlock()
	request, err = rp.Authorize()
	if err != nil {
		t.Fatal(err)
	}
	_, location = manual(t, request.URL)
	_, err = rp.Complete(queryOf(location), request)
	if err == nil || !regexp.MustCompile("audience|aud").MatchString(err.Error()) {
		t.Fatalf("aud: %v", err)
	}
	past := time.Now().Unix() - 3600
	stub.mu.Lock()
	stub.exp = &past
	stub.mu.Unlock()
	request, err = rp.Authorize()
	if err != nil {
		t.Fatal(err)
	}
	_, location = manual(t, request.URL)
	_, err = rp.Complete(queryOf(location), request)
	if err == nil || !regexp.MustCompile("exp|timestamp|old|iat").MatchString(err.Error()) {
		t.Fatalf("exp: %v", err)
	}
	stub.mu.Lock()
	stub.badAtHash = true
	stub.mu.Unlock()
	request, err = rp.Authorize()
	if err != nil {
		t.Fatal(err)
	}
	_, location = manual(t, request.URL)
	_, err = rp.Complete(queryOf(location), request)
	if err == nil || !regexp.MustCompile("at_hash").MatchString(err.Error()) {
		t.Fatalf("at_hash: %v", err)
	}
}

func TestRefreshAndClientCredentials(t *testing.T) {
	stub := startProvider(t)
	rp, err := Create(stub.config(nil))
	if err != nil {
		t.Fatal(err)
	}
	login := signIn(t, rp).login
	refreshed, err := rp.Refresh(login.RefreshToken, "", login)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Subject != login.Subject || refreshed.AccessToken == login.AccessToken {
		t.Fatalf("refresh %+v", refreshed)
	}
	own, err := rp.ClientCredentials("ssf.manage")
	if err != nil {
		t.Fatal(err)
	}
	if own.AccessToken != "cc-token" {
		t.Fatal(own.AccessToken)
	}
	again, err := rp.ClientCredentials("ssf.manage")
	if err != nil {
		t.Fatal(err)
	}
	if again.AccessToken != "cc-token" {
		t.Fatal(again.AccessToken)
	}
}

func TestPAR(t *testing.T) {
	stub := startProvider(t)
	stub.mu.Lock()
	stub.par = true
	stub.mu.Unlock()
	rp, err := Create(stub.config(nil))
	if err != nil {
		t.Fatal(err)
	}
	signed := signIn(t, rp)
	if !strings.Contains(signed.request.URL, "request_uri=") || strings.Contains(signed.request.URL, "code_challenge=") || signed.login.Subject != "user-1" {
		t.Fatalf("par url %s subject %s", signed.request.URL, signed.login.Subject)
	}
}

func TestPostAndPrivateKeyJWT(t *testing.T) {
	stub := startProvider(t)
	posted, err := Create(stub.config(map[string]any{"tokenEndpointAuthMethod": "client_secret_post"}))
	if err != nil {
		t.Fatal(err)
	}
	if signIn(t, posted).login.Subject != "user-1" {
		t.Fatal("post")
	}
	jwtRP, err := Create(stub.config(map[string]any{
		"tokenEndpointAuthMethod": "private_key_jwt",
		"clientSecret":            nil,
		"privateKeyPem":           clientPEM,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if signIn(t, jwtRP).login.Subject != "user-1" {
		t.Fatal("jwt")
	}
}

func TestReadsConfigurationFileNames(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretPath, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OIDC_TEST_SECRET", "from-env")
	file := map[string]any{
		"metadataUrl":  "https://localhost:8081/.well-known/openid-configuration",
		"client_id":    testClient,
		"clientSecret": "env:OIDC_TEST_SECRET",
		"redirectUri":  "http://localhost:3000/callback",
		"scopes":       strings.Split(testScopes, " "),
	}
	env, err := ResolveConfig(file, dir)
	if err != nil {
		t.Fatal(err)
	}
	if env["clientId"] != testClient || env["clientSecret"] != "from-env" || env["issuer"] != "https://localhost:8081" || env["scopes"] != testScopes || env["tokenEndpointAuthMethod"] != "client_secret_basic" {
		t.Fatalf("env %#v", env)
	}
	fromFile := cloneMap(file)
	fromFile["clientSecret"] = "file:secret"
	got, err := ResolveConfig(fromFile, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got["clientSecret"] != "from-file" {
		t.Fatal(got["clientSecret"])
	}
	chain := "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte(chain), 0o600); err != nil {
		t.Fatal(err)
	}
	withCA := cloneMap(file)
	withCA["tlsCa"] = "ca.pem"
	got, err = ResolveConfig(withCA, dir)
	if err != nil || got["tlsCa"] != chain {
		t.Fatalf("path ca %#v %v", got["tlsCa"], err)
	}
	withCA["tlsCa"] = "file:ca.pem"
	got, err = ResolveConfig(withCA, dir)
	if err != nil || got["tlsCa"] != chain {
		t.Fatalf("file ca %#v %v", got["tlsCa"], err)
	}
	withCA["tlsCa"] = chain
	got, err = ResolveConfig(withCA, dir)
	if err != nil || got["tlsCa"] != strings.TrimSpace(chain) {
		t.Fatalf("inline ca %#v %v", got["tlsCa"], err)
	}
	t.Setenv("OIDC_TEST_CA", chain)
	withCA["tlsCa"] = "env:OIDC_TEST_CA"
	got, err = ResolveConfig(withCA, dir)
	if err != nil || got["tlsCa"] != chain {
		t.Fatalf("env ca %#v %v", got["tlsCa"], err)
	}
	os.Unsetenv("OIDC_TEST_CA")
	got, err = ResolveConfig(withCA, dir)
	if err != nil || got["tlsCa"] != nil {
		t.Fatalf("empty env ca %#v %v", got["tlsCa"], err)
	}
	withCA["tlsCa"] = "missing.pem"
	got, err = ResolveConfig(withCA, dir)
	if err != nil || got["tlsCa"] != nil {
		t.Fatalf("missing ca %#v %v", got["tlsCa"], err)
	}
	none := cloneMap(file)
	none["tokenEndpointAuthMethod"] = "none"
	_, err = ResolveConfig(none, dir)
	if err == nil || !regexp.MustCompile("public client").MatchString(err.Error()) {
		t.Fatalf("none: %v", err)
	}
	badScopes := cloneMap(file)
	badScopes["scopes"] = "profile email"
	_, err = ResolveConfig(badScopes, dir)
	if err == nil || !regexp.MustCompile("openid").MatchString(err.Error()) {
		t.Fatalf("scopes: %v", err)
	}
}

func TestSignalsFlag(t *testing.T) {
	dir := t.TempDir()
	file := map[string]any{
		"metadataUrl":  "https://localhost:8081/.well-known/openid-configuration",
		"client_id":    testClient,
		"clientSecret": "secret",
		"redirectUri":  "http://localhost:3000/callback",
		"ssf":          map[string]any{"transmitter": "https://localhost:8081/", "pollIntervalMs": 3000},
	}
	omitted, err := ResolveConfig(file, dir)
	if err != nil {
		t.Fatal(err)
	}
	if omitted["scopes"] != testScopes {
		t.Fatal(omitted["scopes"])
	}
	if _, ok := omitted["signals"]; ok {
		t.Fatal("signals should be omitted")
	}
	ssf, _ := omitted["ssf"].(map[string]any)
	if ssf["transmitter"] != "https://localhost:8081" || ssf["pollIntervalMs"] != 3000 {
		t.Fatalf("ssf %#v", ssf)
	}
	explicitSrc := cloneMap(file)
	explicitSrc["signals"] = true
	explicitSrc["scopes"] = testScopes
	explicitSrc["ssf"] = map[string]any{"transmitter": "https://localhost:8081/", "pollIntervalMs": 3000}
	explicit, err := ResolveConfig(explicitSrc, dir)
	if err != nil {
		t.Fatal(err)
	}
	if explicit["scopes"] != testScopes {
		t.Fatal(explicit["scopes"])
	}
	if _, ok := explicit["signals"]; ok {
		t.Fatal("explicit signals leaked")
	}
	explicitSSF, _ := explicit["ssf"].(map[string]any)
	if explicitSSF["transmitter"] != ssf["transmitter"] || explicitSSF["pollIntervalMs"] != ssf["pollIntervalMs"] {
		t.Fatalf("explicit ssf %#v", explicitSSF)
	}
	listedSrc := cloneMap(file)
	listedSrc["signals"] = false
	listedSrc["scopes"] = testScopes
	listedSrc["ssf"] = map[string]any{"transmitter": "not-a-url"}
	listed, err := ResolveConfig(listedSrc, dir)
	if err != nil {
		t.Fatal(err)
	}
	if listed["signals"] != false || listed["ssf"] != nil || listed["scopes"] != "openid profile email offline_access" {
		t.Fatalf("listed %#v", listed)
	}
	if strings.Contains(listed["scopes"].(string), "ssf.read") || strings.Contains(listed["scopes"].(string), "ssf.manage") {
		t.Fatal(listed["scopes"])
	}
	defaults, err := ResolveConfig(merge(file, map[string]any{"signals": false}), dir)
	if err != nil {
		t.Fatal(err)
	}
	if defaults["signals"] != false || defaults["ssf"] != nil || defaults["scopes"] != "openid profile email offline_access" || !strings.Contains(defaults["scopes"].(string), "openid") {
		t.Fatalf("defaults %#v", defaults)
	}
	_, err = ResolveConfig(merge(file, map[string]any{"signals": false, "scopes": "ssf.read ssf.manage"}), dir)
	if err == nil || !regexp.MustCompile("openid").MatchString(err.Error()) {
		t.Fatalf("dropped openid: %v", err)
	}
	_, err = ResolveConfig(merge(file, map[string]any{"signals": "no"}), dir)
	oe := oidcErr(t, err)
	if oe.Code != "config" || oe.Error() != "signals must be true or false" {
		t.Fatalf("signals error [%s] %s", oe.Code, oe.Error())
	}
}

func cloneMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func merge(base, over map[string]any) map[string]any {
	out := cloneMap(base)
	for k, v := range over {
		out[k] = v
	}
	return out
}
