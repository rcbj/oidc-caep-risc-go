// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"
)

var frontChannel = []string{"access_token", "id_token", "refresh_token", "token_type"}

// Transaction is the sign-in kept until the browser returns.
type Transaction struct {
	State        string
	Nonce        string
	CodeVerifier string
	RedirectURI  string
	URL          string
	MaxAge       *float64
	ExpectedSub  string
	// ACRValues are the acr_values requested, space-separated. Complete
	// requires the ID token's acr to be one of them.
	ACRValues string
}

// Login is a completed sign-in. Tokens stay in this process.
type Login struct {
	Subject           string
	Issuer            string
	Claims            map[string]any
	AccessToken       string
	IDToken           string
	TokenType         string
	Email             string
	Name              string
	PreferredUsername string
	SID               string
	RefreshToken      string
	ExpiresAt         float64
	HasExpires        bool
	Scope             string
	// Session is the session-cache handle (CompleteSession), or "".
	Session string
}

// AuthorizeOptions are the optional Authentication Request parameters.
// RedirectURI is held to the same rule as the configured one. ACRValues
// replaces the acrValues setting for this request.
type AuthorizeOptions struct {
	RedirectURI string
	Scope       string
	Prompt      string
	LoginHint   string
	MaxAge      *float64
	ACRValues   string
	ExpectedSub string
}

// EndSessionOptions builds an RP-Initiated Logout URL.
// A nil PostLogout uses the configuration's post-logout redirect.
type EndSessionOptions struct {
	IDToken    string
	PostLogout *string
	State      string
	LogoutHint string
}

// Access is a client-credentials token.
type Access struct {
	AccessToken string
	TokenType   string
	ExpiresAt   float64
	HasExpires  bool
	Scope       string
}

type tokenResponse struct {
	AccessToken  string
	TokenType    string
	IDToken      string
	RefreshToken string
	ExpiresIn    *float64
	Scope        string
}

// RelyingParty is a confidential OpenID Connect client.
type RelyingParty struct {
	config       map[string]any
	metadata     map[string]any
	key          any
	algs         []string
	dpop         *dpopKey
	mu           sync.Mutex
	jwks         []map[string]any
	jwksSet      bool
	usedCodes    map[string]float64
	ccScope      string
	ccToken      Access
	ccUntil      float64
	ccSet        bool
	nonces       map[string]string
	store        SessionStore
	sessionLocks map[string]*sessionLock
}

func (rp *RelyingParty) Config() map[string]any   { return rp.config }
func (rp *RelyingParty) Metadata() map[string]any { return rp.metadata }

func (rp *RelyingParty) TLS() map[string]string {
	if ca, ok := rp.config["tlsCa"].(string); ok && ca != "" {
		return map[string]string{"ca": ca}
	}
	return map[string]string{}
}

// Create discovers the provider, or uses metadata already loaded, and returns a client.
func Create(config map[string]any) (*RelyingParty, error) {
	if config == nil {
		return nil, errCode("config", "the configuration must be a JSON object")
	}
	config = copyConfig(config)
	if err := applySettings(config); err != nil {
		return nil, err
	}
	method := sprint(config["tokenEndpointAuthMethod"])
	if method == "private_key_jwt" && sprint(config["privateKeyPem"]) == "" {
		return nil, errCode("config", "private_key_jwt needs a private key")
	}
	if method != "private_key_jwt" && sprint(config["clientSecret"]) == "" {
		return nil, fmtErr("config", "%s needs a client secret", method)
	}
	allow := isExactTrue(config["allowInsecure"])
	if !allow {
		if issuer := sprint(config["issuer"]); issuer != "" && schemeOf(issuer) == "http" {
			return nil, errCode("config", "issuer must use https (set allowInsecure for a development provider)")
		}
	}
	metadata, _ := asMap(config["metadata"])
	if metadata == nil {
		metadataURL := sprint(config["metadataUrl"])
		if metadataURL == "" {
			return nil, errCode("config", "metadataUrl or metadata is required")
		}
		if !allow && schemeOf(metadataURL) != "https" {
			return nil, errCode("config", "metadataUrl must use https (set allowInsecure for a development provider)")
		}
		var err error
		metadata, err = DiscoverProvider(metadataURL, tlsMap(config))
		if err != nil {
			return nil, err
		}
	}
	if !allow {
		for name, value := range metadata {
			text, ok := value.(string)
			if !ok || !strings.HasPrefix(text, "http:") {
				continue
			}
			if strings.HasSuffix(name, "endpoint") || name == "jwks_uri" || name == "issuer" {
				return nil, fmtErr("discovery", "%s must use https: %s", name, text)
			}
		}
	}
	if methods, ok := asStringList(metadata["token_endpoint_auth_methods_supported"]); ok && len(methods) > 0 && !containsString(methods, method) {
		return nil, fmtErr("discovery", "the provider does not advertise %s", method)
	}
	if challenges, ok := asStringList(metadata["code_challenge_methods_supported"]); ok && len(challenges) > 0 && !containsString(challenges, "S256") {
		return nil, errCode("discovery", "the provider does not advertise PKCE S256")
	}
	var key any
	if pemText := sprint(config["privateKeyPem"]); pemText != "" {
		alg := sprint(config["privateKeyAlg"])
		if alg == "" {
			alg = "RS256"
		}
		loaded, err := LoadPrivateKey(pemText, alg)
		if err != nil {
			return nil, err
		}
		key = loaded
	}
	pinned := sprint(config["idTokenSignedResponseAlg"])
	algs, err := AllowedIDTokenAlgorithms(stringList(metadata["id_token_signing_alg_values_supported"]), pinned, stringList(config["idTokenSigningAlgs"]))
	if err != nil {
		return nil, err
	}
	parEndpoint := sprint(metadata["pushed_authorization_request_endpoint"])
	if sprint(config["par"]) == "always" && parEndpoint == "" {
		return nil, errCode("discovery", "par is always, and the provider has no pushed authorization endpoint")
	}
	if isExactTrue(metadata["require_pushed_authorization_requests"]) {
		if sprint(config["par"]) == "never" {
			return nil, errCode("config", "par is never, and the provider requires pushed authorization requests")
		}
		if parEndpoint == "" {
			return nil, errCode("discovery", "the provider requires pushed authorization requests and has no pushed authorization endpoint")
		}
	}
	dpop, err := dpopFor(config, metadata)
	if err != nil {
		return nil, err
	}
	return &RelyingParty{
		config:       config,
		metadata:     metadata,
		key:          key,
		algs:         algs,
		dpop:         dpop,
		usedCodes:    map[string]float64{},
		nonces:       map[string]string{},
		store:        NewMemorySessionStore(),
		sessionLocks: map[string]*sessionLock{},
	}, nil
}

// dpopFor is the DPoP key under the dpop setting, or nil when no proofs are
// sent: never; auto when the provider does not advertise ES256 for DPoP.
// always fails when it does not.
func dpopFor(config, metadata map[string]any) (*dpopKey, error) {
	mode := sprint(config["dpop"])
	if mode == "never" {
		return nil, nil
	}
	advertised, listed := asStringList(metadata["dpop_signing_alg_values_supported"])
	if !containsString(advertised, "ES256") {
		if mode != "always" {
			return nil, nil
		}
		if !listed {
			return nil, errCode("discovery", "dpop is always, and the provider does not advertise dpop_signing_alg_values_supported")
		}
		return nil, fmtErr("discovery", "dpop is always, and the provider does not advertise ES256 for DPoP (%s)", strings.Join(advertised, ", "))
	}
	return newDPoPKey(sprint(config["dpopKey"]))
}

func copyConfig(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func tlsMap(config map[string]any) map[string]string {
	if ca, ok := config["tlsCa"].(string); ok && ca != "" {
		return map[string]string{"ca": ca}
	}
	return nil
}

// Authorize builds the Authentication Request. Keep the transaction until Complete.
func (rp *RelyingParty) Authorize() (*Transaction, error) {
	return rp.AuthorizeOptions(AuthorizeOptions{})
}

func (rp *RelyingParty) AuthorizeOptions(opts AuthorizeOptions) (*Transaction, error) {
	redirectURI := opts.RedirectURI
	if redirectURI == "" {
		redirectURI = sprint(rp.config["redirectUri"])
	} else if _, err := checkRedirect(redirectURI, "the redirect URI"); err != nil {
		return nil, err
	}
	acrValues := strings.Join(strings.Fields(opts.ACRValues), " ")
	if acrValues == "" {
		acrValues = sprint(rp.config["acrValues"])
	}
	scope := opts.Scope
	if scope == "" {
		scope = sprint(rp.config["scopes"])
	}
	state, err := RandomToken()
	if err != nil {
		return nil, errCause("protocol", err.Error(), err)
	}
	nonce, err := RandomToken()
	if err != nil {
		return nil, errCause("protocol", err.Error(), err)
	}
	verifier, err := RandomToken()
	if err != nil {
		return nil, errCause("protocol", err.Error(), err)
	}
	params := map[string]string{
		"response_type":         "code",
		"client_id":             sprint(rp.config["clientId"]),
		"redirect_uri":          redirectURI,
		"scope":                 scope,
		"state":                 state,
		"nonce":                 nonce,
		"code_challenge":        CodeChallengeS256(verifier),
		"code_challenge_method": "S256",
	}
	order := []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"}
	if opts.Prompt != "" {
		params["prompt"] = opts.Prompt
		order = append(order, "prompt")
	}
	if opts.LoginHint != "" {
		params["login_hint"] = opts.LoginHint
		order = append(order, "login_hint")
	}
	if opts.MaxAge != nil {
		params["max_age"] = trimFloat(*opts.MaxAge)
		order = append(order, "max_age")
	}
	if acrValues != "" {
		params["acr_values"] = acrValues
		order = append(order, "acr_values")
	}
	if rp.dpop != nil {
		params["dpop_jkt"] = rp.dpop.jkt
		order = append(order, "dpop_jkt")
	}
	txn := &Transaction{State: state, Nonce: nonce, CodeVerifier: verifier, RedirectURI: redirectURI, MaxAge: opts.MaxAge, ExpectedSub: opts.ExpectedSub, ACRValues: acrValues}
	parEndpoint := sprint(rp.metadata["pushed_authorization_request_endpoint"])
	mode := sprint(rp.config["par"])
	required := isExactTrue(rp.metadata["require_pushed_authorization_requests"])
	usePAR := mode == "always" || (mode == "auto" && parEndpoint != "") || required
	if usePAR && parEndpoint == "" {
		return nil, errCode("discovery", "a pushed authorization request is needed, and the provider has no pushed authorization endpoint")
	}
	if usePAR {
		pushed, _, err := rp.postForm(parEndpoint, params, order)
		if err != nil {
			return nil, err
		}
		requestURI, _ := pushed["request_uri"].(string)
		if requestURI == "" {
			return nil, errCode("protocol", "the pushed authorization response has no request_uri")
		}
		txn.URL = withQuery(sprint(rp.metadata["authorization_endpoint"]), map[string]string{
			"client_id":   sprint(rp.config["clientId"]),
			"request_uri": requestURI,
		}, []string{"client_id", "request_uri"})
		return txn, nil
	}
	txn.URL = withQuery(sprint(rp.metadata["authorization_endpoint"]), params, order)
	return txn, nil
}

func trimFloat(v float64) string {
	text := strings.TrimRight(strings.TrimRight(sprintfFloat(v), "0"), ".")
	if text == "" || text == "-" {
		return "0"
	}
	return text
}

func sprintfFloat(v float64) string {
	return strings.TrimSpace(strings.ReplaceAll(jsonNumber(v), "+", ""))
}

func jsonNumber(v float64) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

// Complete exchanges the code from the redirect URI. A code is accepted once.
func (rp *RelyingParty) Complete(query map[string]string, txn *Transaction) (*Login, error) {
	if txn == nil {
		txn = &Transaction{}
	}
	for _, name := range frontChannel {
		if _, ok := query[name]; ok {
			return nil, fmtErr("validation", "%s was returned on the redirect, and a code-flow client refuses it", name)
		}
	}
	if query["error"] != "" {
		message := query["error"]
		if query["error_description"] != "" {
			message = query["error"] + ": " + query["error_description"]
		}
		return nil, errOAuth("protocol", message, query["error"])
	}
	state := query["state"]
	if txn.State == "" || !sameText(state, txn.State) {
		return nil, errCode("validation", "the callback state does not match this sign-in")
	}
	if iss, ok := query["iss"]; ok && iss != sprint(rp.metadata["issuer"]) {
		return nil, fmtErr("validation", "iss mismatch in the callback: %s", iss)
	}
	if _, ok := query["iss"]; !ok && isExactTrue(rp.metadata["authorization_response_iss_parameter_supported"]) {
		return nil, errCode("validation", "iss is missing from the callback, and the provider requires it")
	}
	code := query["code"]
	if code == "" {
		return nil, errCode("validation", "the callback has no code")
	}
	if err := rp.rememberCode(code); err != nil {
		return nil, err
	}
	tokens, err := rp.token(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  txn.RedirectURI,
		"code_verifier": txn.CodeVerifier,
	}, []string{"grant_type", "code", "redirect_uri", "code_verifier"})
	if err != nil {
		return nil, err
	}
	if tokens.IDToken == "" {
		return nil, errCode("protocol", "the token response has no id_token")
	}
	extra := tokenChecks{Nonce: &txn.Nonce, AccessToken: tokens.AccessToken, Code: code, MaxAge: txn.MaxAge}
	claims, err := rp.idToken(tokens.IDToken, extra)
	if err != nil {
		return nil, err
	}
	if txn.ExpectedSub != "" && sprint(claims["sub"]) != txn.ExpectedSub {
		return nil, errCode("validation", "the provider signed in a different account from the one requested")
	}
	if requested := strings.Fields(txn.ACRValues); len(requested) > 0 {
		acr, ok := claims["acr"].(string)
		if !ok || acr == "" {
			return nil, errCode("validation", "acr_values was requested, and the ID token has no acr")
		}
		if !containsString(requested, acr) {
			return nil, fmtErr("validation", "the ID token acr %s is not one of the requested acr_values (%s)", acr, strings.Join(requested, " "))
		}
	}
	return loginFrom(tokens, claims), nil
}

// Refresh performs the refresh-token grant. A new ID token's subject is checked against previous.
func (rp *RelyingParty) Refresh(refreshToken, scope string, previous *Login) (*Login, error) {
	if refreshToken == "" {
		return nil, errCode("protocol", "there is no refresh token")
	}
	body := map[string]string{"grant_type": "refresh_token", "refresh_token": refreshToken}
	order := []string{"grant_type", "refresh_token"}
	if scope != "" {
		body["scope"] = scope
		order = append(order, "scope")
	}
	tokens, err := rp.token(body, order)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	idToken := tokens.IDToken
	if previous != nil {
		claims = previous.Claims
		if idToken == "" {
			idToken = previous.IDToken
		}
	}
	if tokens.IDToken != "" {
		if previous == nil {
			return nil, errCode("validation", "the refresh returned an ID token and there is no previous sign-in to check it against")
		}
		sub := previous.Subject
		checked, err := rp.idToken(tokens.IDToken, tokenChecks{AccessToken: tokens.AccessToken, PreviousSub: &sub})
		if err != nil {
			return nil, err
		}
		claims = checked
		idToken = tokens.IDToken
	}
	if claims == nil || idToken == "" || (previous == nil && tokens.IDToken == "") {
		return nil, errCode("protocol", "the refresh returned no ID token and no previous sign-in was given")
	}
	if tokens.RefreshToken == "" {
		tokens.RefreshToken = refreshToken
	}
	tokens.IDToken = idToken
	return loginFrom(tokens, claims), nil
}

// ClientCredentials performs the client-credentials grant and caches the token until shortly before it expires.
func (rp *RelyingParty) ClientCredentials(scope string) (Access, error) {
	if scope == "" {
		scope = "ssf.manage"
	}
	now := nowSec()
	rp.mu.Lock()
	if rp.ccSet && rp.ccScope == scope && rp.ccUntil > now {
		token := rp.ccToken
		rp.mu.Unlock()
		return token, nil
	}
	rp.mu.Unlock()
	tokens, err := rp.token(map[string]string{"grant_type": "client_credentials", "scope": scope}, []string{"grant_type", "scope"})
	if err != nil {
		return Access{}, err
	}
	token := accessFrom(tokens)
	until := now + 60
	if token.HasExpires {
		until = token.ExpiresAt - 30
	}
	rp.mu.Lock()
	rp.ccScope = scope
	rp.ccToken = token
	rp.ccUntil = until
	rp.ccSet = true
	rp.mu.Unlock()
	return token, nil
}

// UserInfo calls UserInfo and checks that sub is expectedSub.
func (rp *RelyingParty) UserInfo(accessToken, expectedSub string) (map[string]any, error) {
	if expectedSub == "" {
		return nil, errCode("validation", "userinfo needs the subject to check the response against")
	}
	endpoint := sprint(rp.metadata["userinfo_endpoint"])
	if endpoint == "" {
		return nil, errCode("discovery", "the provider has no userinfo_endpoint")
	}
	tokenType := "Bearer"
	if rp.dpop != nil {
		tokenType = "DPoP"
	}
	answer, err := rp.resourceSend("GET", endpoint, accessToken, tokenType, map[string]string{
		"accept": "application/json, application/jwt",
	}, nil, rp.TLS(), "protocol")
	if err != nil {
		return nil, err
	}
	if answer.Status == 401 {
		return nil, errOAuth("protocol", "userinfo refused the access token", "invalid_token")
	}
	if answer.Status != 200 {
		return nil, fmtErr("protocol", "userinfo answered %d", answer.Status)
	}
	if strings.Contains(answer.ContentType, "application/jwt") {
		return rp.idToken(strings.TrimSpace(answer.Body), tokenChecks{Algorithms: rp.algs, NotIDToken: true})
	}
	body, err := decodeLoose([]byte(answer.Body))
	if err != nil {
		return nil, errCause("protocol", "userinfo did not answer JSON", err)
	}
	claims, ok := asMap(body)
	if !ok {
		return nil, errCode("validation", "userinfo did not answer a JSON object")
	}
	if sprint(claims["sub"]) != expectedSub {
		return nil, errCode("validation", "userinfo sub does not match the ID token sub")
	}
	return claims, nil
}

// EndSessionURL is the RP-Initiated Logout URL, or "" when the provider has no end-session endpoint.
func (rp *RelyingParty) EndSessionURL(opts EndSessionOptions) string {
	endpoint := sprint(rp.metadata["end_session_endpoint"])
	if endpoint == "" {
		return ""
	}
	redirect := ""
	if opts.PostLogout != nil {
		redirect = *opts.PostLogout
	} else {
		redirect = sprint(rp.config["postLogoutRedirectUri"])
	}
	query := map[string]string{}
	order := []string{}
	if opts.IDToken != "" {
		query["id_token_hint"] = opts.IDToken
		order = append(order, "id_token_hint")
	}
	if redirect != "" {
		query["post_logout_redirect_uri"] = redirect
		order = append(order, "post_logout_redirect_uri")
	}
	query["client_id"] = sprint(rp.config["clientId"])
	order = append(order, "client_id")
	if opts.LogoutHint != "" {
		query["logout_hint"] = opts.LogoutHint
		order = append(order, "logout_hint")
	}
	if opts.State != "" {
		query["state"] = opts.State
		order = append(order, "state")
	}
	return withQuery(endpoint, query, order)
}

func (rp *RelyingParty) idToken(token string, extra tokenChecks) (map[string]any, error) {
	checks := rp.checks(extra)
	claims, err := ValidateIDToken(token, checks)
	if err == nil {
		return claims, nil
	}
	oe, ok := err.(*OidcError)
	if !ok || oe.Code != "signature" {
		return nil, err
	}
	rp.mu.Lock()
	rp.jwksSet = false
	rp.mu.Unlock()
	keys, keyErr := rp.keys(true)
	if keyErr != nil {
		return nil, err
	}
	checks.JWKS = keys
	return ValidateIDToken(token, checks)
}

func (rp *RelyingParty) checks(extra tokenChecks) tokenChecks {
	checks := extra
	checks.Issuer = sprint(rp.metadata["issuer"])
	checks.ClientID = sprint(rp.config["clientId"])
	if extra.Algorithms != nil {
		checks.Algorithms = extra.Algorithms
	} else {
		checks.Algorithms = rp.algs
	}
	if tol, ok := asFloat(rp.config["clockToleranceSec"]); ok {
		checks.ClockToleranceSec = tol
	}
	if v, ok := rp.config["maxIdTokenAgeSec"]; ok && v != nil {
		if age, ok := asFloat(v); ok {
			checks.MaxIDTokenAgeSec = &age
		}
	}
	if secret := sprint(rp.config["clientSecret"]); secret != "" {
		checks.ClientSecret = secret
	}
	if !extra.NotIDToken && rp.config["requireIdTokenTypAndAtHash"] != false {
		checks.RequireTyp = true
		checks.RequireAtHash = true
	}
	keys, err := rp.keys(false)
	if err == nil {
		checks.JWKS = keys
	}
	return checks
}

func (rp *RelyingParty) keys(force bool) ([]map[string]any, error) {
	rp.mu.Lock()
	if !force && rp.jwksSet {
		keys := rp.jwks
		rp.mu.Unlock()
		return keys, nil
	}
	rp.mu.Unlock()
	fetched, err := FetchJWKS(sprint(rp.metadata["jwks_uri"]), rp.TLS())
	if err != nil {
		return nil, err
	}
	rp.mu.Lock()
	rp.jwks = fetched
	rp.jwksSet = true
	rp.mu.Unlock()
	return fetched, nil
}

func (rp *RelyingParty) token(body map[string]string, order []string) (tokenResponse, error) {
	parsed, proofed, err := rp.postForm(sprint(rp.metadata["token_endpoint"]), body, order)
	if err != nil {
		return tokenResponse{}, err
	}
	access, _ := parsed["access_token"].(string)
	tokenType, _ := parsed["token_type"].(string)
	if access == "" {
		return tokenResponse{}, errCode("protocol", "the token response has no access_token")
	}
	if tokenType == "" {
		return tokenResponse{}, errCode("protocol", "the token response has no token_type")
	}
	if proofed && !strings.EqualFold(tokenType, "DPoP") {
		return tokenResponse{}, fmtErr("protocol", "a DPoP proof was sent, and the token response token_type is %s, not DPoP", tokenType)
	}
	if !proofed && !strings.EqualFold(tokenType, "Bearer") {
		return tokenResponse{}, fmtErr("protocol", "no DPoP proof was sent, and the token response token_type is %s, not Bearer", tokenType)
	}
	out := tokenResponse{AccessToken: access, TokenType: tokenType}
	if text, ok := parsed["id_token"].(string); ok {
		out.IDToken = text
	}
	if text, ok := parsed["refresh_token"].(string); ok {
		out.RefreshToken = text
	}
	if n, ok := asFloat(parsed["expires_in"]); ok {
		out.ExpiresIn = &n
	}
	if text, ok := parsed["scope"].(string); ok {
		out.Scope = text
	}
	return out, nil
}

// postForm posts to the authorization server (PAR or token endpoint) with
// this client's authentication and, when DPoP is in use, a proof. A 400
// use_dpop_nonce is retried once with the nonce the response gave. proofed
// reports whether a proof was sent.
func (rp *RelyingParty) postForm(endpoint string, body map[string]string, order []string) (map[string]any, bool, error) {
	proofed := rp.dpop != nil
	for attempt := 0; ; attempt++ {
		headers := map[string]string{"accept": "application/json", "content-type": "application/x-www-form-urlencoded"}
		fields := map[string]string{}
		for k, v := range body {
			fields[k] = v
		}
		if err := ApplyClientAuth(rp.config, rp.key, fields, headers, sprint(rp.metadata["issuer"])); err != nil {
			return nil, proofed, err
		}
		sendOrder := append([]string(nil), order...)
		for k := range fields {
			if !containsString(sendOrder, k) {
				sendOrder = append(sendOrder, k)
			}
		}
		if proofed {
			proof, err := rp.dpop.proof("POST", endpoint, rp.nonceFor(endpoint), "")
			if err != nil {
				return nil, proofed, err
			}
			headers["dpop"] = proof
		}
		encoded := formBody(fields, sendOrder)
		answer, err := send(endpoint, "POST", headers, &encoded, rp.TLS(), "protocol")
		if err != nil {
			return nil, proofed, err
		}
		if proofed {
			rp.rememberNonce(endpoint, answer.Header)
		}
		parsed, jerr := decodeLoose([]byte(answer.Body))
		if answer.Body != "" && jerr != nil {
			return nil, proofed, errCause("protocol", endpoint+" answered "+itoa(answer.Status)+" with no JSON", jerr)
		}
		doc, _ := asMap(parsed)
		if doc == nil {
			doc = map[string]any{}
		}
		if answer.Status == 200 || answer.Status == 201 {
			return doc, proofed, nil
		}
		oauth := ""
		if text, ok := doc["error"].(string); ok {
			oauth = text
		}
		if proofed && attempt == 0 && answer.Status == 400 && oauth == "use_dpop_nonce" && answer.Header.Get("DPoP-Nonce") != "" {
			continue
		}
		description := ""
		if text, ok := doc["error_description"].(string); ok {
			description = text
		}
		message := endpoint + " answered " + itoa(answer.Status)
		if oauth != "" {
			message += ": " + oauth
		}
		if description != "" {
			message += ": " + description
		}
		return nil, proofed, errOAuth("protocol", message, oauth)
	}
}

func (rp *RelyingParty) rememberCode(code string) error {
	now := nowSec()
	digest := sha256.Sum256([]byte(code))
	key := hex.EncodeToString(digest[:])
	rp.mu.Lock()
	defer rp.mu.Unlock()
	cutoff := now - 10*60
	for digest, at := range rp.usedCodes {
		if at < cutoff {
			delete(rp.usedCodes, digest)
		}
	}
	if _, ok := rp.usedCodes[key]; ok {
		return errCode("validation", "this authorization code was already used")
	}
	rp.usedCodes[key] = now
	return nil
}

func loginFrom(tokens tokenResponse, claims map[string]any) *Login {
	login := &Login{
		Subject:     sprint(claims["sub"]),
		Issuer:      sprint(claims["iss"]),
		Claims:      claims,
		AccessToken: tokens.AccessToken,
		IDToken:     tokens.IDToken,
		TokenType:   tokens.TokenType,
	}
	if text, ok := claimString(claims, "email"); ok {
		login.Email = text
	}
	if text, ok := claimString(claims, "name"); ok {
		login.Name = text
	}
	if text, ok := claimString(claims, "preferred_username"); ok {
		login.PreferredUsername = text
	}
	if text, ok := claimString(claims, "sid"); ok {
		login.SID = text
	}
	if tokens.RefreshToken != "" {
		login.RefreshToken = tokens.RefreshToken
	}
	if tokens.ExpiresIn != nil {
		login.ExpiresAt = nowSec() + *tokens.ExpiresIn
		login.HasExpires = true
	}
	if tokens.Scope != "" {
		login.Scope = tokens.Scope
	}
	return login
}

func claimString(claims map[string]any, name string) (string, bool) {
	text, ok := claims[name].(string)
	if !ok || text == "" {
		return "", false
	}
	return text, true
}

func accessFrom(tokens tokenResponse) Access {
	out := Access{AccessToken: tokens.AccessToken, TokenType: tokens.TokenType, Scope: tokens.Scope}
	if tokens.ExpiresIn != nil {
		out.ExpiresAt = nowSec() + *tokens.ExpiresIn
		out.HasExpires = true
	}
	return out
}

func nowSec() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func withQuery(base string, params map[string]string, order []string) string {
	parts, err := url.Parse(base)
	if err != nil {
		return base
	}
	if parts.Path == "" {
		parts.Path = "/"
	}
	parts.RawQuery = formBody(params, order)
	parts.Fragment = ""
	return parts.String()
}

func itoa(n int) string {
	return jsonNumber(float64(n))
}
