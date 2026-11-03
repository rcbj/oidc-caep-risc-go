// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dpopKey is the relying party's DPoP (RFC 9449) key: ES256 on P-256. It is
// generated when the client is created and held in memory only, unless the
// configuration names one (dpopKey) so several processes share it.
type dpopKey struct {
	private *ecdsa.PrivateKey
	jwk     map[string]string
	jkt     string
}

func newDPoPKey(pemText string) (*dpopKey, error) {
	var private *ecdsa.PrivateKey
	if pemText != "" {
		if !strings.Contains(pemText, "-----BEGIN") {
			return nil, errCode("config", "dpopKey must be a PEM private key (or file:, env:, or a path in a configuration file)")
		}
		loaded, err := LoadPrivateKey(pemText, "ES256")
		if err != nil {
			return nil, errCause("config", "dpopKey must be an ES256 (P-256) private key: "+err.Error(), err)
		}
		private = loaded.(*ecdsa.PrivateKey)
	} else {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, errCause("config", "the DPoP key could not be generated: "+err.Error(), err)
		}
		private = generated
	}
	public, err := private.PublicKey.ECDH()
	if err != nil {
		return nil, errCause("config", "the DPoP key is not a P-256 key: "+err.Error(), err)
	}
	point := public.Bytes()
	if len(point) != 65 {
		return nil, errCode("config", "the DPoP key is not a P-256 key")
	}
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   B64URLEncode(point[1:33]),
		"y":   B64URLEncode(point[33:]),
	}
	// RFC 7638: the required members in lexicographic order, no whitespace.
	canonical := `{"crv":"P-256","kty":"EC","x":"` + jwk["x"] + `","y":"` + jwk["y"] + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return &dpopKey{private: private, jwk: jwk, jkt: B64URLEncode(sum[:])}, nil
}

// HTU is the htu of a proof: the request URL without its query and fragment.
func HTU(rawURL string) string {
	parts, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := parts.EscapedPath()
	if path == "" {
		path = "/"
	}
	return strings.ToLower(parts.Scheme) + "://" + strings.ToLower(parts.Host) + path
}

func originOf(rawURL string) string {
	parts, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return strings.ToLower(parts.Scheme) + "://" + strings.ToLower(parts.Host)
}

// proof is a DPoP proof for one request. accessToken adds ath (a resource request).
func (k *dpopKey) proof(method, rawURL, nonce, accessToken string) (string, error) {
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": k.jwk}
	claims := map[string]any{
		"jti": uuid4(),
		"htm": strings.ToUpper(method),
		"htu": HTU(rawURL),
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = B64URLEncode(sum[:])
	}
	return compactJWS(header, claims, k.private, "ES256")
}

// nonceFor is the latest DPoP-Nonce the server at rawURL's origin gave.
func (rp *RelyingParty) nonceFor(rawURL string) string {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return rp.nonces[originOf(rawURL)]
}

// rememberNonce keeps the DPoP-Nonce a response carried, per server origin.
func (rp *RelyingParty) rememberNonce(rawURL string, header http.Header) {
	if header == nil {
		return
	}
	nonce := strings.TrimSpace(header.Get("DPoP-Nonce"))
	if nonce == "" {
		return
	}
	rp.mu.Lock()
	rp.nonces[originOf(rawURL)] = nonce
	rp.mu.Unlock()
}

// asksForDPoPNonce is a resource server's 401 with
// WWW-Authenticate: DPoP error="use_dpop_nonce".
func asksForDPoPNonce(header http.Header) bool {
	for _, value := range header.Values("WWW-Authenticate") {
		lowered := strings.ToLower(value)
		if strings.HasPrefix(strings.TrimSpace(lowered), "dpop") && strings.Contains(lowered, `error="use_dpop_nonce"`) {
			return true
		}
	}
	return false
}

// DPoPEnabled reports whether this client sends DPoP proofs.
func (rp *RelyingParty) DPoPEnabled() bool { return rp.dpop != nil }

// DPoPThumbprint is the RFC 7638 thumbprint of the DPoP key (dpop_jkt), or "".
func (rp *RelyingParty) DPoPThumbprint() string {
	if rp.dpop == nil {
		return ""
	}
	return rp.dpop.jkt
}

// ResourceRequest calls a protected resource with an access token. A token
// whose type is DPoP is sent as "DPoP <token>" with a proof carrying ath, and
// a 401 asking for a DPoP nonce is retried once with the nonce the response
// gave. Any other token is sent as a Bearer token.
func (rp *RelyingParty) ResourceRequest(method, rawURL, accessToken, tokenType string, headers map[string]string, body *string) (status int, contentType string, responseBody string, err error) {
	answer, err := rp.resourceSend(method, rawURL, accessToken, tokenType, headers, body, rp.TLS(), "protocol")
	if err != nil {
		return 0, "", "", err
	}
	return answer.Status, answer.ContentType, answer.Body, nil
}

func (rp *RelyingParty) resourceSend(method, rawURL, accessToken, tokenType string, headers map[string]string, body *string, tlsOpt map[string]string, code string) (httpAnswer, error) {
	bound := strings.EqualFold(tokenType, "DPoP")
	if bound && rp.dpop == nil {
		return httpAnswer{}, errCode(code, "the access token is DPoP-bound, and this client has no DPoP key")
	}
	for attempt := 0; ; attempt++ {
		sent := map[string]string{}
		for k, v := range headers {
			sent[k] = v
		}
		if bound {
			proof, err := rp.dpop.proof(method, rawURL, rp.nonceFor(rawURL), accessToken)
			if err != nil {
				return httpAnswer{}, err
			}
			sent["authorization"] = "DPoP " + accessToken
			sent["dpop"] = proof
		} else {
			sent["authorization"] = "Bearer " + accessToken
		}
		answer, err := send(rawURL, method, sent, body, tlsOpt, code)
		if err != nil {
			return httpAnswer{}, err
		}
		if bound {
			rp.rememberNonce(rawURL, answer.Header)
			if attempt == 0 && answer.Status == 401 && asksForDPoPNonce(answer.Header) && answer.Header.Get("DPoP-Nonce") != "" {
				continue
			}
		}
		return answer, nil
	}
}
