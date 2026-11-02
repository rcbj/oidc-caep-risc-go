// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"strings"
	"time"
)

var notIDToken = map[string]bool{
	"at+jwt": true, "application/at+jwt": true, "logout+jwt": true, "secevent+jwt": true,
	"dpop+jwt": true, "token-introspection+jwt": true, "software-statement+jwt": true, "jwt-bearer": true,
}

func sameText(left, right string) bool {
	a := []byte(left)
	b := []byte(right)
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal(a, b)
}

// HashClaim is the left half of the digest the algorithm names, base64url, no padding.
func HashClaim(value, alg string) string {
	var sum []byte
	switch {
	case alg == "EdDSA" || alg == "Ed25519":
		full := sha512.Sum512([]byte(value))
		sum = full[:]
	case strings.Contains(alg, "384"):
		full := sha512.Sum384([]byte(value))
		sum = full[:]
	case strings.Contains(alg, "512"):
		full := sha512.Sum512([]byte(value))
		sum = full[:]
	default:
		full := sha256.Sum256([]byte(value))
		sum = full[:]
	}
	return B64URLEncode(sum[:len(sum)/2])
}

type tokenChecks struct {
	Issuer            string
	ClientID          string
	Algorithms        []string
	JWKS              []map[string]any
	ClockToleranceSec float64
	MaxIDTokenAgeSec  *float64
	ClientSecret      string
	Nonce             *string
	AccessToken       string
	Code              string
	PreviousSub       *string
	MaxAge            *float64
}

func decodePart(token string, index int, what string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errCode("signature", "the ID token is not a compact JWS: not a compact JWS")
	}
	raw, err := B64URLDecode(parts[index], what)
	if err != nil {
		return nil, errCause("signature", "the ID token is not a compact JWS: "+err.Error(), err)
	}
	parsed, err := decodeLoose(raw)
	if err != nil {
		return nil, errCause("signature", "the ID token is not a compact JWS: "+err.Error(), err)
	}
	doc, ok := asMap(parsed)
	if !ok {
		return nil, errCode("signature", "the ID token is not a compact JWS: not a JSON object")
	}
	return doc, nil
}

func candidates(jwks []map[string]any, alg, kid string) []map[string]any {
	spec, ok := algSpecs[alg]
	if !ok {
		return nil
	}
	var found []map[string]any
	for _, jwk := range jwks {
		if kid != "" && sprint(jwk["kid"]) != kid {
			continue
		}
		if sprint(jwk["kty"]) != spec.kty {
			continue
		}
		if use, ok := jwk["use"]; ok && use != nil && sprint(use) != "" && sprint(use) != "sig" {
			continue
		}
		if named, ok := jwk["alg"]; ok && named != nil && sprint(named) != "" && sprint(named) != alg {
			continue
		}
		found = append(found, jwk)
	}
	return found
}

func signatureOK(token, alg string, jwks []map[string]any, secret string) (bool, error) {
	parts := strings.Split(token, ".")
	signing := []byte(parts[0] + "." + parts[1])
	sig, err := B64URLDecode(parts[2], "signature")
	if err != nil {
		return false, errCause("signature", "the ID token is not a compact JWS: "+err.Error(), err)
	}
	if strings.HasPrefix(alg, "HS") {
		return VerifySignature([]byte(secret), alg, signing, sig), nil
	}
	header, err := decodePart(token, 0, "header")
	if err != nil {
		return false, err
	}
	kid := ""
	if text, ok := header["kid"].(string); ok {
		kid = text
	}
	keys := candidates(jwks, alg, kid)
	if len(keys) == 0 {
		return false, errCode("signature", "signature verification failed: no applicable key")
	}
	for _, jwk := range keys {
		key, keyErr := PublicKeyFromJWK(jwk)
		if keyErr != nil {
			continue
		}
		if VerifySignature(key, alg, signing, sig) {
			return true, nil
		}
	}
	return false, nil
}

func checkHash(claim any, value, alg, name string) error {
	if claim == nil {
		return nil
	}
	text, ok := claim.(string)
	if !ok || !sameText(text, HashClaim(value, alg)) {
		return fmtErr("validation", "the ID token's %s does not match", name)
	}
	return nil
}

// ValidateIDToken verifies an ID token and returns its payload.
func ValidateIDToken(token string, checks tokenChecks) (map[string]any, error) {
	header, err := decodePart(token, 0, "header")
	if err != nil {
		return nil, err
	}
	alg := sprint(header["alg"])
	if !containsString(checks.Algorithms, alg) {
		shown := alg
		if shown == "" {
			shown = "(no alg)"
		}
		return nil, fmtErr("signature", "the ID token is signed with %s, which this client does not accept", shown)
	}
	if crit, ok := header["crit"]; ok && crit != nil {
		return nil, errCode("validation", "the ID token has a crit header this client does not understand")
	}
	typ := ""
	if header["typ"] != nil {
		typ = strings.ToLower(sprint(header["typ"]))
	}
	if typ != "" && ((typ != "jwt" && typ != "application/jwt") || notIDToken[typ]) {
		return nil, fmtErr("validation", "the ID token typ is %v, not an ID token", header["typ"])
	}
	if strings.HasPrefix(alg, "HS") && checks.ClientSecret == "" {
		return nil, fmtErr("config", "%s ID tokens need the client secret", alg)
	}
	payload, err := decodePart(token, 1, "payload")
	if err != nil {
		return nil, err
	}
	ok, err := signatureOK(token, alg, checks.JWKS, checks.ClientSecret)
	if err != nil {
		if _, is := err.(*OidcError); is {
			return nil, err
		}
		return nil, errCause("signature", "the ID token was refused: signature: "+err.Error(), err)
	}
	if !ok {
		return nil, errCode("signature", "the ID token was refused: signature verification failed")
	}
	if payload["iss"] != checks.Issuer {
		return nil, errCode("validation", "the ID token was refused: issuer mismatch")
	}
	aud := payload["aud"]
	var audiences []string
	if list, ok := aud.([]any); ok {
		for _, item := range list {
			audiences = append(audiences, sprint(item))
		}
	} else if aud == nil {
		audiences = []string{""}
	} else {
		audiences = []string{sprint(aud)}
	}
	if !containsString(audiences, checks.ClientID) {
		return nil, errCode("validation", "the ID token audience does not include this client")
	}
	now := float64(time.Now().UnixNano()) / 1e9
	tolerance := checks.ClockToleranceSec
	exp, expOK := asFloat(payload["exp"])
	if !expOK {
		return nil, errCode("validation", "the ID token was refused: exp is missing")
	}
	if exp+tolerance < now {
		return nil, errCode("validation", "the ID token was refused: exp expired")
	}
	if nbf, ok := asFloat(payload["nbf"]); ok && nbf-tolerance > now {
		return nil, errCode("validation", "the ID token was refused: nbf is in the future")
	}
	if checks.MaxIDTokenAgeSec != nil {
		iat, iatOK := asFloat(payload["iat"])
		if !iatOK {
			return nil, errCode("validation", "the ID token was refused: iat is missing")
		}
		if (now-iat)-tolerance > *checks.MaxIDTokenAgeSec {
			return nil, errCode("validation", "the ID token was refused: iat is too old")
		}
	}
	sub, subOK := payload["sub"].(string)
	if !subOK || sub == "" {
		return nil, errCode("validation", "the ID token has no sub")
	}
	if len(audiences) > 1 && payload["azp"] != checks.ClientID {
		return nil, errCode("validation", "an ID token with several audiences must name this client as azp")
	}
	if azp, present := payload["azp"]; present && azp != nil && azp != checks.ClientID {
		return nil, fmtErr("validation", "the ID token azp is %v, not %s", azp, checks.ClientID)
	}
	if checks.Nonce != nil {
		nonce, nonceOK := payload["nonce"].(string)
		if !nonceOK || !sameText(nonce, *checks.Nonce) {
			return nil, errCode("validation", "the ID token nonce does not match this sign-in")
		}
	}
	if checks.PreviousSub != nil && payload["sub"] != *checks.PreviousSub {
		return nil, errCode("validation", "the refreshed ID token is for a different subject")
	}
	if checks.AccessToken != "" {
		if err := checkHash(payload["at_hash"], checks.AccessToken, alg, "at_hash"); err != nil {
			return nil, err
		}
	}
	if checks.Code != "" {
		if err := checkHash(payload["c_hash"], checks.Code, alg, "c_hash"); err != nil {
			return nil, err
		}
	}
	if checks.MaxAge != nil {
		authTime, ok := asFloat(payload["auth_time"])
		if !ok {
			return nil, errCode("validation", "max_age was requested and the ID token has no auth_time")
		}
		if authTime < float64(time.Now().Unix())-*checks.MaxAge-tolerance {
			return nil, errCode("validation", "the ID token auth_time is older than max_age")
		}
	}
	return payload, nil
}

func FetchJWKS(jwksURI string, tlsOpt map[string]string) ([]map[string]any, error) {
	answer, err := send(jwksURI, "GET", map[string]string{"accept": "application/json"}, nil, tlsOpt, "discovery")
	if err != nil {
		return nil, err
	}
	if answer.Status != 200 {
		return nil, fmtErr("discovery", "the JWKS at %s answered %d", jwksURI, answer.Status)
	}
	body, err := decodeLoose([]byte(answer.Body))
	if err != nil {
		return nil, errCause("discovery", "the JWKS at "+jwksURI+" is not JSON", err)
	}
	doc, ok := asMap(body)
	keysRaw, keysOK := doc["keys"]
	list, listOK := keysRaw.([]any)
	if !ok || !keysOK || !listOK {
		return nil, fmtErr("discovery", "the JWKS at %s has no keys", jwksURI)
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		key, ok := asMap(item)
		if !ok {
			return nil, fmtErr("discovery", "the JWKS at %s has no keys", jwksURI)
		}
		out = append(out, key)
	}
	return out, nil
}
