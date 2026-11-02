// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import "strings"

// VerifyCompactJWS verifies a compact JWS against the keys of a JWKS and returns its header and payload.
// The key comes from the JWKS, never from the token.
func VerifyCompactJWS(token string, keys []map[string]any) (map[string]any, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, errCode("signature", "the SET is not a compact JWS")
	}
	headerRaw, err := B64URLDecode(parts[0], "header")
	if err != nil {
		return nil, nil, errCause("signature", "the SET's header is not base64url", err)
	}
	payloadRaw, err := B64URLDecode(parts[1], "payload")
	if err != nil {
		return nil, nil, errCause("signature", "the SET's payload is not base64url", err)
	}
	headerVal, err := decodeLoose(headerRaw)
	if err != nil {
		return nil, nil, errCause("signature", "the SET's header or payload is not JSON", err)
	}
	payloadVal, err := decodeLoose(payloadRaw)
	if err != nil {
		return nil, nil, errCause("signature", "the SET's header or payload is not JSON", err)
	}
	header, ok := asMap(headerVal)
	payload, ok2 := asMap(payloadVal)
	if !ok || !ok2 {
		return nil, nil, errCode("signature", "the SET's header or payload is not a JSON object")
	}
	alg := sprint(header["alg"])
	spec, known := algSpecs[alg]
	if !known || spec.mode == "hmac" {
		shown := alg
		if shown == "" {
			shown = "(no alg)"
		}
		return nil, nil, fmtErr("signature", "the SET is signed with %s, which this receiver does not verify (%s)", shown, strings.Join(SupportedJWSAlgs, ", "))
	}
	if crit, present := header["crit"]; present && crit != nil {
		return nil, nil, errCode("signature", "the SET's header has a crit member this receiver does not understand")
	}
	kid := ""
	if text, is := header["kid"].(string); is {
		kid = text
	}
	var matched []map[string]any
	for _, jwk := range keys {
		if kid != "" && sprint(jwk["kid"]) != kid {
			continue
		}
		if sprint(jwk["kty"]) != spec.kty {
			continue
		}
		if use, has := jwk["use"]; has && use != nil && sprint(use) != "" && sprint(use) != "sig" {
			continue
		}
		if named, has := jwk["alg"]; has && named != nil && sprint(named) != "" && sprint(named) != alg {
			continue
		}
		matched = append(matched, jwk)
	}
	if len(matched) == 0 {
		suffix := ""
		if kid != "" {
			suffix = " with kid " + kid
		}
		return nil, nil, fmtErr("signature", "the transmitter publishes no %s signing key%s", spec.kty, suffix)
	}
	signature, err := B64URLDecode(parts[2], "signature")
	if err != nil {
		return nil, nil, errCause("signature", "the SET's signature is not base64url", err)
	}
	data := []byte(parts[0] + "." + parts[1])
	for _, jwk := range matched {
		key, keyErr := PublicKeyFromJWK(jwk)
		if keyErr != nil {
			return nil, nil, keyErr
		}
		if VerifySignature(key, alg, data, signature) {
			return header, payload, nil
		}
	}
	return nil, nil, errCode("signature", "the SET's signature does not verify against the transmitter's keys")
}
