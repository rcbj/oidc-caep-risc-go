// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto/rand"
	"crypto/sha256"
)

// RandomToken is 32 random bytes, base64url. A PKCE verifier and a state or nonce.
func RandomToken() (string, error) {
	return randomTokenN(32)
}

func randomTokenN(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return B64URLEncode(buf), nil
}

// CodeChallengeS256 is RFC 7636 S256: base64url(SHA-256(verifier)), with no padding.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return B64URLEncode(sum[:])
}
