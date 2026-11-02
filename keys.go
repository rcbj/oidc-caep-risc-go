// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"math/big"
)

type algSpec struct {
	kty  string
	hash string
	mode string
}

var algSpecs = map[string]algSpec{
	"RS256":   {"RSA", "sha256", "pkcs1"},
	"RS384":   {"RSA", "sha384", "pkcs1"},
	"RS512":   {"RSA", "sha512", "pkcs1"},
	"PS256":   {"RSA", "sha256", "pss"},
	"PS384":   {"RSA", "sha384", "pss"},
	"PS512":   {"RSA", "sha512", "pss"},
	"ES256":   {"EC", "sha256", "p1363"},
	"ES384":   {"EC", "sha384", "p1363"},
	"ES512":   {"EC", "sha512", "p1363"},
	"EdDSA":   {"OKP", "", "eddsa"},
	"Ed25519": {"OKP", "", "eddsa"},
	"HS256":   {"oct", "sha256", "hmac"},
	"HS384":   {"oct", "sha384", "hmac"},
	"HS512":   {"oct", "sha512", "hmac"},
}

// AsymmetricJWSAlgs are the asymmetric JWS algorithms this client verifies.
// HMAC algorithms are accepted only when an ID token names one explicitly.
var AsymmetricJWSAlgs = []string{
	"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519",
}

// SupportedJWSAlgs are the algorithms a Security Event Token may use.
var SupportedJWSAlgs = []string{
	"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "Ed25519",
}

func hashOf(name string) (crypto.Hash, func() hash.Hash) {
	switch name {
	case "sha384":
		return crypto.SHA384, sha512.New384
	case "sha512":
		return crypto.SHA512, sha512.New
	default:
		return crypto.SHA256, sha256.New
	}
}

func digest(name string, data []byte) []byte {
	_, fn := hashOf(name)
	h := fn()
	h.Write(data)
	return h.Sum(nil)
}

func curveOf(alg string) elliptic.Curve {
	switch alg {
	case "ES384":
		return elliptic.P384()
	case "ES512":
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}

func curveSize(curve elliptic.Curve) int {
	switch curve {
	case elliptic.P384():
		return 48
	case elliptic.P521():
		return 66
	default:
		return 32
	}
}

func algForCurve(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "ES256"
	case elliptic.P384():
		return "ES384"
	case elliptic.P521():
		return "ES512"
	default:
		return ""
	}
}

func LoadPrivateKey(pemText, alg string) (any, error) {
	spec, ok := algSpecs[alg]
	if !ok || spec.mode == "hmac" {
		return nil, fmtErr("config", "the private key could not be read as %s: unsupported algorithm", alg)
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmtErr("config", "the private key could not be read as %s: not a PEM key", alg)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if pkcs1, pkcsErr := x509.ParsePKCS1PrivateKey(block.Bytes); pkcsErr == nil {
			key = pkcs1
			err = nil
		} else if ec, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			key = ec
			err = nil
		}
	}
	if err != nil {
		return nil, errCause("config", "the private key could not be read as "+alg+": "+err.Error(), err)
	}
	switch spec.kty {
	case "RSA":
		if _, ok := key.(*rsa.PrivateKey); ok {
			return key, nil
		}
	case "EC":
		if ec, ok := key.(*ecdsa.PrivateKey); ok && algForCurve(ec.Curve) == alg {
			return key, nil
		}
	case "OKP":
		if _, ok := key.(ed25519.PrivateKey); ok {
			return key, nil
		}
	}
	return nil, fmtErr("config", "the private key could not be read as %s: key type does not match %s", alg, alg)
}

func SignJWS(key any, alg string, input []byte) ([]byte, error) {
	spec, ok := algSpecs[alg]
	if !ok {
		return nil, fmtErr("protocol", "the client assertion could not be signed: unsupported algorithm")
	}
	sig, err := signRaw(key, spec, input)
	if err != nil {
		return nil, errCause("protocol", "the client assertion could not be signed: "+err.Error(), err)
	}
	return sig, nil
}

func signRaw(key any, spec algSpec, input []byte) ([]byte, error) {
	switch spec.mode {
	case "hmac":
		secret, ok := key.([]byte)
		if !ok {
			return nil, errCode("protocol", "hmac key is not bytes")
		}
		_, fn := hashOf(spec.hash)
		mac := hmac.New(fn, secret)
		mac.Write(input)
		return mac.Sum(nil), nil
	case "pkcs1", "pss":
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errCode("protocol", "not an RSA key")
		}
		ch, _ := hashOf(spec.hash)
		sum := digest(spec.hash, input)
		if spec.mode == "pkcs1" {
			return rsa.SignPKCS1v15(rand.Reader, priv, ch, sum)
		}
		return rsa.SignPSS(rand.Reader, priv, ch, sum, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: ch})
	case "p1363":
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errCode("protocol", "not an EC key")
		}
		sum := digest(spec.hash, input)
		r, s, err := ecdsa.Sign(rand.Reader, priv, sum)
		if err != nil {
			return nil, err
		}
		size := curveSize(priv.Curve)
		return concatRS(r, s, size), nil
	case "eddsa":
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errCode("protocol", "not an Ed25519 key")
		}
		return ed25519.Sign(priv, input), nil
	default:
		return nil, errCode("protocol", "unsupported algorithm")
	}
}

func concatRS(r, s *big.Int, size int) []byte {
	out := make([]byte, size*2)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[size-len(rb):size], rb)
	copy(out[2*size-len(sb):], sb)
	return out
}

// VerifySignature reports whether signature matches. A malformed signature is a miss.
func VerifySignature(key any, alg string, input, signature []byte) bool {
	spec, ok := algSpecs[alg]
	if !ok || key == nil {
		return false
	}
	switch spec.mode {
	case "hmac":
		secret, ok := key.([]byte)
		if !ok {
			return false
		}
		_, fn := hashOf(spec.hash)
		mac := hmac.New(fn, secret)
		mac.Write(input)
		return hmac.Equal(mac.Sum(nil), signature)
	case "pkcs1", "pss":
		pub, ok := rsaPublic(key)
		if !ok {
			return false
		}
		ch, _ := hashOf(spec.hash)
		sum := digest(spec.hash, input)
		if spec.mode == "pkcs1" {
			return rsa.VerifyPKCS1v15(pub, ch, sum, signature) == nil
		}
		return rsa.VerifyPSS(pub, ch, sum, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: ch}) == nil
	case "p1363":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		size := curveSize(pub.Curve)
		if len(signature) != size*2 {
			return false
		}
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		sum := digest(spec.hash, input)
		return ecdsa.Verify(pub, sum, r, s)
	case "eddsa":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(pub, input, signature)
	default:
		return false
	}
}

func rsaPublic(key any) (*rsa.PublicKey, bool) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k, true
	case *rsa.PrivateKey:
		return &k.PublicKey, true
	default:
		return nil, false
	}
}

func PublicKeyFromJWK(jwk map[string]any) (any, error) {
	kty := sprint(jwk["kty"])
	key, err := publicFromJWK(jwk, kty)
	if err != nil {
		if _, ok := err.(*OidcError); ok {
			return nil, err
		}
		kid := sprint(jwk["kid"])
		return nil, errCause("signature", "the transmitter's key "+kid+" cannot be read: "+err.Error(), err)
	}
	if key == nil {
		return nil, fmtErr("signature", "the key type %s cannot be read", kty)
	}
	return key, nil
}

func publicFromJWK(jwk map[string]any, kty string) (any, error) {
	switch kty {
	case "RSA":
		nRaw, nOK := asString(jwk["n"])
		eRaw, eOK := asString(jwk["e"])
		if !nOK || !eOK {
			return nil, errCode("signature", "missing modulus")
		}
		nb, err := B64URLDecode(nRaw, "n")
		if err != nil {
			return nil, err
		}
		eb, err := B64URLDecode(eRaw, "e")
		if err != nil {
			return nil, err
		}
		e := new(big.Int).SetBytes(eb)
		if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > int64(^uint(0)>>1) {
			return nil, errCode("signature", "bad exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
	case "EC":
		crv := sprint(jwk["crv"])
		var curve elliptic.Curve
		var size int
		switch crv {
		case "P-256":
			curve, size = elliptic.P256(), 32
		case "P-384":
			curve, size = elliptic.P384(), 48
		case "P-521":
			curve, size = elliptic.P521(), 66
		default:
			return nil, errCode("signature", "unknown curve")
		}
		xb, err := B64URLDecode(sprint(jwk["x"]), "x")
		if err != nil {
			return nil, err
		}
		yb, err := B64URLDecode(sprint(jwk["y"]), "y")
		if err != nil {
			return nil, err
		}
		if len(xb) != size || len(yb) != size {
			return nil, errCode("signature", "EC coordinate length")
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}, nil
	case "OKP":
		crv, has := jwk["crv"]
		if has && crv != nil && sprint(crv) != "Ed25519" {
			return nil, errCode("signature", sprint(crv))
		}
		xb, err := B64URLDecode(sprint(jwk["x"]), "x")
		if err != nil {
			return nil, err
		}
		if len(xb) != ed25519.PublicKeySize {
			return nil, errCode("signature", "Ed25519 length")
		}
		return ed25519.PublicKey(append([]byte(nil), xb...)), nil
	default:
		return nil, nil
	}
}
