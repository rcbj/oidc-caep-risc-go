// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func formEncode(value string) string {
	var b strings.Builder
	for _, c := range []byte(value) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-_.!~*'()", rune(c)) {
			b.WriteByte(c)
			continue
		}
		if c == ' ' {
			b.WriteByte('+')
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func formBody(fields map[string]string, order []string) string {
	values := url.Values{}
	if order == nil {
		for k, v := range fields {
			values.Set(k, v)
		}
		return values.Encode()
	}
	var b strings.Builder
	first := true
	seen := map[string]bool{}
	write := func(k, v string) {
		if first {
			first = false
		} else {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(k))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(v))
		seen[k] = true
	}
	for _, k := range order {
		if v, ok := fields[k]; ok {
			write(k, v)
		}
	}
	for k, v := range fields {
		if !seen[k] {
			write(k, v)
		}
	}
	return b.String()
}

func uuid4() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

func compactJWS(header, payload any, key any, alg string) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signing := B64URLEncode(hb) + "." + B64URLEncode(pb)
	sig, err := SignJWS(key, alg, []byte(signing))
	if err != nil {
		return "", err
	}
	return signing + "." + B64URLEncode(sig), nil
}

// ApplyClientAuth adds this client's authentication. A client assertion's audience is the issuer.
func ApplyClientAuth(config map[string]any, key any, body map[string]string, headers map[string]string, audience string) error {
	method := sprint(config["tokenEndpointAuthMethod"])
	clientID := sprint(config["clientId"])
	switch method {
	case "client_secret_basic":
		raw := formEncode(clientID) + ":" + formEncode(sprint(config["clientSecret"]))
		headers["authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
		return nil
	case "client_secret_post":
		body["client_id"] = clientID
		body["client_secret"] = sprint(config["clientSecret"])
		return nil
	default:
		if key == nil {
			return errCode("config", "private_key_jwt has no signing key")
		}
		alg := sprint(config["privateKeyAlg"])
		if alg == "" {
			alg = "RS256"
		}
		now := time.Now().Unix()
		header := struct {
			Alg string `json:"alg"`
			Typ string `json:"typ"`
		}{Alg: alg, Typ: "JWT"}
		claims := struct {
			Iss string `json:"iss"`
			Sub string `json:"sub"`
			Aud string `json:"aud"`
			Jti string `json:"jti"`
			Iat int64  `json:"iat"`
			Exp int64  `json:"exp"`
		}{Iss: clientID, Sub: clientID, Aud: audience, Jti: uuid4(), Iat: now, Exp: now + 60}
		assertion, err := compactJWS(header, claims, key, alg)
		if err != nil {
			return err
		}
		body["client_id"] = clientID
		body["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		body["client_assertion"] = assertion
		return nil
	}
}
