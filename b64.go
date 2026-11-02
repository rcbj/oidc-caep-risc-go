// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func B64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func B64URLDecode(value, what string) ([]byte, error) {
	if strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return nil, fmt.Errorf("%s is not base64url", what)
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not base64url", what)
	}
	return raw, nil
}
