// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import "fmt"

// OidcError is every failure this module reports.
// Code is config, discovery, protocol, validation, signature, session, or ssf.
// OAuthError is the OAuth error code when the provider named one.
type OidcError struct {
	Code       string
	Message    string
	OAuthError string
	Cause      error
}

func (e *OidcError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *OidcError) Unwrap() error { return e.Cause }

func errCode(code, message string) *OidcError {
	return &OidcError{Code: code, Message: message}
}

func errCause(code, message string, cause error) *OidcError {
	return &OidcError{Code: code, Message: message, Cause: cause}
}

func errOAuth(code, message, oauth string) *OidcError {
	return &OidcError{Code: code, Message: message, OAuthError: oauth}
}

func fmtErr(code, format string, args ...any) *OidcError {
	return errCode(code, fmt.Sprintf(format, args...))
}
