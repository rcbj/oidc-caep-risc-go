// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"encoding/json"
	"net/url"
	"strings"
)

// DefaultScopes are the scopes RelyingParty asks for unless the configuration names others.
const DefaultScopes = "openid profile email offline_access ssf.read ssf.manage"

var requiredMetadata = []string{
	"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
	"response_types_supported", "subject_types_supported", "id_token_signing_alg_values_supported",
}

func IssuerFromMetadataURL(metadataURL string) (string, error) {
	parts, err := url.Parse(metadataURL)
	if err != nil || (parts.Scheme != "http" && parts.Scheme != "https") || parts.Host == "" {
		return "", fmtErr("config", "metadataUrl is not a URL: %s", metadataURL)
	}
	const marker = "/.well-known/openid-configuration"
	path := parts.Path
	at := strings.Index(path, marker)
	if at < 0 {
		return "", fmtErr("config", "metadataUrl must be the openid-configuration URL, not %s", metadataURL)
	}
	prefix := strings.TrimRight(path[:at], "/")
	return parts.Scheme + "://" + parts.Host + prefix, nil
}

func mustBeURL(value any, name string) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return "", fmtErr("discovery", "OpenID Provider metadata %s is missing", name)
	}
	parts, err := url.Parse(text)
	if err != nil || (parts.Scheme != "http" && parts.Scheme != "https") || parts.Hostname() == "" {
		return "", fmtErr("discovery", "OpenID Provider metadata %s is not a valid URL", name)
	}
	if name == "issuer" && (parts.RawQuery != "" || parts.Fragment != "") {
		return "", errCode("discovery", "issuer must not contain a query or fragment")
	}
	return text, nil
}

func ValidateProviderMetadata(raw map[string]any, expectedIssuer string) (map[string]any, error) {
	if raw == nil {
		return nil, errCode("discovery", "OpenID Provider metadata must be a JSON object")
	}
	var missing []string
	for _, key := range requiredMetadata {
		if _, ok := raw[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, fmtErr("discovery", "OpenID Provider metadata is missing %s", strings.Join(missing, ", "))
	}
	metadata := map[string]any{}
	for _, key := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
		value, err := mustBeURL(raw[key], key)
		if err != nil {
			return nil, err
		}
		metadata[key] = value
	}
	metadata["response_types_supported"] = raw["response_types_supported"]
	metadata["subject_types_supported"] = raw["subject_types_supported"]
	metadata["id_token_signing_alg_values_supported"] = raw["id_token_signing_alg_values_supported"]
	for _, key := range []string{"userinfo_endpoint", "end_session_endpoint", "pushed_authorization_request_endpoint", "revocation_endpoint"} {
		if v, ok := raw[key]; ok && v != nil {
			value, err := mustBeURL(v, key)
			if err != nil {
				return nil, err
			}
			metadata[key] = value
		}
	}
	for _, key := range []string{"token_endpoint_auth_methods_supported", "code_challenge_methods_supported", "scopes_supported", "grant_types_supported"} {
		if v, ok := raw[key]; ok && v != nil {
			list, ok := asStringList(v)
			if !ok {
				return nil, fmtErr("discovery", "%s must be an array", key)
			}
			metadata[key] = list
		}
	}
	if v, ok := raw["authorization_response_iss_parameter_supported"]; ok && v != nil {
		metadata["authorization_response_iss_parameter_supported"] = isExactTrue(v)
	}
	responseTypes, ok := asStringList(metadata["response_types_supported"])
	if !ok || !containsString(responseTypes, "code") {
		return nil, errCode("discovery", "OpenID Provider does not support response_type=code")
	}
	metadata["response_types_supported"] = responseTypes
	subjects, ok := asStringList(metadata["subject_types_supported"])
	if !ok {
		return nil, errCode("discovery", "subject_types_supported must be an array")
	}
	metadata["subject_types_supported"] = subjects
	algs, ok := asStringList(metadata["id_token_signing_alg_values_supported"])
	if !ok {
		return nil, errCode("discovery", "id_token_signing_alg_values_supported must be an array")
	}
	metadata["id_token_signing_alg_values_supported"] = algs
	if expectedIssuer != "" && metadata["issuer"] != expectedIssuer {
		return nil, fmtErr("discovery", "issuer mismatch: expected %q, got %q", expectedIssuer, metadata["issuer"])
	}
	return metadata, nil
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func DiscoverProvider(metadataURL string, tlsOpt map[string]string) (map[string]any, error) {
	expected, err := IssuerFromMetadataURL(metadataURL)
	if err != nil {
		return nil, err
	}
	answer, err := send(metadataURL, "GET", map[string]string{"accept": "application/json"}, nil, tlsOpt, "discovery")
	if err != nil {
		return nil, err
	}
	if answer.Status != 200 {
		return nil, fmtErr("discovery", "%s answered %d", metadataURL, answer.Status)
	}
	body, err := decodeLoose([]byte(answer.Body))
	if err != nil {
		return nil, errCause("discovery", metadataURL+" did not answer JSON", err)
	}
	doc, ok := asMap(body)
	if !ok {
		return nil, errCode("discovery", "OpenID Provider metadata must be a JSON object")
	}
	return ValidateProviderMetadata(doc, expected)
}

func WellKnownURLs(issuer, suffix string) []string {
	parts, err := url.Parse(issuer)
	if err != nil {
		return nil
	}
	path := strings.TrimRight(parts.Path, "/")
	origin := parts.Scheme + "://" + parts.Host
	inserted := origin + "/.well-known/" + suffix + path
	appended := origin + path + "/.well-known/" + suffix
	if inserted == appended {
		return []string{inserted}
	}
	return []string{inserted, appended}
}

func IDTokenAlgorithms(advertised []string, pinned string) ([]string, error) {
	if pinned != "" {
		if !containsString(advertised, pinned) {
			return nil, fmtErr("discovery", "the provider does not advertise id_token alg %s", pinned)
		}
		return []string{pinned}, nil
	}
	var allowed []string
	for _, alg := range advertised {
		if containsString(AsymmetricJWSAlgs, alg) {
			allowed = append(allowed, alg)
		}
	}
	if len(allowed) == 0 {
		return nil, fmtErr("discovery", "none of the provider's ID token algorithms can be verified (%s)", strings.Join(advertised, ", "))
	}
	return allowed, nil
}

func schemeOf(value string) string {
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parts, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return parts.Scheme
}

func parseJSONObject(text string) (any, error) {
	return decodeLoose([]byte(text))
}

func marshalJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}
