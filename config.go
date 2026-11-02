// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

var authMethods = []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}

func readPath(path, baseDir, what string) (string, error) {
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(baseDir, path)
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return "", errCause("config", "could not read "+what+" at "+full+": "+err.Error(), err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func secretValue(raw, baseDir, what string) (string, error) {
	if strings.HasPrefix(raw, "env:") {
		name := raw[4:]
		value := os.Getenv(name)
		if value == "" {
			return "", fmtErr("config", "%s reads %s, and that variable is empty", what, name)
		}
		return value, nil
	}
	if strings.HasPrefix(raw, "file:") {
		return readPath(raw[5:], baseDir, what)
	}
	return raw, nil
}

func keyValue(raw, baseDir, what string) (string, error) {
	if strings.HasPrefix(raw, "env:") || strings.HasPrefix(raw, "file:") || strings.Contains(raw, "-----BEGIN") {
		return secretValue(raw, baseDir, what)
	}
	return readPath(raw, baseDir, what)
}

func readTrust(raw any, baseDir string) (string, bool) {
	if raw == nil {
		return "", false
	}
	value := strings.TrimSpace(sprint(raw))
	if value == "" {
		return "", false
	}
	if strings.Contains(value, "-----BEGIN") {
		return value, true
	}
	if strings.HasPrefix(value, "env:") {
		got := os.Getenv(value[4:])
		if got == "" {
			return "", false
		}
		return got, true
	}
	path := value
	if strings.HasPrefix(value, "file:") {
		path = value[5:]
	}
	if path == "" {
		return "", false
	}
	full := path
	if !filepath.IsAbs(path) {
		full = filepath.Join(baseDir, path)
	}
	body, err := os.ReadFile(full)
	if err != nil {
		return "", false
	}
	return string(body), true
}

func signalsOn(value any, present bool) (bool, error) {
	if !present || value == nil || isExactTrue(value) {
		if present && value != nil && !isExactTrue(value) {
			if _, ok := value.(bool); !ok {
				return false, errCode("config", "signals must be true or false")
			}
		}
		if b, ok := value.(bool); ok && !b {
			return false, nil
		}
		return true, nil
	}
	if b, ok := value.(bool); ok {
		return b, nil
	}
	return false, errCode("config", "signals must be true or false")
}

func isLoopback(hostname string) bool {
	return hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" || hostname == "[::1]"
}

func checkRedirect(value, name string, allowInsecure bool) (string, error) {
	parts, err := url.Parse(value)
	if err != nil || (parts.Scheme != "http" && parts.Scheme != "https") || parts.Hostname() == "" {
		return "", fmtErr("config", "%s is not a URL: %s", name, value)
	}
	if parts.Scheme == "https" {
		return value, nil
	}
	if parts.Scheme == "http" && (isLoopback(parts.Hostname()) || allowInsecure) {
		return value, nil
	}
	return "", fmtErr("config", "%s must use https, or http on loopback: %s", name, value)
}

// ResolveConfig reads a configuration object and fills the defaults.
// baseDir is where relative paths start.
// signals is omitted when CAEP and RISC are on, and present as false when they are off.
func ResolveConfig(raw map[string]any, baseDir string) (map[string]any, error) {
	if raw == nil {
		return nil, errCode("config", "the configuration must be a JSON object")
	}
	clientID := strings.TrimSpace(firstString(raw, "clientId", "client_id"))
	if clientID == "" {
		return nil, errCode("config", "client_id is required")
	}
	method := sprint(raw["tokenEndpointAuthMethod"])
	if method == "" {
		method = "client_secret_basic"
	}
	if method == "none" {
		return nil, errCode("config", `tokenEndpointAuthMethod "none" is a public client; this library authenticates a confidential client`)
	}
	if !containsString(authMethods, method) {
		return nil, fmtErr("config", "tokenEndpointAuthMethod must be %s, not %s", strings.Join(authMethods, ", "), method)
	}
	redirectURI := strings.TrimSpace(firstString(raw, "redirectUri", "redirect_uri"))
	if redirectURI == "" {
		return nil, errCode("config", "redirectUri is required")
	}
	allowInsecure := isExactTrue(raw["allowInsecure"])
	_, signalsPresent := raw["signals"]
	signals, err := signalsOn(raw["signals"], signalsPresent)
	if err != nil {
		return nil, err
	}
	var scopes string
	if v, ok := raw["scopes"]; !ok || v == nil {
		scopes = strings.TrimSpace(DefaultScopes)
	} else if list, ok := asStringList(v); ok {
		var parts []string
		for _, item := range list {
			item = strings.TrimSpace(item)
			if item != "" {
				parts = append(parts, item)
			}
		}
		scopes = strings.Join(parts, " ")
	} else {
		scopes = strings.TrimSpace(sprint(v))
	}
	if !signals {
		var kept []string
		for _, part := range strings.Fields(scopes) {
			if part != "ssf.read" && part != "ssf.manage" {
				kept = append(kept, part)
			}
		}
		scopes = strings.Join(kept, " ")
	}
	if !containsString(strings.Fields(scopes), "openid") {
		return nil, errCode("config", "scopes must include openid")
	}
	par := "auto"
	if v, ok := raw["par"]; ok && v != nil {
		par = sprint(v)
	}
	if par != "auto" && par != "always" && par != "never" {
		return nil, errCode("config", "par must be auto, always, or never")
	}
	issuer := ""
	if v, ok := raw["issuer"]; ok && v != nil && strings.TrimSpace(sprint(v)) != "" {
		issuer = strings.TrimSpace(sprint(v))
	}
	metadataURL := ""
	if v, ok := raw["metadataUrl"]; ok && v != nil && strings.TrimSpace(sprint(v)) != "" {
		metadataURL = strings.TrimSpace(sprint(v))
	}
	if metadataURL != "" {
		fromURL, err := IssuerFromMetadataURL(metadataURL)
		if err != nil {
			return nil, err
		}
		if issuer != "" && issuer != fromURL {
			return nil, fmtErr("config", "issuer %s is not the issuer of %s (%s)", issuer, metadataURL, fromURL)
		}
		issuer = fromURL
	}
	var metadata map[string]any
	if v, ok := raw["metadataFile"]; ok && v != nil && sprint(v) != "" {
		full := sprint(v)
		if !filepath.IsAbs(full) {
			full = filepath.Join(baseDir, full)
		}
		body, err := os.ReadFile(full)
		if err != nil {
			return nil, errCause("config", "could not read metadata at "+full+": "+err.Error(), err)
		}
		parsed, err := decodeLoose(body)
		if err != nil {
			return nil, errCause("config", "could not read metadata at "+full+": "+err.Error(), err)
		}
		doc, ok := asMap(parsed)
		if !ok {
			return nil, errCause("config", "could not read metadata at "+full+": not an object", errCode("config", "not an object"))
		}
		metadata, err = ValidateProviderMetadata(doc, issuer)
		if err != nil {
			return nil, err
		}
		issuer = sprint(metadata["issuer"])
	}
	if metadataURL == "" && metadata == nil {
		return nil, errCode("config", "metadataUrl or metadataFile is required")
	}
	needsSecret := method != "private_key_jwt"
	clientSecret := ""
	if v, ok := raw["clientSecret"]; ok && v != nil && sprint(v) != "" {
		clientSecret, err = secretValue(sprint(v), baseDir, "the client secret")
		if err != nil {
			return nil, err
		}
	}
	if needsSecret && clientSecret == "" {
		return nil, fmtErr("config", "%s needs clientSecret", method)
	}
	privateKey := ""
	if v, ok := raw["privateKey"]; ok && v != nil && sprint(v) != "" {
		privateKey, err = keyValue(sprint(v), baseDir, "the private key")
		if err != nil {
			return nil, err
		}
	}
	if method == "private_key_jwt" && privateKey == "" {
		return nil, errCode("config", "private_key_jwt needs privateKey")
	}
	tlsCA, hasCA := readTrust(raw["tlsCa"], baseDir)
	post := strings.TrimSpace(firstString(raw, "postLogoutRedirectUri", "post_logout_redirect_uri"))
	var ssf map[string]any
	if signals {
		if doc, ok := asMap(raw["ssf"]); ok && doc["transmitter"] != nil && strings.TrimSpace(sprint(doc["transmitter"])) != "" {
			transmitter := strings.TrimRight(strings.TrimSpace(sprint(doc["transmitter"])), "/")
			if !strings.HasPrefix(transmitter, "http://") && !strings.HasPrefix(transmitter, "https://") {
				return nil, errCode("config", "ssf.transmitter must be an http(s) URL")
			}
			ssf = map[string]any{"transmitter": transmitter}
			if truthy(doc["pollIntervalMs"]) {
				ssf["pollIntervalMs"] = doc["pollIntervalMs"]
			}
		}
	}
	checkedRedirect, err := checkRedirect(redirectURI, "redirectUri", allowInsecure)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if issuer != "" {
		out["issuer"] = issuer
	}
	if metadataURL != "" {
		out["metadataUrl"] = metadataURL
	}
	if metadata != nil {
		out["metadata"] = metadata
	}
	out["clientId"] = clientID
	if clientSecret != "" {
		out["clientSecret"] = clientSecret
	}
	if privateKey != "" {
		out["privateKeyPem"] = privateKey
	}
	if v, ok := raw["privateKeyAlg"]; ok && v != nil && sprint(v) != "" {
		out["privateKeyAlg"] = v
	} else {
		out["privateKeyAlg"] = "RS256"
	}
	out["tokenEndpointAuthMethod"] = method
	out["redirectUri"] = checkedRedirect
	if post != "" {
		checked, err := checkRedirect(post, "postLogoutRedirectUri", allowInsecure)
		if err != nil {
			return nil, err
		}
		out["postLogoutRedirectUri"] = checked
	}
	out["scopes"] = scopes
	if v, ok := raw["idTokenSignedResponseAlg"]; ok && v != nil && sprint(v) != "" {
		out["idTokenSignedResponseAlg"] = v
	}
	out["par"] = par
	if v, ok := raw["clockToleranceSec"]; !ok || v == nil {
		out["clockToleranceSec"] = 30
	} else {
		out["clockToleranceSec"] = v
	}
	if v, ok := raw["maxIdTokenAgeSec"]; !ok || v == nil {
		out["maxIdTokenAgeSec"] = 600
	} else {
		out["maxIdTokenAgeSec"] = v
	}
	out["allowInsecure"] = allowInsecure
	if hasCA {
		out["tlsCa"] = tlsCA
	}
	if !signals {
		out["signals"] = false
	}
	if ssf != nil {
		out["ssf"] = ssf
	}
	return out, nil
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := raw[key]; ok && v != nil {
			return sprint(v)
		}
	}
	return ""
}

// ReadConfigFile reads a configuration file. Relative paths start in the file's directory.
func ReadConfigFile(path string) (map[string]any, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, errCause("config", "could not read "+path+": "+err.Error(), err)
	}
	parsed, err := decodeLoose(body)
	if err != nil {
		return nil, errCause("config", "could not read "+path+": "+err.Error(), err)
	}
	doc, ok := asMap(parsed)
	if !ok {
		return nil, errCode("config", "the configuration must be a JSON object")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	return ResolveConfig(doc, filepath.Dir(abs))
}

func FromFile(path string) (*RelyingParty, error) {
	cfg, err := ReadConfigFile(path)
	if err != nil {
		return nil, err
	}
	return Create(cfg)
}
