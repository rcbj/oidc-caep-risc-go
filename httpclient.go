// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxBodyBytes = 2 * 1024 * 1024
	httpTimeout  = 15 * time.Second
)

// Redirects are not followed. A custom CA is added to the system pool; verification stays on.
var defaultTransport = &http.Transport{
	Proxy:                 func(*http.Request) (*url.URL, error) { return nil, nil },
	DialContext:           (&net.Dialer{Timeout: httpTimeout}).DialContext,
	TLSHandshakeTimeout:   httpTimeout,
	ResponseHeaderTimeout: httpTimeout,
	MaxIdleConns:          8,
	IdleConnTimeout:       30 * time.Second,
}

type httpAnswer struct {
	Status      int
	ContentType string
	Body        string
	Header      http.Header
}

func tlsConfigFor(ca string) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if ca != "" && !roots.AppendCertsFromPEM([]byte(ca)) {
		return nil, errCode("protocol", "the configured tlsCa is not a PEM trust anchor")
	}
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}

func send(rawURL, method string, headers map[string]string, body *string, tlsOpt map[string]string, code string) (httpAnswer, error) {
	parts, err := url.Parse(rawURL)
	if err != nil || (parts.Scheme != "http" && parts.Scheme != "https") || parts.Hostname() == "" {
		return httpAnswer{}, fmtErr(code, "%s is not an http(s) URL", rawURL)
	}
	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(*body)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		return httpAnswer{}, errCause(code, rawURL+": "+err.Error(), err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Close = true
	ca := ""
	if tlsOpt != nil {
		ca = tlsOpt["ca"]
	}
	transport := defaultTransport
	closeIdle := false
	if ca != "" {
		cfg, cfgErr := tlsConfigFor(ca)
		if cfgErr != nil {
			if oe, ok := cfgErr.(*OidcError); ok {
				oe.Code = code
			}
			return httpAnswer{}, cfgErr
		}
		cloned := defaultTransport.Clone()
		cloned.TLSClientConfig = cfg
		transport = cloned
		closeIdle = true
	}
	client := &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if closeIdle {
		defer transport.CloseIdleConnections()
	}
	if err != nil {
		if errorIsTimeout(err) {
			return httpAnswer{}, errCause(code, rawURL+" did not answer within 15 s", err)
		}
		return httpAnswer{}, errCause(code, rawURL+": "+err.Error(), err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		if errorIsTimeout(err) {
			return httpAnswer{}, errCause(code, rawURL+" did not answer within 15 s", err)
		}
		return httpAnswer{}, errCause(code, rawURL+": "+err.Error(), err)
	}
	if len(raw) > maxBodyBytes {
		return httpAnswer{}, fmtErr(code, "%s answered more than %d bytes", rawURL, maxBodyBytes)
	}
	return httpAnswer{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: string(raw), Header: resp.Header}, nil
}

func errorIsTimeout(err error) bool {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Timeout() {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
