// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

// tlsCa: the install script writes the whole listener CA trust chain to the
// file the parameter names, and the library takes that file as its trust store,
// verifying the host name and refusing a forged leaf in front of the real CAs.
//
// The stub provider is HTTPS on a four-certificate chain shaped like iya-sts's
// (leaf, TLS Issuing CA, Intermediate, Root) and publishes it, leaf first, at
// GET /tls/server-certificate. The scripts run with the test image's python3
// and openssl (Dockerfile, test stage).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const defaultTLSCa = "generated/idp-ca.pem"

type chainCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func makeChainCert(t *testing.T, cn string, issuer *chainCert, ca bool, ip string) *chainCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if ip != "" {
		template.IPAddresses = []net.IP{net.ParseIP(ip)}
	}
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.cert, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &chainCert{cert: cert, key: key, pem: string(block)}
}

type chainProvider struct {
	origin    string
	published string
	root      *chainCert
	issuing   *chainCert
	server    *httptest.Server
}

// startChainProvider serves the leaf, then presented (the CAs the handshake sends).
func startChainProvider(t *testing.T, leaf *chainCert, presented []*chainCert, published string) *chainProvider {
	t.Helper()
	p := &chainProvider{published: published}
	mux := http.NewServeMux()
	mux.HandleFunc("/tls/server-certificate", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte(p.published))
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.origin})
	})
	chain := [][]byte{leaf.cert.Raw}
	for _, ca := range presented {
		chain = append(chain, ca.cert.Raw)
	}
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: leaf.key}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	p.server = server
	p.origin = server.URL
	return p
}

type stsChain struct {
	root, intermediate, issuing, leaf *chainCert
	published                         string
}

func newStsChain(t *testing.T) stsChain {
	t.Helper()
	root := makeChainCert(t, "sts Root CA", nil, true, "")
	intermediate := makeChainCert(t, "sts Intermediate CA", root, true, "")
	issuing := makeChainCert(t, "sts TLS Issuing CA", intermediate, true, "")
	leaf := makeChainCert(t, "127.0.0.1", issuing, false, "127.0.0.1")
	return stsChain{
		root: root, intermediate: intermediate, issuing: issuing, leaf: leaf,
		published: leaf.pem + issuing.pem + intermediate.pem + root.pem,
	}
}

func (c stsChain) start(t *testing.T) *chainProvider {
	p := startChainProvider(t, c.leaf, []*chainCert{c.issuing, c.intermediate}, c.published)
	p.root = c.root
	p.issuing = c.issuing
	return p
}

// chainDemoDir writes the shipped demo/oidc.json, pointed at the stub, into a temp dir.
func chainDemoDir(t *testing.T, origin string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("demo", "oidc.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	config["metadataUrl"] = origin + "/.well-known/openid-configuration"
	dir := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(dir, "oidc.json"), out, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runPython(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("python3 is not on PATH; run the suite with docker build --target test .")
	}
	abs := make([]string, 0, len(args))
	for i, arg := range args {
		if i == 0 {
			arg, _ = filepath.Abs(arg)
		}
		abs = append(abs, arg)
	}
	cmd := exec.Command("python3", abs...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestShippedDemoNamesGeneratedIdpCaPem(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("demo", "oidc.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if config["tlsCa"] != defaultTLSCa {
		t.Fatalf("tlsCa %v", config["tlsCa"])
	}
}

func TestInstallScriptWritesWholeChainToTLSCa(t *testing.T) {
	chain := newStsChain(t)
	p := chain.start(t)
	dir := chainDemoDir(t, p.origin)
	// No admin secret: the install script saves the chain first, then stops
	// at the missing secret. The chain is what this test is about.
	out, err := runPython(t, []string{"ADMIN_API_CLIENT_SECRET=", "STS_ADMIN_API_CLIENT_SECRET="},
		"scripts/configure_iya_sts.py", "--config", filepath.Join(dir, "oidc.json"), "--idp", p.origin)
	if err == nil {
		t.Fatalf("the install script ran on without an admin secret:\n%s", out)
	}
	target := filepath.Join(dir, defaultTLSCa)
	saved, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("no chain at %s: %v\n%s", target, readErr, out)
	}
	if string(saved) != p.published {
		t.Fatalf("saved chain is not the published one:\n%s", saved)
	}
	if strings.Count(string(saved), "BEGIN CERTIFICATE") != 4 {
		t.Fatalf("saved %d certificates", strings.Count(string(saved), "BEGIN CERTIFICATE"))
	}
	if !strings.Contains(out, "(4 certificate(s)) to "+target) || !strings.Contains(out, "CN=sts Root CA") {
		t.Fatalf("output does not name the path and the anchor:\n%s", out)
	}
	digest := sha256.Sum256(p.root.cert.Raw)
	parts := make([]string, len(digest))
	for i, b := range digest {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	if !strings.Contains(out, "sha256 "+strings.Join(parts, ":")) {
		t.Fatalf("output does not carry the anchor's SHA-256:\n%s", out)
	}
}

func TestRefreshEntryPointWritesTLSCa(t *testing.T) {
	chain := newStsChain(t)
	p := chain.start(t)
	dir := chainDemoDir(t, p.origin)
	out, err := runPython(t, nil, "scripts/trust_chain.py", "--config", filepath.Join(dir, "oidc.json"))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	saved, err := os.ReadFile(filepath.Join(dir, defaultTLSCa))
	if err != nil || string(saved) != p.published {
		t.Fatalf("refresh did not write the chain: %v\n%s", err, out)
	}
}

// libraryTrust resolves the demo config the way the demo does and returns tlsCa.
func libraryTrust(t *testing.T, dir string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "generated", "client-secret"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "oidc.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]any
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	config, err := ResolveConfig(file, dir)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := config["tlsCa"].(string)
	if ca == "" {
		t.Fatal("tlsCa did not resolve to the saved chain")
	}
	return ca
}

func TestLibraryTrustsProviderThroughSavedFile(t *testing.T) {
	chain := newStsChain(t)
	p := chain.start(t)
	dir := chainDemoDir(t, p.origin)
	url := p.origin + "/.well-known/openid-configuration"
	if _, err := send(url, "GET", nil, nil, nil, "discovery"); err == nil {
		t.Fatal("the stub was trusted without tlsCa")
	}
	if out, err := runPython(t, nil, "scripts/trust_chain.py", "--config", filepath.Join(dir, "oidc.json")); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	ca := libraryTrust(t, dir)
	if ca != chain.published {
		t.Fatalf("tlsCa resolved to something other than the saved chain")
	}
	answer, err := send(url, "GET", nil, nil, map[string]string{"ca": ca}, "discovery")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]string
	if answer.Status != 200 || json.Unmarshal([]byte(answer.Body), &doc) != nil || doc["issuer"] != p.origin {
		t.Fatalf("discovery answered %d %s", answer.Status, answer.Body)
	}
	// The root alone is enough: every PEM block of the file is a trust anchor,
	// not only the first (which is the leaf).
	if _, err := send(url, "GET", nil, nil, map[string]string{"ca": chain.root.pem}, "discovery"); err != nil {
		t.Fatalf("root only: %v", err)
	}
}

func TestLibraryVerifiesTheHostName(t *testing.T) {
	chain := newStsChain(t)
	p := chain.start(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(p.origin, "https://"))
	ca := map[string]string{"ca": chain.published}
	if _, err := send("https://127.0.0.1:"+port+"/.well-known/openid-configuration", "GET", nil, nil, ca, "discovery"); err != nil {
		t.Fatalf("127.0.0.1 through the IP SAN: %v", err)
	}
	// Right chain, wrong name: the leaf names only IP 127.0.0.1, not localhost.
	_, err := send("https://localhost:"+port+"/.well-known/openid-configuration", "GET", nil, nil, ca, "discovery")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("localhost was accepted on a 127.0.0.1-only certificate: %v", err)
	}
}

func TestLibraryRefusesForgedLeafBeforeRealCAs(t *testing.T) {
	chain := newStsChain(t)
	forger := makeChainCert(t, "forger CA", nil, true, "")
	forged := makeChainCert(t, "127.0.0.1", forger, false, "127.0.0.1")
	// The forged leaf, followed by the real Issuing and Intermediate CAs.
	p := startChainProvider(t, forged, []*chainCert{chain.issuing, chain.intermediate}, chain.published)
	ca := map[string]string{"ca": chain.published}
	if _, err := send(p.origin+"/.well-known/openid-configuration", "GET", nil, nil, ca, "discovery"); err == nil {
		t.Fatal("a forged leaf in front of the real CA certificates was trusted")
	}
}
