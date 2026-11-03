// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	ssfKey   *rsa.PrivateKey
	ssfOther *rsa.PrivateKey
	ssfJWK   map[string]any
)

func init() {
	var err error
	ssfKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	ssfOther, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	ssfJWK = publicJWK(&ssfKey.PublicKey, "k1")
}

type quietLog struct{}

func (quietLog) Info(string)  {}
func (quietLog) Warn(string)  {}
func (quietLog) Error(string) {}

func signSET(payload map[string]any, key *rsa.PrivateKey, header map[string]any) string {
	if header == nil {
		header = map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"}
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoSHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type transmitter struct {
	url           string
	server        *httptest.Server
	mu            sync.Mutex
	order         []string
	queue         map[string]string
	acked         []string
	errs          map[string]map[string]string
	streams       []map[string]any
	created       int
	authorization string
	verifyState   string
	verifyStatus  int
	// dpopToken, when set, is the only access token accepted, as a DPoP-bound
	// token with a proof; nonce, when set, must be in that proof.
	dpopToken string
	nonce     string
	proofs    int
	nonceAsks int
}

func startTransmitter(t *testing.T) *transmitter {
	t.Helper()
	tx := &transmitter{queue: map[string]string{}, errs: map[string]map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", tx.serve)
	tx.server = httptest.NewServer(mux)
	tx.url = tx.server.URL
	t.Cleanup(tx.server.Close)
	return tx
}

func (tx *transmitter) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	auth := r.Header.Get("Authorization")
	tx.mu.Lock()
	tx.authorization = auth
	dpopToken := tx.dpopToken
	nonce := tx.nonce
	tx.mu.Unlock()
	open := path == "/.well-known/ssf-configuration" || strings.HasPrefix(path, "/jwks")
	if dpopToken != "" && !open {
		if auth != "DPoP "+dpopToken {
			writeJSON(w, 401, map[string]any{"error": "invalid_token"})
			return
		}
		_, problem := (&providerStub{url: tx.url}).checkProof(r, dpopToken, nonce)
		if problem == "use_dpop_nonce" {
			tx.mu.Lock()
			tx.nonceAsks++
			tx.mu.Unlock()
			w.Header().Set("DPoP-Nonce", nonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			writeJSON(w, 401, map[string]any{"error": "use_dpop_nonce"})
			return
		}
		if problem != "" {
			writeJSON(w, 401, map[string]any{"error": "invalid_dpop_proof", "error_description": problem})
			return
		}
		tx.mu.Lock()
		tx.proofs++
		tx.mu.Unlock()
	} else if auth != "Bearer app-token" && !open {
		writeJSON(w, 401, map[string]any{"error": "invalid_token"})
		return
	}
	if path == "/.well-known/ssf-configuration" {
		writeJSON(w, 200, map[string]any{
			"issuer":                     tx.url,
			"jwks_uri":                   tx.url + "/jwks",
			"configuration_endpoint":     tx.url + "/ssf/stream",
			"verification_endpoint":      tx.url + "/ssf/verify",
			"delivery_methods_supported": []string{pollMethod},
		})
		return
	}
	if path == "/jwks" {
		writeJSON(w, 200, map[string]any{"keys": []any{ssfJWK}})
		return
	}
	if path == "/ssf/stream" && r.Method == http.MethodGet {
		tx.mu.Lock()
		streams := append([]map[string]any{}, tx.streams...)
		tx.mu.Unlock()
		writeJSON(w, 200, streams)
		return
	}
	if path == "/ssf/stream" && r.Method == http.MethodPost {
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		tx.mu.Lock()
		tx.created++
		created := tx.created
		delivery, _ := doc["delivery"].(map[string]any)
		method := ""
		if delivery != nil {
			method, _ = delivery["method"].(string)
		}
		stream := map[string]any{
			"stream_id":        fmt.Sprintf("s%d", created),
			"iss":              tx.url,
			"aud":              "my-app",
			"delivery":         map[string]any{"method": method, "endpoint_url": fmt.Sprintf("%s/ssf/poll/s%d", tx.url, created)},
			"events_requested": doc["events_requested"],
			"events_delivered": doc["events_requested"],
		}
		tx.streams = append(tx.streams, stream)
		tx.mu.Unlock()
		writeJSON(w, 201, stream)
		return
	}
	if path == "/ssf/verify" {
		var doc map[string]any
		_ = json.Unmarshal(body, &doc)
		state, _ := doc["state"].(string)
		tx.mu.Lock()
		tx.verifyState = state
		tx.verifyStatus = 204
		tx.mu.Unlock()
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(204)
		return
	}
	if strings.HasPrefix(path, "/ssf/poll/") {
		var doc struct {
			Ack     []string                     `json:"ack"`
			SetErrs map[string]map[string]string `json:"setErrs"`
		}
		_ = json.Unmarshal(body, &doc)
		tx.mu.Lock()
		for _, jti := range doc.Ack {
			tx.acked = append(tx.acked, jti)
			delete(tx.queue, jti)
		}
		for jti, errDoc := range doc.SetErrs {
			tx.errs[jti] = errDoc
			delete(tx.queue, jti)
		}
		raw := tx.pollBody()
		tx.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", jsonNumber(float64(len(raw))))
		w.WriteHeader(200)
		_, _ = w.Write(raw)
		return
	}
	writeJSON(w, 404, map[string]any{"error": "not_found"})
}

func (tx *transmitter) pollBody() []byte {
	var b strings.Builder
	b.WriteString(`{"sets":{`)
	first := true
	for _, jti := range tx.order {
		token, ok := tx.queue[jti]
		if !ok {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		jb, _ := json.Marshal(jti)
		tb, _ := json.Marshal(token)
		b.Write(jb)
		b.WriteByte(':')
		b.Write(tb)
	}
	b.WriteString(`},"moreAvailable":false}`)
	return []byte(b.String())
}

func (tx *transmitter) deliver(eventType string, subID map[string]any, extra map[string]any, key *rsa.PrivateKey, aud, iss string) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	jti := fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:])
	if key == nil {
		key = ssfKey
	}
	if aud == "" {
		aud = "my-app"
	}
	if iss == "" {
		iss = tx.url
	}
	event := map[string]any{"event_timestamp": 1}
	for k, v := range extra {
		event[k] = v
	}
	payload := map[string]any{
		"iss":    iss,
		"aud":    aud,
		"jti":    jti,
		"iat":    time.Now().Unix(),
		"sub_id": subID,
		"events": map[string]any{eventType: event},
	}
	token := signSET(payload, key, nil)
	tx.mu.Lock()
	tx.queue[jti] = token
	tx.order = append(tx.order, jti)
	tx.mu.Unlock()
	return jti
}

func TestVerifiesASETAgainstTheJWKS(t *testing.T) {
	_, payload, err := VerifyCompactJWS(signSET(map[string]any{"a": 1}, ssfKey, nil), []map[string]any{ssfJWK})
	if err != nil {
		t.Fatal(err)
	}
	if payload["a"] != int64(1) {
		t.Fatalf("payload %#v", payload["a"])
	}
	_, _, err = VerifyCompactJWS(signSET(map[string]any{"a": 1}, ssfOther, nil), []map[string]any{ssfJWK})
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("other key: %v", err)
	}
	_, _, err = VerifyCompactJWS(signSET(map[string]any{"a": 1}, ssfKey, map[string]any{"alg": "RS256", "kid": "nope"}), []map[string]any{ssfJWK})
	if err == nil || !strings.Contains(err.Error(), "kid nope") {
		t.Fatalf("kid: %v", err)
	}
	_, _, err = VerifyCompactJWS(signSET(map[string]any{"a": 1}, ssfKey, map[string]any{"alg": "none"}), []map[string]any{ssfJWK})
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("none: %v", err)
	}
}

func TestReadsSubjectForms(t *testing.T) {
	if Event["sessionRevoked"] != "https://schemas.openid.net/secevent/caep/event-type/session-revoked" {
		t.Fatal(Event["sessionRevoked"])
	}
	if Event["credentialCompromise"] != "https://schemas.openid.net/secevent/risc/event-type/credential-compromise" {
		t.Fatal(Event["credentialCompromise"])
	}
	got := SubjectOf(map[string]any{
		"format":  "complex",
		"user":    map[string]any{"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"},
		"session": map[string]any{"format": "opaque", "id": "S1"},
	}, "https://i")
	if got["person"] != "urn:uuid:a" || got["idpSession"] != "S1" || len(got) != 2 {
		t.Fatalf("complex %#v", got)
	}
	other := SubjectOf(map[string]any{"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}, "https://i")
	if len(other) != 0 {
		t.Fatalf("other issuer %#v", other)
	}
	email := SubjectOf(map[string]any{"format": "email", "email": "A@x.com"}, "https://i")
	if email["email"] != "A@x.com" || len(email) != 1 {
		t.Fatalf("email %#v", email)
	}
}

func TestPollsAndEndsOnlyTheNamedSession(t *testing.T) {
	stub := startTransmitter(t)
	var ended [][]string
	var seen []SignalEvent
	var mu sync.Mutex
	receiver, err := NewSignalsReceiver(stub.url, func(ids []string, _ SignalEvent) {
		mu.Lock()
		ended = append(ended, append([]string(nil), ids...))
		mu.Unlock()
	}, ReceiverOptions{
		Headers:        func() map[string]string { return map[string]string{"authorization": "Bearer app-token"} },
		PollIntervalMs: 60000,
		Log:            quietLog{},
	})
	if err != nil {
		t.Fatal(err)
	}
	receiver.On("*", func(event SignalEvent) {
		mu.Lock()
		seen = append(seen, event)
		mu.Unlock()
	})
	if err := receiver.Start(); err != nil {
		t.Fatal(err)
	}
	receiver.Stop()
	stub.mu.Lock()
	created := stub.created
	auth := stub.authorization
	stub.mu.Unlock()
	if created != 1 {
		t.Fatalf("created %d", created)
	}
	if auth != "Bearer app-token" {
		t.Fatalf("authorization %q", auth)
	}
	if sprint(receiver.Stream()["stream_id"]) != "s1" {
		t.Fatalf("stream %#v", receiver.Stream()["stream_id"])
	}
	receiver.Track(map[string]any{"local_id": "L-a1", "person": "urn:uuid:alice", "email": "alice@example.com", "idp_session": "IDP-A1"})
	receiver.Track(map[string]any{"local_id": "L-a2", "person": "urn:uuid:alice", "email": "alice@example.com", "idp_session": "IDP-A2"})
	receiver.Track(map[string]any{"local_id": "L-b1", "person": "urn:uuid:bob", "email": "bob@example.com", "idp_session": "IDP-B1"})
	revoked := stub.deliver(Event["sessionRevoked"], map[string]any{
		"format":  "complex",
		"user":    map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"},
		"session": map[string]any{"format": "opaque", "id": "IDP-A1"},
	}, nil, nil, "", "")
	stub.deliver(Event["credentialChange"], map[string]any{"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}, map[string]any{"credential_type": "password"}, nil, "", "")
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotEnded := append([][]string{}, ended...)
	gotSeen := append([]SignalEvent{}, seen...)
	mu.Unlock()
	if len(gotEnded) != 1 || len(gotEnded[0]) != 1 || gotEnded[0][0] != "L-a1" {
		t.Fatalf("ended %#v", gotEnded)
	}
	if len(gotSeen) != 2 || !gotSeen[0].Ended || gotSeen[1].Type != Event["credentialChange"] || gotSeen[1].Ended {
		t.Fatalf("seen %+v", gotSeen)
	}
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	stub.mu.Lock()
	acked := append([]string{}, stub.acked...)
	stub.mu.Unlock()
	if len(acked) == 0 || acked[0] != revoked {
		t.Fatalf("acked %#v want first %s", acked, revoked)
	}
	count := 0
	for _, item := range acked {
		if item == revoked {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("revoked count %d in %#v", count, acked)
	}
	bad := stub.deliver(Event["accountDisabled"], map[string]any{"format": "email", "email": "alice@example.com"}, nil, ssfOther, "", "")
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.PollOnce(); err != nil {
		t.Fatal(err)
	}
	stub.mu.Lock()
	errDoc := stub.errs[bad]
	stub.mu.Unlock()
	if errDoc["err"] != "invalid_key" {
		t.Fatalf("setErrs %#v", errDoc)
	}
	if err := receiver.Verify("abc"); err != nil {
		t.Fatal(err)
	}
	stub.mu.Lock()
	state := stub.verifyState
	status := stub.verifyStatus
	stub.mu.Unlock()
	if state != "abc" || status != 204 {
		t.Fatalf("verify state %q status %d", state, status)
	}
	receiver.Stop()
}

func TestOidcErrorIsExported(t *testing.T) {
	err := &OidcError{Code: "config", Message: "signals must be true or false"}
	if err.Error() != "signals must be true or false" || err.Code != "config" {
		t.Fatal(err)
	}
}
