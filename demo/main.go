// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rcbj/oidc-caep-risc-go"
)

//go:embed public/styles.css public/app.js
var assets embed.FS

const (
	cookieSession = "oidc_session"
	cookieTxn     = "oidc_txn"
)

type session struct {
	Login   *oidc.Login
	Expires float64
}

type liveEvent struct {
	Type string  `json:"type"`
	JTI  *string `json:"jti"`
}

type app struct {
	mu            sync.Mutex
	sessions      map[string]*session
	secret        []byte
	secureCookies bool
	configPath    string
	publicURL     string
	publicGiven   bool
	rp            *oidc.RelyingParty
	rpErr         error
	loaded        bool
	receiver      *oidc.SignalsReceiver
	receiverState string
	events        []liveEvent
}

func main() {
	fs := flag.NewFlagSet("oidc-caep-risc-demo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	publicURL := fs.String("public-url", "", "origin that replaces loopback redirects")
	configFlag := fs.String("config", "", "path to oidc.json")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	path := os.Getenv("OIDC_CONFIG")
	if *configFlag != "" {
		path = *configFlag
		_ = os.Setenv("OIDC_CONFIG", path)
	}
	if path == "" {
		path = "demo/oidc.json"
	}
	given := os.Getenv("PUBLIC_URL") != "" || os.Getenv("OIDC_PUBLIC_URL_GIVEN") != ""
	public := os.Getenv("PUBLIC_URL")
	if *publicURL != "" {
		public = strings.TrimRight(*publicURL, "/")
		given = true
	}
	secret := []byte(os.Getenv("SESSION_SECRET"))
	if len(secret) == 0 {
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	application := &app{
		sessions:      map[string]*session{},
		secret:        secret,
		secureCookies: true,
		configPath:    path,
		publicURL:     public,
		publicGiven:   given,
		receiverState: "",
	}
	port := envPort()
	if raw, err := os.ReadFile(path); err == nil {
		doc := map[string]any{}
		if json.Unmarshal(raw, &doc) == nil {
			applyRedirects(doc, port, application.publicURL, application.publicGiven)
			redirect := sprint(doc["redirectUri"])
			if redirect == "" {
				redirect = sprint(doc["redirect_uri"])
			}
			if redirect == "" {
				redirect = "http://localhost/"
			}
			if parsed, err := url.Parse(redirect); err == nil {
				host := parsed.Hostname()
				application.secureCookies = parsed.Scheme == "https" || host == "localhost" || host == "127.0.0.1"
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "cannot read configuration: %v\n", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", application.route)
	server := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", port), Handler: mux}
	fmt.Printf("oidc-caep-risc-go demo on port %d\n", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func envPort() int {
	raw := strings.TrimSpace(os.Getenv("PORT"))
	if raw == "" {
		return 3000
	}
	var port int
	if _, err := fmt.Sscan(raw, &port); err != nil || port < 1 || port > 65535 || fmt.Sprint(port) != raw {
		return 3000
	}
	return port
}

func applyRedirects(raw map[string]any, port int, public string, given bool) {
	redirect := sprint(raw["redirectUri"])
	if redirect == "" {
		redirect = sprint(raw["redirect_uri"])
	}
	post := sprint(raw["postLogoutRedirectUri"])
	if post == "" {
		post = sprint(raw["post_logout_redirect_uri"])
	}
	movedR, movedP := redirectsFor(redirect, post, public, given, port)
	if raw["redirectUri"] != nil || raw["redirect_uri"] == nil {
		raw["redirectUri"] = movedR
	} else {
		raw["redirect_uri"] = movedR
	}
	if raw["postLogoutRedirectUri"] != nil || raw["post_logout_redirect_uri"] != nil || post != "" {
		if raw["post_logout_redirect_uri"] != nil && raw["postLogoutRedirectUri"] == nil {
			raw["post_logout_redirect_uri"] = movedP
		} else {
			raw["postLogoutRedirectUri"] = movedP
		}
	}
}

func redirectsFor(redirect, post, public string, given bool, port int) (string, string) {
	if given && public != "" {
		return moveOrigin(redirect, public), moveOrigin(post, public)
	}
	if port > 0 {
		return onPort(redirect, port), onPort(post, port)
	}
	return redirect, post
}

func onPort(raw string, port int) string {
	parts, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := parts.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return raw
	}
	hostname := host
	if strings.Contains(host, ":") {
		hostname = "[" + host + "]"
	}
	user := ""
	if parts.User != nil {
		user = parts.User.String() + "@"
	}
	parts.Host = fmt.Sprintf("%s%s:%d", user, hostname, port)
	if parts.Path == "" {
		parts.Path = "/"
	}
	return parts.String()
}

func moveOrigin(value, public string) string {
	baseText := public
	if !strings.HasSuffix(baseText, "/") {
		baseText += "/"
	}
	base, err := url.Parse(baseText)
	if err != nil {
		return value
	}
	nxt, err := url.Parse(value)
	if err != nil {
		return value
	}
	host := base.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if base.Port() != "" {
		nxt.Host = host + ":" + base.Port()
	} else {
		nxt.Host = host
	}
	nxt.Scheme = base.Scheme
	if nxt.Path == "" {
		nxt.Path = "/"
	}
	return nxt.String()
}

func (a *app) route(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			fmt.Fprintf(os.Stderr, "demo: %v\n", recovered)
			a.send(w, 500, page("Error", message("Something went wrong", "The demo could not answer this request. The details are in its log.", "Home")), "text/html; charset=utf-8", nil)
		}
	}()
	path := r.URL.Path
	if path == "/healthz" {
		a.send(w, 200, "ok", "text/plain", nil)
		return
	}
	if path == "/live-status" && r.Method == http.MethodGet {
		a.liveStatus(w, r)
		return
	}
	if path == "/styles.css" && r.Method == http.MethodGet {
		raw, _ := assets.ReadFile("public/styles.css")
		a.send(w, 200, string(raw), "text/css; charset=utf-8", nil)
		return
	}
	if path == "/app.js" && r.Method == http.MethodGet {
		raw, _ := assets.ReadFile("public/app.js")
		a.send(w, 200, string(raw), "text/javascript; charset=utf-8", nil)
		return
	}
	if path == "/" && r.Method == http.MethodGet {
		a.home(w, r)
		return
	}
	if path == "/login" && r.Method == http.MethodGet {
		a.login(w, r)
		return
	}
	if path == "/callback" && r.Method == http.MethodGet {
		a.callback(w, r)
		return
	}
	if path == "/logout" && r.Method == http.MethodPost {
		a.logout(w, r)
		return
	}
	a.send(w, 404, page("Not found", "<h1>Not found</h1>"), "text/html; charset=utf-8", nil)
}

func (a *app) home(w http.ResponseWriter, r *http.Request) {
	_, sess := a.sessionOf(r)
	var problem string
	rp, err := a.relyingParty()
	if err != nil {
		problem = "The relying party is not configured yet: " + err.Error() + ". Run scripts/configure_iya_sts.py."
	}
	if sess != nil && sess.Login != nil {
		login := sess.Login
		who := login.PreferredUsername
		if who == "" {
			who = login.Email
		}
		if who == "" {
			who = login.Subject
		}
		rows := ""
		for _, row := range [][2]string{
			{"Subject", login.Subject},
			{"Issuer", login.Issuer},
			{"Email", login.Email},
			{"Name", login.Name},
			{"Username", login.PreferredUsername},
		} {
			if row[1] == "" {
				continue
			}
			rows += "<tr><th>" + html.EscapeString(row[0]) + "</th><td>" + html.EscapeString(row[1]) + "</td></tr>"
		}
		body := "<h1>Signed in as " + html.EscapeString(who) + "</h1><table class=\"facts\">" + rows + "</table><p><small>The access token and the refresh token stay in this process. This page does not show them.</small></p><p><small>Shared Signals: " + html.EscapeString(a.state()) + "</small></p><form method=\"post\" action=\"/logout\"><button type=\"submit\">Sign out</button></form>"
		a.send(w, 200, page("Signed in", body), "text/html; charset=utf-8", nil)
		return
	}
	issuer := ""
	if rp != nil {
		if text := sprint(rp.Metadata()["issuer"]); text != "" {
			issuer = " of " + html.EscapeString(text)
		}
	}
	problemHTML := ""
	if problem != "" {
		problemHTML = "<p class=\"problem\">" + html.EscapeString(problem) + "</p>"
	}
	body := "<h1>Sign in with OpenID Connect</h1>" + problemHTML + "<p>This application is a confidential client" + issuer + ". It sends the browser to the authorization endpoint (Authorization Code, PKCE S256) and takes the tokens on the back channel.</p><p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with OpenID Connect</a></p>"
	a.send(w, 200, page("Sign in", body), "text/html; charset=utf-8", nil)
}

// liveStatus reports the sign-in and the Shared Signals events this process
// has accepted, for scripts/live_iya_sts.py. It never includes a token.
func (a *app) liveStatus(w http.ResponseWriter, r *http.Request) {
	_, sess := a.sessionOf(r)
	var subject any
	if sess != nil && sess.Login != nil {
		who := sess.Login.PreferredUsername
		if who == "" {
			who = sess.Login.Email
		}
		if who == "" {
			who = sess.Login.Subject
		}
		if who != "" {
			subject = who
		}
	}
	a.mu.Lock()
	events := append([]liveEvent{}, a.events...)
	state := a.receiverState
	a.mu.Unlock()
	raw, _ := json.Marshal(map[string]any{
		"signedIn": sess != nil,
		"subject":  subject,
		"receiver": state,
		"events":   events,
	})
	a.send(w, 200, string(raw), "application/json", nil)
}

// rememberLiveEvent records an accepted event for /live-status. The receiver
// ends a session only when the event's IdP session id matches one it tracks.
// A session-revoked that matched none leaves this demo's one login in place,
// so the demo ends that one local session and untracks it.
func (a *app) rememberLiveEvent(event oidc.SignalEvent) {
	var jti *string
	if event.JTI != "" {
		value := event.JTI
		jti = &value
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, liveEvent{Type: event.Type, JTI: jti})
	if event.Type != oidc.Event["sessionRevoked"] || len(event.Sessions) != 0 || len(a.sessions) != 1 {
		return
	}
	for sid := range a.sessions {
		delete(a.sessions, sid)
		if a.receiver != nil {
			a.receiver.Untrack(sid)
		}
	}
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	rp, err := a.relyingParty()
	if err != nil {
		a.send(w, 500, page("Error", message("Something went wrong", err.Error(), "")), "text/html; charset=utf-8", nil)
		return
	}
	request, err := rp.Authorize()
	if err != nil {
		a.send(w, 500, page("Error", message("Something went wrong", err.Error(), "")), "text/html; charset=utf-8", nil)
		return
	}
	txn := map[string]string{"state": request.State, "nonce": request.Nonce, "code_verifier": request.CodeVerifier, "redirect_uri": request.RedirectURI}
	a.redirect(w, http.StatusFound, request.URL, []string{a.cookie(cookieTxn, a.seal(txn), "/callback", 600)})
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	rp, err := a.relyingParty()
	clear := a.cookie(cookieTxn, "", "/callback", 0)
	if err != nil {
		a.send(w, 500, page("Error", message("Something went wrong", err.Error(), "")), "text/html; charset=utf-8", []string{clear})
		return
	}
	query := map[string]string{}
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			query[key] = values[0]
		}
	}
	txn := a.unseal(cookieValue(r, cookieTxn))
	if txn == nil {
		a.send(w, 400, page("Sign-in failed", message("Sign-in failed", "validation: this callback is not a sign-in this browser started", "Start again")), "text/html; charset=utf-8", []string{clear})
		return
	}
	request := &oidc.Transaction{State: txn["state"], Nonce: txn["nonce"], CodeVerifier: txn["code_verifier"], RedirectURI: txn["redirect_uri"]}
	login, err := rp.Complete(query, request)
	if err != nil {
		what := err.Error()
		if oe, ok := err.(*oidc.OidcError); ok {
			what = oe.Code + ": " + oe.Error()
		}
		a.send(w, 400, page("Sign-in failed", message("Sign-in failed", what, "Start again")), "text/html; charset=utf-8", []string{clear})
		return
	}
	sid := randomToken()
	a.mu.Lock()
	a.sessions[sid] = &session{Login: login, Expires: float64(time.Now().Unix()) + 8*3600}
	receiver := a.receiver
	a.mu.Unlock()
	if receiver != nil {
		receiver.Track(oidc.TrackedFromLogin(sid, login, nil))
	}
	a.redirect(w, 303, "/", []string{clear, a.cookie(cookieSession, sid, "/", 8*3600)})
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	sid, _ := a.sessionOf(r)
	if sid != "" {
		a.mu.Lock()
		delete(a.sessions, sid)
		receiver := a.receiver
		a.mu.Unlock()
		if receiver != nil {
			receiver.Untrack(sid)
		}
	}
	a.redirect(w, 303, "/", []string{a.cookie(cookieSession, "", "/", 0)})
}

func (a *app) relyingParty() (*oidc.RelyingParty, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.loaded {
		return a.rp, a.rpErr
	}
	a.loaded = true
	rp, err := a.load()
	a.rp = rp
	a.rpErr = err
	if err != nil {
		return nil, err
	}
	a.startReceiver(rp)
	return rp, nil
}

func (a *app) load() (*oidc.RelyingParty, error) {
	raw, err := os.ReadFile(a.configPath)
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if file := os.Getenv("OIDC_METADATA_FILE"); file != "" {
		doc["metadataFile"] = file
		delete(doc, "metadataUrl")
		delete(doc, "issuer")
	}
	port := envPort()
	applyRedirects(doc, port, a.publicURL, a.publicGiven)
	if doc["signals"] == false {
		a.receiverState = "not configured (signals are off)"
	} else if ssf, ok := doc["ssf"].(map[string]any); !ok || sprint(ssf["transmitter"]) == "" {
		a.receiverState = "not configured (no ssf block in the configuration file)"
	} else {
		a.receiverState = "starting"
	}
	base := configDir(a.configPath)
	resolved, err := oidc.ResolveConfig(doc, base)
	if err != nil {
		return nil, err
	}
	return oidc.Create(resolved)
}

func (a *app) startReceiver(rp *oidc.RelyingParty) {
	cfg := rp.Config()
	if cfg["signals"] == false || cfg["ssf"] == nil || a.receiver != nil {
		if cfg["signals"] == false {
			a.receiverState = "not configured (signals are off)"
		}
		return
	}
	ssf, _ := cfg["ssf"].(map[string]any)
	if ssf == nil || sprint(ssf["transmitter"]) == "" {
		return
	}
	interval := number(ssf["pollIntervalMs"])
	if interval == 0 {
		interval = 5000
	}
	receiver, err := oidc.NewSignalsReceiver(sprint(ssf["transmitter"]), func(ids []string, _ oidc.SignalEvent) {
		a.mu.Lock()
		for _, id := range ids {
			delete(a.sessions, id)
		}
		a.mu.Unlock()
	}, oidc.ReceiverOptions{
		TLS:            rp.TLS(),
		Headers:        func() map[string]string { return a.signalHeaders(rp) },
		Description:    "oidc-caep-risc-go demo (" + sprint(cfg["clientId"]) + ")",
		PollIntervalMs: interval,
	})
	if err != nil {
		a.receiverState = "not running: " + err.Error()
		fmt.Fprintf(os.Stderr, "ssf: the receiver did not start: %v\n", err)
		return
	}
	receiver.On("*", a.rememberLiveEvent)
	a.receiver = receiver
	if err := receiver.Start(); err != nil {
		a.receiver = nil
		a.receiverState = "not running: " + err.Error()
		fmt.Fprintf(os.Stderr, "ssf: the receiver did not start: %v\n", err)
		return
	}
	a.receiverState = fmt.Sprintf("polling stream %s at %s", sprint(receiver.Stream()["stream_id"]), sprint(ssf["transmitter"]))
}

func (a *app) signalHeaders(rp *oidc.RelyingParty) map[string]string {
	access, err := rp.ClientCredentials("ssf.manage")
	if err != nil {
		return map[string]string{}
	}
	return map[string]string{"authorization": "Bearer " + access.AccessToken}
}

func (a *app) state() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.receiverState
}

func (a *app) sessionOf(r *http.Request) (string, *session) {
	sid := cookieValue(r, cookieSession)
	a.mu.Lock()
	defer a.mu.Unlock()
	sess := a.sessions[sid]
	if sess == nil {
		return "", nil
	}
	if sess.Expires <= float64(time.Now().Unix()) {
		delete(a.sessions, sid)
		return "", nil
	}
	return sid, sess
}

func (a *app) cookie(name, value, path string, maxAge int) string {
	parts := []string{name + "=" + value, "Path=" + path, "HttpOnly", "SameSite=Lax"}
	if a.secureCookies {
		parts = append(parts, "Secure")
	}
	if maxAge >= 0 {
		parts = append(parts, fmt.Sprintf("Max-Age=%d", maxAge))
	}
	return strings.Join(parts, "; ")
}

func (a *app) send(w http.ResponseWriter, status int, body, contentType string, cookies []string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	for _, cookie := range cookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (a *app) redirect(w http.ResponseWriter, status int, location string, cookies []string) {
	w.Header().Set("Location", location)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Length", "0")
	for _, cookie := range cookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	w.WriteHeader(status)
}

// messageTemplate draws the demo's message pages. html/template escapes each
// value for the context it lands in, so an error text that carries quotes or
// markup (an authorization server's error_description, a JSON fragment) stays
// text.
var messageTemplate = template.Must(template.New("message").Parse(
	`<h1>{{.Heading}}</h1><p class="problem">{{.Problem}}</p>{{if .Link}}<p><a href="/">{{.Link}}</a></p>{{end}}`))

func message(heading, problem, link string) string {
	var out strings.Builder
	if err := messageTemplate.Execute(&out, struct{ Heading, Problem, Link string }{heading, problem, link}); err != nil {
		fmt.Fprintf(os.Stderr, "demo: message page: %v\n", err)
		return "<h1>Something went wrong</h1>"
	}
	return out.String()
}

func page(title, body string) string {
	return "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>" + html.EscapeString(title) + "</title><link rel=\"stylesheet\" href=\"/styles.css\"></head>\n<body><header><a href=\"/\">oidc-caep-risc demo</a></header><main>\n" + body + "\n</main><footer>A traditional web application signing in with OpenID Connect through oidc-caep-risc.</footer></body>\n</html>\n"
}

func (a *app) seal(value map[string]string) string {
	raw, _ := json.Marshal(value)
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + a.mac(body)
}

func (a *app) unseal(token string) map[string]string {
	if token == "" || !strings.Contains(token, ".") {
		return nil
	}
	body, tag, _ := strings.Cut(token, ".")
	if !hmac.Equal([]byte(a.mac(body)), []byte(tag)) {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

func (a *app) mac(value string) string {
	sum := hmac.New(sha256.New, a.secret)
	_, _ = sum.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum.Sum(nil))
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func randomToken() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func configDir(path string) string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "."
	}
	return path[:i]
}

func sprint(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func number(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}
