// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

const pollMethod = "urn:ietf:rfc:8936"

// Logger receives receiver progress. The default writes a line.
type Logger interface {
	Info(message string)
	Warn(message string)
	Error(message string)
}

type stdLogger struct{}

func (stdLogger) Info(message string)  { fmt.Println(message) }
func (stdLogger) Warn(message string)  { fmt.Println(message) }
func (stdLogger) Error(message string) { fmt.Println(message) }

// SignalEvent is one event from a Security Event Token.
type SignalEvent struct {
	Type     string
	Payload  map[string]any
	Subject  map[string]string
	JTI      string
	Sessions []string
	Ended    bool
	IAT      *float64
	Txn      string
}

// ReceiverOptions are the optional parts of a SignalsReceiver.
// Client makes every call to the transmitter with Client's client-credentials
// token for Scope (default ssf.manage), with a DPoP proof when that token is
// DPoP-bound, and clears the session cache entry of every session an event
// ends. Headers, when Client is nil, supplies the headers instead.
type ReceiverOptions struct {
	TLS             map[string]string
	Client          *RelyingParty
	Scope           string
	Headers         func() map[string]string
	EventsRequested []string
	EndOn           []string
	Index           *SessionIndex
	Description     string
	PollIntervalMs  int
	MaxEvents       int
	Log             Logger
}

type flight struct {
	done     chan struct{}
	result   bool
	err      error
	finished bool
}

// SignalsReceiver finds or creates this application's poll stream and turns events into local sessions.
type SignalsReceiver struct {
	transmitter     string
	onEnd           func([]string, SignalEvent)
	tls             map[string]string
	client          *RelyingParty
	scope           string
	headers         func() map[string]string
	eventsRequested []string
	endOn           []string
	description     string
	pollMS          int
	maxEvents       int
	log             Logger
	index           *SessionIndex

	mu       sync.Mutex
	config   map[string]any
	stream   map[string]any
	keys     []map[string]any
	keysAt   float64
	running  bool
	ack      []string
	errs     map[string]map[string]string
	handlers map[string][]func(SignalEvent)
	inflight *flight
	stop     chan struct{}
	done     chan struct{}
}

func NewSignalsReceiver(transmitter string, onEnd func([]string, SignalEvent), opts ReceiverOptions) (*SignalsReceiver, error) {
	if onEnd == nil {
		return nil, errCode("config", "onEndSessions is required")
	}
	if transmitter == "" || !regexp.MustCompile(`^https?://`).MatchString(transmitter) {
		return nil, errCode("config", "transmitter must be an http(s) URL")
	}
	events := opts.EventsRequested
	if len(events) == 0 {
		events = append([]string(nil), DefaultEventsRequested...)
	} else {
		events = append([]string(nil), events...)
	}
	endOn := opts.EndOn
	if len(endOn) == 0 {
		endOn = append([]string(nil), DefaultEndingEvents...)
	} else {
		endOn = append([]string(nil), endOn...)
	}
	poll := opts.PollIntervalMs
	if poll <= 0 {
		poll = 5000
	}
	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = 50
	}
	log := opts.Log
	if log == nil {
		log = stdLogger{}
	}
	scope := opts.Scope
	if scope == "" {
		scope = "ssf.manage"
	}
	index := opts.Index
	if index == nil {
		index = NewSessionIndex(0)
	}
	return &SignalsReceiver{
		transmitter:     strings.TrimRight(transmitter, "/"),
		onEnd:           onEnd,
		tls:             opts.TLS,
		client:          opts.Client,
		scope:           scope,
		headers:         opts.Headers,
		eventsRequested: events,
		endOn:           endOn,
		description:     opts.Description,
		pollMS:          poll,
		maxEvents:       maxEvents,
		log:             log,
		index:           index,
		errs:            map[string]map[string]string{},
		handlers:        map[string][]func(SignalEvent){},
	}, nil
}

// Stream is the stream the receiver is polling, once started.
func (r *SignalsReceiver) Stream() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stream
}

func (r *SignalsReceiver) Track(session map[string]any) { r.index.Add(session) }

func (r *SignalsReceiver) Untrack(localID string) { r.index.Remove(localID) }

func (r *SignalsReceiver) On(eventType string, handler func(SignalEvent)) *SignalsReceiver {
	r.mu.Lock()
	r.handlers[eventType] = append(r.handlers[eventType], handler)
	r.mu.Unlock()
	return r
}

func (r *SignalsReceiver) call(method, rawURL string, body any) (int, any, string, error) {
	headers := map[string]string{"accept": "application/json"}
	if r.headers != nil {
		if extra := r.headers(); len(extra) > 0 {
			for k, v := range extra {
				headers[k] = v
			}
		}
	}
	var payload *string
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, "", errCause("ssf", err.Error(), err)
		}
		text := string(raw)
		payload = &text
		headers["content-type"] = "application/json"
	}
	var answer httpAnswer
	var err error
	if r.client != nil {
		access, ccErr := r.client.ClientCredentials(r.scope)
		if ccErr != nil {
			return 0, nil, "", ccErr
		}
		answer, err = r.client.resourceSend(method, rawURL, access.AccessToken, access.TokenType, headers, payload, r.tls, "ssf")
	} else {
		answer, err = send(rawURL, method, headers, payload, r.tls, "ssf")
	}
	if err != nil {
		return 0, nil, "", err
	}
	var parsed any
	if answer.Body != "" {
		decoded, decErr := decodeLoose([]byte(answer.Body))
		if decErr != nil {
			parsed = answer.Body
		} else {
			parsed = decoded
		}
	}
	return answer.Status, parsed, answer.Body, nil
}

func (r *SignalsReceiver) discover() (map[string]any, error) {
	urls := WellKnownURLs(r.transmitter, "ssf-configuration")
	last := fmtErr("ssf", "no transmitter configuration at %s", strings.Join(urls, " or "))
	for i, one := range urls {
		status, parsed, _, err := r.call("GET", one, nil)
		if err != nil {
			return nil, err
		}
		doc, _ := asMap(parsed)
		if status == 404 && i != len(urls)-1 {
			continue
		}
		if status != 200 || doc == nil || sprint(doc["configuration_endpoint"]) == "" || sprint(doc["jwks_uri"]) == "" {
			last = fmtErr("ssf", "%s answered %d without a usable transmitter configuration", one, status)
			continue
		}
		if methods, ok := asStringList(doc["delivery_methods_supported"]); ok && len(methods) > 0 && !containsString(methods, pollMethod) {
			return nil, errCode("ssf", "the transmitter does not offer poll delivery (RFC 8936)")
		}
		return doc, nil
	}
	return nil, last
}

func (r *SignalsReceiver) jwks(force bool) ([]map[string]any, error) {
	r.mu.Lock()
	if !force && len(r.keys) > 0 && nowSec()-r.keysAt < 3600 {
		keys := r.keys
		r.mu.Unlock()
		return keys, nil
	}
	uri := ""
	if r.config != nil {
		uri = sprint(r.config["jwks_uri"])
	}
	r.mu.Unlock()
	status, parsed, _, err := r.call("GET", uri, nil)
	if err != nil {
		return nil, err
	}
	doc, _ := asMap(parsed)
	list, _ := doc["keys"].([]any)
	if status != 200 || list == nil {
		return nil, fmtErr("ssf", "the transmitter's JWKS answered %d", status)
	}
	keys := make([]map[string]any, 0, len(list))
	for _, item := range list {
		key, ok := asMap(item)
		if !ok {
			return nil, fmtErr("ssf", "the transmitter's JWKS answered %d", status)
		}
		keys = append(keys, key)
	}
	r.mu.Lock()
	r.keys = keys
	r.keysAt = nowSec()
	r.mu.Unlock()
	return keys, nil
}

func (r *SignalsReceiver) ensureStream() (map[string]any, error) {
	endpoint := sprint(r.config["configuration_endpoint"])
	status, parsed, _, err := r.call("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	if status == 200 {
		var all []any
		switch t := parsed.(type) {
		case []any:
			all = t
		case nil:
		default:
			all = []any{t}
		}
		for _, item := range all {
			stream, ok := asMap(item)
			if !ok {
				continue
			}
			delivery, _ := asMap(stream["delivery"])
			if sprint(delivery["method"]) == pollMethod && sprint(stream["stream_id"]) != "" {
				return stream, nil
			}
		}
	} else if status != 404 {
		return nil, fmtErr("ssf", "listing the streams at %s answered %d: %s", endpoint, status, clip(jsonCompact(parsed), 300))
	}
	body := map[string]any{"delivery": map[string]any{"method": pollMethod}, "events_requested": r.eventsRequested}
	if r.description != "" {
		body["description"] = r.description
	}
	createdStatus, created, _, err := r.call("POST", endpoint, body)
	if err != nil {
		return nil, err
	}
	stream, _ := asMap(created)
	if (createdStatus != 200 && createdStatus != 201) || sprint(stream["stream_id"]) == "" {
		return nil, fmtErr("ssf", "creating a stream at %s answered %d: %s", endpoint, createdStatus, clip(jsonCompact(created), 300))
	}
	return stream, nil
}

// Start finds the transmitter and the stream, then polls until Stop.
func (r *SignalsReceiver) Start() error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	cfg, err := r.discover()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.config = cfg
	r.mu.Unlock()
	if _, err := r.jwks(true); err != nil {
		return err
	}
	stream, err := r.ensureStream()
	if err != nil {
		return err
	}
	delivery, _ := asMap(stream["delivery"])
	if sprint(delivery["endpoint_url"]) == "" {
		return errCode("ssf", "the stream has no poll endpoint_url")
	}
	delivered, _ := stream["events_delivered"].([]any)
	r.log.Info(fmt.Sprintf("ssf: polling stream %s at %s, delivering %d event type(s)", sprint(stream["stream_id"]), sprint(delivery["endpoint_url"]), len(delivered)))
	r.mu.Lock()
	if r.running {
		r.stream = stream
		r.mu.Unlock()
		return nil
	}
	r.stream = stream
	r.running = true
	r.stop = make(chan struct{})
	r.done = make(chan struct{})
	done := r.done
	stop := r.stop
	r.mu.Unlock()
	go func() {
		defer close(done)
		r.loop(stop)
	}()
	return nil
}

// Stop stops polling. Acknowledgements not yet sent go out on the next Start's first poll.
// It waits until the poll loop has left, so a later PollOnce is not the poll Start already had in flight.
func (r *SignalsReceiver) Stop() {
	r.mu.Lock()
	r.running = false
	stop := r.stop
	done := r.done
	if stop != nil {
		select {
		case <-stop:
		default:
			close(stop)
		}
	}
	r.mu.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
	}
	r.mu.Lock()
	if r.done == done {
		r.done = nil
	}
	r.mu.Unlock()
}

func (r *SignalsReceiver) loop(stop <-chan struct{}) {
	for {
		r.mu.Lock()
		running := r.running
		interval := r.pollMS
		r.mu.Unlock()
		if !running {
			return
		}
		delay := time.Duration(interval) * time.Millisecond
		more, err := r.PollOnce()
		if err != nil {
			r.log.Warn("ssf: poll failed: " + err.Error())
			backoff := interval * 4
			if backoff > 60000 {
				backoff = 60000
			}
			delay = time.Duration(backoff) * time.Millisecond
		} else if more {
			delay = 0
		}
		r.mu.Lock()
		running = r.running
		r.mu.Unlock()
		if !running {
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// PollOnce is one poll. A call while a poll is in flight joins it.
func (r *SignalsReceiver) PollOnce() (bool, error) {
	r.mu.Lock()
	if r.inflight == nil || r.inflight.finished {
		f := &flight{done: make(chan struct{})}
		r.inflight = f
		go func() {
			result, err := r.pollNow()
			r.mu.Lock()
			f.result = result
			f.err = err
			f.finished = true
			close(f.done)
			r.mu.Unlock()
		}()
	}
	f := r.inflight
	r.mu.Unlock()
	<-f.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return f.result, f.err
}

func (r *SignalsReceiver) pollNow() (bool, error) {
	r.mu.Lock()
	stream := r.stream
	ack := append([]string(nil), r.ack...)
	r.ack = nil
	setErrs := r.errs
	r.errs = map[string]map[string]string{}
	r.mu.Unlock()
	delivery, _ := asMap(stream["delivery"])
	endpoint := sprint(delivery["endpoint_url"])
	body := map[string]any{"maxEvents": r.maxEvents, "returnImmediately": true}
	if len(ack) > 0 {
		body["ack"] = ack
	}
	if len(setErrs) > 0 {
		body["setErrs"] = setErrs
	}
	status, parsed, raw, err := r.call("POST", endpoint, body)
	if err != nil {
		r.restore(ack, setErrs)
		return false, err
	}
	if status != 200 {
		r.restore(ack, setErrs)
		return false, fmtErr("ssf", "the poll answered %d: %s", status, clip(jsonCompact(parsed), 300))
	}
	sets := orderedStringMap(raw, "sets")
	doc, _ := asMap(parsed)
	for _, jti := range sets.order {
		token := sets.values[jti]
		if handleErr := r.handle(jti, token); handleErr != nil {
			description := handleErr.Error()
			r.log.Warn("ssf: SET " + jti + " refused: " + description)
			errCodeName := "invalid_request"
			if oe, ok := handleErr.(*OidcError); ok && oe.Code == "signature" {
				errCodeName = "invalid_key"
			}
			r.mu.Lock()
			r.errs[jti] = map[string]string{"err": errCodeName, "description": description}
			r.mu.Unlock()
			continue
		}
		r.mu.Lock()
		r.ack = append(r.ack, jti)
		r.mu.Unlock()
	}
	return isExactTrue(doc["moreAvailable"]), nil
}

func (r *SignalsReceiver) restore(ack []string, setErrs map[string]map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ack = append(append([]string(nil), ack...), r.ack...)
	if r.errs == nil {
		r.errs = map[string]map[string]string{}
	}
	for k, v := range setErrs {
		if _, ok := r.errs[k]; !ok {
			r.errs[k] = v
		}
	}
}

type orderedMap struct {
	order  []string
	values map[string]string
}

func orderedStringMap(raw, key string) orderedMap {
	out := orderedMap{values: map[string]string{}}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return out
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return out
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return out
		}
		name, _ := keyTok.(string)
		if name != key {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return out
			}
			continue
		}
		objTok, err := dec.Token()
		if err != nil {
			return out
		}
		if delim, ok := objTok.(json.Delim); !ok || delim != '{' {
			return out
		}
		for dec.More() {
			jt, err := dec.Token()
			if err != nil {
				return out
			}
			jti, _ := jt.(string)
			var token string
			if err := dec.Decode(&token); err != nil {
				return out
			}
			out.order = append(out.order, jti)
			out.values[jti] = token
		}
		_, _ = dec.Token()
		return out
	}
	return out
}

func (r *SignalsReceiver) handle(jti, token string) error {
	keys, err := r.jwks(false)
	if err != nil {
		return err
	}
	header, payload, err := VerifyCompactJWS(token, keys)
	if err != nil {
		if oe, ok := err.(*OidcError); ok && oe.Code == "signature" && (strings.Contains(oe.Message, "publishes no") || strings.Contains(oe.Message, "does not verify")) {
			keys, keyErr := r.jwks(true)
			if keyErr != nil {
				return err
			}
			header, payload, err = VerifyCompactJWS(token, keys)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}
	if header["typ"] != nil && strings.ToLower(sprint(header["typ"])) != "secevent+jwt" {
		return fmtErr("validation", "the SET's typ is %v", header["typ"])
	}
	r.mu.Lock()
	issuer := sprint(r.config["issuer"])
	stream := r.stream
	r.mu.Unlock()
	if payload["iss"] != issuer {
		return fmtErr("validation", "the SET was issued by %v, not %s", payload["iss"], issuer)
	}
	rawAud := stream["aud"]
	var want []string
	if list, ok := rawAud.([]any); ok {
		for _, item := range list {
			want = append(want, sprint(item))
		}
	} else if rawAud != nil && sprint(rawAud) != "" {
		want = []string{sprint(rawAud)}
	}
	got := payload["aud"]
	var aud []string
	if list, ok := got.([]any); ok {
		for _, item := range list {
			aud = append(aud, sprint(item))
		}
	} else if got != nil {
		aud = []string{sprint(got)}
	}
	if len(want) > 0 && !overlaps(aud, want) {
		return fmtErr("validation", "the SET is for %s, not this stream", strings.Join(aud, ", "))
	}
	if payload["jti"] != nil && payload["jti"] != jti {
		return errCode("validation", "the SET's jti is not the one it was delivered under")
	}
	events, ok := asMap(payload["events"])
	if !ok || len(events) == 0 {
		return errCode("validation", "the SET carries no events")
	}
	for eventType, body := range events {
		bodyMap, _ := asMap(body)
		var subjectSrc map[string]any
		if payload["sub_id"] != nil {
			subjectSrc, _ = asMap(payload["sub_id"])
		} else if bodyMap != nil {
			subjectSrc, _ = asMap(bodyMap["subject"])
		}
		subject := SubjectOf(subjectSrc, issuer)
		sessions := r.sessionsFor(eventType, subject)
		ends := containsString(r.endOn, eventType) && len(sessions) > 0
		event := SignalEvent{
			Type:     eventType,
			Payload:  bodyMap,
			Subject:  subject,
			JTI:      jti,
			Sessions: append([]string(nil), sessions...),
			Ended:    ends,
		}
		if event.Payload == nil {
			event.Payload = map[string]any{}
		}
		if iat, ok := asFloat(payload["iat"]); ok {
			event.IAT = &iat
		}
		if txn, ok := payload["txn"].(string); ok {
			event.Txn = txn
		}
		if ends {
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						r.log.Error(fmt.Sprintf("ssf: onEndSessions threw for %s (SET %s is still acknowledged): %v", eventType, jti, recovered))
						event.Ended = false
					}
				}()
				r.onEnd(event.Sessions, event)
			}()
			if event.Ended {
				for _, localID := range sessions {
					r.index.Remove(localID)
					if r.client != nil {
						if err := r.client.RemoveSession(localID); err != nil {
							r.log.Warn("ssf: the session cache entry for an ended session was not removed: " + err.Error())
						}
					}
				}
			}
		}
		r.mu.Lock()
		handlers := append([]func(SignalEvent){}, r.handlers[eventType]...)
		star := append([]func(SignalEvent){}, r.handlers["*"]...)
		r.mu.Unlock()
		for _, handler := range append(handlers, star...) {
			func(handler func(SignalEvent)) {
				defer func() {
					if recovered := recover(); recovered != nil {
						r.log.Error(fmt.Sprintf("ssf: a handler for %s threw (SET %s is still acknowledged): %v", eventType, jti, recovered))
					}
				}()
				handler(event)
			}(handler)
		}
	}
	return nil
}

func overlaps(got, want []string) bool {
	for _, one := range got {
		if containsString(want, one) {
			return true
		}
	}
	return false
}

func (r *SignalsReceiver) sessionsFor(eventType string, subject map[string]string) []string {
	if eventType == Event["verification"] || eventType == Event["streamUpdated"] {
		return []string{}
	}
	if subject["idpSession"] != "" {
		found := r.index.ByIDPSession(subject["idpSession"])
		if len(found) > 0 || eventType == Event["sessionRevoked"] {
			return found
		}
	}
	if subject["person"] != "" {
		return r.index.ByPerson(subject["person"])
	}
	if subject["email"] != "" {
		return r.index.ByEmail(subject["email"])
	}
	return []string{}
}

// Verify asks the transmitter for a verification event.
func (r *SignalsReceiver) Verify(state string) error {
	r.mu.Lock()
	endpoint := ""
	if r.config != nil {
		endpoint = sprint(r.config["verification_endpoint"])
	}
	streamID := sprint(r.stream["stream_id"])
	r.mu.Unlock()
	if endpoint == "" {
		return errCode("ssf", "the transmitter publishes no verification_endpoint")
	}
	body := map[string]any{"stream_id": streamID}
	if state != "" {
		body["state"] = state
	}
	status, _, _, err := r.call("POST", endpoint, body)
	if err != nil {
		return err
	}
	if status != 200 && status != 204 {
		return fmtErr("ssf", "verification answered %d", status)
	}
	return nil
}
