// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import (
	"strings"
	"sync"
	"time"
)

// SessionIndex is one process's memory of local sessions, bounded: expired sessions go first, then the oldest.
type SessionIndex struct {
	mu       sync.Mutex
	max      int
	order    []string
	sessions map[string]map[string]any
}

func NewSessionIndex(maxSessions int) *SessionIndex {
	if maxSessions <= 0 {
		maxSessions = 100000
	}
	return &SessionIndex{max: maxSessions, sessions: map[string]map[string]any{}}
}

func (s *SessionIndex) Add(session map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	localID := sprint(session["local_id"])
	if len(s.sessions) >= s.max && s.sessions[localID] == nil {
		now := nowSec()
		kept := s.order[:0]
		for _, key := range s.order {
			value := s.sessions[key]
			if value == nil {
				continue
			}
			if exp, ok := stamp(value["expires_at"]); ok && exp <= now {
				delete(s.sessions, key)
				continue
			}
			kept = append(kept, key)
		}
		s.order = kept
		for len(s.sessions) >= s.max && len(s.order) > 0 {
			oldest := s.order[0]
			s.order = s.order[1:]
			delete(s.sessions, oldest)
		}
	}
	stored := map[string]any{}
	for k, v := range session {
		stored[k] = v
	}
	if email, ok := stored["email"].(string); ok && email != "" {
		stored["email"] = strings.ToLower(email)
	}
	if _, exists := s.sessions[localID]; !exists {
		s.order = append(s.order, localID)
	}
	s.sessions[localID] = stored
}

func (s *SessionIndex) Remove(localID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[localID]; !ok {
		return
	}
	delete(s.sessions, localID)
	kept := s.order[:0]
	for _, key := range s.order {
		if key != localID {
			kept = append(kept, key)
		}
	}
	s.order = kept
}

func (s *SessionIndex) find(match func(map[string]any) bool) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := nowSec()
	var out []string
	kept := s.order[:0]
	for _, key := range s.order {
		value := s.sessions[key]
		if value == nil {
			continue
		}
		if exp, ok := stamp(value["expires_at"]); ok && exp <= now {
			delete(s.sessions, key)
			continue
		}
		kept = append(kept, key)
		if match(value) {
			out = append(out, key)
		}
	}
	s.order = kept
	return out
}

func (s *SessionIndex) ByPerson(person string) []string {
	return s.find(func(session map[string]any) bool { return sprint(session["person"]) == person })
}

func (s *SessionIndex) ByEmail(email string) []string {
	wanted := strings.ToLower(email)
	return s.find(func(session map[string]any) bool { return sprint(session["email"]) == wanted })
}

func (s *SessionIndex) ByIDPSession(idpSession string) []string {
	return s.find(func(session map[string]any) bool { return sprint(session["idp_session"]) == idpSession })
}

func stamp(value any) (float64, bool) {
	if value == nil {
		return 0, false
	}
	if t, ok := value.(time.Time); ok {
		return float64(t.UnixNano()) / 1e9, true
	}
	return asFloat(value)
}

// TrackedFromLogin is what an OpenID Connect sign-in says about the session, for the index.
func TrackedFromLogin(localID string, login *Login, expiresAt *float64) map[string]any {
	session := map[string]any{"local_id": localID, "person": ""}
	if login != nil {
		session["person"] = login.Subject
		if login.Email != "" {
			session["email"] = login.Email
		}
		if login.SID != "" {
			session["idp_session"] = login.SID
		}
	}
	if expiresAt != nil {
		session["expires_at"] = *expiresAt
	}
	return session
}
