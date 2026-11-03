// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

import "sync"

// SessionRefreshMargin is how much life a cached access token must have left
// for SessionAccessToken to return it without a refresh.
const SessionRefreshMargin = 30.0

// SessionStore holds the tokens of completed sign-ins, keyed by a session
// identifier the application chooses. Get answers nil and no error for a
// session it does not hold. The default is MemorySessionStore; an application
// that runs several processes replaces it with a shared store.
type SessionStore interface {
	Get(sessionID string) (*Login, error)
	Set(sessionID string, login *Login) error
	Delete(sessionID string) error
}

// MemorySessionStore is the default SessionStore: this process's memory.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Login
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: map[string]*Login{}}
}

func (m *MemorySessionStore) Get(sessionID string) (*Login, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	login := m.sessions[sessionID]
	if login == nil {
		return nil, nil
	}
	copied := *login
	return &copied, nil
}

func (m *MemorySessionStore) Set(sessionID string, login *Login) error {
	copied := *login
	m.mu.Lock()
	m.sessions[sessionID] = &copied
	m.mu.Unlock()
	return nil
}

func (m *MemorySessionStore) Delete(sessionID string) error {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	return nil
}

// Len is the number of sessions held.
func (m *MemorySessionStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

type sessionLock struct {
	mu   sync.Mutex
	refs int
}

// SetSessionStore replaces the session store. Call it before the first sign-in.
func (rp *RelyingParty) SetSessionStore(store SessionStore) {
	if store == nil {
		store = NewMemorySessionStore()
	}
	rp.mu.Lock()
	rp.store = store
	rp.mu.Unlock()
}

// SessionStore is the store CompleteSession writes to.
func (rp *RelyingParty) SessionStore() SessionStore {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return rp.store
}

// CompleteSession is Complete, and keeps the sign-in's tokens in the session
// store under sessionID. An empty sessionID makes a new handle. The handle is
// Login.Session either way.
func (rp *RelyingParty) CompleteSession(query map[string]string, txn *Transaction, sessionID string) (*Login, error) {
	login, err := rp.Complete(query, txn)
	if err != nil {
		return nil, err
	}
	if sessionID == "" {
		handle, err := RandomToken()
		if err != nil {
			return nil, errCause("session", err.Error(), err)
		}
		sessionID = handle
	}
	login.Session = sessionID
	if err := rp.SessionStore().Set(sessionID, login); err != nil {
		return nil, errCause("session", "the session store refused the sign-in: "+err.Error(), err)
	}
	return login, nil
}

// SessionAccessToken returns a valid access token for a session: the cached
// one while it has more than 30 seconds left, otherwise one obtained with the
// refresh token (with a DPoP proof when DPoP is in use), and the cache is
// updated. A failed refresh removes the session and is refused.
func (rp *RelyingParty) SessionAccessToken(sessionID string) (Access, error) {
	if sessionID == "" {
		return Access{}, errCode("session", "there is no session identifier")
	}
	unlock := rp.lockSession(sessionID)
	defer unlock()
	store := rp.SessionStore()
	login, err := store.Get(sessionID)
	if err != nil {
		return Access{}, errCause("session", "the session store could not be read: "+err.Error(), err)
	}
	if login == nil {
		return Access{}, errCode("session", "there is no such session")
	}
	if !login.HasExpires || login.ExpiresAt-nowSec() > SessionRefreshMargin {
		return accessOfLogin(login), nil
	}
	if login.RefreshToken == "" {
		_ = store.Delete(sessionID)
		return Access{}, errCode("session", "the session's access token has expired, and there is no refresh token")
	}
	refreshed, err := rp.Refresh(login.RefreshToken, "", login)
	if err != nil {
		_ = store.Delete(sessionID)
		refusal := errCause("session", "the session's refresh was refused: "+err.Error(), err)
		if oe, ok := err.(*OidcError); ok {
			refusal.OAuthError = oe.OAuthError
		}
		return Access{}, refusal
	}
	refreshed.Session = sessionID
	if err := store.Set(sessionID, refreshed); err != nil {
		return Access{}, errCause("session", "the session store refused the refreshed tokens: "+err.Error(), err)
	}
	return accessOfLogin(refreshed), nil
}

// Session is the sign-in a session holds, or nil.
func (rp *RelyingParty) Session(sessionID string) (*Login, error) {
	login, err := rp.SessionStore().Get(sessionID)
	if err != nil {
		return nil, errCause("session", "the session store could not be read: "+err.Error(), err)
	}
	return login, nil
}

// RemoveSession clears a session's tokens: sign-out, or a CAEP session-revoked.
func (rp *RelyingParty) RemoveSession(sessionID string) error {
	if sessionID == "" {
		return nil
	}
	if err := rp.SessionStore().Delete(sessionID); err != nil {
		return errCause("session", "the session store could not remove the session: "+err.Error(), err)
	}
	return nil
}

// lockSession serialises refreshes of one session in this process, so a
// rotated refresh token is not spent twice.
func (rp *RelyingParty) lockSession(sessionID string) func() {
	rp.mu.Lock()
	lock := rp.sessionLocks[sessionID]
	if lock == nil {
		lock = &sessionLock{}
		rp.sessionLocks[sessionID] = lock
	}
	lock.refs++
	rp.mu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		rp.mu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(rp.sessionLocks, sessionID)
		}
		rp.mu.Unlock()
	}
}

func accessOfLogin(login *Login) Access {
	return Access{
		AccessToken: login.AccessToken,
		TokenType:   login.TokenType,
		ExpiresAt:   login.ExpiresAt,
		HasExpires:  login.HasExpires,
		Scope:       login.Scope,
	}
}
