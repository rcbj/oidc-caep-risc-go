// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

package oidc

const (
	caepPrefix = "https://schemas.openid.net/secevent/caep/event-type/"
	riscPrefix = "https://schemas.openid.net/secevent/risc/event-type/"
	ssfPrefix  = "https://schemas.openid.net/secevent/ssf/event-type/"
)

// Event is the CAEP, RISC, and SSF event type each short name refers to.
var Event = map[string]string{
	"sessionRevoked":                  caepPrefix + "session-revoked",
	"tokenClaimsChange":               caepPrefix + "token-claims-change",
	"credentialChange":                caepPrefix + "credential-change",
	"assuranceLevelChange":            caepPrefix + "assurance-level-change",
	"deviceComplianceChange":          caepPrefix + "device-compliance-change",
	"sessionEstablished":              caepPrefix + "session-established",
	"sessionPresented":                caepPrefix + "session-presented",
	"riskLevelChange":                 caepPrefix + "risk-level-change",
	"accountCredentialChangeRequired": riscPrefix + "account-credential-change-required",
	"accountPurged":                   riscPrefix + "account-purged",
	"accountDisabled":                 riscPrefix + "account-disabled",
	"accountEnabled":                  riscPrefix + "account-enabled",
	"identifierChanged":               riscPrefix + "identifier-changed",
	"identifierRecycled":              riscPrefix + "identifier-recycled",
	"credentialCompromise":            riscPrefix + "credential-compromise",
	"optIn":                           riscPrefix + "opt-in",
	"optOutInitiated":                 riscPrefix + "opt-out-initiated",
	"optOutCancelled":                 riscPrefix + "opt-out-cancelled",
	"optOutEffective":                 riscPrefix + "opt-out-effective",
	"recoveryActivated":               riscPrefix + "recovery-activated",
	"recoveryInformationChanged":      riscPrefix + "recovery-information-changed",
	"sessionsRevoked":                 riscPrefix + "sessions-revoked",
	"verification":                    ssfPrefix + "verification",
	"streamUpdated":                   ssfPrefix + "stream-updated",
}

func eventsWithPrefix(prefix string) []string {
	order := []string{
		"sessionRevoked", "tokenClaimsChange", "credentialChange", "assuranceLevelChange",
		"deviceComplianceChange", "sessionEstablished", "sessionPresented", "riskLevelChange",
		"accountCredentialChangeRequired", "accountPurged", "accountDisabled", "accountEnabled",
		"identifierChanged", "identifierRecycled", "credentialCompromise", "optIn", "optOutInitiated",
		"optOutCancelled", "optOutEffective", "recoveryActivated", "recoveryInformationChanged",
		"sessionsRevoked", "verification", "streamUpdated",
	}
	var out []string
	for _, name := range order {
		if uri := Event[name]; len(uri) >= len(prefix) && uri[:len(prefix)] == prefix {
			out = append(out, uri)
		}
	}
	return out
}

// CAEPEvents and RISCEvents follow the order the event names were defined.
var (
	CAEPEvents = eventsWithPrefix(caepPrefix)
	RISCEvents = eventsWithPrefix(riscPrefix)
)

// DefaultEventsRequested is the poll stream's events_requested when the caller does not name one.
var DefaultEventsRequested = []string{
	Event["sessionRevoked"], Event["credentialChange"], Event["assuranceLevelChange"], Event["tokenClaimsChange"],
	Event["accountDisabled"], Event["accountEnabled"], Event["accountPurged"], Event["credentialCompromise"],
	Event["sessionsRevoked"], Event["accountCredentialChangeRequired"],
}

// DefaultEndingEvents end local sessions.
var DefaultEndingEvents = []string{
	Event["sessionRevoked"], Event["accountDisabled"], Event["accountPurged"],
	Event["credentialCompromise"], Event["sessionsRevoked"],
}

func present(document map[string]any, names ...string) any {
	if document == nil {
		return nil
	}
	for _, name := range names {
		if v, ok := document[name]; ok && v != nil {
			return v
		}
	}
	return nil
}

func simpleSubject(identifier map[string]any, issuer string) map[string]string {
	if identifier == nil {
		return map[string]string{}
	}
	fmtName := sprint(present(identifier, "format", "subject_type"))
	switch fmtName {
	case "iss_sub":
		sub, ok := identifier["sub"].(string)
		iss := identifier["iss"]
		if ok && (iss == nil || iss == issuer) {
			return map[string]string{"sub": sub}
		}
	case "email":
		if email, ok := identifier["email"].(string); ok {
			return map[string]string{"email": email}
		}
	case "opaque":
		if id, ok := identifier["id"].(string); ok {
			return map[string]string{"opaque": id}
		}
	case "aliases":
		list, ok := identifier["identifiers"].([]any)
		if !ok {
			return map[string]string{}
		}
		merged := map[string]string{}
		for _, one := range list {
			doc, ok := asMap(one)
			if !ok {
				continue
			}
			for k, v := range simpleSubject(doc, issuer) {
				merged[k] = v
			}
		}
		return merged
	}
	return map[string]string{}
}

// SubjectOf reads an event's subject. A complex subject's user is the person and its session the provider session.
func SubjectOf(subID map[string]any, issuer string) map[string]string {
	if subID == nil {
		return map[string]string{}
	}
	fmtName := sprint(present(subID, "format", "subject_type"))
	_, hasUser := subID["user"]
	_, hasSession := subID["session"]
	userVal, _ := asMap(subID["user"])
	sessionVal, _ := asMap(subID["session"])
	if fmtName == "complex" || (fmtName == "" && ((hasUser && subID["user"] != nil) || (hasSession && subID["session"] != nil))) {
		user := simpleSubject(userVal, issuer)
		session := simpleSubject(sessionVal, issuer)
		out := map[string]string{}
		if user["sub"] != "" {
			out["person"] = user["sub"]
		}
		if user["email"] != "" {
			out["email"] = user["email"]
		}
		sessionID := session["opaque"]
		if sessionID == "" {
			sessionID = session["sub"]
		}
		if sessionID != "" {
			out["idpSession"] = sessionID
		}
		return out
	}
	one := simpleSubject(subID, issuer)
	out := map[string]string{}
	if one["sub"] != "" {
		out["person"] = one["sub"]
	}
	if one["email"] != "" {
		out["email"] = one["email"]
	}
	return out
}
