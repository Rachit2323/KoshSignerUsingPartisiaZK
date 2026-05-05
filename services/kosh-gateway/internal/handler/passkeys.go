package handler

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/kosh/gateway/internal/session"
)

// passkeyUser implements webauthn.User.
type passkeyUser struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.id }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// pendingSession holds the WebAuthn session data between start and finish calls.
type pendingSession struct {
	id      string
	waData  *webauthn.SessionData
	regBody *registerStartBody // only set during registration
}

// PasskeyStore manages WebAuthn state + in-progress ceremony sessions.
type PasskeyStore struct {
	mu          sync.Mutex
	user        *passkeyUser
	pendingRegs  map[string]*pendingSession  // registration_id → session
	pendingAuths map[string]*pendingSession  // authentication_id → session
	wauth       *webauthn.WebAuthn
	sessions    *session.Store
}

type registerStartBody struct {
	Label           string  `json:"label"`
	ContractAddress *string `json:"contract_address"`
	KeyID           *uint32 `json:"key_id"`
}

func NewPasskeyStore(rpID, rpOrigin string, sessions *session.Store) (*PasskeyStore, error) {
	wauth, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Kosh Signer",
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}
	return &PasskeyStore{
		wauth:        wauth,
		sessions:     sessions,
		pendingRegs:  make(map[string]*pendingSession),
		pendingAuths: make(map[string]*pendingSession),
		user: &passkeyUser{
			id:   []byte("kosh-default-user"),
			name: "kosh",
		},
	}, nil
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// POST /api/v1/passkeys/register/start
func (s *PasskeyStore) HandleRegisterStart(w http.ResponseWriter, r *http.Request) {
	var body registerStartBody
	json.NewDecoder(r.Body).Decode(&body)

	s.mu.Lock()
	defer s.mu.Unlock()

	options, waSession, err := s.wauth.BeginRegistration(s.user)
	if err != nil {
		jsonError(w, "begin registration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	regID := newID()
	s.pendingRegs[regID] = &pendingSession{id: regID, waData: waSession, regBody: &body}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"registration_id": regID,
		"options":         options,
	})
}

// POST /api/v1/passkeys/register/finish
func (s *PasskeyStore) HandleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	// Read full body once.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Frontend sends { registration_id, credential: { id, rawId, type, response: {...} } }
	// WebAuthn library expects the body to be just the credential object directly.
	var envelope struct {
		RegistrationID string          `json:"registration_id"`
		Credential     json.RawMessage `json:"credential"`
	}
	json.Unmarshal(bodyBytes, &envelope)

	regID := r.URL.Query().Get("registration_id")
	if regID == "" {
		regID = envelope.RegistrationID
	}

	// Use credential sub-object as the body if present, otherwise use full body (fallback).
	credBody := bodyBytes
	if len(envelope.Credential) > 0 {
		credBody = envelope.Credential
	}
	r.Body = io.NopCloser(bytes.NewReader(credBody))

	s.mu.Lock()
	pending, ok := s.pendingRegs[regID]
	if !ok {
		s.mu.Unlock()
		jsonError(w, "unknown registration_id", http.StatusBadRequest)
		return
	}
	delete(s.pendingRegs, regID)
	s.mu.Unlock()

	cred, err := s.wauth.FinishRegistration(s.user, *pending.waData, r)
	if err != nil {
		jsonError(w, "finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.user.credentials = append(s.user.credentials, *cred)
	s.mu.Unlock()

	label := "My Key"
	if pending.regBody != nil && pending.regBody.Label != "" {
		label = pending.regBody.Label
	}

	acct := &session.Account{
		AccountID:  newID(),
		Label:      label,
		LinkedKeys: []session.LinkedKey{},
	}
	tok, err := s.sessions.NewToken(acct)
	if err != nil {
		jsonError(w, "session error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"session_token": tok,
		"account":       acct,
	})
}

// POST /api/v1/passkeys/auth/start
func (s *PasskeyStore) HandleAuthStart(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	options, waSession, err := s.wauth.BeginLogin(s.user)
	if err != nil {
		jsonError(w, "begin login: "+err.Error(), http.StatusInternalServerError)
		return
	}

	authID := newID()
	s.pendingAuths[authID] = &pendingSession{id: authID, waData: waSession}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"authentication_id": authID,
		"options":           options,
	})
}

// POST /api/v1/passkeys/auth/finish
func (s *PasskeyStore) HandleAuthFinish(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Frontend sends { authentication_id, credential: { id, rawId, type, response: {...} } }
	var envelope struct {
		AuthenticationID string          `json:"authentication_id"`
		Credential       json.RawMessage `json:"credential"`
	}
	json.Unmarshal(bodyBytes, &envelope)

	authID := r.URL.Query().Get("authentication_id")
	if authID == "" {
		authID = envelope.AuthenticationID
	}

	// Use credential sub-object as the body for webauthn.
	credBody := bodyBytes
	if len(envelope.Credential) > 0 {
		credBody = envelope.Credential
	}
	r.Body = io.NopCloser(bytes.NewReader(credBody))

	s.mu.Lock()
	pending, ok := s.pendingAuths[authID]
	if !ok {
		s.mu.Unlock()
		jsonError(w, "unknown authentication_id", http.StatusBadRequest)
		return
	}
	delete(s.pendingAuths, authID)
	s.mu.Unlock()

	cred, err := s.wauth.FinishLogin(s.user, *pending.waData, r)
	if err != nil {
		jsonError(w, "finish login: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// Update stored credential sign count
	s.mu.Lock()
	for i, c := range s.user.credentials {
		if string(c.ID) == string(cred.ID) {
			s.user.credentials[i] = *cred
			break
		}
	}
	s.mu.Unlock()

	acct := &session.Account{
		AccountID:  newID(),
		Label:      "kosh",
		LinkedKeys: []session.LinkedKey{},
	}
	tok, err := s.sessions.NewToken(acct)
	if err != nil {
		jsonError(w, "session error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"session_token": tok,
		"account":       acct,
	})
}

// GET /api/v1/passkeys/me
func (h *Handler) HandlePasskeysMe(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("x-kosh-session")
	if tok == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"me": map[string]any{"authenticated": false}})
		return
	}
	acct, ok := h.sessions.Get(tok)
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		json.NewEncoder(w).Encode(map[string]any{"me": map[string]any{"authenticated": false}})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"me": map[string]any{
			"authenticated": true,
			"account":       acct,
		},
	})
}

// POST /api/v1/passkeys/select-key
func (h *Handler) HandlePasskeysSelectKey(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("x-kosh-session")
	var body struct {
		ContractAddress string `json:"contract_address"`
		KeyID           uint32 `json:"key_id"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	ok := h.sessions.Update(tok, func(acct *session.Account) {
		for i, k := range acct.LinkedKeys {
			if k.ContractAddress == body.ContractAddress && k.KeyID == body.KeyID {
				acct.SelectedKey = &acct.LinkedKeys[i]
				return
			}
		}
	})
	if !ok {
		jsonError(w, "invalid session", http.StatusUnauthorized)
		return
	}
	acct, _ := h.sessions.Get(tok)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"account": acct})
}

// POST /api/v1/passkeys/link-key
func (h *Handler) HandlePasskeysLinkKey(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("x-kosh-session")
	var body struct {
		ContractAddress string `json:"contract_address"`
		KeyID           uint32 `json:"key_id"`
		Label           string `json:"label"`
		CombinedPkHex   string `json:"combined_pk_hex"`
		EvmAddress      string `json:"evm_address"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	ok := h.sessions.Update(tok, func(acct *session.Account) {
		lk := session.LinkedKey{
			ContractAddress: body.ContractAddress,
			KeyID:           body.KeyID,
			Label:           body.Label,
			CombinedPkHex:   body.CombinedPkHex,
			EvmAddress:      body.EvmAddress,
		}
		acct.LinkedKeys = append(acct.LinkedKeys, lk)
		acct.SelectedKey = &acct.LinkedKeys[len(acct.LinkedKeys)-1]
	})
	if !ok {
		jsonError(w, "invalid session", http.StatusUnauthorized)
		return
	}
	acct, _ := h.sessions.Get(tok)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"account": acct})
}
