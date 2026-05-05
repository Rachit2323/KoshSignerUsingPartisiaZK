package handler

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// passkeyUser implements webauthn.User for a simple single-user setup.
type passkeyUser struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.id }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// PasskeyStore holds the single kosh user + in-progress sessions.
type PasskeyStore struct {
	mu          sync.RWMutex
	user        *passkeyUser
	regSession  *webauthn.SessionData
	authSession *webauthn.SessionData
	wauth       *webauthn.WebAuthn
}

func NewPasskeyStore(rpID, rpOrigin string) (*PasskeyStore, error) {
	wauth, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Kosh Signer",
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}
	return &PasskeyStore{
		wauth: wauth,
		user: &passkeyUser{
			id:   []byte("kosh-default-user"),
			name: "kosh",
		},
	}, nil
}

// POST /api/v1/passkeys/register/start
func (s *PasskeyStore) HandleRegisterStart(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	options, session, err := s.wauth.BeginRegistration(s.user)
	if err != nil {
		jsonError(w, "begin registration: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.regSession = session

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// POST /api/v1/passkeys/register/finish
func (s *PasskeyStore) HandleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.regSession == nil {
		jsonError(w, "no registration session in progress", http.StatusBadRequest)
		return
	}

	cred, err := s.wauth.FinishRegistration(s.user, *s.regSession, r)
	if err != nil {
		jsonError(w, "finish registration: "+err.Error(), http.StatusBadRequest)
		return
	}
	s.regSession = nil
	s.user.credentials = append(s.user.credentials, *cred)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "registered"})
}

// POST /api/v1/passkeys/auth/start
func (s *PasskeyStore) HandleAuthStart(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	options, session, err := s.wauth.BeginLogin(s.user)
	if err != nil {
		jsonError(w, "begin login: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.authSession = session

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// POST /api/v1/passkeys/auth/finish
func (s *PasskeyStore) HandleAuthFinish(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.authSession == nil {
		jsonError(w, "no auth session in progress", http.StatusBadRequest)
		return
	}

	cred, err := s.wauth.FinishLogin(s.user, *s.authSession, r)
	if err != nil {
		jsonError(w, "finish login: "+err.Error(), http.StatusUnauthorized)
		return
	}
	s.authSession = nil

	// Update stored credential (sign count)
	s.mu.Unlock()
	s.mu.Lock()
	for i, c := range s.user.credentials {
		if string(c.ID) == string(cred.ID) {
			s.user.credentials[i] = *cred
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "authenticated"})
}
