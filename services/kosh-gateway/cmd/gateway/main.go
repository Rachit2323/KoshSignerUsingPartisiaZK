package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/kosh/gateway/internal/auth"
	"github.com/kosh/gateway/internal/client"
	"github.com/kosh/gateway/internal/config"
	"github.com/kosh/gateway/internal/handler"
	"github.com/kosh/gateway/internal/middleware"
	"github.com/kosh/gateway/internal/session"
)

func main() {
	cfg := config.Load()

	partyAddrs := []string{cfg.Party1Addr, cfg.Party2Addr, cfg.Party3Addr}
	clients, err := client.Dial(cfg.CoordinatorAddr, cfg.PolicyAddr, partyAddrs)
	if err != nil {
		log.Fatalf("dial services: %v", err)
	}

	sess := session.New()

	pk, err := handler.NewPasskeyStore(cfg.WebAuthnRPID, cfg.WebAuthnOrigin, sess)
	if err != nil {
		log.Fatalf("init webauthn: %v", err)
	}

	h := handler.New(clients, pk, sess)
	mux := http.NewServeMux()

	// ── Public endpoints (no JWT) ──────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/health", h.HandleHealth)

	mux.HandleFunc("POST /api/v1/token", func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			apiKey = "default"
		}
		tok, err := auth.IssueToken(cfg.JWTSecret, apiKey)
		if err != nil {
			http.Error(w, `{"error":"token generation failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tok})
	})

	// WebAuthn passkey flows — public (browser initiates before JWT exists)
	mux.HandleFunc("POST /api/v1/passkeys/register/start", pk.HandleRegisterStart)
	mux.HandleFunc("POST /api/v1/passkeys/register/finish", pk.HandleRegisterFinish)
	mux.HandleFunc("POST /api/v1/passkeys/auth/start", pk.HandleAuthStart)
	mux.HandleFunc("POST /api/v1/passkeys/auth/finish", pk.HandleAuthFinish)

	// Passkey account — authenticated via x-kosh-session (not JWT)
	mux.HandleFunc("GET /api/v1/passkeys/me", h.HandlePasskeysMe)
	mux.HandleFunc("POST /api/v1/passkeys/select-key", h.HandlePasskeysSelectKey)
	mux.HandleFunc("POST /api/v1/passkeys/link-key", h.HandlePasskeysLinkKey)
	mux.HandleFunc("POST /api/v1/passkeys/create-key", h.HandlePasskeysCreateKey)
	mux.HandleFunc("POST /api/v1/passkeys/reuse-sign", h.HandlePasskeysReuseSign)

	// Runtime status
	mux.HandleFunc("GET /api/v1/runtime/preflight", h.HandlePreflight)
	mux.HandleFunc("GET /api/v1/runtime/active", h.HandleRuntimeActive)

	// ── JWT-protected endpoints ────────────────────────────────────────────────
	mux.HandleFunc("POST /api/v1/keys", h.HandleKeysPost)
	mux.HandleFunc("GET /api/v1/keys/{id}", h.HandleKeysGet)
	mux.HandleFunc("POST /api/v1/sign", h.HandleSignPost)
	mux.HandleFunc("GET /api/v1/sign/{id}", h.HandleSignGet)
	mux.HandleFunc("POST /api/v1/policies", h.HandlePoliciesPost)
	mux.HandleFunc("GET /api/v1/policies", h.HandlePoliciesGet)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", h.HandlePoliciesDelete)

	// Threshold contract state (read-only, public)
	mux.HandleFunc("GET /api/v1/threshold/key-status", h.HandleThresholdKeyStatus)
	mux.HandleFunc("GET /api/v1/threshold/task-signature", h.HandleThresholdTaskSignature)

	// Job polling
	mux.HandleFunc("GET /api/v1/jobs/{id}", h.HandleJobGet)

	// ── Middleware chain: CORS → JWT ───────────────────────────────────────────
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: middleware.CORS(auth.Middleware(cfg.JWTSecret)(mux)),
	}

	log.Printf("kosh-gateway listening on :%s  (WebAuthn RPID=%s origin=%s)",
		cfg.Port, cfg.WebAuthnRPID, cfg.WebAuthnOrigin)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
