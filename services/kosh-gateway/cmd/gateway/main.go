package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/kosh/gateway/internal/auth"
	"github.com/kosh/gateway/internal/client"
	"github.com/kosh/gateway/internal/config"
	"github.com/kosh/gateway/internal/handler"
)

func main() {
	cfg := config.Load()

	partyAddrs := []string{cfg.Party1Addr, cfg.Party2Addr, cfg.Party3Addr}
	clients, err := client.Dial(cfg.CoordinatorAddr, cfg.PolicyAddr, partyAddrs)
	if err != nil {
		log.Fatalf("dial services: %v", err)
	}

	pk, err := handler.NewPasskeyStore(cfg.WebAuthnRPID, cfg.WebAuthnOrigin)
	if err != nil {
		log.Fatalf("init webauthn: %v", err)
	}

	h := handler.New(clients, pk)
	mux := http.NewServeMux()

	// ── Public endpoints (no JWT) ──────────────────────────────────────────────
	mux.HandleFunc("GET /api/v1/health", h.HandleHealth)

	// Token issuance (exchange API key → JWT)
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

	// WebAuthn passkey registration + auth (public — browser initiates before JWT exists)
	mux.HandleFunc("POST /api/v1/passkeys/register/start", pk.HandleRegisterStart)
	mux.HandleFunc("POST /api/v1/passkeys/register/finish", pk.HandleRegisterFinish)
	mux.HandleFunc("POST /api/v1/passkeys/auth/start", pk.HandleAuthStart)
	mux.HandleFunc("POST /api/v1/passkeys/auth/finish", pk.HandleAuthFinish)

	// ── Protected endpoints (JWT required) ────────────────────────────────────
	// DKG key generation
	mux.HandleFunc("POST /api/v1/keys", h.HandleKeysPost)
	mux.HandleFunc("GET /api/v1/keys/{id}", h.HandleKeysGet)

	// Signing
	mux.HandleFunc("POST /api/v1/sign", h.HandleSignPost)
	mux.HandleFunc("GET /api/v1/sign/{id}", h.HandleSignGet)

	// Policies
	mux.HandleFunc("POST /api/v1/policies", h.HandlePoliciesPost)
	mux.HandleFunc("GET /api/v1/policies", h.HandlePoliciesGet)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", h.HandlePoliciesDelete)

	// Job status (matches frontend GET /api/v1/jobs/:id)
	mux.HandleFunc("GET /api/v1/jobs/{id}", h.HandleJobGet)

	// Runtime status (matches frontend preflight + active checks)
	mux.HandleFunc("GET /api/v1/runtime/preflight", h.HandlePreflight)
	mux.HandleFunc("GET /api/v1/runtime/active", h.HandleRuntimeActive)

	// ── JWT middleware wraps all routes ───────────────────────────────────────
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: auth.Middleware(cfg.JWTSecret)(mux),
	}

	log.Printf("kosh-gateway listening on :%s  (WebAuthn RPID=%s, origin=%s)",
		cfg.Port, cfg.WebAuthnRPID, cfg.WebAuthnOrigin)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
