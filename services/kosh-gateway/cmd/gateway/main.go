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

	h := handler.New(clients)
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /api/v1/health", h.HandleHealth)

	// Token issuance (no auth required — uses shared API key from env/header)
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

	// Protected routes
	mux.HandleFunc("POST /api/v1/keys", h.HandleKeysPost)
	mux.HandleFunc("GET /api/v1/keys/{id}", h.HandleKeysGet)
	mux.HandleFunc("POST /api/v1/sign", h.HandleSignPost)
	mux.HandleFunc("GET /api/v1/sign/{id}", h.HandleSignGet)
	mux.HandleFunc("POST /api/v1/policies", h.HandlePoliciesPost)
	mux.HandleFunc("GET /api/v1/policies", h.HandlePoliciesGet)
	mux.HandleFunc("DELETE /api/v1/policies/{id}", h.HandlePoliciesDelete)

	// Wrap everything in JWT middleware
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: auth.Middleware(cfg.JWTSecret)(mux),
	}

	log.Printf("kosh-gateway listening on :%s", cfg.Port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
