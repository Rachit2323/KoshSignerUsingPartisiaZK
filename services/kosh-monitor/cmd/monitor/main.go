package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/kosh/monitor/internal/contract"
	"github.com/kosh/monitor/internal/health"
	"github.com/kosh/monitor/internal/metrics"
)

func main() {
	port := getEnv("PORT", "9090")
	coordAddr := getEnv("COORDINATOR_ADDR", "localhost:50051")
	policyAddr := getEnv("POLICY_ADDR", "localhost:50052")
	gatewayAddr := getEnv("GATEWAY_ADDR", "localhost:8080")
	party1Addr := getEnv("PARTY_1_ADDR", "localhost:50060")
	party2Addr := getEnv("PARTY_2_ADDR", "localhost:50061")
	party3Addr := getEnv("PARTY_3_ADDR", "localhost:50062")
	nodeURL := getEnv("PARTISIA_NODE_URL", "")
	signerAddr := getEnv("SIGNER_ADDRESS", "")
	healthIntervalSecs, _ := strconv.Atoi(getEnv("HEALTH_INTERVAL_SECS", "15"))
	pollIntervalSecs, _ := strconv.Atoi(getEnv("POLL_INTERVAL_SECS", "30"))

	metrics.Register()

	// Start health checkers (goroutines, one per service)
	health.Start(health.Config{
		CoordinatorAddr: coordAddr,
		PolicyAddr:      policyAddr,
		GatewayAddr:     gatewayAddr,
		PartyAddrs:      []string{party1Addr, party2Addr, party3Addr},
		Interval:        time.Duration(healthIntervalSecs) * time.Second,
	})

	// Start contract state poller (only if configured)
	if nodeURL != "" && signerAddr != "" {
		poller := contract.NewPoller(
			nodeURL, signerAddr,
			time.Duration(pollIntervalSecs)*time.Second,
			func(state contract.ContractState) {
				log.Printf("[monitor] contract state fetched at %s: %d keys",
					state.FetchedAt.Format(time.RFC3339), len(state.RawState))
			},
		)
		poller.Start()
	}

	mux := http.NewServeMux()

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Health summary endpoint — JSON status of all services
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":      "ok",
			"coordinator": coordAddr,
			"policy":      policyAddr,
			"gateway":     gatewayAddr,
			"party1":      party1Addr,
			"party2":      party2Addr,
			"party3":      party3Addr,
		})
	})

	// Readiness probe
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	log.Printf("kosh-monitor listening on :%s (health every %ds, poll every %ds)",
		port, healthIntervalSecs, pollIntervalSecs)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
