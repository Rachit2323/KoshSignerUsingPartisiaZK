package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// GET /api/v1/runtime/preflight?mode=create|sign&contract_address=&key_id=
// Returns the shape the frontend expects (RuntimePreflight type in main.ts).
func (h *Handler) HandlePreflight(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "create"
	}

	coordOnline := h.clients.Coord != nil
	partiesUp := len(h.clients.Parties)
	ready := coordOnline && partiesUp >= 2

	// Check if a key exists by reading the bulletin board for the given key_id
	keyExists := false
	keyID := r.URL.Query().Get("key_id")
	if keyID != "" && coordOnline {
		req := bbReq("dkg_complete_" + keyID)
		if resp, err := h.clients.Coord.Read(r.Context(), &req); err == nil {
			keyExists = resp.Found
		}
	}

	w.Header().Set("Content-Type", "application/json")
	canCreate := ready
	canSign := ready && keyExists
	message := ""
	if !ready {
		message = "Local signing services are not fully available."
	} else if !keyExists && mode == "sign" {
		message = "Key is not loaded on this backend. Create it again on this backend first."
	}

	json.NewEncoder(w).Encode(map[string]any{
		"preflight": map[string]any{
			"ok":                    ready,
			"backend_reachable":     true,
			"relay_configured":      coordOnline,
			"sender_address":        "",
			"sender_gas_balance":    "0",
			"sender_gas_ok":         true,
			"local_runtime_present": true,
			"key_exists_onchain":    keyExists,
			"can_create":            canCreate,
			"can_sign":              canSign,
			"message":               message,
			"checked_at":            time.Now().UTC().Format(time.RFC3339),
		},
	})
}

// GET /api/v1/runtime/active
// Returns currently running jobs and overall system readiness.
func (h *Handler) HandleRuntimeActive(w http.ResponseWriter, r *http.Request) {
	running := h.jobs.ListRunning()

	type jobSummary struct {
		ID     string    `json:"id"`
		Type   string    `json:"type"`
		Status JobStatus `json:"status"`
	}
	summaries := make([]jobSummary, len(running))
	for i, j := range running {
		summaries[i] = jobSummary{ID: j.ID, Type: j.Type, Status: j.Status}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"ok":           true,
		"runtime":      map[string]any{"running_jobs": summaries, "parties_up": len(h.clients.Parties)},
		"checked_at":   time.Now().UTC().Format(time.RFC3339),
	})
}
