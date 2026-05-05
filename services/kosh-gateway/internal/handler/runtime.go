package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

type PreflightResponse struct {
	Mode        string `json:"mode"`         // "create" or "sign"
	Ready       bool   `json:"ready"`
	CoordOnline bool   `json:"coord_online"`
	PartiesUp   int    `json:"parties_up"`
	CheckedAt   string `json:"checked_at"`
}

// GET /api/v1/runtime/preflight?mode=create|sign
// Checks coordinator reachability and reports how many parties are up.
func (h *Handler) HandlePreflight(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "create"
	}

	coordOnline := false
	if h.clients.Coord != nil {
		coordOnline = true
	}

	partiesUp := len(h.clients.Parties)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(PreflightResponse{
		Mode:        mode,
		Ready:       coordOnline && partiesUp >= 2,
		CoordOnline: coordOnline,
		PartiesUp:   partiesUp,
		CheckedAt:   time.Now().UTC().Format(time.RFC3339),
	})
}

// GET /api/v1/runtime/active
// Returns currently running jobs and overall system readiness.
func (h *Handler) HandleRuntimeActive(w http.ResponseWriter, r *http.Request) {
	running := h.jobs.ListRunning()

	ids := make([]string, len(running))
	for i, j := range running {
		ids[i] = j.ID
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"running_jobs": ids,
		"count":        len(ids),
		"parties_up":   len(h.clients.Parties),
		"checked_at":   time.Now().UTC().Format(time.RFC3339),
	})
}
