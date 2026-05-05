package handler

import (
	"context"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"

	party_pb "github.com/kosh/gateway/pb/party"
)

type DkgRequest struct {
	KeyID      uint32 `json:"key_id"`
	NumParties uint32 `json:"num_parties"`
	Threshold  uint32 `json:"threshold"`
}

type DkgResponse struct {
	KeyID        uint32 `json:"key_id"`
	CombinedPkHex string `json:"combined_pk_hex"`
	Status       string `json:"status"`
}

// POST /api/v1/keys — fan-out StartDkg to all parties in parallel goroutines.
func (h *Handler) HandleKeysPost(w http.ResponseWriter, r *http.Request) {
	var req DkgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.KeyID == 0 {
		jsonError(w, "key_id required", http.StatusBadRequest)
		return
	}
	if req.NumParties == 0 {
		req.NumParties = uint32(len(h.clients.Parties))
	}
	if req.Threshold == 0 {
		req.Threshold = req.NumParties/2 + 1
	}

	ctx, cancel := context.WithTimeout(r.Context(), dkgTimeout)
	defer cancel()

	type result struct {
		partyIdx int
		pkHex    string
		err      error
	}

	results := make(chan result, len(h.clients.Parties))
	var wg sync.WaitGroup

	for i, party := range h.clients.Parties {
		wg.Add(1)
		go func(idx int, pc party_pb.PartyServiceClient) {
			defer wg.Done()
			stream, err := pc.StartDkg(ctx, &party_pb.DkgRequest{
				KeyId:      req.KeyID,
				NumParties: req.NumParties,
				Threshold:  req.Threshold,
			})
			if err != nil {
				results <- result{idx, "", fmt.Errorf("party %d StartDkg: %w", idx+1, err)}
				return
			}
			// Drain stream — capture the DKG_COMPLETE message which contains combined_pk
			var lastPk string
			for {
				ev, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					results <- result{idx, "", fmt.Errorf("party %d stream: %w", idx+1, err)}
					return
				}
				if ev.Phase == party_pb.DkgEvent_DKG_FAILED {
					results <- result{idx, "", fmt.Errorf("party %d DKG failed: %s", idx+1, ev.Message)}
					return
				}
				if ev.Phase == party_pb.DkgEvent_DKG_COMPLETE {
					// message = "combined_pk=<hex>"
					lastPk = ev.Message
					break
				}
			}
			results <- result{idx, lastPk, nil}
		}(i, party)
	}

	go func() { wg.Wait(); close(results) }()

	var combinedPk string
	for res := range results {
		if res.err != nil {
			jsonError(w, res.err.Error(), http.StatusInternalServerError)
			return
		}
		if res.partyIdx == 0 {
			// Extract hex from "combined_pk=<hex>"
			msg := res.pkHex
			if len(msg) > len("combined_pk=") {
				combinedPk = msg[len("combined_pk="):]
			} else {
				combinedPk = msg
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DkgResponse{
		KeyID:        req.KeyID,
		CombinedPkHex: combinedPk,
		Status:       "complete",
	})
}

// GET /api/v1/keys/:id — read current state from coordinator bulletin board.
func (h *Handler) HandleKeysGet(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("id")
	if keyID == "" {
		jsonError(w, "key_id required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	req2 := bbReq(fmt.Sprintf("dkg_complete_%s", keyID))
	resp, err := h.clients.Coord.Read(ctx, &req2)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !resp.Found {
		json.NewEncoder(w).Encode(map[string]any{"key_id": keyID, "status": "not_found"})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"key_id": keyID, "status": "complete", "data": resp.Value})
}

// hexToBytes converts a hex string (with or without 0x prefix) to bytes.
func hexToBytes(s string) ([]byte, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	return hex.DecodeString(s)
}
