package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	party_pb "github.com/kosh/gateway/pb/party"
	policy_pb "github.com/kosh/gateway/pb/policy"
)

type SignRequest struct {
	KeyID         uint32   `json:"key_id"`
	MessageHashHex string  `json:"message_hash"`
	TxTag         string   `json:"tx_tag"`
	SigningSubset  []uint32 `json:"signing_subset"`
}

type SignResponse struct {
	Signature string `json:"signature"`
	KeyID     uint32 `json:"key_id"`
	TxTag     string `json:"tx_tag"`
}

// POST /api/v1/sign — validate policy, then fan-out StartSign to signing parties.
func (h *Handler) HandleSignPost(w http.ResponseWriter, r *http.Request) {
	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.KeyID == 0 {
		jsonError(w, "key_id required", http.StatusBadRequest)
		return
	}
	msgBytes, err := hexToBytes(req.MessageHashHex)
	if err != nil {
		jsonError(w, "invalid message_hash hex: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.SigningSubset) == 0 {
		// Default: all parties
		for i := 1; i <= len(h.clients.Parties); i++ {
			req.SigningSubset = append(req.SigningSubset, uint32(i))
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), signTimeout)
	defer cancel()

	// ── Policy check ───────────────────────────────────────────────────────────
	vResp, err := h.clients.Policy.Validate(ctx, &policy_pb.ValidateRequest{
		TxTag:          req.TxTag,
		SigningParties: req.SigningSubset,
	})
	if err != nil {
		jsonError(w, "policy service error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !vResp.Ok {
		jsonError(w, "policy violation: "+vResp.ViolationMessage, http.StatusUnprocessableEntity)
		return
	}

	// ── Fan-out StartSign to each party in the signing subset ─────────────────
	type result struct {
		partyIdx  uint32
		signature []byte
		err       error
	}
	results := make(chan result, len(req.SigningSubset))
	var wg sync.WaitGroup

	for _, partyIdx := range req.SigningSubset {
		if int(partyIdx) > len(h.clients.Parties) {
			jsonError(w, fmt.Sprintf("party %d not configured", partyIdx), http.StatusBadRequest)
			return
		}
		wg.Add(1)
		go func(pi uint32) {
			defer wg.Done()
			pc := h.clients.Parties[pi-1]
			stream, err := pc.StartSign(ctx, &party_pb.SignRequest{
				KeyId:         req.KeyID,
				MessageHash:   msgBytes,
				TxTag:         req.TxTag,
				SigningSubset:  req.SigningSubset,
			})
			if err != nil {
				results <- result{pi, nil, fmt.Errorf("party %d StartSign: %w", pi, err)}
				return
			}
			for {
				ev, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					results <- result{pi, nil, fmt.Errorf("party %d stream: %w", pi, err)}
					return
				}
				if ev.Phase == party_pb.SignEvent_SIGN_FAILED {
					results <- result{pi, nil, fmt.Errorf("party %d sign failed: %s", pi, ev.Message)}
					return
				}
				if ev.Phase == party_pb.SignEvent_SIGN_COMPLETE {
					results <- result{pi, ev.Signature, nil}
					return
				}
			}
			results <- result{pi, nil, nil}
		}(partyIdx)
	}

	go func() { wg.Wait(); close(results) }()

	// Collect — take signature from party 1 (the aggregator)
	var finalSig []byte
	for res := range results {
		if res.err != nil {
			jsonError(w, res.err.Error(), http.StatusInternalServerError)
			return
		}
		if res.partyIdx == 1 && len(res.signature) > 0 {
			finalSig = res.signature
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SignResponse{
		Signature: fmt.Sprintf("0x%x", finalSig),
		KeyID:     req.KeyID,
		TxTag:     req.TxTag,
	})
}

// GET /api/v1/sign/:id — read sign session status from coordinator.
func (h *Handler) HandleSignGet(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")
	ctx := r.Context()
	req2 := bbReq(fmt.Sprintf("sign_session_%s", sessionID))
	resp, err := h.clients.Coord.Read(ctx, &req2)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !resp.Found {
		json.NewEncoder(w).Encode(map[string]any{"session_id": sessionID, "status": "not_found"})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"session_id": sessionID, "status": "found", "data": resp.Value})
}
