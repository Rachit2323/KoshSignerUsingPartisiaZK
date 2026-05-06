package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	party_pb "github.com/kosh/gateway/pb/party"
	policy_pb "github.com/kosh/gateway/pb/policy"
	bb_pb "github.com/kosh/gateway/pb/bb"
)

type createKeyBody struct {
	ContractAddress string `json:"contract_address"`
	NumParties      uint32 `json:"num_parties"`
	KeyID           uint32 `json:"key_id"`
}

// POST /api/v1/passkeys/create-key
// Validates x-kosh-session, kicks off DKG in background, returns job immediately.
func (h *Handler) HandlePasskeysCreateKey(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("x-kosh-session")
	if _, ok := h.sessions.Get(tok); !ok {
		jsonError(w, "invalid session", http.StatusUnauthorized)
		return
	}

	var body createKeyBody
	json.NewDecoder(r.Body).Decode(&body)

	numParties := body.NumParties
	if numParties == 0 {
		numParties = uint32(len(h.clients.Parties))
	}
	keyID := body.KeyID
	if keyID == 0 {
		keyID = 1
	}
	threshold := numParties/2 + 1

	// Use timestamp-based key_id so each run gets fresh BB topics
	if keyID == 1 {
		keyID = uint32(time.Now().Unix() & 0xFFFF)
		if keyID == 0 {
			keyID = 1
		}
	}

	job := h.jobs.Create(newID(), "dkg")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), dkgTimeout)
		defer cancel()

		// Clear stale bulletin board state before starting DKG
		if h.clients.Coord != nil {
			h.clients.Coord.Clear(ctx, &bb_pb.ClearRequest{})
		}

		type res struct {
			idx   int
			pkHex string
			err   error
		}
		results := make(chan res, len(h.clients.Parties))
		var wg sync.WaitGroup

		for i, party := range h.clients.Parties {
			wg.Add(1)
			go func(idx int, pc party_pb.PartyServiceClient) {
				defer wg.Done()
				stream, err := pc.StartDkg(ctx, &party_pb.DkgRequest{
					KeyId: keyID, NumParties: numParties, Threshold: threshold,
				})
				if err != nil {
					results <- res{idx, "", fmt.Errorf("party %d: %w", idx+1, err)}
					return
				}
				for {
					ev, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						results <- res{idx, "", fmt.Errorf("party %d stream: %w", idx+1, err)}
						return
					}
					if ev.Phase == party_pb.DkgEvent_DKG_FAILED {
						results <- res{idx, "", fmt.Errorf("party %d DKG failed: %s", idx+1, ev.Message)}
						return
					}
					if ev.Phase == party_pb.DkgEvent_DKG_COMPLETE {
						results <- res{idx, ev.Message, nil}
						return
					}
				}
				results <- res{idx, "", nil}
			}(i, party)
		}
		go func() { wg.Wait(); close(results) }()

		var combinedPk string
		for r := range results {
			if r.err != nil {
				h.jobs.Fail(job.ID, r.err.Error())
				return
			}
			if r.idx == 0 {
				msg := r.pkHex
				const prefix = "combined_pk="
				if len(msg) > len(prefix) {
					combinedPk = msg[len(prefix):]
				} else {
					combinedPk = msg
				}
			}
		}

		evmAddr := deriveEvmAddress(combinedPk)
		if h.clients.Coord != nil {
			_, _ = h.clients.Coord.Post(ctx, &bb_pb.PostRequest{
				Topic: fmt.Sprintf("dkg_complete_%d", keyID),
				Value: fmt.Sprintf("combined_pk=%s", combinedPk),
			})
		}
		h.jobs.Complete(job.ID, map[string]any{
			"key_id":           keyID,
			"contract_address": body.ContractAddress,
			"combined_pk_hex":  combinedPk,
			"evm_address":      evmAddr,
		})
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"job": job})
}

type reuseSignBody struct {
	TxTag         string   `json:"tx_tag"`
	SigningParties []uint32 `json:"signing_parties"`
	Threshold     uint32   `json:"threshold"`
	MsgHashHex    string   `json:"msg_hash_hex"`
	SessionID     uint32   `json:"session_id"`
}

// POST /api/v1/passkeys/reuse-sign
// Validates x-kosh-session, kicks off threshold signing in background, returns job immediately.
func (h *Handler) HandlePasskeysReuseSign(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("x-kosh-session")
	account, ok := h.sessions.Get(tok)
	if !ok {
		jsonError(w, "invalid session", http.StatusUnauthorized)
		return
	}
	if account.SelectedKey == nil {
		jsonError(w, "no selected key for this passkey session", http.StatusBadRequest)
		return
	}

	var body reuseSignBody
	json.NewDecoder(r.Body).Decode(&body)

	if body.MsgHashHex == "" {
		jsonError(w, "msg_hash_hex required", http.StatusBadRequest)
		return
	}
	if len(body.SigningParties) == 0 {
		for i := 1; i <= len(h.clients.Parties); i++ {
			body.SigningParties = append(body.SigningParties, uint32(i))
		}
	}
	if body.SessionID == 0 {
		body.SessionID = account.SelectedKey.KeyID
	}

	msgBytes, err := hexToBytes(body.MsgHashHex)
	if err != nil {
		jsonError(w, "invalid msg_hash_hex: "+err.Error(), http.StatusBadRequest)
		return
	}

	selectedKeyID := account.SelectedKey.KeyID
	selectedContract := account.SelectedKey.ContractAddress
	selectedEvmAddress := account.SelectedKey.EvmAddress
	selectedPk := account.SelectedKey.CombinedPkHex

	job := h.jobs.Create(newID(), "sign")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), signTimeout)
		defer cancel()

		// Policy check
		vResp, err := h.clients.Policy.Validate(ctx, &policy_pb.ValidateRequest{
			TxTag: body.TxTag, SigningParties: body.SigningParties,
		})
		if err != nil || !vResp.Ok {
			msg := "policy error"
			if err != nil {
				msg = err.Error()
			} else {
				msg = vResp.ViolationMessage
			}
			h.jobs.Fail(job.ID, msg)
			return
		}

		type res struct {
			partyIdx  uint32
			signature []byte
			err       error
		}
		results := make(chan res, len(body.SigningParties))
		var wg sync.WaitGroup

		for _, pi := range body.SigningParties {
			if int(pi) > len(h.clients.Parties) {
				continue
			}
			wg.Add(1)
			go func(pIdx uint32) {
				defer wg.Done()
				pc := h.clients.Parties[pIdx-1]
				stream, err := pc.StartSign(ctx, &party_pb.SignRequest{
					KeyId: selectedKeyID, MessageHash: msgBytes,
					TxTag: body.TxTag, SigningSubset: body.SigningParties,
				})
				if err != nil {
					results <- res{pIdx, nil, fmt.Errorf("party %d: %w", pIdx, err)}
					return
				}
				for {
					ev, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						results <- res{pIdx, nil, fmt.Errorf("party %d stream: %w", pIdx, err)}
						return
					}
					if ev.Phase == party_pb.SignEvent_SIGN_FAILED {
						results <- res{pIdx, nil, fmt.Errorf("party %d failed: %s", pIdx, ev.Message)}
						return
					}
					if ev.Phase == party_pb.SignEvent_SIGN_COMPLETE {
						results <- res{pIdx, ev.Signature, nil}
						return
					}
				}
				results <- res{pIdx, nil, nil}
			}(pi)
		}
		go func() { wg.Wait(); close(results) }()

		var finalSig []byte
		var firstErr error
		for r := range results {
			if r.err != nil {
				if len(finalSig) > 0 {
					continue
				}
				if firstErr == nil {
					firstErr = r.err
				}
				continue
			}
			if r.partyIdx == 1 && len(r.signature) > 0 {
				finalSig = r.signature
				cancel()
				break
			}
		}
		if len(finalSig) == 0 {
			if firstErr != nil {
				h.jobs.Fail(job.ID, firstErr.Error())
			} else {
				h.jobs.Fail(job.ID, "signing did not produce a final signature")
			}
			return
		}

		h.jobs.Complete(job.ID, map[string]any{
			"signature_hex":    fmt.Sprintf("0x%x", finalSig),
			"key_id":           selectedKeyID,
			"contract_address": selectedContract,
			"evm_address":      selectedEvmAddress,
			"combined_pk_hex":  selectedPk,
			"task_id":          body.SessionID,
		})
		if h.clients.Coord != nil && body.SessionID != 0 && len(finalSig) > 0 {
			_, _ = h.clients.Coord.Post(ctx, &bb_pb.PostRequest{
				Topic: fmt.Sprintf("sign_complete_%d", body.SessionID),
				Value: fmt.Sprintf("0x%x", finalSig),
			})
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"job": job})
}
