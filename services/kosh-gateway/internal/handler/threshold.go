package handler

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// deriveEvmAddress derives an Ethereum address from a compressed secp256k1 public key hex.
// EVM address = keccak256(uncompressed_pubkey[1:])[12:]   (i.e. keccak256(X || Y), last 20 bytes)
func deriveEvmAddress(combinedPkHex string) string {
	if len(combinedPkHex) == 0 {
		return ""
	}
	pkBytes, err := hex.DecodeString(combinedPkHex)
	if err != nil || len(pkBytes) != 33 {
		return ""
	}
	// Decompress the 33-byte compressed pubkey to (X, Y) coordinates.
	pub, err := secp256k1.ParsePubKey(pkBytes)
	if err != nil {
		return ""
	}
	xBytes := pub.X().Bytes()
	yBytes := pub.Y().Bytes()
	// Left-pad both X and Y to 32 bytes
	xy := make([]byte, 64)
	copy(xy[32-len(xBytes):32], xBytes)
	copy(xy[64-len(yBytes):64], yBytes)

	h := sha3.NewLegacyKeccak256()
	h.Write(xy)
	hash := h.Sum(nil)
	if len(hash) < 20 {
		return ""
	}
	return "0x" + hex.EncodeToString(hash[12:])
}

// GET /api/v1/threshold/key-status?key_id=&contract_address=
func (h *Handler) HandleThresholdKeyStatus(w http.ResponseWriter, r *http.Request) {
	keyID := r.URL.Query().Get("key_id")
	if keyID == "" {
		jsonError(w, "key_id required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	req := bbReq(fmt.Sprintf("dkg_complete_%s", keyID))
	resp, err := h.clients.Coord.Read(ctx, &req)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !resp.Found {
		json.NewEncoder(w).Encode(map[string]any{
			"key_id":          keyID,
			"exists":          false,
			"phase":           0,
			"verifiedTaskIds": []any{},
		})
		return
	}

	// value = "combined_pk=<hex>"
	combinedPk := resp.Value
	const prefix = "combined_pk="
	if len(combinedPk) > len(prefix) {
		combinedPk = combinedPk[len(prefix):]
	}

	json.NewEncoder(w).Encode(map[string]any{
		"key_id":          keyID,
		"exists":          true,
		"phase":           4,
		"combined_pk_hex": combinedPk,
		"evm_address":     deriveEvmAddress(combinedPk),
		"verifiedTaskIds": []any{},
	})
}

// GET /api/v1/threshold/task-signature?task_id=&key_id=&contract_address=
func (h *Handler) HandleThresholdTaskSignature(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		jsonError(w, "task_id required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	req := bbReq(fmt.Sprintf("sign_complete_%s", taskID))
	resp, err := h.clients.Coord.Read(ctx, &req)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if !resp.Found {
		json.NewEncoder(w).Encode(map[string]any{"signatureHex": nil})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"signatureHex": resp.Value})
}
