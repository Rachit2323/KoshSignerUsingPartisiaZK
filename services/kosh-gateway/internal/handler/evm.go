package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	defaultSepoliaRPCURL  = "https://ethereum-sepolia-rpc.publicnode.com"
	defaultSepoliaChainID = 11155111
)

type buildTxBody struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
}

type broadcastSignedTxBody struct {
	SignedTxHex string `json:"signed_tx_hex"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  any             `json:"error"`
}

func (h *Handler) HandleBuildEthTransfer(w http.ResponseWriter, r *http.Request) {
	var body buildTxBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.From == "" || body.To == "" || body.Value == "" {
		jsonError(w, "from, to, and value are required", http.StatusBadRequest)
		return
	}

	nonceHex, err := callEthRPC("eth_getTransactionCount", []any{body.From, "latest"})
	if err != nil {
		jsonError(w, "load nonce: "+err.Error(), http.StatusBadGateway)
		return
	}
	gasPriceHex, err := callEthRPC("eth_gasPrice", []any{})
	if err != nil {
		jsonError(w, "load gas price: "+err.Error(), http.StatusBadGateway)
		return
	}
	gasHex, err := callEthRPC("eth_estimateGas", []any{map[string]any{
		"from":  body.From,
		"to":    body.To,
		"value": decimalToHex(body.Value),
	}})
	if err != nil {
		gasHex = "0x5208"
	}

	nonce, err := parseHexUint64(nonceHex)
	if err != nil {
		jsonError(w, "decode nonce: "+err.Error(), http.StatusBadGateway)
		return
	}

	payload := map[string]any{
		"transaction": map[string]any{
			"to":       body.To,
			"from":     body.From,
			"value":    body.Value,
			"nonce":    nonce,
			"gas":      parseHexBigIntString(gasHex),
			"gasPrice": parseHexBigIntString(gasPriceHex),
			"chainId":  defaultSepoliaChainID,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *Handler) HandleBroadcastSignedTx(w http.ResponseWriter, r *http.Request) {
	var body broadcastSignedTxBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.SignedTxHex) == "" {
		jsonError(w, "signed_tx_hex required", http.StatusBadRequest)
		return
	}

	txHash, err := callEthRPC("eth_sendRawTransaction", []any{normalizeHex(body.SignedTxHex)})
	if err != nil {
		fallbackHash, hashErr := pseudoTxHash(body.SignedTxHex)
		if hashErr != nil {
			jsonError(w, "broadcast failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tx_hash":   fallbackHash,
			"submitted": false,
			"error":     err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tx_hash":   txHash,
		"submitted": true,
	})
}

func callEthRPC(method string, params []any) (string, error) {
	rpcURL := os.Getenv("KOSH_SEPOLIA_RPC_URL")
	if rpcURL == "" {
		rpcURL = defaultSepoliaRPCURL
	}
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	resp, err := http.Post(rpcURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var decoded rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", err
	}
	if decoded.Error != nil {
		return "", fmt.Errorf("%v", decoded.Error)
	}
	var result string
	if err := json.Unmarshal(decoded.Result, &result); err != nil {
		return "", err
	}
	return result, nil
}

func parseHexUint64(value string) (uint64, error) {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if trimmed == "" {
		return 0, nil
	}
	return strconv.ParseUint(trimmed, 16, 64)
}

func parseHexBigIntString(value string) string {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "0x")
	if trimmed == "" {
		return "0"
	}
	n, err := strconv.ParseUint(trimmed, 16, 64)
	if err != nil {
		return "0"
	}
	return strconv.FormatUint(n, 10)
}

func decimalToHex(value string) string {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return "0x0"
	}
	return fmt.Sprintf("0x%x", n)
}

func normalizeHex(value string) string {
	if strings.HasPrefix(value, "0x") {
		return value
	}
	return "0x" + value
}

func pseudoTxHash(signedTxHex string) (string, error) {
	normalized := normalizeHex(signedTxHex)
	raw, err := hex.DecodeString(strings.TrimPrefix(normalized, "0x"))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "0x" + hex.EncodeToString(sum[:]), nil
}
