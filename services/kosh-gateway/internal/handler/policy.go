package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	policy_pb "github.com/kosh/gateway/pb/policy"
)

// POST /api/v1/policies
func (h *Handler) HandlePoliciesPost(w http.ResponseWriter, r *http.Request) {
	var p policy_pb.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := h.clients.Policy.AddPolicy(r.Context(), &policy_pb.AddPolicyRequest{Policy: &p})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"id": resp.Id})
}

// GET /api/v1/policies
func (h *Handler) HandlePoliciesGet(w http.ResponseWriter, r *http.Request) {
	resp, err := h.clients.Policy.ListPolicies(r.Context(), &policy_pb.ListPoliciesRequest{})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"policies": resp.Policies})
}

// DELETE /api/v1/policies/:id
func (h *Handler) HandlePoliciesDelete(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		jsonError(w, "invalid policy id", http.StatusBadRequest)
		return
	}
	resp, err := h.clients.Policy.RemovePolicy(r.Context(), &policy_pb.RemovePolicyRequest{Id: uint32(id)})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": resp.Ok})
}
