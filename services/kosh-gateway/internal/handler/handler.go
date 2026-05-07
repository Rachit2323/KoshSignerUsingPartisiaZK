package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kosh/gateway/internal/client"
	"github.com/kosh/gateway/internal/session"
	bb_pb "github.com/kosh/gateway/pb/bb"
)

const (
	dkgTimeout  = 5 * time.Minute
	signTimeout = 10 * time.Minute
)

type Handler struct {
	clients  *client.Clients
	jobs     *JobStore
	passkeys *PasskeyStore
	sessions *session.Store
}

func New(c *client.Clients, pk *PasskeyStore, sess *session.Store) *Handler {
	return &Handler{clients: c, jobs: NewJobStore(), passkeys: pk, sessions: sess}
}

// GET /api/v1/health
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// bbReq is a helper so handlers can call Coord.Read without importing bb_pb directly.
func bbReq(topic string) bb_pb.ReadRequest {
	return bb_pb.ReadRequest{Topic: topic}
}
