package handler

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type JobStatus string

const (
	JobIdle      JobStatus = "idle"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
)

type Job struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "dkg" or "sign"
	Status    JobStatus `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Result    any       `json:"result,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// JobStore is an in-memory job tracker shared across handlers.
type JobStore struct {
	mu   sync.RWMutex
	jobs map[string]*Job
}

func NewJobStore() *JobStore {
	return &JobStore{jobs: make(map[string]*Job)}
}

func (s *JobStore) Create(id, jobType string) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := &Job{ID: id, Type: jobType, Status: JobRunning, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	s.jobs[id] = j
	return j
}

func (s *JobStore) Complete(id string, result any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		j.Status = JobCompleted
		j.Result = result
		j.UpdatedAt = time.Now()
	}
}

func (s *JobStore) Fail(id, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		j.Status = JobFailed
		j.Error = errMsg
		j.UpdatedAt = time.Now()
	}
}

func (s *JobStore) Get(id string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	return j, ok
}

func (s *JobStore) ListRunning() []*Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var running []*Job
	for _, j := range s.jobs {
		if j.Status == JobRunning {
			running = append(running, j)
		}
	}
	return running
}

// GET /api/v1/jobs/:id
func (h *Handler) HandleJobGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		jsonError(w, "job id required", http.StatusBadRequest)
		return
	}
	job, ok := h.jobs.Get(id)
	if !ok {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}
