package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// handleEnrolments lists all configured enrolments and their pending/complete status.
func (s *Server) handleEnrolments(w http.ResponseWriter, r *http.Request) {
	pending, err := s.enrolMgr.FindPending(r.Context())
	if err != nil {
		slog.Error("failed to find pending enrolments", "error", err)
		http.Error(w, `{"error":"failed to check enrolments"}`, http.StatusInternalServerError)
		return
	}

	type item struct {
		Key        string `json:"key"`
		EngineName string `json:"engine_name"`
		Status     string `json:"status"`
	}
	items := make([]item, 0, len(pending))
	for _, p := range pending {
		status := "pending"
		if ts := s.enrolTracker.GetStatus(p.Key); ts != nil {
			status = string(ts.State)
		}
		items = append(items, item{
			Key:        p.Key,
			EngineName: p.EngineName,
			Status:     status,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"enrolments": items})
}

// handleEnrolmentStart kicks off a single enrolment flow asynchronously.
func (s *Server) handleEnrolmentStart(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		http.Error(w, `{"error":"key is required"}`, http.StatusBadRequest)
		return
	}

	if !s.enrolTracker.Start(r.Context(), s.enrolMgr, key) {
		http.Error(w, `{"error":"enrolment already in progress"}`, http.StatusConflict)
		return
	}

	slog.Info("enrolment started via web UI", "key", key)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{"status": "started"})
}

// handleEnrolmentStatus returns the current status of an in-progress enrolment.
func (s *Server) handleEnrolmentStatus(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		http.Error(w, `{"error":"key is required"}`, http.StatusBadRequest)
		return
	}

	status := s.enrolTracker.GetStatus(key)
	if status == nil {
		http.Error(w, `{"error":"no enrolment in progress"}`, http.StatusNotFound)
		return
	}

	// Clear terminal states after they've been read so the key can be restarted.
	if status.State == "complete" || status.State == "failed" {
		s.enrolTracker.Clear(key)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
