package web

import (
	"errors"
	"net/http"
)

func (s *Server) requireEnrolAuth(w http.ResponseWriter) bool {
	if s.vault == nil || s.vault.Token() == "" {
		writeError(w, "not authenticated", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) handleEnrolStart(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	key := r.PathValue("key")

	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := s.enrolRunner.Start(
		s.shutdownCtx, key, s.vault,
		s.kvMount, s.userKVPrefix(), s.username,
		s.EnrolPromptSecret,
	)
	if err != nil {
		if errors.Is(err, ErrEnrolNotFound) {
			writeError(w, "enrolment not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrEnrolInvalidEngine) {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if errors.Is(err, ErrEnrolNotStartable) {
			writeError(w, err.Error(), http.StatusConflict)
			return
		}
		if errors.Is(err, ErrEnrolAlreadyRunning) || errors.Is(err, ErrEnrolBusy) {
			writeError(w, err.Error(), http.StatusConflict)
			return
		}
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"status": "running"})
}

func (s *Server) handleEnrolSkip(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	key := r.PathValue("key")

	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := s.enrolRunner.Skip(key)
	if err != nil {
		if errors.Is(err, ErrEnrolNotFound) {
			writeError(w, "enrolment not found", http.StatusNotFound)
			return
		}
		writeError(w, err.Error(), http.StatusConflict)
		return
	}

	writeJSON(w, map[string]any{"status": "skipped"})
}

func (s *Server) handleEnrolStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	key := r.PathValue("key")

	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	info, err := s.enrolRunner.GetState(key)
	if err != nil {
		writeError(w, "enrolment not found", http.StatusNotFound)
		return
	}

	writeJSON(w, info)
}

func (s *Server) handleEnrolComplete(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	s.enrolRunner.Complete()
	writeJSON(w, map[string]any{"status": "ok"})
}
