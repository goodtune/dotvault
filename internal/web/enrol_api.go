package web

import (
	"context"
	"net/http"
)

func (s *Server) handleEnrolStart(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := s.enrolRunner.Start(
		context.Background(), key, s.vault,
		s.kvMount, s.userKVPrefix(), s.username,
		s.EnrolPromptSecret,
	)
	if err != nil {
		if err.Error() == "enrolment \""+key+"\" not found" {
			writeError(w, "enrolment not found", http.StatusNotFound)
			return
		}
		if err.Error() == "enrolment \""+key+"\" is already running" {
			writeError(w, "enrolment already running", http.StatusConflict)
			return
		}
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{"status": "running"})
}

func (s *Server) handleEnrolSkip(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := s.enrolRunner.Skip(key)
	if err != nil {
		if err.Error() == "enrolment \""+key+"\" not found" {
			writeError(w, "enrolment not found", http.StatusNotFound)
			return
		}
		writeError(w, err.Error(), http.StatusConflict)
		return
	}

	writeJSON(w, map[string]any{"status": "skipped"})
}

func (s *Server) handleEnrolStatus(w http.ResponseWriter, r *http.Request) {
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
	if s.enrolRunner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	s.enrolRunner.Complete()
	writeJSON(w, map[string]any{"status": "ok"})
}
