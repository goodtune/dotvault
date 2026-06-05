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

// enrolKeyFromRequest reconstructs the enrolment key from the request path,
// supporting both flat keys (served by /enrol/{key}/...) and one-level grouped
// keys. A grouped key arrives in one of two equivalent shapes: percent-encoded
// in a single segment ("databricks%2Fprod", which Go unescapes into PathValue
// without splitting) or as two literal segments served by the parallel
// /enrol/{group}/{name}/... routes. Either way the result is "group/name",
// exactly how the key appears in config and in the Vault path.
func enrolKeyFromRequest(r *http.Request) string {
	if g := r.PathValue("group"); g != "" {
		return g + "/" + r.PathValue("name")
	}
	return r.PathValue("key")
}

func (s *Server) handleEnrolStart(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	key := enrolKeyFromRequest(r)

	runner := s.getEnrolRunner()
	if runner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := runner.Start(
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
	key := enrolKeyFromRequest(r)

	runner := s.getEnrolRunner()
	if runner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := runner.Skip(key)
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
	key := enrolKeyFromRequest(r)

	runner := s.getEnrolRunner()
	if runner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	info, err := runner.GetState(key)
	if err != nil {
		writeError(w, "enrolment not found", http.StatusNotFound)
		return
	}

	writeJSON(w, info)
}

func (s *Server) handleEnrolReset(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	key := enrolKeyFromRequest(r)

	runner := s.getEnrolRunner()
	if runner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	err := runner.Reset(key)
	if err != nil {
		if errors.Is(err, ErrEnrolNotFound) {
			writeError(w, "enrolment not found", http.StatusNotFound)
			return
		}
		writeError(w, err.Error(), http.StatusConflict)
		return
	}

	writeJSON(w, map[string]any{"status": "pending"})
}

func (s *Server) handleEnrolComplete(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrolAuth(w) {
		return
	}
	runner := s.getEnrolRunner()
	if runner == nil {
		writeError(w, "enrolments not initialized", http.StatusServiceUnavailable)
		return
	}

	runner.Complete()
	writeJSON(w, map[string]any{"status": "ok"})
}
