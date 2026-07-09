package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/goodtune/dotvault/internal/paths"
)

// socketFetchTimeout bounds a single token fetch over a peer socket so a hung
// or slow peer cannot stall a login or a lifecycle reload. The endpoint is a
// local IPC socket (typically an SSH RemoteForward'd Unix socket), so the
// round-trip is near-instant in the healthy case; a few seconds is generous
// while still keeping the shell-startup login-check path responsive.
const socketFetchTimeout = 3 * time.Second

// socketTokenBodyLimit caps how much of the peer's response we read before
// decoding. The body is a tiny JSON object ({"token":"hvs.…"}); the limit just
// guards against a misbehaving or hostile peer streaming an unbounded body.
const socketTokenBodyLimit = 1 << 16 // 64 KiB

// PeerSocketClient builds an http.Client that dials the peer dotvault web-API
// Unix-domain socket at socketPath (a leading ~ is expanded), returning the
// client and the expanded path. It is the shared transport seam for every
// peer-socket consumer — the token borrow below and `dotvault browse` — so
// "dial the peer's web API" has exactly one implementation. Callers own the
// error policy: this reports why the socket is unusable (empty path,
// unexpandable ~, missing file) and the caller decides whether that is fatal
// (browse falls back to the local browser) or silently skipped (the borrow).
// A missing socket file is checked here so callers neither log a connection
// error nor pay a dial timeout for the common "peer not connected" case.
func PeerSocketClient(socketPath string) (*http.Client, string, error) {
	if socketPath == "" {
		return nil, "", errors.New("no peer socket configured")
	}
	expanded, err := paths.ExpandHome(socketPath)
	if err != nil {
		return nil, "", fmt.Errorf("expand socket path: %w", err)
	}
	if _, err := os.Stat(expanded); err != nil {
		// Return the expanded path so callers can tell "socket missing"
		// (expanded non-empty) from "path unresolvable" (expanded empty).
		return nil, expanded, fmt.Errorf("peer socket not present: %w", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", expanded)
			},
		},
	}
	return client, expanded, nil
}

// FetchTokenFromSocket retrieves a Vault token from a peer dotvault daemon's
// web API exposed over a Unix-domain socket — the programmatic equivalent of
//
//	curl --unix-socket <socketPath> http://localhost/api/v1/token
//
// It backs dotvault-to-dotvault token sharing: a remote-forwarded socket (e.g.
// ~/.ssh/dotvault.sock created by an SSH RemoteForward from a machine running
// the dotvault web UI) lets a host with no interactive login facility borrow
// the live token from a peer that has one.
//
// It is best-effort and never fatal. An empty path, an unexpandable ~, a
// missing socket file, a stale socket (file present but no listener), a
// non-200 response (the peer holds no token), or a malformed body all resolve
// to ("", nil) so the caller simply carries on with its normal auth flow. The
// returned token is deliberately NOT validated here — callers run LookupSelf
// before adopting it, exactly as they do for the token file and DOTVAULT_TOKEN.
func FetchTokenFromSocket(ctx context.Context, socketPath string) (string, error) {
	if socketPath == "" {
		return "", nil
	}
	// An unusable socket (unexpandable ~, missing file — the common "peer not
	// connected" case) means the peer simply isn't reachable: skip silently
	// rather than failing the auth flow.
	client, expanded, err := PeerSocketClient(socketPath)
	if err != nil {
		// A missing socket file (expanded non-empty) is routine and stays
		// silent; an unresolvable path is worth a debug line.
		if expanded == "" {
			slog.Debug("could not expand peer token socket path; continuing", "socket", socketPath, "error", err)
		}
		return "", nil
	}

	ctx, cancel := context.WithTimeout(ctx, socketFetchTimeout)
	defer cancel()

	// The unix dialer ignores the URL host, but it must still be a valid
	// authority. "localhost" mirrors the documented curl invocation and is on
	// the web server's DNS-rebinding Host allowlist, so the peer accepts it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/api/v1/token", nil)
	if err != nil {
		return "", nil
	}
	resp, err := client.Do(req)
	if err != nil {
		// Stale socket (no listener), timeout, connection reset, etc.
		slog.Debug("could not reach peer token socket; continuing", "socket", expanded, "error", err)
		return "", nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Peer reachable but has no usable token (401) or some transient error.
		slog.Debug("peer token socket returned non-OK; continuing", "socket", expanded, "status", resp.StatusCode)
		return "", nil
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, socketTokenBodyLimit)).Decode(&body); err != nil {
		slog.Debug("could not decode peer token socket response; continuing", "socket", expanded, "error", err)
		return "", nil
	}
	return body.Token, nil
}
