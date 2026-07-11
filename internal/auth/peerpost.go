package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// peerPostTimeout bounds a form POST to a peer dotvault over the forwarded
// socket. Deliberately looser than the token-borrow timeout: the peer performs
// a synchronous launch (opening a browser, delivering a notification) inside
// the request — itself bounded on the peer side — so the round-trip includes an
// actual process launch, not just a JSON read. A shorter caller deadline on ctx
// still wins.
const peerPostTimeout = 10 * time.Second

// peerResponseBodyLimit caps how much of the peer's response we read — the body
// is a tiny JSON envelope either way.
const peerResponseBodyLimit = 1 << 16 // 64 KiB

// ErrPeerUnreachable is returned by PostFormToPeer when the peer could not be
// contacted at all: the socket path is empty, the socket file is missing or
// stale, or the dial failed. It is distinct from a *PeerStatusError, which
// means the peer answered but with a non-200 status.
var ErrPeerUnreachable = errors.New("peer socket unreachable")

// PeerStatusError reports that the peer's web API answered a PostFormToPeer
// request with a non-200 status. Message carries the peer's {"error": …} body
// when present. Callers distinguish a 400 (the peer rejected the request as
// invalid) from a 5xx/502/503 (the peer could not perform the action) via
// Status.
type PeerStatusError struct {
	Status  int
	Message string
}

func (e *PeerStatusError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("peer returned %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("peer returned %d", e.Status)
}

// PostFormToPeer posts form values to a peer dotvault's web API over its
// Unix-domain socket — the programmatic equivalent of
//
//	curl --unix-socket <socketPath> http://localhost/<apiPath> -d k=v …
//
// It is the shared transport for the remote peer-action surfaces: the
// `dotvault browse`/`dotvault notify` CLIs and the client facade's
// Browse/Notify. It reuses PeerSocketClient (the same stat-before-dial unix
// transport the token borrow uses).
//
// Errors are typed so callers can react: ErrPeerUnreachable (wrapped) when the
// peer could not be contacted, or a *PeerStatusError when it answered non-200.
// The request is bounded by peerPostTimeout unless ctx carries a shorter
// deadline.
func PostFormToPeer(ctx context.Context, socketPath, apiPath string, form url.Values) error {
	client, _, err := PeerSocketClient(socketPath)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPeerUnreachable, err)
	}

	ctx, cancel := context.WithTimeout(ctx, peerPostTimeout)
	defer cancel()

	// The unix dialer ignores the URL host, but "localhost" is on the peer web
	// server's DNS-rebinding Host allowlist.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://localhost/"+strings.TrimPrefix(apiPath, "/"), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPeerUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, peerResponseBodyLimit)).Decode(&body)
		return &PeerStatusError{Status: resp.StatusCode, Message: body.Error}
	}
	return nil
}
