package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
)

// peerPostTimeout bounds a form POST to a peer dotvault over the forwarded
// socket. Deliberately looser than the 3s token-borrow timeout: the peer
// performs a synchronous launch (opening a browser, delivering a
// notification) inside the request — bounded at 8s on the peer side — so the
// round-trip includes an actual process launch, not just a JSON read.
const peerPostTimeout = 10 * time.Second

// peerResponseBodyLimit caps how much of the peer's response we read — the
// body is a tiny JSON envelope either way.
const peerResponseBodyLimit = 1 << 16 // 64 KiB

// postFormToPeer posts form values to a peer dotvault's web API over its
// Unix-domain socket — the programmatic equivalent of
//
//	curl --unix-socket <socketPath> http://localhost/<apiPath> -d k=v ...
//
// It is the shared transport for the remote peer-action CLIs (`dotvault
// browse`, `dotvault notify`). It reuses auth.PeerSocketClient (the same
// stat-before-dial unix transport the token borrow uses) and, unlike the
// best-effort token borrow, reports failures: the caller falls back to acting
// locally on any error but wants the reason for its debug log.
func postFormToPeer(ctx context.Context, socketPath, apiPath string, form url.Values) error {
	client, _, err := auth.PeerSocketClient(socketPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, peerPostTimeout)
	defer cancel()

	// The unix dialer ignores the URL host, but "localhost" is on the peer
	// web server's DNS-rebinding Host allowlist.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://localhost/"+strings.TrimPrefix(apiPath, "/"), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, peerResponseBodyLimit)).Decode(&body)
		if body.Error != "" {
			return fmt.Errorf("peer returned %d: %s", resp.StatusCode, body.Error)
		}
		return fmt.Errorf("peer returned %d", resp.StatusCode)
	}
	return nil
}
