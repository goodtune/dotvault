package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"nhooyr.io/websocket"
)

// Event represents a Vault event notification.
type Event struct {
	EventType string
	Path      string
	DataPath  string
	MountPath string
	Version   int
}

// SubscribeEvents connects to the Vault Events API via WebSocket and
// returns a channel of events and an error channel.
// The caller should cancel the context to disconnect.
func (c *Client) SubscribeEvents(ctx context.Context, eventType string) (<-chan Event, <-chan error, error) {
	wsURL, err := c.buildEventsURL(eventType)
	if err != nil {
		return nil, nil, fmt.Errorf("build events URL: %w", err)
	}

	headers := make(http.Header)
	headers.Set("X-Vault-Token", c.raw.Token())

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: headers,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("connect to events API: %w", err)
	}

	events := make(chan Event, 16)
	errCh := make(chan error, 1)

	go func() {
		defer conn.Close(websocket.StatusNormalClosure, "done")
		defer close(events)
		defer close(errCh)

		for {
			_, msg, err := conn.Read(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return // Context cancelled, clean shutdown
				}
				errCh <- fmt.Errorf("read event: %w", err)
				return
			}

			evt, err := parseEvent(msg)
			if err != nil {
				continue // Skip unparseable events
			}

			select {
			case events <- evt:
			case <-ctx.Done():
				return
			}
		}
	}()

	return events, errCh, nil
}

func (c *Client) buildEventsURL(eventType string) (string, error) {
	addr := c.raw.Address()
	u, err := url.Parse(addr)
	if err != nil {
		return "", fmt.Errorf("parse vault address: %w", err)
	}

	// Switch scheme to ws/wss
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}

	u.Path = fmt.Sprintf("/v1/sys/events/subscribe/%s", eventType)
	q := u.Query()
	q.Set("json", "true")
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// cloudEvent is the CloudEvents envelope used by Vault's Events API.
type cloudEvent struct {
	Data json.RawMessage `json:"data"`
}

type eventData struct {
	EventType string       `json:"event_type"`
	Event     eventPayload `json:"event"`
}

type eventPayload struct {
	ID       string          `json:"id"`
	Metadata json.RawMessage `json:"metadata"`
}

type eventMetadata struct {
	Path           string `json:"path"`
	DataPath       string `json:"data_path"`
	MountPath      string `json:"mount_path"`
	Operation      string `json:"operation"`
	CurrentVersion int    `json:"current_version"`
}

func parseEvent(msg []byte) (Event, error) {
	// Vault Events API wraps in CloudEvents format
	// Try to parse the nested structure
	var ce cloudEvent
	if err := json.Unmarshal(msg, &ce); err != nil {
		return Event{}, fmt.Errorf("unmarshal cloud event: %w", err)
	}

	var ed eventData
	if err := json.Unmarshal(ce.Data, &ed); err != nil {
		// Try direct parse if not wrapped
		if err2 := json.Unmarshal(msg, &ed); err2 != nil {
			return Event{}, fmt.Errorf("unmarshal event data: %w", err)
		}
	}

	var meta eventMetadata
	if err := json.Unmarshal(ed.Event.Metadata, &meta); err != nil {
		return Event{}, fmt.Errorf("unmarshal event metadata: %w", err)
	}

	// Clean up the path — remove "data/" prefix for KVv2
	path := meta.DataPath
	if path == "" {
		path = meta.Path
	}
	// Strip mount prefix and "data/" segment
	path = strings.TrimPrefix(path, meta.MountPath)
	path = strings.TrimPrefix(path, "data/")

	return Event{
		EventType: ed.EventType,
		Path:      path,
		DataPath:  meta.DataPath,
		MountPath: meta.MountPath,
		Version:   meta.CurrentVersion,
	}, nil
}
