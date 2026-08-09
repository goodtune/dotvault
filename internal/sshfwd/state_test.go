package sshfwd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
)

// errConnRefusedStub stands in for a real ECONNREFUSED without needing a
// closed port; Classify matches on syscall.ECONNREFUSED.
var errConnRefusedStub = syscall.ECONNREFUSED

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorClass
	}{
		{"nil", nil, ClassNone},
		{"host key unknown", fmt.Errorf("wrap: %w", ErrHostKeyUnknown), ClassHostKey},
		{"dns", &net.DNSError{Err: "no such host", IsNotFound: true}, ClassDNS},
		{"refused", fmt.Errorf("dial tcp: %w", errConnRefusedStub), ClassRefused},
		{"auth", fmt.Errorf("wrap: %w", ErrAuth), ClassAuth},
		{"bind", fmt.Errorf("wrap: %w", ErrBind), ClassBind},
		{"handshake", fmt.Errorf("wrap: %w", ErrHandshake), ClassHandshake},
		{"other", errors.New("something else"), ClassOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.err); got != tt.want {
				t.Errorf("Classify(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestRemoteStatusJSONShape(t *testing.T) {
	s := RemoteStatus{
		Host:         "foo.example.com",
		State:        string(StateConnected),
		RemoteSocket: "/home/me/.ssh/dotvault.sock",
		Target:       "unix:/run/user/1000/dotvault/api.sock",
		Reconnects:   2,
	}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"host"`, `"state"`, `"remote_socket"`, `"target"`,
		`"reconnects"`, `"active_connections"`, `"last_error"`,
	} {
		if !strings.Contains(string(data), key) {
			t.Errorf("marshalled status missing %s: %s", key, data)
		}
	}
	if strings.Contains(string(data), `"connected_since"`) {
		t.Errorf("connected_since must be omitted when unset: %s", data)
	}
}

func TestStatesAreDistinct(t *testing.T) {
	all := []State{
		StateConnecting, StateConnected, StateReconnecting,
		StateOffline, StateAuthError, StateHostKeyError, StateDisabled,
	}
	seen := map[State]bool{}
	for _, s := range all {
		if s == "" {
			t.Error("empty state constant")
		}
		if seen[s] {
			t.Errorf("duplicate state %q", s)
		}
		seen[s] = true
	}
}
