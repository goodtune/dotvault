package sshfwd

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSender is a requestSender test double. fn is called for every
// SendRequest and controls whether — and how slowly — it "replies".
type fakeSender struct {
	fn func() error
}

func (f *fakeSender) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return true, nil, f.fn()
}

func TestKeepaliveSuccessResetsCounter(t *testing.T) {
	// Alternate failure/success forever. With strikes=2 this must never trip,
	// because a single success between failures resets the streak back to
	// zero — the only way Keepalive can return here is via ctx cancellation.
	var calls int64
	sender := &fakeSender{fn: func() error {
		n := atomic.AddInt64(&calls, 1)
		if n%2 == 0 {
			return nil // every second call "succeeds"
		}
		return errors.New("transient failure")
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- Keepalive(ctx, sender, 10*time.Millisecond, 2) }()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Keepalive returned %v, want context.DeadlineExceeded (a reset streak should never trip strikes=2)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Keepalive did not return within 5s of ctx deadline")
	}

	if atomic.LoadInt64(&calls) < 4 {
		t.Errorf("only %d SendRequest calls observed, want several alternating failure/success calls", calls)
	}
}

func TestKeepaliveReturnsAfterConsecutiveFailures(t *testing.T) {
	wantErr := errors.New("permanent failure")
	sender := &fakeSender{fn: func() error { return wantErr }}

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- Keepalive(context.Background(), sender, 10*time.Millisecond, 3) }()

	select {
	case err := <-done:
		if !errors.Is(err, wantErr) {
			t.Fatalf("Keepalive returned %v, want it to wrap %v", err, wantErr)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("Keepalive took %s to trip 3 strikes at a 10ms interval; too slow", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Keepalive did not return after 3 consecutive failures within 5s")
	}
}

func TestKeepaliveUnansweredRequestCountsAsStrike(t *testing.T) {
	// fn blocks forever — simulating a wedged sshd or a black-holed route,
	// exactly the case the bounded-request wait exists for. If Keepalive
	// blocked on this the way a bare cl.SendRequest call would, this test
	// would hang until killed; it must instead treat each unanswered request
	// as a strike and return well within the 5s test timeout.
	block := make(chan struct{}) // never closed
	sender := &fakeSender{fn: func() error {
		<-block
		return nil // unreachable
	}}

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- Keepalive(context.Background(), sender, 100*time.Millisecond, 2) }()

	select {
	case err := <-done:
		if !errors.Is(err, errKeepaliveTimeout) {
			t.Fatalf("Keepalive returned %v, want it to wrap errKeepaliveTimeout", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("Keepalive took %s to trip 2 strikes at a 100ms interval; too slow", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Keepalive did not return within 5s; an unanswered request must count as a strike, not block forever")
	}
}

func TestKeepaliveCancellationReturnsPromptly(t *testing.T) {
	block := make(chan struct{}) // never closed
	sender := &fakeSender{fn: func() error {
		<-block
		return nil // unreachable
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Keepalive(ctx, sender, 50*time.Millisecond, 100) }()

	// Let one request get in flight, then cancel while it is blocked.
	time.Sleep(75 * time.Millisecond)
	start := time.Now()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Keepalive returned %v, want context.Canceled", err)
		}
		if elapsed := time.Since(start); elapsed > 1*time.Second {
			t.Errorf("Keepalive took %s to honour cancellation while a request was in flight; too slow", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Keepalive did not return promptly after ctx cancellation with a request in flight")
	}
}

func TestKeepaliveValidatesArguments(t *testing.T) {
	sender := &fakeSender{fn: func() error { return nil }}
	if err := Keepalive(context.Background(), sender, 0, 3); err == nil {
		t.Error("Keepalive accepted a non-positive interval")
	}
	if err := Keepalive(context.Background(), sender, time.Second, 0); err == nil {
		t.Error("Keepalive accepted a non-positive strikes count")
	}
}

func TestIsAuthFailure(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{"real x/crypto rejection", "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain", true},
		{"unable to authenticate substring alone", "some wrapper: unable to authenticate here", true},
		{"no supported methods remain substring alone", "no supported methods remain after publickey", true},
		{"unrelated handshake error", "ssh: handshake failed: EOF", false},
		{"host key mismatch text", "host key for example.com changed: pinned AAA, offered BBB", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAuthFailure(errors.New(tt.msg)); got != tt.want {
				t.Errorf("isAuthFailure(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}

// runInShell feeds cmd to a POSIX shell (via `sh -c`) and returns its stdout.
// shellQuote's whole job is producing text that survives exactly this
// round-trip on the remote, which always runs a POSIX shell — the local
// build's OS is irrelevant to what it must produce.
func runInShell(t *testing.T, cmd string) (string, error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX shell to verify shellQuote's round-trip against on Windows")
	}
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"plain path", "/home/me/.ssh/dotvault.sock"},
		{"embedded single quote", "/home/me/o'brien/dotvault.sock"},
		{"multiple embedded quotes", "''/weird''/path''"},
		{"spaces", "/home/me/my sock/dotvault.sock"},
		{"dollar sign", "/home/me/$HOME/dotvault.sock"},
		{"backtick", "/home/me/`whoami`/dotvault.sock"},
		{"semicolon", "/home/me;rm -rf /;/dotvault.sock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quoted := shellQuote(tt.input)
			// The quoted form must always be wrapped in single quotes...
			if !strings.HasPrefix(quoted, "'") || !strings.HasSuffix(quoted, "'") {
				t.Fatalf("shellQuote(%q) = %q, does not start/end with a single quote", tt.input, quoted)
			}
			// ...and running it through `printf %s` in a POSIX shell must
			// reproduce the original string byte-for-byte — the actual
			// property that matters at the rm -f call site.
			out, err := runInShell(t, "printf %s "+quoted)
			if err != nil {
				t.Fatalf("shellQuote(%q) produced a string the shell rejected: %v", tt.input, err)
			}
			if out != tt.input {
				t.Errorf("shellQuote(%q) round-tripped through the shell as %q", tt.input, out)
			}
		})
	}
}
