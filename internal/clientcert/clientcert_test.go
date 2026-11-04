package clientcert

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestPairCombinedAddsSeparatorNewline(t *testing.T) {
	p := &Pair{CertPEM: []byte("CERT"), KeyPEM: []byte("KEY\n")}
	if got := string(p.Combined()); got != "CERT\nKEY\n" {
		t.Fatalf("Combined = %q", got)
	}
	p = &Pair{CertPEM: []byte("CERT\n"), KeyPEM: []byte("KEY\n")}
	if got := string(p.Combined()); got != "CERT\nKEY\n" {
		t.Fatalf("Combined = %q", got)
	}
}

func TestLeafDERSkipsNonCertificateBlocks(t *testing.T) {
	if LeafDER([]byte("not pem")) != nil {
		t.Error("LeafDER of non-PEM input is not nil")
	}
	in := []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n")
	if got := LeafDER(in); string(got) != "\x01\x02\x03" {
		t.Errorf("LeafDER = %x, want 010203", got)
	}
}

func TestTransient(t *testing.T) {
	wrap := func(errs ...error) error {
		var err error = errs[len(errs)-1]
		for i := len(errs) - 2; i >= 0; i-- {
			err = fmt.Errorf("%w: %w", errs[i], err)
		}
		return fmt.Errorf("client certificate: %w", err)
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"no token", ErrNoToken, true},
		{"paced", wrap(ErrSignPaced), true},
		{"token being replaced", wrap(ErrReauthInProgress, context.DeadlineExceeded), true},
		{"deadline while a sign is in flight", wrap(ErrSignInProgress, context.DeadlineExceeded), true},
		// An explicit cancel is the caller going away: not something a
		// retry by that caller fixes, and the FUSE mount reports it EINTR.
		{"cancel while a sign is in flight", wrap(ErrSignInProgress, context.Canceled), false},
		{"plain cancel", context.Canceled, false},
		{"the sign itself timed out", fmt.Errorf("clientcert: sign: %w", context.DeadlineExceeded), false},
		{"no username", ErrNoUsername, false},
		{"denied", errors.New("permission denied"), false},
	}
	for _, tc := range cases {
		if got := Transient(tc.err); got != tc.want {
			t.Errorf("%s: Transient(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}
