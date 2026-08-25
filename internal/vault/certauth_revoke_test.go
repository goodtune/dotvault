package vault

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
)

// TestFormatSerial pins the encoding Vault's PKI endpoints accept. Getting it
// wrong is silent: a well-formed request naming a serial the CA has never
// issued is answered without revoking anything.
func TestFormatSerial(t *testing.T) {
	tests := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{"nil is no serial", nil, ""},
		{"single byte", big.NewInt(0x0a), "0a"},
		{"odd-length hex pads", big.NewInt(0xabc), "0a:bc"},
		{"multi-byte", big.NewInt(0xaabbcc), "aa:bb:cc"},
		// A serial's leading zero bytes are not part of its value, so they do
		// not survive — 0x00ff and 0xff are the same integer and Vault records
		// the shorter form.
		{"leading zero byte is not significant", big.NewInt(0x00ff), "ff"},
		// Non-conformant but parseable; must render as a serial rather than as
		// the empty string, which would read as "no serial" and skip the call.
		{"zero", big.NewInt(0), "00"},
		// x509 parsing accepts negative serials. big.Int's %x would render
		// "-2a" and yield the malformed "0-:2a"; the magnitude is what Vault
		// stores.
		{"negative uses the magnitude", big.NewInt(-0x2a), "2a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatSerial(tc.serial); got != tc.want {
				t.Errorf("FormatSerial(%v) = %q, want %q", tc.serial, got, tc.want)
			}
		})
	}
}

// TestFormatSerialMatchesAParsedCertificate is the end-to-end check that the
// encoding agrees with a real certificate's serial rather than only with the
// table above.
func TestFormatSerialMatchesAParsedCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(0x0102030405)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "serial-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := FormatSerial(parsed.SerialNumber), "01:02:03:04:05"; got != want {
		t.Errorf("FormatSerial(parsed) = %q, want %q", got, want)
	}
}

// TestRevokeCertificate covers the endpoint, path shape, and body the PKI
// revoke call must produce. The certificate lives at the CA under its serial
// alone, so a wrong path or field name fails silently from the caller's
// perspective — the rotation reports success and the superseded certificate
// keeps authenticating.
func TestRevokeCertificate(t *testing.T) {
	t.Run("posts the serial to <mount>/revoke", func(t *testing.T) {
		var gotPath string
		var gotBody map[string]any
		var gotToken string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotToken = r.Header.Get("X-Vault-Token")
			json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"revocation_time": 1700000000},
			})
		}))
		defer ts.Close()

		c, err := NewClient(Config{Address: ts.URL, Token: "operational-token"})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := c.RevokeCertificate(context.Background(), "pki", "aa:bb:cc"); err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}
		if gotPath != "/v1/pki/revoke" {
			t.Errorf("path = %q, want /v1/pki/revoke", gotPath)
		}
		if got := gotBody["serial_number"]; got != "aa:bb:cc" {
			t.Errorf("serial_number = %v, want aa:bb:cc", got)
		}
		if gotToken != "operational-token" {
			t.Errorf("X-Vault-Token = %q, want the client's token", gotToken)
		}
	})

	t.Run("trims mount slashes", func(t *testing.T) {
		var gotPath string
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
		}))
		defer ts.Close()

		c, _ := NewClient(Config{Address: ts.URL, Token: "t"})
		if err := c.RevokeCertificate(context.Background(), "/pki-int/", "01"); err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}
		if gotPath != "/v1/pki-int/revoke" {
			t.Errorf("path = %q, want /v1/pki-int/revoke", gotPath)
		}
	})

	t.Run("empty serial never reaches Vault", func(t *testing.T) {
		called := false
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		defer ts.Close()

		c, _ := NewClient(Config{Address: ts.URL, Token: "t"})
		if err := c.RevokeCertificate(context.Background(), "pki", ""); err == nil {
			t.Error("RevokeCertificate with no serial = nil, want an error")
		}
		if called {
			t.Error("an empty serial must not be sent to Vault")
		}
	})

	t.Run("a denied revoke is an error", func(t *testing.T) {
		// The common misconfiguration: the downscoped operational token's
		// policies omit update on pki/revoke. The caller logs this rather than
		// failing the rotation, but it must be able to tell.
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		}))
		defer ts.Close()

		c, _ := NewClient(Config{Address: ts.URL, Token: "t"})
		err := c.RevokeCertificate(context.Background(), "pki", "aa:bb:cc")
		if err == nil {
			t.Fatal("RevokeCertificate against a 403 = nil, want an error")
		}
		if !strings.Contains(err.Error(), "pki/revoke") {
			t.Errorf("error = %v, want it to name the path", err)
		}
	})
}
