package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/config"
	"github.com/goodtune/dotvault/internal/vault"
)

// buildClientCertSource builds the client certificate source the FUSE mount
// and the Docker volume plugin serve from, or nil when client_cert is
// disabled or the source cannot be built. It is never fatal: a certificate is
// an addition to the mount and the volumes, so a misconfiguration is logged
// once and the daemon carries on without one.
//
// Built once and shared by both consumers, so a certificate signed for one is
// the one the other serves. It is safe to build before authentication: the
// ephemeral source signs lazily and reports clientcert.ErrNoToken until the
// client holds a token, and the held source reads the envelope on demand.
func buildClientCertSource(cfg *config.Config, vc *vault.Client, username string) clientcert.Source {
	// A nil *vault.Client must become a nil interface, not a non-nil
	// Signer wrapping a nil pointer.
	var signer clientcert.Signer
	if vc != nil {
		signer = vc
	}
	return newClientCertSource(cfg, signer, username)
}

func newClientCertSource(cfg *config.Config, signer clientcert.Signer, username string) clientcert.Source {
	src, err := clientcert.New(cfg, signer, username, mtlsStorageDir(cfg))
	if err != nil {
		slog.Warn("client certificate not served", "error", err)
		return nil
	}
	return src
}

// printClientCertStatus renders the client certificate section of `dotvault
// status`.
//
// It describes what the configuration would serve and, for a held
// certificate, what is on disk. It never signs and never contacts Vault: this
// is a one-shot command with no daemon state, and issuing a certificate to
// answer an informational question would make an observation command mutating.
// What the running daemon is actually serving, with the last error, is on
// /api/v1/status.
func printClientCertStatus(cfg *config.Config) {
	writeClientCertStatus(os.Stdout, cfg, auth.InspectCertCredential)
}

func writeClientCertStatus(w io.Writer, cfg *config.Config, inspect func(storageDir string) (auth.CertCredentialInfo, error)) {
	if !cfg.ClientCert.Enabled {
		return
	}
	fmt.Fprintln(w, "\nClient certificate:")

	role := cfg.ClientCertPKIRole()
	ttl := cfg.ClientCert.TTL
	if ttl <= 0 {
		ttl = config.DefaultClientCertTTL
	}

	if !cfg.ClientCertHeld() {
		fmt.Fprintln(w, "  source:      short-lived (signed on demand, never stored)")
		printClientCertIssuance(w, cfg, role, ttl)
		return
	}

	if role != "" {
		fmt.Fprintln(w, "  source:      held (this host's certificate), falling back to short-lived")
	} else {
		fmt.Fprintln(w, "  source:      held (this host's certificate)")
	}
	info, err := inspect(mtlsStorageDir(cfg))
	switch {
	case err != nil:
		fmt.Fprintf(w, "  held:        unreadable (%v)\n", err)
	case !info.Present:
		fmt.Fprintln(w, "  held:        no certificate enrolled on this host")
	case info.Expired:
		fmt.Fprintf(w, "  held:        expired %s\n", info.NotAfter.Format(time.RFC3339))
	default:
		fmt.Fprintf(w, "  held:        valid until %s\n", info.NotAfter.Format(time.RFC3339))
	}
	if role != "" {
		printClientCertIssuance(w, cfg, role, ttl)
	}
}

func printClientCertIssuance(w io.Writer, cfg *config.Config, role string, ttl time.Duration) {
	fmt.Fprintf(w, "  pki:         %s, role %s\n", cfg.ClientCertPKIMount(), role)
	fmt.Fprintf(w, "  ttl:         %s\n", ttl)
}
