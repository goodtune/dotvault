package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/clientcert/source"
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
	var signer source.Signer
	if vc != nil {
		signer = vc
	}
	warnInheritedClientCertRole(cfg)
	return newClientCertSource(cfg, signer, username)
}

// warnInheritedClientCertRole logs, once per daemon start, when this host
// signs client certificates under the role inherited from vault.mtls.pki_role
// (config.ClientCertRoleInherited). Inheritance is supported — one base config
// can serve a workstation and its borrow_only remotes — but every certificate
// signed under the login role is also a Vault login, and the token it yields
// outlives the certificate.
func warnInheritedClientCertRole(cfg *config.Config) {
	if !cfg.ClientCertRoleInherited() {
		return
	}
	slog.Warn("client_cert.pki_role is unset, so client certificates are signed under vault.mtls.pki_role, the role this host's login certificates use; "+
		"each one can log in to Vault, and the token that login yields takes the cert auth role's TTL and is renewable, outliving the certificate. "+
		"Set client_cert.pki_role to a dedicated role on a CA the cert auth method does not trust to keep them apart",
		"pki_mount", cfg.ClientCertPKIMount(),
		"pki_role", cfg.Vault.MTLS.PKIRole)
}

func newClientCertSource(cfg *config.Config, signer source.Signer, username string) clientcert.Source {
	src, err := source.New(cfg, signer, username, mtlsStorageDir(cfg))
	if err != nil {
		slog.Warn("client certificate not served", "error", err)
		return nil
	}
	return src
}

// clientCertLifecycle is what the daemon's lifecycle manager offers the
// certificate source: the gate a sign waits on while the token is being
// replaced, and the report of a token rejection the sign saw first.
// *auth.LifecycleManager satisfies it.
type clientCertLifecycle interface {
	source.ReauthGate
	source.RejectionReporter
}

// wireClientCertLifecycle hands the lifecycle manager to the certificate
// source once it exists, which is after the source: the source is built
// before authentication so the Docker plugin can serve from the start. It
// mirrors the SSH agent's SetReauthGate/SetReauthReporter pair, and is a no-op
// for a nil source or one that signs nothing (the held source alone).
func wireClientCertLifecycle(src clientcert.Source, lm clientCertLifecycle) {
	if w, ok := src.(source.LifecycleWirer); ok {
		w.SetReauthGate(lm)
		w.SetReauthReporter(lm)
	}
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
