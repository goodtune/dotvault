package config

import (
	"fmt"
	"text/template"
	"text/template/parse"
	"time"
)

const (
	// DefaultClientCertTTL is how long a client certificate issued for the
	// ephemeral source lives when client_cert.ttl is unset. Short on purpose:
	// the certificate is minted on demand and never stored, so a short life
	// bounds the damage of a leaked copy without costing the user anything.
	DefaultClientCertTTL = 5 * time.Minute

	// MinClientCertTTL is the floor for client_cert.ttl. Rotation happens
	// when less than half of the issued lifetime remains, so anything much
	// shorter would have a consumer racing the refresh on every read.
	MinClientCertTTL = time.Minute

	// DefaultClientCertCommonName is the subject common name template used
	// when client_cert.common_name is unset.
	DefaultClientCertCommonName = "{{.token_username}}"
)

// clientCertTemplateVars are the only variables a client_cert.common_name
// template may reference. Both are deliberately unambiguous about where the
// value comes from: token_username is what Vault says the token belongs to,
// os_user is the account the daemon runs as. The two generic names
// ({{.user}}, {{.vault_username}}) used elsewhere are refused because they
// do not say which of those they mean, and a certificate subject is the one
// place where guessing wrong grants somebody else's identity.
var clientCertTemplateVars = map[string]bool{
	"token_username": true,
	"os_user":        true,
}

// ClientCertConfig configures serving a mutual-TLS client certificate to
// other tools, through the FUSE mount, Docker volumes and the client library.
//
// Disabled by default. Static: it is read once at startup, refused in a
// remote document and not user-overridable via the per-user overlay — a
// certificate is a credential a process can present to a service, which is a
// wider grant than the read-only view of the user's own secrets the overlay's
// one precedent (fuse) allows.
//
// The inner fields deliberately omit `omitempty` for the round-trip reason
// every other optional section states: an exported config must re-emit
// cleared values so a re-import can blank a previously-set field. The
// top-level ClientCert field keeps `omitempty` so operators who do not use
// the feature see no empty block in downloads.
type ClientCertConfig struct {
	Enabled bool `yaml:"enabled"`

	// PKIMount is the PKI secrets engine mount used to sign. Empty inherits
	// vault.mtls.pki_mount, else DefaultPKIMount. Resolved by
	// Config.ClientCertPKIMount, not defaulted in place, so an export
	// round-trips the operator's literal value.
	PKIMount string `yaml:"pki_mount"`

	// PKIRole is the PKI role signed against. Empty inherits
	// vault.mtls.pki_role. Required when the section is enabled and no
	// held credential can serve instead (see Config.ClientCertHeld).
	PKIRole string `yaml:"pki_role"`

	// CommonName is a text/template for the certificate subject CN, over
	// {{.token_username}} and {{.os_user}} only. Empty means
	// DefaultClientCertCommonName.
	CommonName string `yaml:"common_name"`

	// TTL is the parsed form of RawTTL, filled in by validation.
	TTL time.Duration `yaml:"-"`

	// RawTTL is the requested lifetime as a duration string. Empty means
	// DefaultClientCertTTL; anything below MinClientCertTTL is an error.
	// There is no ceiling here — the PKI role's max_ttl is the authoritative
	// cap.
	RawTTL string `yaml:"ttl"`

	// KeyType is "ec" or "rsa". Empty means ec; validation fills it in.
	KeyType string `yaml:"key_type"`

	// KeyBits is the RSA modulus (2048/3072/4096/8192); 0 means the backend
	// default. Invalid with key_type ec.
	KeyBits int `yaml:"key_bits"`
}

// ClientCertPKIMount resolves the PKI mount: this section's own value, else
// the one vault.mtls names, else the default. The vault.mtls fallback is read
// whatever the auth method, borrow_only included — a borrow-only host never
// logs in with a certificate, but the shared base config still names the PKI
// that issues its client certificates.
func (c *Config) ClientCertPKIMount() string {
	if c.ClientCert.PKIMount != "" {
		return c.ClientCert.PKIMount
	}
	if c.Vault.MTLS.PKIMount != "" {
		return c.Vault.MTLS.PKIMount
	}
	return DefaultPKIMount
}

// ClientCertPKIRole resolves the PKI role: this section's own value, else
// vault.mtls.pki_role, else "". An empty result means no role is resolvable;
// the held source does not need one.
func (c *Config) ClientCertPKIRole() string {
	if c.ClientCert.PKIRole != "" {
		return c.ClientCert.PKIRole
	}
	return c.Vault.MTLS.PKIRole
}

// ClientCertRoleInherited reports whether this host signs client
// certificates under the role it inherited from vault.mtls.pki_role: the
// section is enabled, the host signs (not held), client_cert.pki_role is empty
// and vault.mtls.pki_role is set.
//
// Inheritance is deliberate — it lets one base config serve a workstation and
// its borrow_only remotes — but it has a consequence the daemon warns about at
// startup: that role is the one the login certificates are signed under, so
// the CA the cert auth method trusts signs these too, and each such
// certificate can log in to Vault. The token that login yields takes the cert
// auth role's TTL and is renewable, so it outlives the certificate's few
// minutes. A dedicated client_cert.pki_role on a CA the cert auth method does
// not trust keeps the two apart.
func (c *Config) ClientCertRoleInherited() bool {
	return c.ClientCert.Enabled && !c.ClientCertHeld() &&
		c.ClientCert.PKIRole == "" && c.Vault.MTLS.PKIRole != ""
}

// ClientCertCommonName resolves the subject CN template.
func (c *Config) ClientCertCommonName() string {
	if c.ClientCert.CommonName != "" {
		return c.ClientCert.CommonName
	}
	return DefaultClientCertCommonName
}

// ClientCertHeld reports whether the certificate served is the one this host
// already holds, rather than a fresh ephemeral one. It is decided from the
// configured method alone: exactly "mtls", the file backend whose key the
// daemon can read. mtls+tpm and mtls+os keep the key where it cannot be
// exported, so they, and every non-cert method, use the ephemeral source.
// Never inferred from the in-memory key type.
//
// A borrow_only host is never held: it ignores auth_method and runs no
// certificate login, so there is no credential on it to serve whatever the
// shared base config says. It issues ephemerally like any other host and so
// needs a PKI role of its own.
func (c *Config) ClientCertHeld() bool {
	return ClientCertHeldFor(c.ClientCert.Enabled, c.Vault.AuthMethod, c.Vault.BorrowOnly)
}

// ClientCertHeldFor is the held rule over its three inputs, for callers that
// carry them without a *Config (the client/ facade's projection). It is the
// one definition: ClientCertHeld calls it, so the two cannot drift.
func ClientCertHeldFor(enabled bool, method string, borrowOnly bool) bool {
	return enabled && method == "mtls" && !borrowOnly
}

// validateClientCert checks the client_cert section and fills in TTL and
// KeyType.
//
// Like validateDocker, it runs whether or not the section is enabled: a bad
// duration or template is a mistake worth naming at load time rather than at
// the moment someone flips `enabled: true`. Only the requirement for a PKI
// role is conditional on being enabled, since a disabled section issues
// nothing.
func (c *Config) validateClientCert() error {
	cc := &c.ClientCert

	switch cc.RawTTL {
	case "":
		cc.TTL = DefaultClientCertTTL
	default:
		d, err := ParseDuration(cc.RawTTL)
		if err != nil {
			return fmt.Errorf("client_cert.ttl %q: %w", cc.RawTTL, err)
		}
		if d < MinClientCertTTL {
			return fmt.Errorf("client_cert.ttl %q: must be at least %s", cc.RawTTL, MinClientCertTTL)
		}
		cc.TTL = d
	}

	keyType, err := validateKeyParams("client_cert", cc.KeyType, cc.KeyBits)
	if err != nil {
		return err
	}
	cc.KeyType = keyType

	if err := validateClientCertCommonName(c.ClientCertCommonName()); err != nil {
		return err
	}

	if cc.Enabled && !c.ClientCertHeld() && c.ClientCertPKIRole() == "" {
		return fmt.Errorf("client_cert.pki_role is required (no vault.mtls.pki_role to inherit)")
	}
	return nil
}

// validateClientCertCommonName parses a common_name template and rejects any
// field reference outside clientCertTemplateVars. References are found by
// walking the parse tree rather than scanning the text, so a field inside an
// {{if}}, {{with}}, {{range}} or a pipeline is caught the same as a bare one.
func validateClientCertCommonName(cn string) error {
	t, err := template.New("client_cert.common_name").Parse(cn)
	if err != nil {
		return fmt.Errorf("client_cert.common_name %q: %w", cn, err)
	}
	for _, tt := range t.Templates() {
		if tt.Tree == nil {
			continue
		}
		if name, ok := unknownTemplateField(tt.Tree.Root); ok {
			return fmt.Errorf("client_cert.common_name %q: unknown variable .%s; only {{.token_username}} and {{.os_user}} are available", cn, name)
		}
	}
	return nil
}

// unknownTemplateField walks n and returns the first field reference whose
// name is not an allowed client_cert variable.
func unknownTemplateField(n parse.Node) (string, bool) {
	switch n := n.(type) {
	case nil:
		return "", false
	case *parse.ListNode:
		if n == nil {
			return "", false
		}
		for _, c := range n.Nodes {
			if name, bad := unknownTemplateField(c); bad {
				return name, true
			}
		}
	case *parse.ActionNode:
		return unknownTemplateField(n.Pipe)
	case *parse.PipeNode:
		if n == nil {
			return "", false
		}
		for _, c := range n.Cmds {
			if name, bad := unknownTemplateField(c); bad {
				return name, true
			}
		}
	case *parse.CommandNode:
		for _, a := range n.Args {
			if name, bad := unknownTemplateField(a); bad {
				return name, true
			}
		}
	case *parse.FieldNode:
		if len(n.Ident) > 0 && !clientCertTemplateVars[n.Ident[0]] {
			return n.Ident[0], true
		}
	case *parse.VariableNode:
		// $.user is the root context reached through the $ variable.
		if len(n.Ident) > 1 && n.Ident[0] == "$" && !clientCertTemplateVars[n.Ident[1]] {
			return n.Ident[1], true
		}
	case *parse.ChainNode:
		return unknownTemplateField(n.Node)
	case *parse.IfNode:
		return unknownBranch(&n.BranchNode)
	case *parse.RangeNode:
		return unknownBranch(&n.BranchNode)
	case *parse.WithNode:
		return unknownBranch(&n.BranchNode)
	case *parse.TemplateNode:
		return unknownTemplateField(n.Pipe)
	}
	return "", false
}

func unknownBranch(b *parse.BranchNode) (string, bool) {
	if name, bad := unknownTemplateField(b.Pipe); bad {
		return name, true
	}
	if name, bad := unknownTemplateField(b.List); bad {
		return name, true
	}
	return unknownTemplateField(b.ElseList)
}
