package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
)

// VaultStoreConfig configures the production Vault KVv2 backend. The driver
// is built directly on github.com/hashicorp/vault/api — the daemon's
// internal/vault wrapper is deliberately not reused, because it carries
// events/MFA machinery a storage driver doesn't want.
type VaultStoreConfig struct {
	// Address is the Vault server URL. Required.
	Address string
	// Mount is the KVv2 mount the service stores under. Default "kv".
	Mount string
	// Path is the base path under the mount. Layer documents live at
	// {Mount}/data/{Path}/layers/{key}, group membership at
	// {Mount}/data/{Path}/groups/{user}. Default "dotvault-config".
	Path string
	// Auth selects the auth method: "token" (dev) or "kubernetes".
	// Default "token".
	Auth string
	// Token is the Vault token for token auth. Falls back to the
	// VAULT_TOKEN environment variable when empty.
	Token string
	// CACert optionally pins the CA bundle used to verify Vault's TLS
	// certificate.
	CACert string

	// K8sMount is the Kubernetes auth mount. Default "kubernetes".
	K8sMount string
	// K8sRole is the Kubernetes auth role. Required for kubernetes auth.
	K8sRole string
	// K8sJWTPath is the projected service-account token file. It is
	// re-read from disk on every login so projected-token rotation needs
	// no restart. Default is the standard service-account path.
	K8sJWTPath string
}

const defaultK8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// layerDocField is the single KVv2 field carrying a layer document.
const layerDocField = "doc"

// groupsField is the single KVv2 field carrying a JSON-encoded group list.
const groupsField = "groups"

type vaultStore struct {
	client *api.Client
	cfg    VaultStoreConfig

	// mu guards the login state for kubernetes auth: the client token and
	// the renewAt deadline after which the next operation re-logs-in.
	mu      sync.Mutex
	renewAt time.Time
}

// OpenVault constructs the Vault KVv2 Store. For kubernetes auth the initial
// login happens here so a bad role or missing JWT fails at startup rather
// than on the first request.
func OpenVault(ctx context.Context, cfg VaultStoreConfig) (Store, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault store: address is required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "kv"
	}
	if cfg.Path == "" {
		cfg.Path = "dotvault-config"
	}
	if cfg.Auth == "" {
		cfg.Auth = "token"
	}
	if cfg.K8sMount == "" {
		cfg.K8sMount = "kubernetes"
	}
	if cfg.K8sJWTPath == "" {
		cfg.K8sJWTPath = defaultK8sJWTPath
	}

	apiCfg := api.DefaultConfig()
	apiCfg.Address = cfg.Address
	if cfg.CACert != "" {
		if err := apiCfg.ConfigureTLS(&api.TLSConfig{CACert: cfg.CACert}); err != nil {
			return nil, fmt.Errorf("vault store: configure TLS: %w", err)
		}
	}
	client, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("vault store: create client: %w", err)
	}

	s := &vaultStore{client: client, cfg: cfg}
	switch cfg.Auth {
	case "token":
		token := cfg.Token
		if token == "" {
			token = os.Getenv("VAULT_TOKEN")
		}
		if token == "" {
			return nil, fmt.Errorf("vault store: token auth requires a token (config or VAULT_TOKEN)")
		}
		client.SetToken(token)
	case "kubernetes":
		if cfg.K8sRole == "" {
			return nil, fmt.Errorf("vault store: kubernetes auth requires a role")
		}
		if err := s.login(ctx); err != nil {
			return nil, fmt.Errorf("vault store: initial kubernetes login: %w", err)
		}
	default:
		return nil, fmt.Errorf("vault store: unknown auth method %q (want token or kubernetes)", cfg.Auth)
	}
	return s, nil
}

// login performs a Kubernetes auth login, re-reading the service-account JWT
// from disk so projected-token rotation is picked up without a restart.
// Callers hold no lock; login takes mu itself.
func (s *vaultStore) login(ctx context.Context) error {
	jwt, err := os.ReadFile(s.cfg.K8sJWTPath)
	if err != nil {
		return fmt.Errorf("read service-account JWT: %w", err)
	}
	secret, err := s.client.Logical().WriteWithContext(ctx,
		"auth/"+s.cfg.K8sMount+"/login",
		map[string]any{"role": s.cfg.K8sRole, "jwt": strings.TrimSpace(string(jwt))})
	if err != nil {
		return fmt.Errorf("kubernetes login: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return fmt.Errorf("kubernetes login: response carried no client token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client.SetToken(secret.Auth.ClientToken)
	// Proactively re-login at two-thirds of the lease so requests don't
	// routinely hit the expiry edge; the 403-retry below covers the rest.
	s.renewAt = time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second * 2 / 3)
	return nil
}

// do runs op with the auth lifecycle applied: a proactive re-login when the
// kubernetes lease is past its renewal point, and a single re-login + retry
// when Vault answers 403 (token revoked or expired early).
func (s *vaultStore) do(ctx context.Context, op func() error) error {
	if s.cfg.Auth == "kubernetes" {
		s.mu.Lock()
		stale := time.Now().After(s.renewAt)
		s.mu.Unlock()
		if stale {
			if err := s.login(ctx); err != nil {
				return err
			}
		}
	}
	err := op()
	if err != nil && s.cfg.Auth == "kubernetes" && isPermissionDenied(err) {
		if lerr := s.login(ctx); lerr != nil {
			return errors.Join(err, lerr)
		}
		return op()
	}
	return err
}

func isPermissionDenied(err error) bool {
	var re *api.ResponseError
	return errors.As(err, &re) && re.StatusCode == http.StatusForbidden
}

func (s *vaultStore) layerDataPath(key string) string {
	return path.Join(s.cfg.Mount, "data", s.cfg.Path, "layers", key)
}

func (s *vaultStore) layerMetaPath(key string) string {
	return path.Join(s.cfg.Mount, "metadata", s.cfg.Path, "layers", key)
}

func (s *vaultStore) groupsDataPath(user string) string {
	return path.Join(s.cfg.Mount, "data", s.cfg.Path, "groups", user)
}

// readField reads a single string field from a KVv2 secret. A missing
// secret (or a deleted current version) is ("", false, nil).
func (s *vaultStore) readField(ctx context.Context, dataPath, field string) (string, bool, error) {
	var value string
	var found bool
	err := s.do(ctx, func() error {
		secret, err := s.client.Logical().ReadWithContext(ctx, dataPath)
		if err != nil {
			return err
		}
		if secret == nil {
			return nil
		}
		data, _ := secret.Data["data"].(map[string]any)
		if data == nil {
			return nil
		}
		v, ok := data[field].(string)
		if !ok {
			return fmt.Errorf("secret at %s: missing or non-string field %q", dataPath, field)
		}
		value, found = v, true
		return nil
	})
	return value, found, err
}

func (s *vaultStore) writeField(ctx context.Context, dataPath, field, value string) error {
	return s.do(ctx, func() error {
		_, err := s.client.Logical().WriteWithContext(ctx, dataPath,
			map[string]any{"data": map[string]any{field: value}})
		return err
	})
}

func (s *vaultStore) GetLayer(ctx context.Context, key string) ([]byte, bool, error) {
	value, found, err := s.readField(ctx, s.layerDataPath(key), layerDocField)
	if err != nil {
		return nil, false, fmt.Errorf("get layer %q: %w", key, err)
	}
	if !found {
		return nil, false, nil
	}
	return []byte(value), true, nil
}

func (s *vaultStore) PutLayer(ctx context.Context, key string, doc []byte) error {
	if err := s.writeField(ctx, s.layerDataPath(key), layerDocField, string(doc)); err != nil {
		return fmt.Errorf("put layer %q: %w", key, err)
	}
	return nil
}

func (s *vaultStore) DeleteLayer(ctx context.Context, key string) error {
	// Metadata delete removes all versions, so a re-listed store doesn't
	// resurrect a "deleted" layer as a soft-deleted current version.
	err := s.do(ctx, func() error {
		_, err := s.client.Logical().DeleteWithContext(ctx, s.layerMetaPath(key))
		return err
	})
	if err != nil {
		return fmt.Errorf("delete layer %q: %w", key, err)
	}
	return nil
}

func (s *vaultStore) ListLayers(ctx context.Context, prefix string) ([]string, error) {
	base := path.Join(s.cfg.Mount, "metadata", s.cfg.Path, "layers")
	var keys []string
	if err := s.listRecursive(ctx, base, "", &keys); err != nil {
		return nil, fmt.Errorf("list layers: %w", err)
	}
	out := keys[:0]
	for _, k := range keys {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

// listRecursive walks the KVv2 metadata tree under base, accumulating full
// layer keys relative to base. Folder entries carry a trailing slash in
// LIST responses.
func (s *vaultStore) listRecursive(ctx context.Context, base, rel string, out *[]string) error {
	var entries []string
	err := s.do(ctx, func() error {
		secret, err := s.client.Logical().ListWithContext(ctx, path.Join(base, rel))
		if err != nil {
			return err
		}
		entries = entries[:0]
		if secret == nil {
			return nil
		}
		raw, _ := secret.Data["keys"].([]any)
		for _, e := range raw {
			if name, ok := e.(string); ok {
				entries = append(entries, name)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, name := range entries {
		if strings.HasSuffix(name, "/") {
			if err := s.listRecursive(ctx, base, rel+name, out); err != nil {
				return err
			}
			continue
		}
		*out = append(*out, rel+name)
	}
	return nil
}

func (s *vaultStore) GetGroups(ctx context.Context, user string) ([]string, bool, error) {
	value, found, err := s.readField(ctx, s.groupsDataPath(user), groupsField)
	if err != nil {
		return nil, false, fmt.Errorf("get groups for %q: %w", user, err)
	}
	if !found {
		return nil, false, nil
	}
	var groups []string
	if err := json.Unmarshal([]byte(value), &groups); err != nil {
		return nil, false, fmt.Errorf("decode groups for %q: %w", user, err)
	}
	if groups == nil {
		groups = []string{}
	}
	return groups, true, nil
}

func (s *vaultStore) PutGroups(ctx context.Context, user string, groups []string) error {
	if groups == nil {
		groups = []string{}
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return fmt.Errorf("encode groups for %q: %w", user, err)
	}
	if err := s.writeField(ctx, s.groupsDataPath(user), groupsField, string(raw)); err != nil {
		return fmt.Errorf("put groups for %q: %w", user, err)
	}
	return nil
}

func (s *vaultStore) Ping(ctx context.Context) error {
	// Token lookup-self exercises both reachability and a usable token,
	// which is what /readyz wants to know — a healthy Vault the service
	// cannot authenticate to is not ready.
	return s.do(ctx, func() error {
		_, err := s.client.Auth().Token().LookupSelfWithContext(ctx)
		return err
	})
}

func (s *vaultStore) Close() error {
	return nil
}
