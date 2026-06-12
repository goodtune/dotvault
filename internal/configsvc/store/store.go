// Package store provides the persistence backends for the dotvault-config
// service: layer documents (partial configs keyed by canonical layer key) and
// static group membership. Two drivers exist behind the Store interface — a
// pure-Go SQLite driver for development and tests, and a Vault KVv2 driver
// for production — opened via the Open / OpenVault factory pair, following
// the same pattern as the ghp prior art so a future driver (e.g. postgres)
// slots in without touching callers.
package store

import (
	"context"
	"fmt"
	"time"
)

// ServiceAccount is a local, non-human identity defined in the storage layer
// itself — the automation principal the admin API authenticates via mTLS
// (the client certificate's CN must equal Name). Disabled accounts are
// rejected at authentication regardless of certificate validity, which is
// the immediate-revocation lever for Vault-minted short-lived certs.
type ServiceAccount struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Disabled    bool      `json:"disabled,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitzero"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
}

// Store persists configuration layers, static group membership, and service
// accounts. Layer keys are the canonical composition keys ("global",
// "os/linux", "group/sydney", "user/alice") and are treated as opaque
// strings by the drivers. Layer documents are stored as raw bytes —
// validation is the caller's concern (the seed and admin-API paths validate
// before writing; the compose path validates on read so a corrupt layer
// surfaces as an error naming the key).
type Store interface {
	// GetLayer returns the document stored under key. The boolean reports
	// presence: a missing layer is (nil, false, nil), never an error.
	GetLayer(ctx context.Context, key string) ([]byte, bool, error)

	// PutLayer stores doc under key, replacing any existing document.
	PutLayer(ctx context.Context, key string, doc []byte) error

	// DeleteLayer removes the layer. Deleting a missing layer is a no-op.
	DeleteLayer(ctx context.Context, key string) error

	// ListLayers returns the keys of all stored layers with the given
	// prefix, sorted lexicographically. An empty prefix lists everything.
	ListLayers(ctx context.Context, prefix string) ([]string, error)

	// GetGroups returns the static group membership recorded for user. The
	// boolean reports presence: an unknown user is (nil, false, nil). This
	// backs the static groups.Resolver.
	GetGroups(ctx context.Context, user string) ([]string, bool, error)

	// PutGroups records the static group membership for user, replacing
	// any existing entry. An empty (non-nil) list is a valid membership.
	PutGroups(ctx context.Context, user string, groups []string) error

	// DeleteGroups removes the static membership entry for user. Deleting
	// a missing entry is a no-op.
	DeleteGroups(ctx context.Context, user string) error

	// ListGroupUsers returns the usernames that have a static membership
	// entry, sorted lexicographically.
	ListGroupUsers(ctx context.Context) ([]string, error)

	// GetServiceAccount returns the named service account. The boolean
	// reports presence: an unknown account is (nil, false, nil).
	GetServiceAccount(ctx context.Context, name string) (*ServiceAccount, bool, error)

	// PutServiceAccount stores the account under sa.Name, replacing any
	// existing entry.
	PutServiceAccount(ctx context.Context, sa *ServiceAccount) error

	// DeleteServiceAccount removes the account. Deleting a missing account
	// is a no-op.
	DeleteServiceAccount(ctx context.Context, name string) error

	// ListServiceAccounts returns the stored account names, sorted
	// lexicographically.
	ListServiceAccounts(ctx context.Context) ([]string, error)

	// Ping verifies the backend is reachable and usable; it gates the
	// service's /readyz probe.
	Ping(ctx context.Context) error

	// Close releases the backend connection.
	Close() error
}

// Open constructs a Store for a DSN-style driver. Currently "sqlite"
// (modernc.org/sqlite — pure Go, so CGO stays off) is the only DSN driver;
// the Vault driver takes structured config and has its own constructor,
// OpenVault.
func Open(ctx context.Context, driver, dsn string) (Store, error) {
	switch driver {
	case "sqlite":
		return openSQLite(ctx, dsn)
	default:
		return nil, fmt.Errorf("unknown store driver %q (want \"sqlite\"; the vault driver is opened via OpenVault)", driver)
	}
}
