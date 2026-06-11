package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// sqliteStore is the development/test backend: layers(key, doc, updated_at)
// and groups(username, groups) per the design spec, plus
// service_accounts(name, doc) for the admin surface.
type sqliteStore struct {
	db *sql.DB
}

func openSQLite(ctx context.Context, dsn string) (*sqliteStore, error) {
	if dsn == "" {
		return nil, fmt.Errorf("sqlite store: dsn is required")
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	// A single pooled connection serialises writers (SQLite allows one) and
	// keeps ":memory:" coherent — each additional pooled connection would
	// otherwise open its own empty in-memory database.
	db.SetMaxOpenConns(1)
	const schema = `
CREATE TABLE IF NOT EXISTS layers (
	key        TEXT PRIMARY KEY,
	doc        BLOB NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS groups (
	username TEXT PRIMARY KEY,
	groups   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS service_accounts (
	name TEXT PRIMARY KEY,
	doc  TEXT NOT NULL
);`
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create sqlite schema: %w", err)
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) GetLayer(ctx context.Context, key string) ([]byte, bool, error) {
	var doc []byte
	err := s.db.QueryRowContext(ctx, `SELECT doc FROM layers WHERE key = ?`, key).Scan(&doc)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get layer %q: %w", key, err)
	}
	return doc, true, nil
}

func (s *sqliteStore) PutLayer(ctx context.Context, key string, doc []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO layers (key, doc, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET doc = excluded.doc, updated_at = excluded.updated_at`,
		key, doc, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("put layer %q: %w", key, err)
	}
	return nil
}

func (s *sqliteStore) DeleteLayer(ctx context.Context, key string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM layers WHERE key = ?`, key); err != nil {
		return fmt.Errorf("delete layer %q: %w", key, err)
	}
	return nil
}

func (s *sqliteStore) ListLayers(ctx context.Context, prefix string) ([]string, error) {
	// Prefix-filter in Go rather than via LIKE so prefixes containing
	// LIKE metacharacters ("%", "_") need no escaping. The table is small.
	rows, err := s.db.QueryContext(ctx, `SELECT key FROM layers`)
	if err != nil {
		return nil, fmt.Errorf("list layers: %w", err)
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("list layers: %w", err)
		}
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list layers: %w", err)
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *sqliteStore) GetGroups(ctx context.Context, user string) ([]string, bool, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT groups FROM groups WHERE username = ?`, user).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get groups for %q: %w", user, err)
	}
	var groups []string
	if err := json.Unmarshal([]byte(raw), &groups); err != nil {
		return nil, false, fmt.Errorf("decode groups for %q: %w", user, err)
	}
	if groups == nil {
		groups = []string{}
	}
	return groups, true, nil
}

func (s *sqliteStore) PutGroups(ctx context.Context, user string, groups []string) error {
	if groups == nil {
		groups = []string{}
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return fmt.Errorf("encode groups for %q: %w", user, err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO groups (username, groups) VALUES (?, ?)
		 ON CONFLICT(username) DO UPDATE SET groups = excluded.groups`,
		user, string(raw))
	if err != nil {
		return fmt.Errorf("put groups for %q: %w", user, err)
	}
	return nil
}

func (s *sqliteStore) DeleteGroups(ctx context.Context, user string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM groups WHERE username = ?`, user); err != nil {
		return fmt.Errorf("delete groups for %q: %w", user, err)
	}
	return nil
}

func (s *sqliteStore) ListGroupUsers(ctx context.Context) ([]string, error) {
	return s.listColumn(ctx, `SELECT username FROM groups ORDER BY username`, "list group users")
}

func (s *sqliteStore) GetServiceAccount(ctx context.Context, name string) (*ServiceAccount, bool, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT doc FROM service_accounts WHERE name = ?`, name).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get service account %q: %w", name, err)
	}
	var sa ServiceAccount
	if err := json.Unmarshal([]byte(raw), &sa); err != nil {
		return nil, false, fmt.Errorf("decode service account %q: %w", name, err)
	}
	return &sa, true, nil
}

func (s *sqliteStore) PutServiceAccount(ctx context.Context, sa *ServiceAccount) error {
	raw, err := json.Marshal(sa)
	if err != nil {
		return fmt.Errorf("encode service account %q: %w", sa.Name, err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO service_accounts (name, doc) VALUES (?, ?)
		 ON CONFLICT(name) DO UPDATE SET doc = excluded.doc`,
		sa.Name, string(raw))
	if err != nil {
		return fmt.Errorf("put service account %q: %w", sa.Name, err)
	}
	return nil
}

func (s *sqliteStore) DeleteServiceAccount(ctx context.Context, name string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM service_accounts WHERE name = ?`, name); err != nil {
		return fmt.Errorf("delete service account %q: %w", name, err)
	}
	return nil
}

func (s *sqliteStore) ListServiceAccounts(ctx context.Context) ([]string, error) {
	return s.listColumn(ctx, `SELECT name FROM service_accounts ORDER BY name`, "list service accounts")
}

// listColumn collects a single-string-column query result.
func (s *sqliteStore) listColumn(ctx context.Context, query, what string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return out, nil
}

func (s *sqliteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}
