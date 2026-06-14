package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/goodtune/dotvault/internal/configsvc/store"
	"github.com/goodtune/dotvault/internal/configsvc/store/storetest"
)

func TestSQLiteConformanceMemory(t *testing.T) {
	st, err := store.Open(context.Background(), "sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	storetest.Run(t, st)
}

func TestSQLiteConformanceFile(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "configsvc.db")
	st, err := store.Open(context.Background(), "sqlite", dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	storetest.Run(t, st)
}

func TestSQLitePersistsAcrossOpen(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "configsvc.db")

	st, err := store.Open(ctx, "sqlite", dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.PutLayer(ctx, "global", []byte("rules: []\n")); err != nil {
		t.Fatalf("PutLayer: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st, err = store.Open(ctx, "sqlite", dsn)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer st.Close()
	if _, ok, err := st.GetLayer(ctx, "global"); err != nil || !ok {
		t.Fatalf("GetLayer after reopen = ok=%v err=%v, want present", ok, err)
	}
}

func TestOpenUnknownDriver(t *testing.T) {
	if _, err := store.Open(context.Background(), "postgres", "dsn"); err == nil {
		t.Fatal("Open with unknown driver succeeded, want error")
	}
}

func TestOpenSQLiteEmptyDSN(t *testing.T) {
	if _, err := store.Open(context.Background(), "sqlite", ""); err == nil {
		t.Fatal("Open with empty dsn succeeded, want error")
	}
}
