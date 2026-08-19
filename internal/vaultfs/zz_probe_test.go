//go:build linux || darwin || freebsd

package vaultfs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeLargeDocumentRead(t *testing.T) {
	store := newMemStore()
	store.put("big", map[string]any{"v": strings.Repeat("x", 400*1024)})
	mnt := mountForTest(t, store, Options{CacheTTL: time.Second})
	b, err := os.ReadFile(filepath.Join(mnt, "big"))
	if err != nil {
		t.Fatalf("read big: %v", err)
	}
	t.Logf("read %d bytes", len(b))
}

func TestProbeConcurrentRW(t *testing.T) {
	store := newMemStore()
	store.put("gh", map[string]any{"a": "1"})
	mnt := mountForTest(t, store, Options{ReadWrite: true, CacheTTL: time.Second})
	f, err := os.OpenFile(filepath.Join(mnt, "gh"), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			buf := make([]byte, 64)
			_, _ = f.ReadAt(buf, 0)
		}
	}()
	for i := 0; i < 200; i++ {
		_, _ = f.WriteAt([]byte(`{"a":"22222"}`), 0)
	}
	<-done
}
