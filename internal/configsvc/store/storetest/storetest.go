// Package storetest holds the driver-neutral conformance suite for
// configsvc store implementations. The sqlite driver runs it as a unit test;
// the Vault driver runs it under test/integration against a real dev Vault;
// a future driver (e.g. postgres) gets its contract checked by calling Run.
package storetest

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// Run exercises the Store contract against st. The store should be empty
// (or namespaced to this test) when passed in; Run does not Close it.
func Run(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()

	t.Run("ping", func(t *testing.T) {
		if err := st.Ping(ctx); err != nil {
			t.Fatalf("Ping: %v", err)
		}
	})

	t.Run("layers", func(t *testing.T) {
		if _, ok, err := st.GetLayer(ctx, "global"); err != nil || ok {
			t.Fatalf("GetLayer on empty store = ok=%v err=%v, want absent", ok, err)
		}

		doc := []byte("rules: []\n")
		if err := st.PutLayer(ctx, "global", doc); err != nil {
			t.Fatalf("PutLayer: %v", err)
		}
		got, ok, err := st.GetLayer(ctx, "global")
		if err != nil || !ok {
			t.Fatalf("GetLayer = ok=%v err=%v, want present", ok, err)
		}
		if string(got) != string(doc) {
			t.Fatalf("GetLayer = %q, want %q", got, doc)
		}

		// Overwrite replaces wholesale.
		doc2 := []byte("sync:\n  interval: 5m\n")
		if err := st.PutLayer(ctx, "global", doc2); err != nil {
			t.Fatalf("PutLayer overwrite: %v", err)
		}
		got, _, _ = st.GetLayer(ctx, "global")
		if string(got) != string(doc2) {
			t.Fatalf("GetLayer after overwrite = %q, want %q", got, doc2)
		}

		// Nested keys and prefix listing.
		for _, key := range []string{"os/linux", "os/darwin", "group/sydney", "user/alice"} {
			if err := st.PutLayer(ctx, key, []byte("rules: []\n")); err != nil {
				t.Fatalf("PutLayer %q: %v", key, err)
			}
		}
		keys, err := st.ListLayers(ctx, "os/")
		if err != nil {
			t.Fatalf("ListLayers(os/): %v", err)
		}
		if want := []string{"os/darwin", "os/linux"}; !reflect.DeepEqual(keys, want) {
			t.Fatalf("ListLayers(os/) = %v, want %v", keys, want)
		}
		keys, err = st.ListLayers(ctx, "")
		if err != nil {
			t.Fatalf("ListLayers(): %v", err)
		}
		if want := []string{"global", "group/sydney", "os/darwin", "os/linux", "user/alice"}; !reflect.DeepEqual(keys, want) {
			t.Fatalf("ListLayers() = %v, want %v", keys, want)
		}

		// Delete is effective and idempotent.
		if err := st.DeleteLayer(ctx, "os/darwin"); err != nil {
			t.Fatalf("DeleteLayer: %v", err)
		}
		if _, ok, _ := st.GetLayer(ctx, "os/darwin"); ok {
			t.Fatal("GetLayer after delete reports present")
		}
		if err := st.DeleteLayer(ctx, "os/darwin"); err != nil {
			t.Fatalf("DeleteLayer (missing): %v", err)
		}
		keys, _ = st.ListLayers(ctx, "os/")
		if want := []string{"os/linux"}; !reflect.DeepEqual(keys, want) {
			t.Fatalf("ListLayers(os/) after delete = %v, want %v", keys, want)
		}
	})

	t.Run("layer key fidelity", func(t *testing.T) {
		// Keys are opaque to the driver: spaces (Windows account names) and
		// mixed case must round-trip exactly, and lookups must be exact
		// matches.
		keys := []string{"user/Alice Smith", "user/alice smith", "user/MixedCase"}
		for i, key := range keys {
			doc := []byte(fmt.Sprintf("sync:\n  interval: %dm\n", i+1))
			if err := st.PutLayer(ctx, key, doc); err != nil {
				t.Fatalf("PutLayer %q: %v", key, err)
			}
		}
		for i, key := range keys {
			got, ok, err := st.GetLayer(ctx, key)
			if err != nil || !ok {
				t.Fatalf("GetLayer %q = ok=%v err=%v, want present", key, ok, err)
			}
			if want := fmt.Sprintf("sync:\n  interval: %dm\n", i+1); string(got) != want {
				t.Fatalf("GetLayer %q = %q, want %q (exact-match lookup)", key, got, want)
			}
		}
		for _, key := range keys {
			if err := st.DeleteLayer(ctx, key); err != nil {
				t.Fatalf("DeleteLayer %q: %v", key, err)
			}
		}
	})

	t.Run("groups", func(t *testing.T) {
		if _, ok, err := st.GetGroups(ctx, "nobody"); err != nil || ok {
			t.Fatalf("GetGroups for unknown user = ok=%v err=%v, want absent", ok, err)
		}

		if err := st.PutGroups(ctx, "alice", []string{"sydney", "newyork"}); err != nil {
			t.Fatalf("PutGroups: %v", err)
		}
		got, ok, err := st.GetGroups(ctx, "alice")
		if err != nil || !ok {
			t.Fatalf("GetGroups = ok=%v err=%v, want present", ok, err)
		}
		if want := []string{"sydney", "newyork"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("GetGroups = %v, want %v", got, want)
		}

		// Overwrite replaces wholesale; an explicit empty membership is
		// present-but-empty, distinct from an unknown user.
		if err := st.PutGroups(ctx, "alice", []string{}); err != nil {
			t.Fatalf("PutGroups (empty): %v", err)
		}
		got, ok, err = st.GetGroups(ctx, "alice")
		if err != nil || !ok {
			t.Fatalf("GetGroups after empty put = ok=%v err=%v, want present", ok, err)
		}
		if len(got) != 0 {
			t.Fatalf("GetGroups after empty put = %v, want empty", got)
		}
	})
}
