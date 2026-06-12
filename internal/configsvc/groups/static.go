package groups

import (
	"context"

	"github.com/goodtune/dotvault/internal/configsvc/store"
)

// staticResolver reads membership maps from the store — the entries seeded
// from a groups.yaml. An unknown user is an empty membership, not an error.
type staticResolver struct {
	st store.Store
}

// NewStatic returns a Resolver backed by the store's membership table.
func NewStatic(st store.Store) Resolver {
	return &staticResolver{st: st}
}

func (r *staticResolver) Groups(ctx context.Context, user string) ([]string, error) {
	groups, ok, err := r.st.GetGroups(ctx, user)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return groups, nil
}
