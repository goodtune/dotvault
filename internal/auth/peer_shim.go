package auth

import (
	"context"

	"github.com/goodtune/dotvault/internal/peer"
)

// BorrowFromSockets is a transitional shim, deleted once callers borrow
// through peer.Borrower (Task 6/7).
func BorrowFromSockets(ctx context.Context, socketPaths []string) (string, string) {
	for _, p := range socketPaths {
		if p == "" {
			continue
		}
		if token, _ := peer.FetchToken(ctx, p); token != "" {
			return token, p
		}
	}
	return "", ""
}
