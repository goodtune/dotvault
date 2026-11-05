package auth

import "github.com/goodtune/dotvault/internal/tokengate"

// The lifecycle manager is what the daemon wires into every tokengate
// consumer (the SSH agent's backend, the client certificate source).
var (
	_ tokengate.Gate      = (*LifecycleManager)(nil)
	_ tokengate.Signaller = (*LifecycleManager)(nil)
	_ tokengate.Reporter  = (*LifecycleManager)(nil)
)
