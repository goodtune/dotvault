//go:build windows

package agent

import (
	"strings"
	"testing"
)

// TestPipeLeafName covers the normalisation the existence filter compares
// against the (lower-cased) namespace listing. The pipe namespace is
// case-insensitive, so a candidate spelled \\.\Pipe\x names the same pipe as
// \\.\pipe\x — a case-sensitive prefix trim silently dropped it.
func TestPipeLeafName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`\\.\pipe\openssh-ssh-agent`, "openssh-ssh-agent"},
		{`\\.\Pipe\OpenSSH-SSH-Agent`, "openssh-ssh-agent"},
		{`//./pipe/openssh-ssh-agent`, "openssh-ssh-agent"},
		{`openssh-ssh-agent`, "openssh-ssh-agent"},
	} {
		if got := pipeLeafName(tc.in); got != tc.want {
			t.Errorf("pipeLeafName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestExistingPipesReportsEnumeration pins the contract the candidate filter
// depends on: an empty set must be distinguishable from a failed listing, or a
// failure reads as "no agents are running" and disables detection wholesale.
func TestExistingPipesReportsEnumeration(t *testing.T) {
	names, ok := existingPipes()
	if !ok {
		t.Skip("pipe namespace not enumerable in this environment")
	}
	if names == nil {
		t.Error("a successful enumeration must return a non-nil set")
	}
}

// TestCandidateEndpointsAreNormalised checks the Windows candidate list stays
// dial-able: every entry must carry the pipe prefix, since dialEndpoint passes
// it to the pipe API verbatim and $SSH_AUTH_SOCK can hold any spelling at all.
//
// The earlier version of this test asserted only that entries were non-empty
// while its name and comment promised the prefix check — a test that describes
// more than it verifies is worse than none, because it makes the property look
// covered.
func TestCandidateEndpointsAreNormalised(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "openssh-ssh-agent") // a bare leaf, not dial-able as-is
	for _, ep := range candidateEndpoints() {
		if !strings.HasPrefix(ep, pipePrefix) {
			t.Errorf("candidate %q does not carry the %q prefix; dialEndpoint cannot open it", ep, pipePrefix)
		}
	}
}

// TestCandidateEndpointsDedupeEquivalentSpellings pins the other half: one pipe
// must appear once however it was spelled. A duplicate endpoint means the same
// agent is listed twice, and an ssh client offering one key twice burns two of
// a server's MaxAuthTries attempts.
func TestCandidateEndpointsDedupeEquivalentSpellings(t *testing.T) {
	// The forward-slash spelling of the pipe the fixed list already contains.
	t.Setenv("SSH_AUTH_SOCK", "//./pipe/openssh-ssh-agent")
	seen := map[string]int{}
	for _, ep := range candidateEndpoints() {
		seen[strings.ToLower(ep)]++
	}
	for ep, n := range seen {
		if n > 1 {
			t.Errorf("endpoint %q appears %d times, want once", ep, n)
		}
	}
}
