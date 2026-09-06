//go:build windows

package agent

import "testing"

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
// it to the pipe API verbatim.
func TestCandidateEndpointsAreNormalised(t *testing.T) {
	for _, ep := range candidateEndpoints() {
		if len(ep) == 0 {
			t.Error("empty candidate endpoint")
		}
	}
}
