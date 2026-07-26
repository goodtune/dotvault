package auth

import (
	"errors"
	"testing"

	"github.com/goodtune/dotvault/internal/securestore"
)

// lifecycleStore is a fake CertStorer+CertLifecycle backend. The real one is
// Windows-only CNG, so the transactional contract is exercised here instead:
// what matters is that internal/auth calls commit and rollback at the right
// moments, which is platform-neutral.
type lifecycleStore struct {
	securestore.Storage
	storeCertErr error
	committed    [][2][]byte // (new, old) pairs
	rolledBack   [][]byte
}

func (f *lifecycleStore) StoreCert(handle []byte, certPEM string) ([]byte, error) {
	if f.storeCertErr != nil {
		return nil, f.storeCertErr
	}
	// Mimic the OS backend: the installed leaf re-keys the handle.
	return append(append([]byte{}, handle...), []byte("+leaf")...), nil
}

func (f *lifecycleStore) CommitCert(newHandle, oldHandle []byte) error {
	f.committed = append(f.committed, [2][]byte{newHandle, oldHandle})
	return nil
}

func (f *lifecycleStore) RollbackCert(newHandle []byte) error {
	f.rolledBack = append(f.rolledBack, newHandle)
	return nil
}

// plainStore implements Storage but NOT CertLifecycle — the file/tpm shape.
type plainStore struct{ securestore.Storage }

// TestCertRotationHelpers pins the two-phase rotation contract added for the
// P1 PR-review findings.
//
// The OS-native backend creates a new CNG key container and installs another
// CurrentUser\My leaf per rotation. Before this, a failure part-way through
// destroyed the key matching the still-current certificate (the container was
// overwritten) and every rotation left another simultaneously valid client
// identity behind. Correctness now depends on internal/auth calling commit only
// once the replacement is persisted AND operational, and rolling back otherwise.
func TestCertRotationHelpers(t *testing.T) {
	t.Run("commitPassesBothHandles", func(t *testing.T) {
		f := &lifecycleStore{}
		commitCertRotation(f, []byte("new"), []byte("old"))
		if len(f.committed) != 1 {
			t.Fatalf("commits = %d, want 1", len(f.committed))
		}
		got := f.committed[0]
		if string(got[0]) != "new" || string(got[1]) != "old" {
			t.Errorf("committed (%q,%q), want (new,old)", got[0], got[1])
		}
	})

	t.Run("commitToleratesNilOldHandle", func(t *testing.T) {
		// First enrolment: nothing to retire.
		f := &lifecycleStore{}
		commitCertRotation(f, []byte("new"), nil)
		if len(f.committed) != 1 || f.committed[0][1] != nil {
			t.Errorf("committed = %v, want one entry with a nil old handle", f.committed)
		}
	})

	t.Run("rollbackDiscardsReplacement", func(t *testing.T) {
		f := &lifecycleStore{}
		rollbackCertRotation(f, []byte("abandoned"))
		if len(f.rolledBack) != 1 || string(f.rolledBack[0]) != "abandoned" {
			t.Errorf("rolledBack = %q, want [abandoned]", f.rolledBack)
		}
	})

	t.Run("noopWithoutCapability", func(t *testing.T) {
		// file/tpm: the handle IS the key material, so overwriting the envelope
		// is the whole transaction and there is nothing to sweep. These must not
		// panic or misbehave on a backend that does not implement the interface.
		p := &plainStore{}
		commitCertRotation(p, []byte("new"), []byte("old"))
		rollbackCertRotation(p, []byte("new"))
	})

	t.Run("advisoryErrorsAreSwallowed", func(t *testing.T) {
		// A live, working credential must not be rejected because a stale
		// artefact could not be swept.
		f := &erroringLifecycle{}
		commitCertRotation(f, []byte("new"), []byte("old"))
		rollbackCertRotation(f, []byte("new"))
	})
}

type erroringLifecycle struct{ securestore.Storage }

func (e *erroringLifecycle) StoreCert(h []byte, _ string) ([]byte, error) { return h, nil }
func (e *erroringLifecycle) CommitCert(_, _ []byte) error {
	return errors.New("sweep failed")
}
func (e *erroringLifecycle) RollbackCert(_ []byte) error { return errors.New("sweep failed") }
