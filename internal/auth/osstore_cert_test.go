package auth

import (
	"crypto"
	"testing"

	"github.com/goodtune/dotvault/internal/securestore"
)

// fakeCertStore is a securestore.Storage that also implements CertStorer, so the
// cert-auth flow's storeCertInNativeStore helper exercises the "os"-backend
// branch without a live Windows certificate store.
type fakeCertStore struct {
	called    bool
	gotHandle []byte
	gotCert   string
	retHandle []byte
}

func (f *fakeCertStore) Capabilities() securestore.Capabilities {
	return securestore.Capabilities{Name: "os", HardwareBound: true}
}
func (f *fakeCertStore) Generate(securestore.KeyType, bool) (crypto.Signer, []byte, error) {
	return nil, nil, nil
}
func (f *fakeCertStore) Import(crypto.PrivateKey, bool) (crypto.Signer, []byte, error) {
	return nil, nil, nil
}
func (f *fakeCertStore) Load([]byte) (crypto.Signer, error) { return nil, nil }
func (f *fakeCertStore) Close() error                       { return nil }
func (f *fakeCertStore) StoreCert(handle []byte, certPEM string) ([]byte, error) {
	f.called = true
	f.gotHandle = handle
	f.gotCert = certPEM
	return f.retHandle, nil
}

func TestStoreCertInNativeStore(t *testing.T) {
	// A CertStorer backend ("os"): the cert is pushed into the store and the
	// returned handle is adopted for persistence.
	t.Run("cert-storer backend installs and re-handles", func(t *testing.T) {
		cs := &fakeCertStore{retHandle: []byte("new-handle")}
		cred := &sealedCredential{CertPEM: "PEMDATA", Handle: []byte("old-handle")}
		if err := storeCertInNativeStore(cs, cred); err != nil {
			t.Fatalf("storeCertInNativeStore: %v", err)
		}
		if !cs.called {
			t.Fatal("StoreCert was not called for a CertStorer backend")
		}
		if cs.gotCert != "PEMDATA" {
			t.Errorf("StoreCert cert = %q, want %q", cs.gotCert, "PEMDATA")
		}
		if string(cs.gotHandle) != "old-handle" {
			t.Errorf("StoreCert handle = %q, want %q", cs.gotHandle, "old-handle")
		}
		if string(cred.Handle) != "new-handle" {
			t.Errorf("cred.Handle = %q, want it updated to %q", cred.Handle, "new-handle")
		}
	})

	// A plain Storage backend (file/tpm) does not implement CertStorer: the
	// helper is a no-op and the handle is preserved untouched.
	t.Run("non-cert-storer backend is a no-op", func(t *testing.T) {
		fileStore, err := securestore.Open("file")
		if err != nil {
			t.Fatal(err)
		}
		cred := &sealedCredential{CertPEM: "PEMDATA", Handle: []byte("keep")}
		if err := storeCertInNativeStore(fileStore, cred); err != nil {
			t.Fatalf("storeCertInNativeStore (file): %v", err)
		}
		if string(cred.Handle) != "keep" {
			t.Errorf("cred.Handle = %q, want it preserved as %q", cred.Handle, "keep")
		}
	})
}
