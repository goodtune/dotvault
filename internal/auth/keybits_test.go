package auth

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/goodtune/dotvault/internal/securestore"
	"github.com/goodtune/dotvault/internal/vault"
)

// errAfterGenerate short-circuits the flow immediately after Generate. These
// tests are about the arguments Generate receives, so everything downstream
// (PKI signing, a real Vault, a usable signer) is deliberately never reached.
var errAfterGenerate = errors.New("stop after generate")

// recordingStore captures what the cert-auth flow asked the backend to generate.
type recordingStore struct {
	gotKeyType securestore.KeyType
	gotBits    int
	gotSeal    bool
	calls      int
}

func (r *recordingStore) Capabilities() securestore.Capabilities {
	return securestore.Capabilities{Name: "file"}
}

func (r *recordingStore) Generate(kt securestore.KeyType, bits int, seal bool) (crypto.Signer, []byte, error) {
	r.calls++
	r.gotKeyType, r.gotBits, r.gotSeal = kt, bits, seal
	return nil, nil, errAfterGenerate
}

func (r *recordingStore) Import(crypto.PrivateKey, bool) (crypto.Signer, []byte, error) {
	return nil, nil, errAfterGenerate
}
func (r *recordingStore) Load([]byte) (crypto.Signer, error) { return nil, errAfterGenerate }
func (r *recordingStore) Close() error                       { return nil }

// TestKeyBitsReachesGenerate pins that vault.mtls.key_bits is handed to the
// secure store, at BOTH sites that mint a key — rotation and first enrolment.
//
// This is the assertion that matters, and the one a config-only test would
// miss. Validation proves the value parses; if it were then dropped between
// config and the backend, dotvault would silently keep generating 2048-bit keys
// and an operator whose Vault PKI role pins RSA at 4096 would keep seeing
// issuance rejected — by a Vault-side error that says nothing about dotvault's
// configuration. Asserting the plumbing is what catches that.
func TestKeyBitsReachesGenerate(t *testing.T) {
	tests := []struct {
		name     string
		keyType  string
		keyBits  int
		wantBits int
	}{
		{name: "rsa4096", keyType: "rsa", keyBits: 4096, wantBits: 4096},
		{name: "rsa8192", keyType: "rsa", keyBits: 8192, wantBits: 8192},
		// Unset must arrive as 0 so the BACKEND applies the default. Having
		// this layer substitute 2048 would duplicate the default in two
		// places, free to drift apart.
		{name: "unsetStaysZero", keyType: "rsa", keyBits: 0, wantBits: 0},
		{name: "ecCarriesZero", keyType: "ec", keyBits: 0, wantBits: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := func() *MTLSParams {
				return &MTLSParams{
					Method:     "mtls",
					KeyType:    tt.keyType,
					KeyBits:    tt.keyBits,
					CommonName: "{{.user}}",
					CertMount:  "cert",
					CertRole:   "dotvault",
					PKIMount:   "pki",
					PKIRole:    "dotvault-client",
				}
			}

			// Site 1: rotation. Reached with no Vault I/O at all.
			t.Run("reissue", func(t *testing.T) {
				st := &recordingStore{}
				m := &Manager{Username: "u", MTLS: params()}
				old := &sealedCredential{NotAfter: time.Now().Add(time.Hour)}

				err := m.reissue(context.Background(), st, old)
				if !errors.Is(err, errAfterGenerate) {
					t.Fatalf("reissue() = %v, want it to stop at Generate", err)
				}
				assertGenerate(t, st, tt.keyType, tt.wantBits)
			})

			// Site 2: first enrolment via bootstrap. The BootstrapLogin hook
			// stands in for the human login, so this needs no live Vault
			// either — the sibling client is built locally and never dialled
			// before Generate is called.
			t.Run("seedCredential", func(t *testing.T) {
				vc, err := vault.NewClient(vault.Config{Address: "http://127.0.0.1:1"})
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}
				st := &recordingStore{}
				m := &Manager{
					Username:       "u",
					VaultClient:    vc,
					MTLS:           params(),
					BootstrapLogin: func(context.Context) (string, error) { return "s.bootstrap", nil },
				}

				_, _, err = m.seedCredential(context.Background(), st)
				if !errors.Is(err, errAfterGenerate) {
					t.Fatalf("seedCredential() = %v, want it to stop at Generate", err)
				}
				assertGenerate(t, st, tt.keyType, tt.wantBits)
			})
		})
	}
}

func assertGenerate(t *testing.T, st *recordingStore, wantType string, wantBits int) {
	t.Helper()
	if st.calls != 1 {
		t.Fatalf("Generate called %d times, want 1", st.calls)
	}
	if string(st.gotKeyType) != wantType {
		t.Errorf("Generate key type = %q, want %q", st.gotKeyType, wantType)
	}
	if st.gotBits != wantBits {
		t.Errorf("Generate bits = %d, want %d — key_bits did not reach the backend", st.gotBits, wantBits)
	}
}
