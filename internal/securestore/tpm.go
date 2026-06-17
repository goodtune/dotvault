//go:build linux || windows

package securestore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"

	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// pcrSelection is the set of PCRs the key is bound to when seal_to_pcrs is
// enabled. PCRs 0/2/4 cover firmware, option ROMs, and the boot manager — a
// firmware or boot-config change after sealing causes the unseal to fail,
// which the cert-auth flow surfaces as a recoverable error that offers the
// bootstrap fallback.
//
// PCR7 (Secure Boot state) is included on Linux but deliberately EXCLUDED on
// Windows: there, BitLocker claims PCR7 for its own VMK binding, and any
// Secure Boot / firmware change that makes BitLocker re-seal would also break
// our unseal. Dropping PCR7 on Windows keeps the boot-state binding meaningful
// (0/2/4 still move on a tampered boot) without coupling our credential's
// availability to BitLocker's re-seal cycle. The token seal never uses PCRs at
// all (SealData passes sealToPCRs=false); this selection only applies to the
// opt-in mtls+tpm cert-key seal_to_pcrs path.
var pcrSelection = pcrSelectionFor(runtime.GOOS)

// pcrSelectionFor returns the PCR set for the given GOOS, excluding PCR7 on
// Windows per the rationale above. Split out as a pure function so the
// Windows-exclusion branch is unit-testable on a non-Windows CI runner.
func pcrSelectionFor(goos string) tpm2.PCRSelection {
	pcrs := []int{0, 2, 4, 7}
	if goos == "windows" {
		pcrs = []int{0, 2, 4}
	}
	return tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrs}
}

// loadSRK derives the Storage Root Key as a *transient* primary in the owner
// hierarchy (TPM2_CreatePrimary), instead of client.StorageRootKey*, which
// persists the key to a reserved handle via TPM2_EvictControl. EvictControl is
// an owner-hierarchy operation that Windows TBS blocks for standard-user
// processes (0x80280400), so the persisting variant fails on a perfectly
// healthy and accessible Windows TPM. A primary key is deterministic — the
// same template under the same hierarchy seed on the same chip always derives
// the same key — so recreating it transiently on every operation costs nothing
// and still unseals any blob previously sealed under the persistent SRK of the
// same (ECC) template. The returned key owns an open transient handle; callers
// MUST Close() it (which FlushContexts the handle, freeing the TPM's limited
// transient object slots).
func loadSRK(rw io.ReadWriter) (*client.Key, error) {
	return client.NewKey(rw, tpm2.HandleOwner, client.SRKTemplateECC())
}

// tpmStorage seals the EC P-256 private scalar under the TPM Storage Root
// Key. Only EC keys are supported: a TPM sealed-data object's sensitive area
// is bounded (commonly 128 bytes) and a P-256 scalar is 32 bytes, whereas an
// RSA private key does not fit. EC is also the macOS Secure Enclave's only
// algorithm, so EC-only keeps cross-platform configs portable.
//
// The scalar is unsealed into process memory to sign; the at-rest protection
// and the machine binding (the blob is useless off the originating chip, and
// off the sealed boot state when seal_to_pcrs is set) are the security
// properties this backend provides. A fully TPM-resident signing key, where
// the scalar never leaves the chip, is a documented follow-up.
type tpmStorage struct {
	rw io.ReadWriteCloser
}

func openHardware() (Storage, error) {
	rw, err := openTPMDevice()
	if err != nil {
		return nil, fmt.Errorf("%w: open TPM: %v", ErrUnsupported, err)
	}
	// Verify we can load the SRK before declaring the backend usable, so a
	// present-but-broken TPM surfaces at Open rather than first use.
	srk, err := loadSRK(rw)
	if err != nil {
		rw.Close()
		return nil, fmt.Errorf("%w: load storage root key: %v", ErrUnsupported, err)
	}
	srk.Close()
	return &tpmStorage{rw: rw}, nil
}

func (t *tpmStorage) Capabilities() Capabilities {
	return Capabilities{Name: "tpm", HardwareBound: true}
}

func (t *tpmStorage) Generate(kt KeyType, sealToPCRs bool) (crypto.Signer, []byte, error) {
	if kt == KeyRSA {
		return nil, nil, errors.New("securestore: the TPM backend supports key_type ec only (RSA does not fit a sealed-data object)")
	}
	signer, err := newSoftwareKey(KeyEC)
	if err != nil {
		return nil, nil, err
	}
	handle, err := t.seal(signer.(*ecdsa.PrivateKey), sealToPCRs)
	if err != nil {
		return nil, nil, err
	}
	return signer, handle, nil
}

func (t *tpmStorage) Import(key crypto.PrivateKey, sealToPCRs bool) (crypto.Signer, []byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("securestore: the TPM backend can only seal EC P-256 keys, got %T", key)
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, nil, errors.New("securestore: the TPM backend requires an EC P-256 key")
	}
	handle, err := t.seal(ecKey, sealToPCRs)
	if err != nil {
		return nil, nil, err
	}
	return ecKey, handle, nil
}

func (t *tpmStorage) Load(handle []byte) (crypto.Signer, error) {
	scalar, err := t.unsealBytes(handle)
	if err != nil {
		return nil, err
	}
	return scalarToKey(scalar)
}

// SealData seals an arbitrary blob (e.g. a Vault token) under the SRK. It is
// SRK-bound only — never PCR-bound — because the token is ephemeral and
// re-derivable, so binding it to the boot state would needlessly strand it
// across a firmware update. The machine binding (useless off the originating
// chip) is the property that matters here.
func (t *tpmStorage) SealData(data []byte) ([]byte, error) {
	return t.sealBytes(data, false)
}

// UnsealData reverses SealData.
func (t *tpmStorage) UnsealData(handle []byte) ([]byte, error) {
	return t.unsealBytes(handle)
}

func (t *tpmStorage) Close() error {
	if t.rw == nil {
		return nil
	}
	return t.rw.Close()
}

// seal seals the 32-byte private scalar under the SRK and returns the
// marshalled SealedBytes proto as the handle.
func (t *tpmStorage) seal(key *ecdsa.PrivateKey, sealToPCRs bool) ([]byte, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("securestore: the TPM backend requires an EC P-256 key")
	}
	scalar := key.D.FillBytes(make([]byte, 32))
	return t.sealBytes(scalar, sealToPCRs)
}

// sealBytes seals an arbitrary blob under the SRK (optionally PCR-bound) and
// returns the marshalled SealedBytes proto as the handle. It is the shared
// path behind both EC-scalar sealing (seal) and data sealing (SealData).
func (t *tpmStorage) sealBytes(data []byte, sealToPCRs bool) ([]byte, error) {
	srk, err := loadSRK(t.rw)
	if err != nil {
		return nil, fmt.Errorf("securestore: load SRK: %w", err)
	}
	defer srk.Close()

	opts := client.SealOpts{}
	if sealToPCRs {
		opts.Current = pcrSelection
	}
	sealed, err := srk.Seal(data, opts)
	if err != nil {
		return nil, fmt.Errorf("securestore: TPM seal failed: %w", err)
	}
	handle, err := proto.Marshal(sealed)
	if err != nil {
		return nil, fmt.Errorf("securestore: marshal sealed bytes: %w", err)
	}
	return handle, nil
}

// unsealBytes reverses sealBytes, returning the original blob.
func (t *tpmStorage) unsealBytes(handle []byte) ([]byte, error) {
	var sb pb.SealedBytes
	if err := proto.Unmarshal(handle, &sb); err != nil {
		return nil, fmt.Errorf("securestore: unmarshal sealed handle: %w", err)
	}
	srk, err := loadSRK(t.rw)
	if err != nil {
		return nil, fmt.Errorf("securestore: load SRK: %w", err)
	}
	defer srk.Close()

	data, err := srk.Unseal(&sb, client.UnsealOpts{})
	if err != nil {
		return nil, fmt.Errorf("securestore: TPM unseal failed (wrong machine, or boot state changed since sealing): %w", err)
	}
	return data, nil
}

// scalarToKey reconstructs an EC P-256 private key from its 32-byte scalar.
func scalarToKey(scalar []byte) (crypto.Signer, error) {
	d := new(big.Int).SetBytes(scalar)
	curve := elliptic.P256()
	if d.Sign() == 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("securestore: unsealed scalar out of range")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = d
	priv.X, priv.Y = curve.ScalarBaseMult(scalar)
	return priv, nil
}
