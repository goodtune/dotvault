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

	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// pcrSelection is the set of PCRs the key is bound to when seal_to_pcrs is
// enabled. PCRs 0/2/4/7 cover firmware, option ROMs, the boot manager, and
// Secure Boot state — a firmware or boot-config change after sealing causes
// the unseal to fail, which the cert-auth flow surfaces as a recoverable
// error that offers the bootstrap fallback.
var pcrSelection = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 2, 4, 7}}

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
	srk, err := client.StorageRootKeyECC(rw)
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
	var sb pb.SealedBytes
	if err := proto.Unmarshal(handle, &sb); err != nil {
		return nil, fmt.Errorf("securestore: unmarshal sealed handle: %w", err)
	}
	srk, err := client.StorageRootKeyECC(t.rw)
	if err != nil {
		return nil, fmt.Errorf("securestore: load SRK: %w", err)
	}
	defer srk.Close()

	scalar, err := srk.Unseal(&sb, client.UnsealOpts{})
	if err != nil {
		return nil, fmt.Errorf("securestore: TPM unseal failed (wrong machine, or boot state changed since sealing): %w", err)
	}
	return scalarToKey(scalar)
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
	srk, err := client.StorageRootKeyECC(t.rw)
	if err != nil {
		return nil, fmt.Errorf("securestore: load SRK: %w", err)
	}
	defer srk.Close()

	scalar := key.D.FillBytes(make([]byte, 32))
	opts := client.SealOpts{}
	if sealToPCRs {
		opts.Current = pcrSelection
	}
	sealed, err := srk.Seal(scalar, opts)
	if err != nil {
		return nil, fmt.Errorf("securestore: TPM seal failed: %w", err)
	}
	handle, err := proto.Marshal(sealed)
	if err != nil {
		return nil, fmt.Errorf("securestore: marshal sealed bytes: %w", err)
	}
	return handle, nil
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
