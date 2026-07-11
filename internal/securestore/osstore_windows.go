//go:build windows

package securestore

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/google/certtostore"
	"golang.org/x/sys/windows"
)

// nCryptGetProperty reads a CNG key property. certtostore keeps its own property
// helpers unexported, so the "os" backend loads the proc itself to verify the
// generated key's export policy (certtostore exposes the raw key handle via
// Key.TransientTpmHandle).
var nCryptGetProperty = windows.NewLazySystemDLL("ncrypt.dll").NewProc("NCryptGetProperty")

// nCryptExportPolicyProperty is NCRYPT_EXPORT_POLICY_PROPERTY (L"Export Policy").
const nCryptExportPolicyProperty = "Export Policy"

// osContainer is the CNG key-container name dotvault generates its cert key
// under, in the current user's key store. dotvault runs per-user and owns a
// single cert credential, so one fixed container is sufficient; the key lands
// in the CurrentUser key store (DPAPI-protected) and the certificate in
// CurrentUser\My, where the system browsers look for client certificates.
const osContainer = "dotvault-mtls"

// osHandle is the opaque securestore handle for the OS backend. It records only
// where the key lives (CNG provider + container); the key material itself never
// leaves the OS store. Load reopens the key by container name (CNG's
// NCryptOpenKey), so the container is the stable association across restarts.
type osHandle struct {
	Provider  string `json:"provider"`
	Container string `json:"container"`
}

// osStorage holds an open handle to the current user's CNG certificate store.
// The store is opened once and kept open for the lifetime of the backend
// (until Close): the crypto.Signer values returned by Generate and Load borrow
// the store's CNG provider handle, so closing it earlier would invalidate a
// signer still in use during the cert-auth TLS handshake.
type osStorage struct {
	wcs       *certtostore.WinCertStore
	container string
}

// openOSStore opens the current user's CNG certificate store (software key
// provider, no admin required) and returns a Storage backed by it. The cert
// lands in CurrentUser\My and the key in the per-user DPAPI key store, so
// browsers and other clients can present it.
func openOSStore() (Storage, error) {
	wcs, err := certtostore.OpenWinCertStoreCurrentUser(
		certtostore.ProviderMSSoftware, osContainer, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("%w: open Windows certificate store: %v", ErrUnsupported, err)
	}
	return &osStorage{wcs: wcs, container: osContainer}, nil
}

func (s *osStorage) Capabilities() Capabilities {
	// HardwareBound in the "non-portable" sense the cert-auth flow cares about:
	// a CurrentUser CNG software key is bound to the user's DPAPI master key and
	// cannot be loaded on another machine, like the TPM backend's blobs.
	return Capabilities{Name: "os", HardwareBound: true}
}

// Generate creates a key in the OS store's container and returns a signer over
// it plus a handle recording the container. sealToPCRs is ignored — boot-state
// binding is a TPM concept; the OS software provider has no equivalent.
func (s *osStorage) Generate(kt KeyType, _ bool) (crypto.Signer, []byte, error) {
	opts, err := generateOpts(kt)
	if err != nil {
		return nil, nil, err
	}
	signer, err := s.wcs.Generate(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key in OS certificate store: %w", err)
	}
	if err := assertNonExportable(signer); err != nil {
		return nil, nil, err
	}
	handle, err := json.Marshal(osHandle{Provider: certtostore.ProviderMSSoftware, Container: s.container})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal os handle: %w", err)
	}
	return signer, handle, nil
}

// assertNonExportable verifies the freshly generated CNG key cannot be exported
// from the store, so the user cannot extract the private key and reuse the
// Vault-issued identity on another machine. A key created with
// NCryptCreatePersistedKey defaults to NCRYPT_ALLOW_EXPORT_NONE (certtostore
// never sets an allow-export flag), so this is the CNG default — but we verify
// it rather than trust it, failing closed if a future certtostore change ever
// made the key exportable. The verification read itself failing is non-fatal
// (logged): the default still protects the key, and a diagnostic hiccup should
// not break authentication.
func assertNonExportable(signer crypto.Signer) error {
	h, ok := signer.(interface{ TransientTpmHandle() uintptr })
	if !ok {
		slog.Warn("cannot introspect OS-store key handle to verify non-exportability; relying on the non-exportable CNG default")
		return nil
	}
	policy, err := keyExportPolicy(h.TransientTpmHandle())
	if err != nil {
		slog.Warn("could not read OS-store key export policy; relying on the non-exportable CNG default", "error", err)
		return nil
	}
	if exportPolicyIsExportable(policy) {
		return fmt.Errorf("refusing to use an exportable OS-store key (export policy %#x): the private key must be non-exportable so it cannot be extracted and reused off this machine", policy)
	}
	return nil
}

// keyExportPolicy reads NCRYPT_EXPORT_POLICY_PROPERTY from a CNG key handle.
func keyExportPolicy(handle uintptr) (uint32, error) {
	prop, err := windows.UTF16PtrFromString(nCryptExportPolicyProperty)
	if err != nil {
		return 0, err
	}
	var policy, cbResult uint32
	r, _, _ := nCryptGetProperty.Call(
		handle,
		uintptr(unsafe.Pointer(prop)),
		uintptr(unsafe.Pointer(&policy)),
		unsafe.Sizeof(policy),
		uintptr(unsafe.Pointer(&cbResult)),
		0,
	)
	if r != 0 {
		return 0, fmt.Errorf("NCryptGetProperty(Export Policy) returned %#x", r)
	}
	return policy, nil
}

// Import is unsupported: certtostore can install certificates but offers no path
// to import an external private key into CNG, so the bring-your-own seeding path
// is rejected for mtls+os at config-load time and never reaches here.
func (s *osStorage) Import(crypto.PrivateKey, bool) (crypto.Signer, []byte, error) {
	return nil, nil, fmt.Errorf("%w: the OS-native certificate store cannot import an external private key (use auth_method mtls for bring-your-own)", ErrUnsupported)
}

// Load reopens the key behind handle from the OS store. CNG locates the key by
// container name, so the cert need not be present for Load to succeed.
func (s *osStorage) Load(handle []byte) (crypto.Signer, error) {
	if _, err := decodeOSHandle(handle); err != nil {
		return nil, err
	}
	key, err := s.wcs.Key()
	if err != nil {
		return nil, fmt.Errorf("load key from OS certificate store: %w", err)
	}
	return key, nil
}

// StoreCert installs the issued certificate (and its issuing CA) into the OS
// store, associating it with the previously generated key. This is what makes
// the credential visible to browsers and other clients — by design the cert
// lands in CurrentUser\My, readable by any process in the user's session; that
// interoperability (browser-presentable mTLS identity) is the whole point of
// the "os" backend and is the documented trade-off (docs/authentication/mtls.md).
// The handle is returned unchanged (the container association is stable).
func (s *osStorage) StoreCert(handle []byte, certPEM string) ([]byte, error) {
	if _, err := decodeOSHandle(handle); err != nil {
		return nil, err
	}
	leaf, intermediate, err := parseLeafAndIssuer(certPEM)
	if err != nil {
		return nil, err
	}
	if err := s.wcs.Store(leaf, intermediate); err != nil {
		return nil, fmt.Errorf("store certificate in OS certificate store: %w", err)
	}
	return handle, nil
}

func (s *osStorage) Close() error {
	if s.wcs == nil {
		return nil
	}
	return s.wcs.Close()
}

// generateOpts maps a securestore KeyType onto certtostore.GenerateOpts. The OS
// software provider supports both EC P-256 and RSA 2048 (unlike the TPM backend,
// which is EC-only).
func generateOpts(kt KeyType) (certtostore.GenerateOpts, error) {
	switch kt {
	case KeyEC, "":
		return certtostore.GenerateOpts{Algorithm: certtostore.EC, Size: 256}, nil
	case KeyRSA:
		return certtostore.GenerateOpts{Algorithm: certtostore.RSA, Size: 2048}, nil
	default:
		return certtostore.GenerateOpts{}, fmt.Errorf("securestore: unknown key type %q", kt)
	}
}

// decodeOSHandle parses and sanity-checks a handle. It rejects a handle whose
// container does not match the one this backend actually opens (osContainer): the
// key lookup keys off the open container, so a mismatched handle could only come
// from a corrupted envelope or a different deployment, and failing loudly beats
// silently operating on the wrong key.
func decodeOSHandle(handle []byte) (osHandle, error) {
	var h osHandle
	if err := json.Unmarshal(handle, &h); err != nil {
		return osHandle{}, fmt.Errorf("decode os handle: %w", err)
	}
	if h.Container == "" {
		return osHandle{}, errors.New("securestore: os handle has no container")
	}
	if h.Container != osContainer {
		return osHandle{}, fmt.Errorf("securestore: os handle container %q does not match expected %q", h.Container, osContainer)
	}
	return h, nil
}
