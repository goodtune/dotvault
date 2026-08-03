//go:build windows

package securestore

import (
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/google/certtostore"
	"golang.org/x/sys/windows"
)

// CNG entry points certtostore keeps unexported. The "os" backend loads them
// itself to verify a generated key's export policy, to free the key handles
// certtostore hands out (its Key type has no Close), and to delete a superseded
// key container.
var (
	ncryptDLL           = windows.NewLazySystemDLL("ncrypt.dll")
	nCryptGetProperty   = ncryptDLL.NewProc("NCryptGetProperty")
	nCryptFreeObject    = ncryptDLL.NewProc("NCryptFreeObject")
	nCryptOpenKey       = ncryptDLL.NewProc("NCryptOpenKey")
	nCryptDeleteKey     = ncryptDLL.NewProc("NCryptDeleteKey")
	nCryptSilentKeyFlag = uintptr(0x40) // NCRYPT_SILENT_FLAG
)

// nCryptExportPolicyProperty is NCRYPT_EXPORT_POLICY_PROPERTY (L"Export Policy").
const nCryptExportPolicyProperty = "Export Policy"

// osStorage holds open handles to the current user's CNG certificate store.
//
// Three lifetimes are managed here, all released by Close:
//
//   - certStore: the store used for certificate operations (install, delete).
//     Container-independent.
//   - keyStores: one certtostore.WinCertStore per key container. certtostore
//     fixes the container at open time and looks keys up by it, so a backend
//     that no longer uses a single fixed container needs one store per
//     container it touches.
//   - keyHandles: the NCRYPT_KEY_HANDLEs behind every crypto.Signer this
//     backend has handed out. certtostore.Key exposes no Close and
//     WinCertStore.Close frees only provider and store handles, so without
//     this every Generate/Load leaked a key handle for the life of the daemon
//     — once per startup, per unattended recovery attempt, per public-client
//     cert login and per re-issue.
//
// The signers are used lazily, during the cert-auth TLS handshake via a
// GetClientCertificate callback, so the handles must outlive the callback. They
// are freed at Close, which every caller in internal/auth defers to the end of
// the flow that owns the login — after certLogin has returned.
type osStorage struct {
	certStore *certtostore.WinCertStore

	mu         sync.Mutex
	keyStores  map[string]*certtostore.WinCertStore
	keyHandles []uintptr
	closed     bool
}

// openOSStore opens the current user's CNG certificate store (software key
// provider, no admin required) and returns a Storage backed by it. The cert
// lands in CurrentUser\My and the key in the per-user DPAPI key store, so
// browsers and other clients can present it.
func openOSStore() (Storage, error) {
	// The container passed here is irrelevant — this store is only used for
	// certificate operations, which do not consult it. Key operations go
	// through keyStore(container).
	wcs, err := certtostore.OpenWinCertStoreCurrentUser(
		certtostore.ProviderMSSoftware, osLegacyContainer, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("%w: open Windows certificate store: %v", ErrUnsupported, err)
	}
	return &osStorage{certStore: wcs, keyStores: map[string]*certtostore.WinCertStore{}}, nil
}

func (s *osStorage) Capabilities() Capabilities {
	// HardwareBound in the "non-portable" sense the cert-auth flow cares about:
	// a CurrentUser CNG software key is bound to the user's DPAPI master key and
	// cannot be loaded on another machine, like the TPM backend's blobs.
	return Capabilities{Name: "os", HardwareBound: true}
}

// keyStore returns (opening on first use) the certtostore store bound to a
// given key container. certtostore takes the container at open time and its
// Key/Generate look up by it, so each container needs its own store.
func (s *osStorage) keyStore(container string) (*certtostore.WinCertStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("securestore: os store is closed")
	}
	if wcs, ok := s.keyStores[container]; ok {
		return wcs, nil
	}
	wcs, err := certtostore.OpenWinCertStoreCurrentUser(
		certtostore.ProviderMSSoftware, container, nil, nil, false)
	if err != nil {
		return nil, fmt.Errorf("open Windows key store for container %q: %w", container, err)
	}
	s.keyStores[container] = wcs
	return wcs, nil
}

// trackSigner records the CNG key handle behind a signer so Close can free it.
func (s *osStorage) trackSigner(signer crypto.Signer) {
	h, ok := signer.(interface{ TransientTpmHandle() uintptr })
	if !ok || h.TransientTpmHandle() == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyHandles = append(s.keyHandles, h.TransientTpmHandle())
}

// Generate creates a key in a *fresh* CNG container and returns a signer over
// it plus a handle recording the container. sealToPCRs is ignored — boot-state
// binding is a TPM concept; the OS software provider has no equivalent.
//
// The container is new every time by design (see osContainerPrefix): certtostore
// generates with NCRYPT_OVERWRITE_KEY_FLAG, so generating into the container the
// current certificate depends on would destroy a credential that is still in
// use if any later step of the rotation failed. The old container is removed
// only by CommitCert, once the replacement is operational.
func (s *osStorage) Generate(kt KeyType, bits int, _ bool) (crypto.Signer, []byte, error) {
	opts, err := generateOpts(kt, bits)
	if err != nil {
		return nil, nil, err
	}
	container, err := newOSContainer()
	if err != nil {
		return nil, nil, err
	}
	wcs, err := s.keyStore(container)
	if err != nil {
		return nil, nil, err
	}
	signer, err := wcs.Generate(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key in OS certificate store: %w", err)
	}
	s.trackSigner(signer)
	if err := assertNonExportable(signer); err != nil {
		return nil, nil, err
	}
	handle, err := encodeOSHandle(osHandle{Provider: certtostore.ProviderMSSoftware, Container: container})
	if err != nil {
		return nil, nil, err
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
// container name, so the cert need not be present for Load to succeed. The
// returned signer's key handle is tracked and freed by Close.
func (s *osStorage) Load(handle []byte) (crypto.Signer, error) {
	h, err := decodeOSHandle(handle)
	if err != nil {
		return nil, err
	}
	wcs, err := s.keyStore(h.Container)
	if err != nil {
		return nil, err
	}
	key, err := wcs.Key()
	if err != nil {
		return nil, fmt.Errorf("load key from OS certificate store: %w", err)
	}
	s.trackSigner(key)
	return key, nil
}

// StoreCert installs the issued certificate (and its issuing CA) into the OS
// store, associating it with the previously generated key. This is what makes
// the credential visible to browsers and other clients — by design the cert
// lands in CurrentUser\My, readable by any process in the user's session; that
// interoperability (browser-presentable mTLS identity) is the whole point of
// the "os" backend and is the documented trade-off (docs/authentication/mtls.md).
//
// The returned handle records the installed leaf's thumbprint and MUST be the
// one persisted: it is what lets this leaf be found again — to delete it as
// superseded once its own replacement commits, or to remove it on rollback if
// this rotation never completes. Without that, every rotation would leave
// another simultaneously valid client certificate in the store for browsers to
// offer.
func (s *osStorage) StoreCert(handle []byte, certPEM string) ([]byte, error) {
	h, err := decodeOSHandle(handle)
	if err != nil {
		return nil, err
	}
	leaf, intermediate, err := parseLeafAndIssuer(certPEM)
	if err != nil {
		return nil, err
	}
	// Record the leaf thumbprint before installing, not after. certtostore's
	// Store adds the leaf to CurrentUser\My first and the issuer to the CA store
	// second; the second add can fail after the leaf already exists. Making the
	// install self-transactional — remove the leaf on any Store error (a no-op if
	// it was never added) — means a partial failure leaves nothing behind, so the
	// caller's RollbackCert never has to clean an orphaned leaf it has no
	// thumbprint for. Without this, every failed rotation left another
	// simultaneously valid client certificate in the store for a browser to offer.
	thumbprint := certSHA1Thumbprint(leaf.Raw)
	if err := s.certStore.Store(leaf, intermediate); err != nil {
		if delErr := deleteUserCertByThumbprint(thumbprint); delErr != nil {
			slog.Warn("could not remove a partially-installed leaf after a failed certificate store",
				"thumbprint", thumbprint, "error", delErr)
		}
		return nil, fmt.Errorf("store certificate in OS certificate store: %w", err)
	}
	h.Thumbprint = thumbprint
	return encodeOSHandle(h)
}

// CommitCert removes the key container and leaf certificate superseded by a
// rotation that has fully committed. See securestore.CertLifecycle for the
// ordering contract; errors here are advisory (the new credential is live).
func (s *osStorage) CommitCert(newHandle, oldHandle []byte) error {
	if len(oldHandle) == 0 {
		return nil // first seed: nothing superseded
	}
	newH, err := decodeOSHandle(newHandle)
	if err != nil {
		return err
	}
	oldH, err := decodeOSHandle(oldHandle)
	if err != nil {
		// A handle we cannot parse is a handle we must not act on: deleting the
		// wrong container or certificate is worse than leaking one.
		return fmt.Errorf("decode superseded os handle: %w", err)
	}
	container, thumbprint := supersededOSArtifacts(newH, oldH)
	return s.discard(container, thumbprint)
}

// RollbackCert removes the key container and any leaf certificate belonging to
// a replacement credential that never became operational, leaving the previous
// credential authoritative. Safe when StoreCert was never reached (there is no
// leaf) and safe to call twice.
func (s *osStorage) RollbackCert(newHandle []byte) error {
	if len(newHandle) == 0 {
		return nil
	}
	h, err := decodeOSHandle(newHandle)
	if err != nil {
		return err
	}
	return s.discard(h.Container, h.Thumbprint)
}

// discard removes a key container and/or a leaf certificate, reporting every
// failure rather than stopping at the first: the two artefacts are independent
// and leaving one behind because the other failed helps nobody.
func (s *osStorage) discard(container, thumbprint string) error {
	var errs []error
	if container != "" {
		if err := s.deleteKeyContainer(container); err != nil {
			errs = append(errs, err)
		} else {
			slog.Debug("removed superseded OS-store key container", "container", container)
		}
	}
	if thumbprint != "" {
		if err := deleteUserCertByThumbprint(thumbprint); err != nil {
			errs = append(errs, err)
		} else {
			slog.Debug("removed superseded OS-store certificate", "thumbprint", thumbprint)
		}
	}
	return errors.Join(errs...)
}

// deleteKeyContainer deletes a persisted CNG key by container name.
// NCryptDeleteKey both deletes the key and frees the handle passed to it, so
// the handle opened here must not also be freed. Any tracked signer over the
// same container becomes unusable, which is the point — the container is being
// discarded.
func (s *osStorage) deleteKeyContainer(container string) error {
	if !validOSContainer(container) {
		return fmt.Errorf("refusing to delete key container %q: not a dotvault container", container)
	}
	wcs, err := s.keyStore(container)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(container)
	if err != nil {
		return err
	}
	var kh uintptr
	r, _, _ := nCryptOpenKey.Call(
		wcs.Prov,
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(name)),
		0,
		nCryptSilentKeyFlag,
	)
	if r != 0 {
		// NTE_BAD_KEYSET (0x80090016): already gone. Deleting what is not there
		// is the desired end state, so this is success, not failure.
		if r == 0x80090016 {
			return nil
		}
		return fmt.Errorf("NCryptOpenKey(%q) returned %#x", container, r)
	}
	if r, _, _ := nCryptDeleteKey.Call(kh, nCryptSilentKeyFlag); r != 0 {
		freeKeyHandle(kh)
		return fmt.Errorf("NCryptDeleteKey(%q) returned %#x", container, r)
	}
	return nil
}

// deleteUserCertByThumbprint removes a certificate from CurrentUser\My by its
// SHA-1 thumbprint. A certificate that is not there is not an error: the end
// state is what matters, and a user may have removed it by hand.
//
// The match is duplicated and the enumeration ended before the delete, rather
// than deleting the context the enumeration is sitting on — deleting the cursor
// out from under CertEnumCertificatesInStore is not something to rely on, and
// there is only ever one certificate to remove.
func deleteUserCertByThumbprint(thumbprint string) error {
	storeName, err := windows.UTF16PtrFromString("MY")
	if err != nil {
		return err
	}
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		windows.CERT_SYSTEM_STORE_CURRENT_USER,
		uintptr(unsafe.Pointer(storeName)),
	)
	if err != nil {
		return fmt.Errorf("open CurrentUser\\My certificate store: %w", err)
	}
	defer windows.CertCloseStore(store, 0)

	var (
		found *windows.CertContext
		prev  *windows.CertContext
	)
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || ctx == nil {
			break
		}
		der := unsafe.Slice(ctx.EncodedCert, ctx.Length)
		if certSHA1Thumbprint(der) == thumbprint {
			found = windows.CertDuplicateCertificateContext(ctx)
			windows.CertFreeCertificateContext(ctx) // ends the enumeration
			break
		}
		prev = ctx
	}
	if found == nil {
		return nil
	}
	if err := windows.CertDeleteCertificateFromStore(found); err != nil {
		return fmt.Errorf("delete certificate %s from CurrentUser\\My: %w", thumbprint, err)
	}
	return nil
}

// freeKeyHandle releases a CNG key handle (NCryptFreeObject).
func freeKeyHandle(h uintptr) error {
	if h == 0 {
		return nil
	}
	if r, _, _ := nCryptFreeObject.Call(h); r != 0 {
		return fmt.Errorf("NCryptFreeObject returned %#x", r)
	}
	return nil
}

// Close frees every handle this backend opened: the CNG key handles behind the
// signers it handed out, and the provider/store handles behind each per-
// container certtostore store. Callers in internal/auth defer it to the end of
// the flow, which is after the cert-auth TLS handshake has consumed the signer.
func (s *osStorage) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	handles, stores := s.keyHandles, s.keyStores
	s.keyHandles, s.keyStores = nil, nil
	s.mu.Unlock()

	var errs []error
	for _, h := range handles {
		if err := freeKeyHandle(h); err != nil {
			errs = append(errs, err)
		}
	}
	for _, wcs := range stores {
		if err := wcs.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.certStore != nil {
		if err := s.certStore.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// generateOpts maps a securestore KeyType onto certtostore.GenerateOpts. The OS
// software provider supports both EC P-256 and RSA (unlike the TPM backend,
// which is EC-only).
//
// bits sizes the RSA modulus; zero selects defaultRSABits. EC ignores it — CNG
// gets P-256 to match the software backend. Sizes above 2048 are safe here
// specifically because this backend opens ProviderMSSoftware, whose ceiling is
// 16384; the TPM KSP caps RSA at 2048, so the same value would fail at runtime
// there.
func generateOpts(kt KeyType, bits int) (certtostore.GenerateOpts, error) {
	switch kt {
	case KeyEC, "":
		return certtostore.GenerateOpts{Algorithm: certtostore.EC, Size: 256}, nil
	case KeyRSA:
		return certtostore.GenerateOpts{Algorithm: certtostore.RSA, Size: rsaBitsOrDefault(bits)}, nil
	default:
		return certtostore.GenerateOpts{}, fmt.Errorf("securestore: unknown key type %q", kt)
	}
}
