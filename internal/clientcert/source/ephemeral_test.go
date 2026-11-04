package source

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/vault"
)

// testClock is a settable clock shared by the source under test and the fake
// CA, so the certificates the CA issues are dated in the same timeline the
// source compares against.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	// Whole seconds: X.509 validity has one-second resolution, so a clock
	// with sub-second precision would make NotBefore differ from "now".
	return &testClock{t: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeSigner is a Signer backed by a real in-test CA. It parses the CSR it is
// given and signs the CSR's public key, so the key the source keeps genuinely
// matches the certificate it serves.
type fakeSigner struct {
	clock  *testClock
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caPEM  []byte

	mu       sync.Mutex
	token    string
	meta     map[string]any
	maxTTL   time.Duration // 0 = no cap
	signErr  error
	delay    time.Duration
	lastTTL  string
	lastCN   string
	signs    atomic.Int32
	lookups  atomic.Int32
	serialNo int64

	// lookupTokens and signTokens record the token each call was made
	// with, in order.
	lookupTokens []string
	signTokens   []string
	// onLookup, when set, runs inside LookupSelfWithToken: a test uses it
	// to swap the client's token while a sign is under way.
	onLookup func()
	// gate, when set, holds every SignCSRWithToken until it is closed.
	gate chan struct{}
	// lookupErr, when set, is what LookupSelfWithToken returns.
	lookupErr error
	// afterToken, when set, runs once after the next Token read: a test
	// uses it to replace the client's token between Current reading it and
	// the sign starting.
	afterToken func()
}

func newFakeSigner(t *testing.T, clock *testClock) *fakeSigner {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             clock.Now().Add(-time.Hour),
		NotAfter:              clock.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSigner{
		clock:    clock,
		caKey:    caKey,
		caCert:   caCert,
		caPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		token:    "s.test-token",
		meta:     map[string]any{"username": "gary"},
		serialNo: 100,
	}
}

func (f *fakeSigner) Token() string {
	f.mu.Lock()
	tok, hook := f.token, f.afterToken
	f.afterToken = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return tok
}

func (f *fakeSigner) setToken(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.token = tok
}

func (f *fakeSigner) setSignErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signErr = err
}

func (f *fakeSigner) LookupSelfWithToken(ctx context.Context, token string) (*vaultapi.Secret, error) {
	f.lookups.Add(1)
	f.mu.Lock()
	hook := f.onLookup
	f.lookupTokens = append(f.lookupTokens, token)
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	data := map[string]any{}
	if f.meta != nil {
		data["meta"] = f.meta
	}
	return &vaultapi.Secret{Data: data}, nil
}

func (f *fakeSigner) SignCSRWithToken(ctx context.Context, token, mount, role, csrPEM, commonName, ttl string) (*vault.IssuedCert, error) {
	f.signs.Add(1)
	f.mu.Lock()
	f.signTokens = append(f.signTokens, token)
	delay, signErr, maxTTL, gate := f.delay, f.signErr, f.maxTTL, f.gate
	f.lastTTL, f.lastCN = ttl, commonName
	f.serialNo++
	serial := f.serialNo
	f.mu.Unlock()

	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if signErr != nil {
		return nil, signErr
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("fake: no CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	life, err := time.ParseDuration(ttl)
	if err != nil {
		return nil, fmt.Errorf("fake: ttl %q: %w", ttl, err)
	}
	if maxTTL > 0 && life > maxTTL {
		life = maxTTL
	}
	now := f.clock.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now,
		NotAfter:     now.Add(life),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		return nil, err
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &vault.IssuedCert{
		CertPEM: string(leaf) + string(f.caPEM),
		Serial:  vault.FormatSerial(big.NewInt(serial)),
	}, nil
}

func defaultOptions(clock *testClock) EphemeralOptions {
	return EphemeralOptions{
		PKIMount:   "pki",
		PKIRole:    "user-client",
		CommonName: "{{.token_username}}",
		TTL:        5 * time.Minute,
		KeyType:    "ec",
		OSUser:     "localgary",
		Now:        clock.Now,
	}
}

func newSource(t *testing.T, f *fakeSigner, o EphemeralOptions) clientcert.Source {
	t.Helper()
	src, err := NewEphemeral(f, o)
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	return src
}

func TestEphemeralSignsOnFirstUse(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))

	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got := f.signs.Load(); got != 1 {
		t.Fatalf("SignCSR calls = %d, want 1", got)
	}
	if p.CommonName != "gary" || f.lastCN != "gary" {
		t.Fatalf("CommonName = %q (requested %q), want gary", p.CommonName, f.lastCN)
	}
	if f.lastTTL != "5m0s" {
		t.Fatalf("ttl sent = %q, want 5m0s", f.lastTTL)
	}
	if p.Source != "ephemeral" {
		t.Fatalf("clientcert.Source = %q, want ephemeral", p.Source)
	}
	if p.Serial == "" {
		t.Fatal("Serial empty")
	}

	// The key must match the certificate: X509KeyPair checks exactly that.
	tc, err := p.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	if len(tc.Certificate) != 2 {
		t.Fatalf("chain length = %d, want leaf + CA", len(tc.Certificate))
	}
	if !bytes.HasPrefix(p.KeyPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("KeyPEM is not PKCS#8 PEM")
	}

	want := append(append([]byte{}, p.CertPEM...), p.KeyPEM...)
	if !bytes.Equal(p.Combined(), want) {
		t.Fatal("Combined() != CertPEM + KeyPEM")
	}

	wantRefresh := p.NotBefore.Add(p.NotAfter.Sub(p.NotBefore) / 2)
	if !p.RefreshAt.Equal(wantRefresh) {
		t.Fatalf("RefreshAt = %v, want %v", p.RefreshAt, wantRefresh)
	}
	if len(p.Fingerprint()) != 64 {
		t.Fatalf("Fingerprint = %q, want 64 hex chars", p.Fingerprint())
	}
}

func TestEphemeralCachesUntilHalfLife(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	p1, err := src.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(2 * time.Minute) // before RefreshAt (2m30s)
	p2, err := src.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 || f.signs.Load() != 1 {
		t.Fatalf("expected cached pair, signs = %d", f.signs.Load())
	}

	clock.Advance(31 * time.Second) // past RefreshAt
	p3, err := src.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f.signs.Load() != 2 {
		t.Fatalf("signs = %d, want 2", f.signs.Load())
	}
	if p3.Serial == p1.Serial {
		t.Fatalf("serial unchanged after refresh: %s", p3.Serial)
	}
	if bytes.Equal(p3.KeyPEM, p1.KeyPEM) {
		t.Fatal("key reused across refresh")
	}
}

func TestEphemeralRotatesOnIssuedLifetime(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.maxTTL = 2 * time.Minute // the role caps the 5m request
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	p, err := src.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.NotAfter.Sub(p.NotBefore); got != 2*time.Minute {
		t.Fatalf("issued lifetime = %v, want 2m", got)
	}
	if want := p.NotBefore.Add(time.Minute); !p.RefreshAt.Equal(want) {
		t.Fatalf("RefreshAt = %v, want NotBefore+1m (%v)", p.RefreshAt, want)
	}

	clock.Advance(59 * time.Second)
	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if f.signs.Load() != 1 {
		t.Fatalf("re-signed before issued half-life: signs = %d", f.signs.Load())
	}
	clock.Advance(2 * time.Second)
	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if f.signs.Load() != 2 {
		t.Fatalf("did not re-sign after issued half-life: signs = %d", f.signs.Load())
	}
}

func TestEphemeralSingleFlight(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	release := make(chan struct{})
	f.gate = release
	src := newSource(t, f, defaultOptions(clock))

	// Hold the sign until every caller is waiting on a flight, so they all
	// arrived while it was in progress. Without that a late caller could be
	// answered from the cache the first sign filled, and the count of one
	// sign would prove nothing about sharing.
	const callers = 20
	var waiting atomic.Int32
	src.(*ephemeral).testHookWait = func() {
		if waiting.Add(1) == callers {
			close(release)
		}
	}

	var wg sync.WaitGroup
	pairs := make([]*clientcert.Pair, callers)
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pairs[i], errs[i] = src.Current(context.Background())
		}()
	}
	wg.Wait()
	if got := waiting.Load(); got != callers {
		t.Fatalf("callers that waited on a flight = %d, want %d", got, callers)
	}
	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if pairs[i] != pairs[0] {
			t.Fatalf("caller %d got a different pair", i)
		}
	}
	if got := f.signs.Load(); got != 1 {
		t.Fatalf("SignCSR calls = %d, want 1", got)
	}
	if got := f.lookups.Load(); got != 1 {
		t.Fatalf("LookupSelf calls = %d, want 1", got)
	}
}

func TestEphemeralCancelledCallerDoesNotAbortSign(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.delay = 100 * time.Millisecond
	src := newSource(t, f, defaultOptions(clock))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	// The caller's deadline is reported as waiting on a sign still in
	// progress, which is what lets a consumer answer "try again" rather than
	// treat it as a failed sign.
	if _, err := src.Current(ctx); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, clientcert.ErrSignInProgress) {
		t.Fatalf("first caller err = %v, want deadline exceeded wrapping ErrSignInProgress", err)
	}
	// A second caller joins the same in-flight sign and gets its result.
	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatalf("second caller: %v", err)
	}
	if p == nil || f.signs.Load() != 1 {
		t.Fatalf("signs = %d, want 1 shared sign", f.signs.Load())
	}
}

func TestEphemeralServesCachedPairWithoutToken(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	p1, err := src.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.setToken("")

	clock.Advance(3 * time.Minute) // past RefreshAt, before NotAfter
	p2, err := src.Current(ctx)
	if err != nil {
		t.Fatalf("Current without token: %v", err)
	}
	if p2 != p1 {
		t.Fatal("expected the cached pair")
	}
	if f.signs.Load() != 1 {
		t.Fatalf("signed without a token: signs = %d", f.signs.Load())
	}

	clock.Advance(3 * time.Minute) // past NotAfter
	if _, err := src.Current(ctx); !errors.Is(err, clientcert.ErrNoToken) {
		t.Fatalf("err = %v, want clientcert.ErrNoToken", err)
	}
}

func TestEphemeralNoTokenNoCache(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setToken("")
	src := newSource(t, f, defaultOptions(clock))
	if _, err := src.Current(context.Background()); !errors.Is(err, clientcert.ErrNoToken) {
		t.Fatalf("err = %v, want clientcert.ErrNoToken", err)
	}
	if f.signs.Load() != 0 {
		t.Fatalf("signs = %d, want 0", f.signs.Load())
	}
}

func TestEphemeralKeepsCachedPairOnSignFailure(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	var buf bytes.Buffer
	restore := captureLogs(&buf)
	defer restore()

	p1, err := src.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signErr := errors.New("permission denied")
	f.setSignErr(signErr)

	clock.Advance(3 * time.Minute) // past RefreshAt
	p2, err := src.Current(ctx)
	if err != nil {
		t.Fatalf("Current after sign failure: %v", err)
	}
	if p2 != p1 {
		t.Fatal("expected the cached pair on sign failure")
	}
	clock.Advance(time.Minute) // still before NotAfter
	if p3, err := src.Current(ctx); err != nil || p3 != p1 {
		t.Fatalf("second failure: pair same = %v, err = %v", p3 == p1, err)
	}
	if got := f.signs.Load(); got != 3 {
		t.Fatalf("signs = %d, want 3 (every call past RefreshAt retries)", got)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("WARN lines = %d, want 1 per failure streak:\n%s", n, buf.String())
	}

	clock.Advance(2 * time.Minute) // past NotAfter
	if _, err := src.Current(ctx); !errors.Is(err, signErr) {
		t.Fatalf("err = %v, want the sign error", err)
	}

	// Recovery ends the streak: the next failure warns again. Three
	// failures so far put the next attempt 40s out.
	f.setSignErr(nil)
	clock.Advance(backoffFor(3))
	if _, err := src.Current(ctx); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	f.setSignErr(signErr)
	clock.Advance(3 * time.Minute)
	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 2 {
		t.Fatalf("WARN lines = %d, want 2 after a new streak:\n%s", n, buf.String())
	}
}

func TestEphemeralWarnsOnFirstFailureWithoutCachedPair(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setSignErr(forbidden())
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	var buf bytes.Buffer
	restore := captureLogs(&buf)
	defer restore()

	// A denial on the very first sign: nothing cached to serve.
	if _, err := src.Current(ctx); err == nil {
		t.Fatal("expected the 403")
	}
	out := buf.String()
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Fatalf("WARN lines = %d, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "role="+defaultOptions(clock).PKIRole) || !strings.Contains(out, "403") {
		t.Fatalf("WARN does not name the role and the cause:\n%s", out)
	}

	// The same denial again, after the backoff: no new WARN.
	clock.Advance(signBackoffBase + time.Second)
	_, _ = src.Current(ctx)
	if f.signs.Load() != 2 {
		t.Fatalf("signs = %d, want 2", f.signs.Load())
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != 1 {
		t.Fatalf("WARN lines = %d after a repeat, want 1:\n%s", n, buf.String())
	}

	// A different error is news.
	f.setSignErr(errors.New("vault is sealed"))
	clock.Advance(backoffFor(2) + time.Second)
	_, _ = src.Current(ctx)
	if n := strings.Count(buf.String(), "level=WARN"); n != 2 {
		t.Fatalf("WARN lines = %d after a different error, want 2:\n%s", n, buf.String())
	}
}

func TestEphemeralCommonNameFallsBackToMetaCommonName(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.meta = map[string]any{"common_name": "gary-cert"}
	src := newSource(t, f, defaultOptions(clock))
	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.CommonName != "gary-cert" {
		t.Fatalf("CommonName = %q, want gary-cert", p.CommonName)
	}
}

func TestEphemeralNoUsernameErrors(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.meta = nil
	src := newSource(t, f, defaultOptions(clock))
	_, err := src.Current(context.Background())
	if !errors.Is(err, clientcert.ErrNoUsername) {
		t.Fatalf("err = %v, want clientcert.ErrNoUsername", err)
	}
	if f.signs.Load() != 0 {
		t.Fatalf("signed with no username: signs = %d", f.signs.Load())
	}
}

func TestEphemeralOSUserTemplate(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	o := defaultOptions(clock)
	o.CommonName = "{{.os_user}}"
	src := newSource(t, f, o)
	p, err := src.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.CommonName != "localgary" {
		t.Fatalf("CommonName = %q, want localgary", p.CommonName)
	}
	if f.lookups.Load() != 0 {
		t.Fatalf("LookupSelf called %d times for an os_user template", f.lookups.Load())
	}
}

func TestEphemeralTokenUsernameCachedPerToken(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	clock.Advance(3 * time.Minute)
	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if f.lookups.Load() != 1 {
		t.Fatalf("lookups = %d, want 1 for one token", f.lookups.Load())
	}

	f.setToken("s.other-token")
	f.meta = map[string]any{"username": "someone-else"}
	clock.Advance(3 * time.Minute)
	p, err := src.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f.lookups.Load() != 2 || p.CommonName != "someone-else" {
		t.Fatalf("lookups = %d, CN = %q; want a fresh lookup for a new token", f.lookups.Load(), p.CommonName)
	}

	e := src.(*ephemeral)
	e.mu.Lock()
	defer e.mu.Unlock()
	if strings.Contains(fmt.Sprintf("%+v", e.user), "s.other-token") {
		t.Fatal("username cache holds the raw token")
	}
}

func TestEphemeralNeverLogsKey(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	var buf bytes.Buffer
	restore := captureLogs(&buf)
	defer restore()

	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	f.setSignErr(errors.New("vault is sealed"))
	clock.Advance(3 * time.Minute)
	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	clock.Advance(3 * time.Minute)
	_, err := src.Current(ctx)
	if err == nil {
		t.Fatal("expected an error past NotAfter")
	}
	if buf.Len() == 0 {
		t.Fatal("expected some log output across the failure path")
	}
	for _, s := range []string{buf.String(), err.Error()} {
		if strings.Contains(s, "-----BEGIN") {
			t.Fatalf("PEM material leaked:\n%s", s)
		}
		if strings.Contains(s, "s.test-token") {
			t.Fatalf("token leaked:\n%s", s)
		}
	}
}

func TestNewEphemeralRejectsBadOptions(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	cases := map[string]func(*EphemeralOptions){
		"no mount":     func(o *EphemeralOptions) { o.PKIMount = "" },
		"no role":      func(o *EphemeralOptions) { o.PKIRole = "" },
		"no cn":        func(o *EphemeralOptions) { o.CommonName = "" },
		"bad template": func(o *EphemeralOptions) { o.CommonName = "{{.token_username" },
		"zero ttl":     func(o *EphemeralOptions) { o.TTL = 0 },
		"bad key type": func(o *EphemeralOptions) { o.KeyType = "dsa" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			o := defaultOptions(clock)
			mut(&o)
			if _, err := NewEphemeral(f, o); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	if _, err := NewEphemeral(nil, defaultOptions(clock)); err == nil {
		t.Fatal("expected an error for a nil signer")
	}
}

func TestTemplateReferencesTokenUsername(t *testing.T) {
	cases := map[string]bool{
		"{{.token_username}}":                true,
		"{{.os_user}}":                       false,
		"literal":                            false,
		"{{if .os_user}}{{.os_user}}{{end}}": false,
		"{{if .os_user}}x{{else}}{{.token_username}}{{end}}": true,
		"{{with .token_username}}{{.}}{{end}}":               true,
		"{{printf \"%s-%s\" .os_user $.token_username}}":     true,
		"{{printf \"%v\" .}}":                                true,
	}
	for tmpl, want := range cases {
		e, err := NewEphemeral(newFakeSigner(t, newTestClock()), EphemeralOptions{
			PKIMount: "pki", PKIRole: "r", CommonName: tmpl, TTL: time.Minute,
		})
		if err != nil {
			t.Fatalf("%q: %v", tmpl, err)
		}
		if got := e.(*ephemeral).needsTokenUsername; got != want {
			t.Errorf("%q: needsTokenUsername = %v, want %v", tmpl, got, want)
		}
	}
}

// captureLogs points slog's default logger at buf (text handler, DEBUG) and
// returns a function restoring the previous default.
func captureLogs(buf *bytes.Buffer) func() {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&syncWriter{w: buf}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return func() { slog.SetDefault(prev) }
}

type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func forbidden() error {
	return &vaultapi.ResponseError{StatusCode: 403, Errors: []string{"permission denied"}}
}

func TestEphemeralBacksOffAfterFailure(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setSignErr(forbidden())
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	for i := range 50 {
		_, err := src.Current(ctx)
		var re *vaultapi.ResponseError
		if !errors.As(err, &re) || re.StatusCode != 403 {
			t.Fatalf("call %d: err = %v, want the 403", i, err)
		}
		clock.Advance(100 * time.Millisecond) // 50 calls span 5s
	}
	if got := f.signs.Load(); got != 1 {
		t.Fatalf("signs within the first window = %d, want 1", got)
	}

	clock.Advance(5*time.Second + time.Millisecond) // past the 10s window
	if _, err := src.Current(ctx); err == nil {
		t.Fatal("expected the 403")
	}
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("signs after the window = %d, want 2", got)
	}

	// The second failure doubles the window to 20s.
	clock.Advance(19 * time.Second)
	if _, err := src.Current(ctx); err == nil {
		t.Fatal("expected the 403")
	}
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("signed inside the doubled window: signs = %d", got)
	}
	clock.Advance(2 * time.Second)
	if _, err := src.Current(ctx); err == nil {
		t.Fatal("expected the 403")
	}
	if got := f.signs.Load(); got != 3 {
		t.Fatalf("signs after the doubled window = %d, want 3", got)
	}

	// Success resets the backoff: the next failure waits only the base window.
	f.setSignErr(nil)
	clock.Advance(backoffFor(3))
	if _, err := src.Current(ctx); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	e := src.(*ephemeral)
	e.mu.Lock()
	failures := e.failures
	e.mu.Unlock()
	if failures != 0 {
		t.Fatalf("failures after success = %d, want 0", failures)
	}

	// Prove it: the next failure (once the new pair is due for refresh)
	// waits only the base window, not the 80s a fourth failure in the old
	// streak would have earned.
	signsBefore := f.signs.Load()
	clock.Advance(3 * time.Minute) // past the 5m pair's RefreshAt
	f.setSignErr(forbidden())
	if _, err := src.Current(ctx); err != nil {
		t.Fatalf("a failed refresh should still serve the valid pair: %v", err)
	}
	if got := f.signs.Load(); got != signsBefore+1 {
		t.Fatalf("signs = %d, want %d (the refresh was attempted)", got, signsBefore+1)
	}
	clock.Advance(signBackoffBase - time.Second)
	_, _ = src.Current(ctx)
	if got := f.signs.Load(); got != signsBefore+1 {
		t.Fatalf("signed inside the base window: signs = %d", got)
	}
	clock.Advance(time.Second)
	_, _ = src.Current(ctx)
	if got := f.signs.Load(); got != signsBefore+2 {
		t.Fatalf("signs = %d, want %d: after a success the window is the base again", got, signsBefore+2)
	}
}

func TestEphemeralBackoffNoTokenTakesPrecedence(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setSignErr(forbidden())
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()
	if _, err := src.Current(ctx); err == nil {
		t.Fatal("expected the 403")
	}
	f.setToken("")
	if _, err := src.Current(ctx); !errors.Is(err, clientcert.ErrNoToken) {
		t.Fatalf("err = %v, want clientcert.ErrNoToken during backoff without a token", err)
	}
}

func TestEphemeralBackoffResetsOnNewToken(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setSignErr(forbidden())
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	// Two failures: the window is now 20s from the second.
	_, _ = src.Current(ctx)
	clock.Advance(signBackoffBase)
	_, _ = src.Current(ctx)
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("signs = %d, want 2", got)
	}

	clock.Advance(11 * time.Second) // inside the 20s window, past minSignInterval
	_, _ = src.Current(ctx)
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("same token signed inside the window: signs = %d", got)
	}

	f.setToken("s.fresh-token")
	f.setSignErr(nil)
	p, err := src.Current(ctx)
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	if p == nil || f.signs.Load() != 3 {
		t.Fatalf("signs = %d, want 3: a new token clears the backoff", f.signs.Load())
	}
}

func TestEphemeralMinIntervalWhenRoleCapsBelowHalfLife(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.maxTTL = 4 * time.Second
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	first, err := src.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 100; i++ { // 99 calls across 9.9s
		clock.Advance(100 * time.Millisecond)
		p, err := src.Current(ctx)
		now := clock.Now()
		switch {
		case now.Before(first.NotAfter):
			if err != nil || p != first {
				t.Fatalf("at +%v: want the cached pair, err = %v", now.Sub(first.NotBefore), err)
			}
		default:
			if !errors.Is(err, clientcert.ErrSignPaced) {
				t.Fatalf("at +%v: err = %v, want clientcert.ErrSignPaced", now.Sub(first.NotBefore), err)
			}
		}
	}
	if got := f.signs.Load(); got != 1 {
		t.Fatalf("signs within minSignInterval = %d, want 1", got)
	}

	clock.Advance(100 * time.Millisecond) // +10s
	if _, err := src.Current(ctx); err != nil {
		t.Fatalf("after minSignInterval: %v", err)
	}
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("signs after minSignInterval = %d, want 2", got)
	}
}

func TestBackoffFor(t *testing.T) {
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := backoffFor(i + 1); got != w {
			t.Errorf("backoffFor(%d) = %v, want %v", i+1, got, w)
		}
	}
	if got := backoffFor(1000); got != signBackoffMax {
		t.Errorf("backoffFor(1000) = %v, want cap", got)
	}
}

func TestEphemeralNewTokenIsNotHeldToMinInterval(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setSignErr(forbidden())
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	if _, err := src.Current(ctx); err == nil {
		t.Fatal("expected the 403")
	}
	clock.Advance(5 * time.Second)
	f.setToken("s.fresh-token")
	f.setSignErr(nil)

	// A token the last attempt was not made with signs at once: the floor
	// paces repeated attempts with one token, and a replacement token (the
	// client facade swapping out one Vault rejected) must not be answered
	// with clientcert.ErrSignPaced for the old token's attempt.
	if _, err := src.Current(ctx); err != nil {
		t.Fatalf("new token inside minSignInterval: %v", err)
	}
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("signs = %d, want 2 (the new token signed immediately)", got)
	}
}

func TestEphemeralSameTokenWithinMinIntervalIsPaced(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.maxTTL = 4 * time.Second // RefreshAt is 2s after issue
	src := newSource(t, f, defaultOptions(clock))
	ctx := context.Background()

	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	f.setToken("s.fresh-token")
	clock.Advance(3 * time.Second) // past RefreshAt
	if _, err := src.Current(ctx); err != nil {
		t.Fatalf("new token: %v", err)
	}
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("signs = %d, want 2", got)
	}

	// The exemption is for a token the last attempt did not use, once: the
	// same new token is held to the floor like any other.
	clock.Advance(3 * time.Second) // past the new pair's RefreshAt, before NotAfter
	p, err := src.Current(ctx)
	if err != nil || p == nil {
		t.Fatalf("same token inside the interval: want the still-valid pair, got %v", err)
	}
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("signs = %d, want 2 (same token inside minSignInterval is paced)", got)
	}
	clock.Advance(2 * time.Second) // past NotAfter, still inside the interval
	if _, err := src.Current(ctx); !errors.Is(err, clientcert.ErrSignPaced) {
		t.Fatalf("err = %v, want clientcert.ErrSignPaced", err)
	}
	if got := f.signs.Load(); got != 2 {
		t.Fatalf("signs = %d, want 2", got)
	}
}

// TestEphemeralSignUsesTheTokenItRead proves one sign is made entirely under
// the token Current read: the username lookup and the sign both present it,
// and a failure is filed under its hash, even when the client's token changes
// while the sign is under way. Reading the token again inside the sign let the
// common name come from one token while another signed, and filed the failure
// under the wrong token, so the backoff reset on a new token never fired.
func TestEphemeralSignUsesTheTokenItRead(t *testing.T) {
	clock := newTestClock()
	f := newFakeSigner(t, clock)
	f.setToken("s.token-a")
	f.setSignErr(forbidden())
	f.onLookup = func() { f.setToken("s.token-b") }
	src := newSource(t, f, defaultOptions(clock))

	if _, err := src.Current(context.Background()); err == nil {
		t.Fatal("expected the 403")
	}
	f.mu.Lock()
	lookups, signs := append([]string(nil), f.lookupTokens...), append([]string(nil), f.signTokens...)
	f.mu.Unlock()
	if len(lookups) != 1 || lookups[0] != "s.token-a" {
		t.Fatalf("lookup tokens = %v, want [s.token-a]", lookups)
	}
	if len(signs) != 1 || signs[0] != "s.token-a" {
		t.Fatalf("sign tokens = %v, want [s.token-a]: the sign must use the token the lookup used", signs)
	}

	e := src.(*ephemeral)
	e.mu.Lock()
	failed := e.failedToken
	cached := e.user
	e.mu.Unlock()
	if failed != sha256.Sum256([]byte("s.token-a")) {
		t.Error("the failure was not filed under the token that signed")
	}
	if !cached.valid || cached.tokenHash != sha256.Sum256([]byte("s.token-a")) {
		t.Error("the username was not cached under the token it was looked up with")
	}
}
