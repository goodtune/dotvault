package source

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"text/template/parse"
	"time"

	"github.com/goodtune/dotvault/internal/auth"
	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/securestore"
	"github.com/goodtune/dotvault/internal/vault"
)

// signTimeout bounds one signing round trip (LookupSelf plus SignCSR). The
// sign runs detached from whichever caller started it, because other callers
// may be waiting on the same result; this is what stops it running forever
// against a hung Vault.
const signTimeout = 30 * time.Second

// Sign pacing. Without it, Current's "past RefreshAt, so sign" rule turns
// every read into a Vault call whenever signing cannot succeed: a FUSE
// `ls -l` stats every file, and a tool polling client.pem reads it in a loop,
// so a persistent pki/sign denial would become one denied request per read,
// multiplied across a fleet. That is the storm the denied-token suppression
// (auth.TokenDenylist) exists to stop on the lookup-self side, and it must
// not be rebuilt here.
//
//   - signBackoffBase / signBackoffMax: after a failed sign, no new sign is
//     attempted until the window has passed. It starts at signBackoffBase,
//     doubles per consecutive failure and stops at signBackoffMax. A success
//     resets it, and so does a token with a different value from the one
//     that failed, since the failure may have been that token's fault.
//     During the window Current answers from memory: the cached pair while
//     it is still valid, otherwise the last sign error.
//   - minSignInterval: the floor between sign attempts of any outcome made
//     with the same token. It covers the case where signing succeeds but the
//     PKI role's max_ttl caps the lifetime so short that RefreshAt is already
//     past (or nearly) when the certificate arrives; without a floor that
//     role would be re-signed on every call. A token different from the one
//     the last attempt used is exempt, as it is from the backoff: the
//     attempt it would be paced against said nothing about it, and the case
//     that matters — the client facade replacing a token Vault rejected —
//     would otherwise answer the replacement with clientcert.ErrSignPaced until the
//     interval ran out. The sign rate is then bounded by how often the token
//     really changes, which its producers limit (the facade replaces a
//     rejected token at most once per ten seconds).
//
// They are constants; tests move time with EphemeralOptions.Now.
const (
	signBackoffBase = 10 * time.Second
	signBackoffMax  = 5 * time.Minute
	minSignInterval = 10 * time.Second
)

// EphemeralOptions configures NewEphemeral. The caller resolves defaults and
// inheritance (config.ClientCertPKIMount and friends); this package only
// checks that what arrives is usable.
type EphemeralOptions struct {
	PKIMount, PKIRole, CommonName string
	TTL                           time.Duration
	KeyType                       string
	KeyBits                       int
	OSUser                        string
	Now                           func() time.Time // nil = time.Now
}

// ephemeral is the clientcert.Source that signs short-lived certificates on demand.
type ephemeral struct {
	s                  Signer
	o                  EphemeralOptions
	cn                 *template.Template
	needsTokenUsername bool
	now                func() time.Time

	mu       sync.Mutex
	cur      *clientcert.Pair
	inflight *flight
	warned   bool   // a WARN has been logged for the current failure streak
	warnedAs string // the error text that WARN carried
	user     usernameCache

	// Sign pacing; see signBackoffBase.
	lastAttempt time.Time         // start of the most recent sign attempt
	lastToken   [sha256.Size]byte // SHA-256 of the token that attempt used
	failures    int               // consecutive failed signs
	retryAt     time.Time         // no sign before this while failures > 0
	lastErr     error             // error of the most recent failed sign
	failedToken [sha256.Size]byte // SHA-256 of the token the last failure used

	// gate and reporter are the token-lifecycle seams (see lifecycle.go):
	// a gateHolder and a reporterHolder, stored after construction because
	// the lifecycle manager is built after the source.
	gate, reporter atomic.Value
	// reauthWait bounds the wait on gate before a sign; signTimeout unless a
	// test shortens it.
	reauthWait time.Duration

	// testHookWait, when set, runs each time a caller is about to wait on a
	// flight. Tests only; set before any concurrent use.
	testHookWait func()
}

// flight is one in-progress sign shared by every caller that arrives while it
// runs. token is the value Current read, and every Vault call of the sign is
// made with it; it is held only for the flight's lifetime. pair and err are
// written before done is closed.
type flight struct {
	token     string
	tokenHash [sha256.Size]byte
	done      chan struct{}
	pair      *clientcert.Pair
	err       error
}

// usernameCache remembers token_username for one token, keyed on the SHA-256
// of the token value so the token itself is never retained here.
type usernameCache struct {
	tokenHash [sha256.Size]byte
	name      string
	valid     bool
}

// NewEphemeral returns a clientcert.Source that signs certificates via
// <PKIMount>/sign/<PKIRole> with s's current token. The common-name template
// is parsed once here; whether it needs a LookupSelf (it references
// token_username) is decided once here too.
func NewEphemeral(s Signer, o EphemeralOptions) (clientcert.Source, error) {
	if s == nil {
		return nil, errors.New("clientcert: nil signer")
	}
	if o.PKIMount == "" {
		return nil, errors.New("clientcert: PKI mount is required")
	}
	if o.PKIRole == "" {
		return nil, errors.New("clientcert: PKI role is required")
	}
	if o.CommonName == "" {
		return nil, errors.New("clientcert: common name template is required")
	}
	if o.TTL <= 0 {
		return nil, fmt.Errorf("clientcert: ttl must be positive, got %s", o.TTL)
	}
	switch securestore.KeyType(o.KeyType) {
	case "", securestore.KeyEC, securestore.KeyRSA:
	default:
		return nil, fmt.Errorf("clientcert: unknown key type %q", o.KeyType)
	}
	t, err := template.New("client_cert.common_name").Option("missingkey=error").Parse(o.CommonName)
	if err != nil {
		return nil, fmt.Errorf("clientcert: common name template: %w", err)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &ephemeral{
		s:                  s,
		o:                  o,
		cn:                 t,
		needsTokenUsername: templateReads(t, "token_username"),
		now:                now,
		reauthWait:         signTimeout,
	}, nil
}

// Current returns the cached certificate while it is inside the first half of
// its issued lifetime, and otherwise signs a new one. Concurrent callers share
// a single sign. When signing is impossible (no token) or fails, a cached
// certificate that has not reached NotAfter is still served. Signs are paced
// (see signBackoffBase): inside a backoff window or minSignInterval, Current
// answers from memory without contacting Vault.
func (e *ephemeral) Current(ctx context.Context) (*clientcert.Pair, error) {
	e.mu.Lock()
	now := e.now()
	if e.cur != nil && now.Before(e.cur.RefreshAt) {
		p := e.cur
		e.mu.Unlock()
		return p, nil
	}
	f := e.inflight
	if f == nil {
		token := e.s.Token()
		if token == "" {
			// Not a sign failure, so no WARN: the daemon is between tokens
			// and the caller's error says so.
			p := e.validLocked(now)
			e.mu.Unlock()
			if p != nil {
				return p, nil
			}
			return nil, clientcert.ErrNoToken
		}
		h := sha256.Sum256([]byte(token))
		if e.failures > 0 && h != e.failedToken {
			e.resetBackoffLocked()
		}
		if earliest := e.nextSignLocked(h); now.Before(earliest) {
			p, err := e.validLocked(now), e.lastErr
			e.mu.Unlock()
			if p != nil {
				return p, nil
			}
			if err == nil {
				err = clientcert.ErrSignPaced
			}
			return nil, err
		}
		e.lastAttempt, e.lastToken = now, h
		f = &flight{token: token, tokenHash: h, done: make(chan struct{})}
		e.inflight = f
		go e.run(ctx, f)
	}
	e.mu.Unlock()

	if e.testHookWait != nil {
		e.testHookWait()
	}
	select {
	case <-f.done:
	case <-ctx.Done():
		// The sign carries on detached; say so, so a consumer can tell
		// "ask again" from a sign that failed.
		return nil, fmt.Errorf("%w: %w", clientcert.ErrSignInProgress, ctx.Err())
	}
	if f.err == nil {
		return f.pair, nil
	}
	e.mu.Lock()
	p := e.validLocked(e.now())
	e.mu.Unlock()
	if p != nil {
		return p, nil
	}
	return nil, f.err
}

// Last returns the most recent pair signed and the most recent sign error,
// without signing or contacting Vault.
func (e *ephemeral) Last() (*clientcert.Pair, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cur, e.lastErr
}

// validLocked returns the cached pair if it has not yet expired.
func (e *ephemeral) validLocked(now time.Time) *clientcert.Pair {
	if e.cur != nil && now.Before(e.cur.NotAfter) {
		return e.cur
	}
	return nil
}

// nextSignLocked is the earliest time a sign with the token hashing to h may
// start: minSignInterval after the last attempt when that attempt used the
// same token, or the end of the failure backoff if later. Current resets the
// backoff before asking when h differs from the token that failed.
func (e *ephemeral) nextSignLocked(h [sha256.Size]byte) time.Time {
	var earliest time.Time
	if !e.lastAttempt.IsZero() && h == e.lastToken {
		earliest = e.lastAttempt.Add(minSignInterval)
	}
	if e.failures > 0 && e.retryAt.After(earliest) {
		earliest = e.retryAt
	}
	return earliest
}

// resetBackoffLocked ends a failure streak's backoff. minSignInterval still
// applies to the token the last attempt used, since it is measured from
// lastAttempt.
func (e *ephemeral) resetBackoffLocked() {
	e.failures = 0
	e.retryAt = time.Time{}
	e.lastErr = nil
}

// backoffFor is the window after the n-th consecutive failure (n >= 1).
func backoffFor(n int) time.Duration {
	d := signBackoffBase
	for i := 1; i < n && d < signBackoffMax; i++ {
		d *= 2
	}
	return min(d, signBackoffMax)
}

// run performs one sign for flight f. It is detached from the starting
// caller's cancellation (that caller may give up while others still wait) but
// keeps its values. It first waits out a token replacement if one is in
// flight (bounded by reauthWait), then signs under signTimeout: two budgets,
// so a replacement that clears late still leaves the sign its full time. A
// token rejection from Vault is reported to the lifecycle manager.
func (e *ephemeral) run(parent context.Context, f *flight) {
	base := context.WithoutCancel(parent)
	var pair *clientcert.Pair
	token, err := e.awaitReplacement(base, f)
	if err == nil {
		ctx, cancel := context.WithTimeout(base, signTimeout)
		pair, err = e.sign(ctx, token)
		cancel()
		e.reportRejection(err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if err == nil {
		e.cur = pair
		e.warned, e.warnedAs = false, ""
		e.resetBackoffLocked()
	} else {
		// Filed under the token the sign actually used, which is the one
		// Current hashed: the sign never re-reads the client's token.
		e.failures++
		e.retryAt = e.now().Add(backoffFor(e.failures))
		e.lastErr = err
		e.failedToken = f.tokenHash
		if !errors.Is(err, clientcert.ErrNoToken) {
			// The replacement ended with no token: not a sign failure,
			// and the caller's error says so, as in Current.
			e.warnLocked(err)
		}
	}
	e.inflight = nil
	f.pair, f.err = pair, err
	close(f.done)
}

// warnLocked logs a sign failure at WARN, naming the mount and role, on the
// first failure of a streak and again only when the error changes. It logs
// whether or not a cached pair is left to serve: a denial on the very first
// sign is the case an operator most needs named, and every reader that
// follows (each stat of a mounted client.pem, each handshake) would otherwise
// see only an errno or an error it may not log.
func (e *ephemeral) warnLocked(err error) {
	msg := err.Error()
	if e.warned && msg == e.warnedAs {
		return
	}
	e.warned, e.warnedAs = true, msg
	if p := e.validLocked(e.now()); p != nil {
		slog.Warn("client certificate refresh failed; serving the current certificate until it expires",
			"source", clientcert.SourceEphemeral,
			"serial", p.Serial,
			"not_after", p.NotAfter,
			"common_name", p.CommonName,
			"mount", e.o.PKIMount,
			"role", e.o.PKIRole,
			"error", err)
		return
	}
	slog.Warn("client certificate signing failed; no certificate to serve until it succeeds",
		"source", clientcert.SourceEphemeral,
		"mount", e.o.PKIMount,
		"role", e.o.PKIRole,
		"error", err)
}

// sign generates a key, has Vault sign it with token, and assembles the clientcert.Pair.
// token is the value Current read, never re-read here: the common name lookup
// and the sign must present the same token, or a swap mid-sign could render
// one token's username into a certificate another token signs.
func (e *ephemeral) sign(ctx context.Context, token string) (*clientcert.Pair, error) {
	cn, err := e.commonName(ctx, token)
	if err != nil {
		return nil, err
	}

	key, err := securestore.NewSoftwareKey(securestore.KeyType(e.o.KeyType), e.o.KeyBits)
	if err != nil {
		return nil, fmt.Errorf("clientcert: generate key: %w", err)
	}
	csr, err := auth.BuildCSR(key, cn)
	if err != nil {
		return nil, fmt.Errorf("clientcert: %w", err)
	}
	issued, err := e.s.SignCSRWithToken(ctx, token, e.o.PKIMount, e.o.PKIRole, csr, cn, e.o.TTL.String())
	if err != nil {
		return nil, fmt.Errorf("clientcert: sign via %s/sign/%s: %w", strings.Trim(e.o.PKIMount, "/"), e.o.PKIRole, err)
	}

	der := clientcert.LeafDER([]byte(issued.CertPEM))
	if der == nil {
		return nil, errors.New("clientcert: Vault returned no certificate")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("clientcert: parse issued certificate: %w", err)
	}
	if !publicKeysEqual(leaf.PublicKey, key.Public()) {
		return nil, errors.New("clientcert: issued certificate does not match the generated key")
	}
	if !leaf.NotAfter.After(e.now()) {
		return nil, fmt.Errorf("clientcert: issued certificate already expired at %s (check the PKI role's ttl and the clock)", leaf.NotAfter.Format(time.RFC3339))
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("clientcert: encode key: %w", err)
	}

	p := &clientcert.Pair{
		CertPEM:    []byte(issued.CertPEM),
		KeyPEM:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		NotBefore:  leaf.NotBefore,
		NotAfter:   leaf.NotAfter,
		RefreshAt:  leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2),
		Serial:     vault.FormatSerial(leaf.SerialNumber),
		CommonName: leaf.Subject.CommonName,
		Source:     clientcert.SourceEphemeral,
	}
	slog.Info("client certificate issued",
		"source", clientcert.SourceEphemeral,
		"serial", p.Serial,
		"not_after", p.NotAfter,
		"common_name", p.CommonName,
		"mount", e.o.PKIMount,
		"role", e.o.PKIRole)
	return p, nil
}

// commonName renders the CN template for token.
func (e *ephemeral) commonName(ctx context.Context, token string) (string, error) {
	data := map[string]string{"os_user": e.o.OSUser}
	if e.needsTokenUsername {
		name, err := e.tokenUsername(ctx, token)
		if err != nil {
			return "", err
		}
		data["token_username"] = name
	}
	var buf bytes.Buffer
	if err := e.cn.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("clientcert: render common name: %w", err)
	}
	cn := buf.String()
	if strings.TrimSpace(cn) == "" {
		return "", errors.New("clientcert: common name template rendered empty")
	}
	return cn, nil
}

// tokenUsername returns meta.username, else meta.common_name, for token,
// looking it up at most once per distinct token value.
func (e *ephemeral) tokenUsername(ctx context.Context, token string) (string, error) {
	h := sha256.Sum256([]byte(token))
	e.mu.Lock()
	if e.user.valid && e.user.tokenHash == h {
		name := e.user.name
		e.mu.Unlock()
		return name, nil
	}
	e.mu.Unlock()

	secret, err := e.s.LookupSelfWithToken(ctx, token)
	if err != nil {
		return "", fmt.Errorf("clientcert: look up token username: %w", err)
	}
	meta := vault.TokenMeta(secret)
	name := meta["username"]
	if name == "" {
		name = meta["common_name"]
	}
	if name == "" {
		return "", clientcert.ErrNoUsername
	}
	// The lookup presented token itself, so the answer is token's whatever
	// the client holds now.
	e.mu.Lock()
	e.user = usernameCache{tokenHash: h, name: name, valid: true}
	e.mu.Unlock()
	return name, nil
}

// publicKeysEqual compares two public keys via their Equal method.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

// templateReads reports whether t can read the named top-level field. It
// walks the parse tree, so a reference inside {{if}}, {{with}}, {{range}} or a
// pipeline counts, as does $.name. Passing the whole context ({{.}} or {{$}}
// at the top level) counts too, conservatively, since the callee may read
// anything from it.
func templateReads(t *template.Template, name string) bool {
	for _, tt := range t.Templates() {
		if tt.Tree != nil && nodeReads(tt.Tree.Root, name, true) {
			return true
		}
	}
	return false
}

// nodeReads walks n. atRoot is false inside a {{with}} or {{range}} body,
// where dot no longer names the root context.
func nodeReads(n parse.Node, name string, atRoot bool) bool {
	switch n := n.(type) {
	case nil:
		return false
	case *parse.ListNode:
		if n == nil {
			return false
		}
		for _, c := range n.Nodes {
			if nodeReads(c, name, atRoot) {
				return true
			}
		}
	case *parse.ActionNode:
		return nodeReads(n.Pipe, name, atRoot)
	case *parse.PipeNode:
		if n == nil {
			return false
		}
		for _, c := range n.Cmds {
			if nodeReads(c, name, atRoot) {
				return true
			}
		}
	case *parse.CommandNode:
		for _, a := range n.Args {
			if nodeReads(a, name, atRoot) {
				return true
			}
		}
	case *parse.FieldNode:
		return atRoot && len(n.Ident) > 0 && n.Ident[0] == name
	case *parse.DotNode:
		return atRoot
	case *parse.VariableNode:
		if len(n.Ident) == 1 && n.Ident[0] == "$" {
			return true
		}
		return len(n.Ident) > 1 && n.Ident[0] == "$" && n.Ident[1] == name
	case *parse.ChainNode:
		return nodeReads(n.Node, name, atRoot)
	case *parse.IfNode:
		return branchReads(&n.BranchNode, name, atRoot, atRoot)
	case *parse.RangeNode:
		return branchReads(&n.BranchNode, name, atRoot, false)
	case *parse.WithNode:
		return branchReads(&n.BranchNode, name, atRoot, false)
	case *parse.TemplateNode:
		return nodeReads(n.Pipe, name, atRoot)
	}
	return false
}

// branchReads walks an if/with/range: the pipeline in the enclosing scope, the
// body in bodyAtRoot's scope, and the else branch in the enclosing scope.
func branchReads(b *parse.BranchNode, name string, atRoot, bodyAtRoot bool) bool {
	return nodeReads(b.Pipe, name, atRoot) ||
		nodeReads(b.List, name, bodyAtRoot) ||
		nodeReads(b.ElseList, name, atRoot)
}
