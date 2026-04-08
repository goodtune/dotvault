# SSH Enrolment Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an SSH enrolment engine that generates Ed25519 key pairs in OpenSSH format and stores them in Vault KVv2, with configurable passphrase protection prompted via CLI or web UI.

**Architecture:** New `SSHEngine` in `internal/enrol/ssh.go` implements the existing `Engine` interface. The `IO` struct gains `Username` and `PromptSecret` fields to support identity-aware engines and masked user input. The manager wires a CLI-based `PromptSecret` (using `golang.org/x/term`), and the web server adds two endpoints for browser-based secret prompting. Passphrase policy is a three-tier setting: `required` (default), `recommended`, `unsafe`.

**Tech Stack:** `crypto/ed25519`, `crypto/rand`, `encoding/pem`, `golang.org/x/crypto/ssh` (marshalling), `golang.org/x/term` (CLI hidden input)

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/enrol/engine.go` | Modify | Add `Username` and `PromptSecret` fields to `IO` struct; register `"ssh"` engine |
| `internal/enrol/ssh.go` | Create | `SSHEngine` implementation: key generation, passphrase prompting, OpenSSH marshalling |
| `internal/enrol/ssh_test.go` | Create | Unit tests for all passphrase modes, key validity, error cases |
| `internal/enrol/manager_test.go` | Modify | Update `testIO` helper to include new `IO` fields |
| `cmd/dotvault/main.go` | Modify | Wire `Username` and CLI `PromptSecret` into `enrol.IO` |
| `internal/web/server.go` | Modify | Add enrolment prompt endpoints and state tracking |
| `internal/web/api.go` | Modify | Add `handleEnrolPrompt` and `handleEnrolSecret` handlers |

---

### Task 1: Add `Username` and `PromptSecret` to `IO` struct

**Files:**
- Modify: `internal/enrol/engine.go:28-34`
- Modify: `internal/enrol/manager_test.go:56-62`

- [ ] **Step 1: Add fields to IO struct**

In `internal/enrol/engine.go`, add `Username` and `PromptSecret` to the `IO` struct:

```go
// IO provides user interaction capabilities to engines.
type IO struct {
	Out          io.Writer
	In           io.Reader // optional; defaults to os.Stdin if nil
	Browser      BrowserOpener
	Log          *slog.Logger
	Username     string                        // authenticated Vault username
	PromptSecret func(label string) (string, error) // masked user input
}
```

- [ ] **Step 2: Update testIO helper**

In `internal/enrol/manager_test.go`, update the `testIO` function to include the new fields so existing tests continue to compile:

```go
func testIO(buf *bytes.Buffer) IO {
	return IO{
		Out:      buf,
		Browser:  func(url string) error { return nil },
		Log:      slog.New(slog.NewTextHandler(buf, nil)),
		Username: "testuser",
	}
}
```

`PromptSecret` is left nil — existing engines (GitHub) don't call it, and the mock engine doesn't either.

- [ ] **Step 3: Run tests to verify nothing is broken**

Run: `go test ./internal/enrol/ -count=1 -short`
Expected: All existing tests pass (tests requiring Vault will be skipped with `-short`).

- [ ] **Step 4: Commit**

```bash
git add internal/enrol/engine.go internal/enrol/manager_test.go
git commit -m "Add Username and PromptSecret fields to enrol.IO struct"
```

---

### Task 2: Implement SSHEngine with TDD — Fields, Name, and unsafe mode

**Files:**
- Create: `internal/enrol/ssh_test.go`
- Create: `internal/enrol/ssh.go`

- [ ] **Step 1: Write failing tests for Name, Fields, and unsafe key generation**

Create `internal/enrol/ssh_test.go`:

```go
package enrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func sshTestIO(promptResponses ...string) IO {
	callIdx := 0
	return IO{
		Out:      &bytes.Buffer{},
		Log:      slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		Username: "testuser",
		PromptSecret: func(label string) (string, error) {
			if callIdx >= len(promptResponses) {
				return "", nil
			}
			resp := promptResponses[callIdx]
			callIdx++
			return resp, nil
		},
	}
}

func TestSSHEngine_Name(t *testing.T) {
	e := &SSHEngine{}
	if got := e.Name(); got != "SSH" {
		t.Errorf("Name() = %q, want %q", got, "SSH")
	}
}

func TestSSHEngine_Fields(t *testing.T) {
	e := &SSHEngine{}
	fields := e.Fields()
	if len(fields) != 2 {
		t.Fatalf("Fields() returned %d fields, want 2", len(fields))
	}
	if fields[0] != "public_key" || fields[1] != "private_key" {
		t.Errorf("Fields() = %v, want [public_key private_key]", fields)
	}
}

func TestSSHEngine_Unsafe_NoPassphrase(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO() // no prompt responses needed
	settings := map[string]any{"passphrase": "unsafe"}

	creds, err := e.Run(context.Background(), settings, io)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Check both fields present
	privPEM := creds["private_key"]
	pubKey := creds["public_key"]
	if privPEM == "" {
		t.Fatal("private_key is empty")
	}
	if pubKey == "" {
		t.Fatal("public_key is empty")
	}

	// Verify private key is valid OpenSSH PEM
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		t.Fatal("private_key is not valid PEM")
	}
	if block.Type != "OPENSSH PRIVATE KEY" {
		t.Errorf("PEM type = %q, want %q", block.Type, "OPENSSH PRIVATE KEY")
	}

	// Verify private key can be parsed without passphrase
	rawKey, err := ssh.ParseRawPrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("ParseRawPrivateKey() error: %v", err)
	}
	if _, ok := rawKey.(*ed25519.PrivateKey); !ok {
		t.Errorf("parsed key type = %T, want *ed25519.PrivateKey", rawKey)
	}

	// Verify public key format
	if !strings.HasPrefix(pubKey, "ssh-ed25519 ") {
		t.Errorf("public_key does not start with 'ssh-ed25519 ': %q", pubKey)
	}
	if !strings.HasSuffix(pubKey, " testuser@dotvault") {
		t.Errorf("public_key does not end with ' testuser@dotvault': %q", pubKey)
	}

	// Verify public key is parseable
	_, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey() error: %v", err)
	}
	if comment != "testuser@dotvault" {
		t.Errorf("comment = %q, want %q", comment, "testuser@dotvault")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/enrol/ -run TestSSH -count=1`
Expected: FAIL — `SSHEngine` not defined.

- [ ] **Step 3: Write minimal SSHEngine implementation**

Create `internal/enrol/ssh.go`:

```go
package enrol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHEngine generates Ed25519 SSH key pairs.
type SSHEngine struct{}

func (e *SSHEngine) Name() string     { return "SSH" }
func (e *SSHEngine) Fields() []string { return []string{"public_key", "private_key"} }

func (e *SSHEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	mode := "required"
	if v, ok := settings["passphrase"].(string); ok && v != "" {
		mode = v
	}

	passphrase, err := promptPassphrase(io, mode)
	if err != nil {
		return nil, err
	}

	comment := io.Username + "@dotvault"

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	// Marshal private key to OpenSSH PEM format.
	var pemBlock *pem.Block
	if passphrase != "" {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privKey, comment, []byte(passphrase))
	} else {
		pemBlock, err = ssh.MarshalPrivateKey(privKey, comment)
	}
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := string(pem.EncodeToMemory(pemBlock))

	// Marshal public key to authorized_keys format with comment.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("create ssh public key: %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + comment

	return map[string]string{
		"private_key": privPEM,
		"public_key":  pubLine,
	}, nil
}

func promptPassphrase(io IO, mode string) (string, error) {
	switch mode {
	case "unsafe":
		return "", nil
	case "required", "recommended":
		// handled below
	default:
		return "", fmt.Errorf("invalid passphrase mode: %q (must be required, recommended, or unsafe)", mode)
	}

	if io.PromptSecret == nil {
		return "", fmt.Errorf("passphrase prompt not available (PromptSecret is nil)")
	}

	first, err := io.PromptSecret("Enter passphrase:")
	if err != nil {
		return "", fmt.Errorf("passphrase prompt: %w", err)
	}

	if first == "" {
		if mode == "required" {
			return "", fmt.Errorf("passphrase is required")
		}
		// recommended: user opted out
		return "", nil
	}

	second, err := io.PromptSecret("Confirm passphrase:")
	if err != nil {
		return "", fmt.Errorf("passphrase confirm prompt: %w", err)
	}

	if first != second {
		return "", fmt.Errorf("passphrases do not match")
	}

	return first, nil
}
```

Note: add `"context"` to the import block — the `Run` method signature requires it.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/enrol/ -run TestSSH -count=1`
Expected: PASS — all three tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/enrol/ssh.go internal/enrol/ssh_test.go
git commit -m "Add SSHEngine with Ed25519 key generation (unsafe mode)"
```

---

### Task 3: TDD — passphrase-protected key generation

**Files:**
- Modify: `internal/enrol/ssh_test.go`

- [ ] **Step 1: Write failing test for passphrase-protected key**

Add to `internal/enrol/ssh_test.go`:

```go
func TestSSHEngine_Required_WithPassphrase(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO("hunter2", "hunter2") // two matching entries
	settings := map[string]any{"passphrase": "required"}

	creds, err := e.Run(context.Background(), settings, io)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	privPEM := creds["private_key"]

	// Verify the key cannot be parsed without passphrase
	_, err = ssh.ParseRawPrivateKey([]byte(privPEM))
	if err == nil {
		t.Fatal("expected error parsing encrypted key without passphrase")
	}

	// Verify the key can be parsed with the correct passphrase
	rawKey, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(privPEM), []byte("hunter2"))
	if err != nil {
		t.Fatalf("ParseRawPrivateKeyWithPassphrase() error: %v", err)
	}
	if _, ok := rawKey.(*ed25519.PrivateKey); !ok {
		t.Errorf("parsed key type = %T, want *ed25519.PrivateKey", rawKey)
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test ./internal/enrol/ -run TestSSHEngine_Required_WithPassphrase -count=1`
Expected: PASS — the implementation from Task 2 already handles this case.

- [ ] **Step 3: Commit**

```bash
git add internal/enrol/ssh_test.go
git commit -m "Add test for passphrase-protected SSH key generation"
```

---

### Task 4: TDD — passphrase error cases

**Files:**
- Modify: `internal/enrol/ssh_test.go`

- [ ] **Step 1: Write tests for all error cases**

Add to `internal/enrol/ssh_test.go`:

```go
func TestSSHEngine_Required_EmptyPassphrase(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO("", "") // empty entries
	settings := map[string]any{"passphrase": "required"}

	_, err := e.Run(context.Background(), settings, io)
	if err == nil {
		t.Fatal("expected error for empty passphrase in required mode")
	}
	if !strings.Contains(err.Error(), "passphrase is required") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "passphrase is required")
	}
}

func TestSSHEngine_Recommended_EmptyPassphrase(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO("", "") // empty entries
	settings := map[string]any{"passphrase": "recommended"}

	creds, err := e.Run(context.Background(), settings, io)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Should produce a valid unencrypted key
	privPEM := creds["private_key"]
	_, err = ssh.ParseRawPrivateKey([]byte(privPEM))
	if err != nil {
		t.Fatalf("key should be unencrypted but ParseRawPrivateKey() failed: %v", err)
	}
}

func TestSSHEngine_Mismatch(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO("hunter2", "hunter3") // mismatched entries
	settings := map[string]any{"passphrase": "required"}

	_, err := e.Run(context.Background(), settings, io)
	if err == nil {
		t.Fatal("expected error for mismatched passphrases")
	}
	if !strings.Contains(err.Error(), "passphrases do not match") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "passphrases do not match")
	}
}

func TestSSHEngine_InvalidMode(t *testing.T) {
	e := &SSHEngine{}
	io := sshTestIO()
	settings := map[string]any{"passphrase": "bogus"}

	_, err := e.Run(context.Background(), settings, io)
	if err == nil {
		t.Fatal("expected error for invalid passphrase mode")
	}
	if !strings.Contains(err.Error(), "invalid passphrase mode") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "invalid passphrase mode")
	}
}

func TestSSHEngine_DefaultMode(t *testing.T) {
	e := &SSHEngine{}
	// No passphrase in settings — defaults to "required"
	io := sshTestIO("mypass", "mypass")
	settings := map[string]any{}

	creds, err := e.Run(context.Background(), settings, io)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Key should be encrypted
	_, err = ssh.ParseRawPrivateKey([]byte(creds["private_key"]))
	if err == nil {
		t.Fatal("expected error parsing encrypted key without passphrase")
	}
	_, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(creds["private_key"]), []byte("mypass"))
	if err != nil {
		t.Fatalf("ParseRawPrivateKeyWithPassphrase() error: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./internal/enrol/ -run "TestSSHEngine_(Required_Empty|Recommended_Empty|Mismatch|InvalidMode|DefaultMode)" -count=1`
Expected: PASS — all error paths are already implemented.

- [ ] **Step 3: Commit**

```bash
git add internal/enrol/ssh_test.go
git commit -m "Add tests for SSH engine passphrase error cases"
```

---

### Task 5: Register SSH engine

**Files:**
- Modify: `internal/enrol/engine.go:36-41`

- [ ] **Step 1: Add SSH engine to registry**

In `internal/enrol/engine.go`, add `"ssh"` to the `engines` map:

```go
var (
	enginesMu sync.RWMutex
	engines   = map[string]Engine{
		"github": &GitHubEngine{},
		"ssh":    &SSHEngine{},
	}
)
```

- [ ] **Step 2: Run all enrol tests to verify**

Run: `go test ./internal/enrol/ -count=1 -short`
Expected: PASS — all tests pass, including existing GitHub/manager tests.

- [ ] **Step 3: Commit**

```bash
git add internal/enrol/engine.go
git commit -m "Register SSH engine in enrolment registry"
```

---

### Task 6: Wire CLI PromptSecret and Username in main.go

**Files:**
- Modify: `cmd/dotvault/main.go:264-273`

- [ ] **Step 1: Add CLI PromptSecret and Username to IO construction**

In `cmd/dotvault/main.go`, update the `enrol.IO` construction at line 269. The `PromptSecret` implementation uses `golang.org/x/term` to read hidden input. Add the necessary imports (`os`, `fmt`, `golang.org/x/term` — `os` and `fmt` are likely already imported).

Replace the IO struct literal at lines 269-273:

```go
	}, vc, enrol.IO{
		Out:     os.Stderr,
		Browser: browser.OpenURL,
		Log:     slog.Default(),
		Username: username,
		PromptSecret: func(label string) (string, error) {
			fmt.Fprintf(os.Stderr, "%s ", label)
			pass, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr) // newline after hidden input
			if err != nil {
				return "", err
			}
			return string(pass), nil
		},
	})
```

Add `"golang.org/x/term"` to the import block. `golang.org/x/term` is already an indirect dependency in `go.mod`.

- [ ] **Step 2: Build to verify compilation**

Run: `go build ./cmd/dotvault/`
Expected: Builds successfully.

- [ ] **Step 3: Commit**

```bash
git add cmd/dotvault/main.go go.mod go.sum
git commit -m "Wire CLI PromptSecret and Username into enrolment IO"
```

---

### Task 7: Add web enrolment prompt endpoints

**Files:**
- Modify: `internal/web/server.go:18-43` (add prompt state fields to Server)
- Modify: `internal/web/server.go:91-121` (register new routes)
- Modify: `internal/web/api.go` (add handler implementations)

- [ ] **Step 1: Add prompt state to Server struct**

In `internal/web/server.go`, add fields to the `Server` struct for managing enrolment prompt state:

```go
type Server struct {
	// ... existing fields ...
	enrolPromptMu    sync.Mutex
	enrolPromptLabel string
	enrolPromptCh    chan string
}
```

Add `"sync"` to the import block.

- [ ] **Step 2: Add PromptSecret method to Server**

Add a method to `internal/web/server.go` that the manager can use as the web `PromptSecret` implementation:

```go
// EnrolPromptSecret implements a web-based PromptSecret. It sets the pending
// prompt state and blocks until the frontend submits a value via the
// /api/v1/enrol/secret endpoint, or the context is cancelled.
func (s *Server) EnrolPromptSecret(ctx context.Context, label string) (string, error) {
	ch := make(chan string, 1)

	s.enrolPromptMu.Lock()
	s.enrolPromptLabel = label
	s.enrolPromptCh = ch
	s.enrolPromptMu.Unlock()

	defer func() {
		s.enrolPromptMu.Lock()
		s.enrolPromptLabel = ""
		s.enrolPromptCh = nil
		s.enrolPromptMu.Unlock()
	}()

	select {
	case val := <-ch:
		return val, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
```

Note this method takes a `context.Context` parameter. The caller in `main.go` will wrap it to match the `func(label string) (string, error)` signature by closing over the context.

- [ ] **Step 3: Register new routes**

In `internal/web/server.go` `registerRoutes()`, add after the existing API routes (line 111):

```go
	// Enrolment prompt routes
	s.mux.HandleFunc("GET /api/v1/enrol/prompt", s.handleEnrolPrompt)
	s.mux.HandleFunc("POST /api/v1/enrol/secret", s.requireCSRF(s.handleEnrolSecret))
```

- [ ] **Step 4: Add handler implementations**

Add to `internal/web/api.go`:

```go
func (s *Server) handleEnrolPrompt(w http.ResponseWriter, r *http.Request) {
	s.enrolPromptMu.Lock()
	label := s.enrolPromptLabel
	pending := s.enrolPromptCh != nil
	s.enrolPromptMu.Unlock()

	writeJSON(w, map[string]any{
		"pending": pending,
		"label":   label,
	})
}

func (s *Server) handleEnrolSecret(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	s.enrolPromptMu.Lock()
	ch := s.enrolPromptCh
	s.enrolPromptMu.Unlock()

	if ch == nil {
		writeError(w, "no pending prompt", http.StatusConflict)
		return
	}

	select {
	case ch <- req.Value:
		writeJSON(w, map[string]any{"status": "accepted"})
	default:
		writeError(w, "prompt already answered", http.StatusConflict)
	}
}
```

- [ ] **Step 5: Build to verify compilation**

Run: `go build ./cmd/dotvault/`
Expected: Builds successfully.

- [ ] **Step 6: Commit**

```bash
git add internal/web/server.go internal/web/api.go
git commit -m "Add web enrolment prompt endpoints for passphrase collection"
```

---

### Task 8: Wire web PromptSecret in main.go

**Files:**
- Modify: `cmd/dotvault/main.go`

- [ ] **Step 1: Conditionally set web PromptSecret when web server is running**

In `cmd/dotvault/main.go`, after the web server is created and started but before the enrolment manager is created, the `PromptSecret` should be set to the web implementation when the web UI is active.

Find the section where the web server is set up (before line 264) and where the enrolment manager IO is constructed. The logic is:

- If the web server is running, use `webServer.EnrolPromptSecret(ctx, label)` as the `PromptSecret`
- Otherwise, use the terminal-based `PromptSecret` from Task 6

Update the IO construction to conditionally select the implementation:

```go
	enrolIO := enrol.IO{
		Out:      os.Stderr,
		Browser:  browser.OpenURL,
		Log:      slog.Default(),
		Username: username,
		PromptSecret: func(label string) (string, error) {
			fmt.Fprintf(os.Stderr, "%s ", label)
			pass, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			return string(pass), nil
		},
	}
	if webServer != nil {
		enrolIO.PromptSecret = func(label string) (string, error) {
			return webServer.EnrolPromptSecret(ctx, label)
		}
	}

	enrolMgr := enrol.NewManager(enrol.ManagerConfig{
		Enrolments: cfg.Enrolments,
		KVMount:    cfg.Vault.KVMount,
		UserPrefix: cfg.Vault.UserPrefix + username + "/",
	}, vc, enrolIO)
```

The variable `webServer` is declared at `main.go:179` as `var webServer *web.Server` and is nil when the web UI is disabled.

- [ ] **Step 2: Build to verify compilation**

Run: `go build ./cmd/dotvault/`
Expected: Builds successfully.

- [ ] **Step 3: Commit**

```bash
git add cmd/dotvault/main.go
git commit -m "Wire web-based PromptSecret when web UI is active"
```

---

### Task 9: Update go.mod dependencies

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Tidy module dependencies**

Run: `go mod tidy`

This will promote `golang.org/x/crypto` from indirect to direct (since `ssh.go` imports `golang.org/x/crypto/ssh`) and promote `golang.org/x/term` from indirect to direct (since `main.go` imports it).

- [ ] **Step 2: Verify the build**

Run: `go build ./...`
Expected: Builds successfully.

- [ ] **Step 3: Run the full test suite**

Run: `go test ./... -count=1 -short`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "Promote golang.org/x/crypto and golang.org/x/term to direct dependencies"
```
