# Windows Registry Enrolment Loading Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Load enrolment configuration from Windows Registry GPO keys, matching the existing Rules registry pattern.

**Architecture:** Add `readRegistryEnrolments` / `readSingleEnrolment` functions mirroring `readRegistryRules` / `readSingleRule`. Each enrolment is a named subkey under `Enrolments\` with an `Engine` REG_SZ value and optional `Settings\` subkey. Update the ADMX template with an Enrolments category and GP Preferences documentation comment.

**Tech Stack:** Go, `golang.org/x/sys/windows/registry`, ADMX XML

---

## File Map

- **Modify:** `internal/config/registry_windows.go` — add `readRegistryEnrolments`, `readSingleEnrolment`, wire into `loadFromRegistry`
- **Modify:** `internal/config/registry_windows_test.go` — add tests for new functions
- **Modify:** `packaging/windows/dotvault.admx` — add Enrolments category and GP Preferences comment

---

### Task 1: Add `readSingleEnrolment` with tests

**Files:**
- Modify: `internal/config/registry_windows_test.go`
- Modify: `internal/config/registry_windows.go`

- [ ] **Step 1: Write the test for `readSingleEnrolment`**

This test requires real registry access (Windows only). It creates temporary registry keys, calls `readSingleEnrolment`, and verifies the result.

Add to `internal/config/registry_windows_test.go`:

```go
func TestReadSingleEnrolment(t *testing.T) {
	// Create a temporary registry key tree simulating:
	//   <testRoot>\Enrolments\gh\Engine = "github"
	//   <testRoot>\Enrolments\gh\Settings\Host = "github.com"
	//   <testRoot>\Enrolments\gh\Settings\Scopes = ["repo", "read:org"]
	base, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\dotvault-test\Enrolments\gh`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatalf("create test key: %v", err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments\gh\Settings`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments\gh`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test\Enrolments`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test`)

	if err := base.SetStringValue("Engine", "github"); err != nil {
		t.Fatalf("set Engine: %v", err)
	}
	base.Close()

	settings, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`SOFTWARE\dotvault-test\Enrolments\gh\Settings`,
		registry.ALL_ACCESS,
	)
	if err != nil {
		t.Fatalf("create Settings key: %v", err)
	}
	if err := settings.SetStringValue("Host", "github.com"); err != nil {
		t.Fatalf("set Host: %v", err)
	}
	if err := settings.SetStringsValue("Scopes", []string{"repo", "read:org"}); err != nil {
		t.Fatalf("set Scopes: %v", err)
	}
	settings.Close()

	enrolment, err := readSingleEnrolment(registry.CURRENT_USER, `SOFTWARE\dotvault-test`, "gh")
	if err != nil {
		t.Fatalf("readSingleEnrolment() error: %v", err)
	}
	if enrolment.Engine != "github" {
		t.Errorf("Engine = %q, want %q", enrolment.Engine, "github")
	}
	if enrolment.Settings == nil {
		t.Fatal("Settings is nil")
	}
	if host, ok := enrolment.Settings["Host"]; !ok || host != "github.com" {
		t.Errorf("Settings[Host] = %v, want %q", enrolment.Settings["Host"], "github.com")
	}
	scopes, ok := enrolment.Settings["Scopes"]
	if !ok {
		t.Fatal("Settings[Scopes] missing")
	}
	scopeSlice, ok := scopes.([]any)
	if !ok {
		t.Fatalf("Settings[Scopes] type = %T, want []any", scopes)
	}
	if len(scopeSlice) != 2 || scopeSlice[0] != "repo" || scopeSlice[1] != "read:org" {
		t.Errorf("Settings[Scopes] = %v, want [repo read:org]", scopeSlice)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestReadSingleEnrolment ./internal/config/ -v`
Expected: FAIL — `readSingleEnrolment` is not defined.

- [ ] **Step 3: Implement `readSingleEnrolment`**

Add to `internal/config/registry_windows.go`, after the `readSingleRule` function (after line 245):

```go
// readSingleEnrolment reads a single enrolment from the registry.
// The basePath parameter is the registry path containing the Enrolments
// subkey (e.g. registryPolicyPath). The name is the enrolment subkey name.
func readSingleEnrolment(root registry.Key, basePath, name string) (Enrolment, error) {
	path := basePath + `\Enrolments\` + name
	key, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return Enrolment{}, err
	}
	defer key.Close()

	enrolment := Enrolment{}
	enrolment.Engine, _ = readRegString(key, "Engine")

	// Read optional Settings subkey.
	settingsPath := path + `\Settings`
	sk, err := registry.OpenKey(root, settingsPath, registry.READ)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return Enrolment{}, fmt.Errorf("open Settings key at %s: %w", settingsPath, err)
	}
	if err == nil {
		defer sk.Close()
		info, err := sk.Stat()
		if err != nil {
			return Enrolment{}, fmt.Errorf("stat Settings key: %w", err)
		}
		names, err := sk.ReadValueNames(int(info.ValueCount))
		if err != nil {
			return Enrolment{}, fmt.Errorf("read Settings value names: %w", err)
		}
		if len(names) > 0 {
			enrolment.Settings = make(map[string]any, len(names))
			for _, vname := range names {
				if s, ok := readRegString(sk, vname); ok {
					enrolment.Settings[vname] = s
				} else if ms := readRegMultiString(sk, vname); ms != nil {
					vals := make([]any, len(ms))
					for i, v := range ms {
						vals[i] = v
					}
					enrolment.Settings[vname] = vals
				}
			}
		}
	}

	return enrolment, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -run TestReadSingleEnrolment ./internal/config/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/registry_windows.go internal/config/registry_windows_test.go
git commit -m "Add readSingleEnrolment for Windows registry config (#21)"
```

---

### Task 2: Add `readRegistryEnrolments` with tests

**Files:**
- Modify: `internal/config/registry_windows_test.go`
- Modify: `internal/config/registry_windows.go`

- [ ] **Step 1: Write the test for missing Enrolments key**

Add to `internal/config/registry_windows_test.go`:

```go
func TestReadRegistryEnrolmentsNotExist(t *testing.T) {
	// Use a path that definitely doesn't exist.
	enrolments, err := readRegistryEnrolments(registry.CURRENT_USER, `SOFTWARE\dotvault-nonexistent`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enrolments != nil {
		t.Errorf("expected nil enrolments, got %v", enrolments)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -run TestReadRegistryEnrolmentsNotExist ./internal/config/ -v`
Expected: FAIL — `readRegistryEnrolments` is not defined.

- [ ] **Step 3: Write test for multiple enrolments**

Add to `internal/config/registry_windows_test.go`:

```go
func TestReadRegistryEnrolmentsMultiple(t *testing.T) {
	// Create two enrolment subkeys under a temporary registry path.
	for _, name := range []string{"gh", "gitlab"} {
		key, _, err := registry.CreateKey(
			registry.CURRENT_USER,
			`SOFTWARE\dotvault-test-enrol\Enrolments\`+name,
			registry.ALL_ACCESS,
		)
		if err != nil {
			t.Fatalf("create key %s: %v", name, err)
		}
		engine := "github"
		if name == "gitlab" {
			engine = "gitlab"
		}
		if err := key.SetStringValue("Engine", engine); err != nil {
			t.Fatalf("set Engine for %s: %v", name, err)
		}
		key.Close()
	}
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments\gh`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments\gitlab`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol\Enrolments`)
	defer registry.DeleteKey(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol`)

	enrolments, err := readRegistryEnrolments(registry.CURRENT_USER, `SOFTWARE\dotvault-test-enrol`)
	if err != nil {
		t.Fatalf("readRegistryEnrolments() error: %v", err)
	}
	if len(enrolments) != 2 {
		t.Fatalf("len(enrolments) = %d, want 2", len(enrolments))
	}
	if enrolments["gh"].Engine != "github" {
		t.Errorf("gh.Engine = %q, want %q", enrolments["gh"].Engine, "github")
	}
	if enrolments["gitlab"].Engine != "gitlab" {
		t.Errorf("gitlab.Engine = %q, want %q", enrolments["gitlab"].Engine, "gitlab")
	}
}
```

- [ ] **Step 4: Implement `readRegistryEnrolments`**

Add to `internal/config/registry_windows.go`, before `readSingleEnrolment`:

```go
// readRegistryEnrolments reads enrolments from the Enrolments subkey under
// the given basePath. Each enrolment is a named subkey containing an Engine
// value and optional Settings subkey.
// Returns (nil, nil) if the Enrolments key does not exist.
func readRegistryEnrolments(root registry.Key, basePath string) (map[string]Enrolment, error) {
	enrolPath := basePath + `\Enrolments`
	key, err := registry.OpenKey(root, enrolPath, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open Enrolments key at %s: %w", enrolPath, err)
	}
	defer key.Close()

	info, err := key.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat Enrolments key: %w", err)
	}

	names, err := key.ReadSubKeyNames(int(info.SubKeyCount))
	if err != nil {
		return nil, fmt.Errorf("enumerate enrolment subkeys: %w", err)
	}

	enrolments := make(map[string]Enrolment, len(names))
	for _, name := range names {
		enrolment, err := readSingleEnrolment(root, basePath, name)
		if err != nil {
			return nil, fmt.Errorf("read enrolment %q: %w", name, err)
		}
		enrolments[name] = enrolment
	}
	return enrolments, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -run TestReadRegistryEnrolments ./internal/config/ -v`
Expected: PASS (both `TestReadRegistryEnrolmentsNotExist` and `TestReadRegistryEnrolmentsMultiple`)

- [ ] **Step 6: Commit**

```bash
git add internal/config/registry_windows.go internal/config/registry_windows_test.go
git commit -m "Add readRegistryEnrolments for Windows registry config (#21)"
```

---

### Task 3: Wire enrolments into `loadFromRegistry`

**Files:**
- Modify: `internal/config/registry_windows.go:42-49`

- [ ] **Step 1: Update `loadFromRegistry` to read enrolments**

In `internal/config/registry_windows.go`, replace lines 42-49:

```go
	// Read rules from the machine-level policy key.
	rules, err := readRegistryRules(registry.LOCAL_MACHINE)
	if err != nil {
		return nil, true, fmt.Errorf("read registry rules: %w", err)
	}
	cfg.Rules = rules

	return cfg, true, nil
```

with:

```go
	// Read rules from the machine-level policy key.
	rules, err := readRegistryRules(registry.LOCAL_MACHINE)
	if err != nil {
		return nil, true, fmt.Errorf("read registry rules: %w", err)
	}
	cfg.Rules = rules

	// Read enrolments from the machine-level policy key.
	enrolments, err := readRegistryEnrolments(registry.LOCAL_MACHINE, registryPolicyPath)
	if err != nil {
		return nil, true, fmt.Errorf("read registry enrolments: %w", err)
	}
	cfg.Enrolments = enrolments

	return cfg, true, nil
```

- [ ] **Step 2: Verify the build compiles**

Run: `go build ./internal/config/`
Expected: Success (no errors)

- [ ] **Step 3: Run all registry tests**

Run: `go test ./internal/config/ -v -run TestLoadFromRegistry`
Expected: PASS (existing `TestLoadFromRegistryNoKeys` still passes)

- [ ] **Step 4: Commit**

```bash
git add internal/config/registry_windows.go
git commit -m "Wire enrolment reading into loadFromRegistry (#21)"
```

---

### Task 4: Update `readRegistryRules` to accept `basePath` parameter

The existing `readRegistryRules` and helpers hard-code `registryPolicyPath`. For consistency with the new enrolment functions (which accept a `basePath` for testability), refactor `readRegistryRules` to also accept a `basePath` parameter. This is not strictly required for the fix but keeps the registry reading API consistent.

**Skip this task.** The existing Rules functions use `registryPolicyPath` directly and work fine. The enrolment functions accept `basePath` for testability because they're new code. Consistency can be addressed separately if desired.

---

### Task 4: Update ADMX template

**Files:**
- Modify: `packaging/windows/dotvault.admx`

- [ ] **Step 1: Add Enrolments comment and category to ADMX**

In `packaging/windows/dotvault.admx`, add the enrolments GP Preferences comment after the existing Rules comment block (after line 30, before the closing `-->`), and add the Enrolments category to the categories block.

Replace the closing comment and policyDefinitions opening (lines 30-57) with:

```xml
    SOFTWARE\Policies\dotvault\Rules\<rule-name>\OAuth\Scopes     (REG_MULTI_SZ)

  Enrolments (credential acquisition flows) are also configured via
  Group Policy Preferences > Registry, targeting:
    SOFTWARE\Policies\dotvault\Enrolments\<name>\Engine            (REG_SZ)
  Optional Settings subkey:
    SOFTWARE\Policies\dotvault\Enrolments\<name>\Settings\<key>    (REG_SZ)
    SOFTWARE\Policies\dotvault\Enrolments\<name>\Settings\<key>    (REG_MULTI_SZ)
-->
<policyDefinitions
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    revision="1.0"
    schemaVersion="1.0"
    xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions">

  <policyNamespaces>
    <target prefix="dotvault" namespace="goodtune.dotvault" />
    <using prefix="windows" namespace="Microsoft.Policies.Windows" />
  </policyNamespaces>

  <resources minRequiredRevision="1.0" />

  <categories>
    <category name="Dotvault" displayName="$(string.Cat_Dotvault)" />
    <category name="Vault" displayName="$(string.Cat_Vault)">
      <parentCategory ref="Dotvault" />
    </category>
    <category name="Sync" displayName="$(string.Cat_Sync)">
      <parentCategory ref="Dotvault" />
    </category>
    <category name="WebUI" displayName="$(string.Cat_WebUI)">
      <parentCategory ref="Dotvault" />
    </category>
    <category name="Enrolments" displayName="$(string.Cat_Enrolments)">
      <parentCategory ref="Dotvault" />
    </category>
  </categories>
```

- [ ] **Step 2: Verify ADMX is well-formed XML**

Run: `xmllint --noout packaging/windows/dotvault.admx`
Expected: No errors (if xmllint is available; otherwise visually inspect)

- [ ] **Step 3: Commit**

```bash
git add packaging/windows/dotvault.admx
git commit -m "Add Enrolments category and GP Preferences docs to ADMX (#21)"
```

---

### Task 5: Final verification

- [ ] **Step 1: Run full test suite**

Run: `make test`
Expected: All tests pass (Windows-specific tests only run on Windows via build tags)

- [ ] **Step 2: Build for all platforms**

Run: `make build-all`
Expected: Success — cross-compilation for linux/darwin/windows all pass

- [ ] **Step 3: Commit any remaining changes (if any)**

Only if there are uncommitted changes from fixing test/build issues.
