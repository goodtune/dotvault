package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTextHandler_ReadExisting(t *testing.T) {
	// Create a temp file with known content
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pem")
	os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"), 0600)

	h := &TextHandler{}
	data, err := h.Read(path)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	s, ok := data.(string)
	if !ok {
		t.Fatalf("Read() returned %T, want string", data)
	}
	if s != "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n" {
		t.Errorf("Read() = %q, want PEM content", s)
	}
}

func TestTextHandler_ReadMissing(t *testing.T) {
	h := &TextHandler{}
	data, err := h.Read("/tmp/nonexistent-dotvault-test-file")
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	s, ok := data.(string)
	if !ok {
		t.Fatalf("Read() returned %T, want string", data)
	}
	if s != "" {
		t.Errorf("Read() = %q, want empty string", s)
	}
}

func TestTextHandler_Parse(t *testing.T) {
	h := &TextHandler{}
	data, err := h.Parse("some content here")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	s := data.(string)
	if s != "some content here" {
		t.Errorf("Parse() = %q, want 'some content here'", s)
	}
}

func TestTextHandler_ParseEmpty(t *testing.T) {
	h := &TextHandler{}
	data, err := h.Parse("")
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	s := data.(string)
	if s != "" {
		t.Errorf("Parse() = %q, want empty string", s)
	}
}

func TestTextHandler_MergeOverwrites(t *testing.T) {
	h := &TextHandler{}

	existing := "old content that should be replaced"
	incoming := "new content from vault"

	merged, err := h.Merge(existing, incoming)
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}

	s := merged.(string)
	if s != "new content from vault" {
		t.Errorf("Merge() = %q, want 'new content from vault'", s)
	}
}

func TestTextHandler_MergeIgnoresExisting(t *testing.T) {
	h := &TextHandler{}

	// Even with existing content, incoming fully replaces
	merged, err := h.Merge("existing", "incoming")
	if err != nil {
		t.Fatalf("Merge() error: %v", err)
	}
	if merged.(string) != "incoming" {
		t.Errorf("Merge() = %v, want 'incoming'", merged)
	}
}

func TestTextHandler_WriteRoundTrip(t *testing.T) {
	h := &TextHandler{}
	dir := t.TempDir()
	path := filepath.Join(dir, "id_rsa")

	content := "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
	if err := h.Write(path, content, 0600); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	data, err := h.Read(path)
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if data.(string) != content {
		t.Errorf("round-trip failed: got %q", data)
	}

	// Verify permissions
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestTextHandler_WriteOverwrites(t *testing.T) {
	h := &TextHandler{}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	// Write initial content
	h.Write(path, "initial", 0600)

	// Overwrite
	h.Write(path, "replaced", 0600)

	got, _ := os.ReadFile(path)
	if string(got) != "replaced" {
		t.Errorf("got %q, want 'replaced'", string(got))
	}
}
