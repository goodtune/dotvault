package vaultfs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Document is a secret rendered as the bytes a reader sees, plus the metadata
// stat reports.
type Document struct {
	// Bytes is the rendered JSON, indented and newline-terminated so `cat`
	// produces something readable and `jq .` has nothing to fix up.
	Bytes []byte

	// ModTime is the current version's created_time — KVv2's nearest
	// equivalent of a modification time. Zero when Vault returned no version
	// metadata, in which case the mount falls back to the mount time so
	// tools that sort or compare timestamps still see a sane value.
	ModTime time.Time

	// Version is the KVv2 version the bytes were rendered from.
	Version int
}

// Size is the file size stat should report.
func (d *Document) Size() int64 { return int64(len(d.Bytes)) }

// renderDocument turns a secret's data section into the file's contents.
//
// Keys are emitted in sorted order (encoding/json sorts map keys), so
// re-reading an unchanged secret produces byte-identical output and the mount
// does not appear to churn to anything watching file checksums.
func renderDocument(s *Secret) (*Document, error) {
	data := s.Data
	if data == nil {
		data = map[string]any{}
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		// The error text from encoding/json can quote the offending value,
		// which here is secret material. Report the failure without it.
		return nil, fmt.Errorf("vaultfs: secret data cannot be rendered as JSON")
	}
	return &Document{
		Bytes:   append(b, '\n'),
		ModTime: s.CreatedTime,
		Version: s.Version,
	}, nil
}

// parseDocument turns the bytes written to a secret file back into a KVv2 data
// map. It is the inverse of renderDocument and the only path by which the
// filesystem can produce a Vault write.
//
// Numbers are decoded as json.Number rather than float64 so a round trip is
// lossless: without it, reading and rewriting a secret unchanged would turn
// 1000000 into 1e+06 and a large integer ID into an approximation. json.Number
// re-marshals as the literal the user wrote.
//
// Every failure is reported as ErrInvalidDocument with no reference to the
// bytes themselves. The content is a credential; a message quoting the
// offending token, or even an offset into it, is a leak into logs and into the
// errno path's diagnostics.
func parseDocument(b []byte) (map[string]any, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return nil, ErrInvalidDocument
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()

	var data map[string]any
	if err := dec.Decode(&data); err != nil {
		return nil, ErrInvalidDocument
	}
	// A bare `null` decodes into a nil map without error, and trailing
	// content after a complete value is silently ignored by Decode — both
	// would otherwise be accepted as valid writes.
	if data == nil || dec.More() {
		return nil, ErrInvalidDocument
	}
	// Vault rejects a KVv2 write with no fields, and an empty object is far
	// more likely to be a truncate the caller never followed with a write
	// (`> file`, or a `touch`) than an intentional erasure of every field.
	// Refusing here turns that into a visible error on close rather than a
	// server-side failure the caller sees as EIO.
	if len(data) == 0 {
		return nil, ErrInvalidDocument
	}
	return data, nil
}
