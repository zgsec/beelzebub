package artifactstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStore_WriteCreatesArtifactAndMeta(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 50*1024*1024, 0, 0)
	body := []byte("<extension>https://evil.example/x</extension>")
	captures := map[string]any{
		"session_key":   "abc123",
		"operator_user": "pwn",
	}
	a, err := s.Write(body, captures)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if a.SHA256 == "" || len(a.SHA256) != 64 {
		t.Fatalf("bad sha: %q", a.SHA256)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, a.SHA256+".bin")); string(got) != string(body) {
		t.Fatalf("body roundtrip mismatch")
	}
	metaBytes, err := os.ReadFile(filepath.Join(dir, a.SHA256+".meta.json"))
	if err != nil {
		t.Fatalf("meta missing: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatalf("meta json: %v", err)
	}
	if meta["schema_version"].(float64) != 1 {
		t.Fatal("schema_version != 1")
	}
	if meta["operator_user"] != "pwn" {
		t.Fatal("operator_user not in meta")
	}
}

func TestStore_RejectsOversize(t *testing.T) {
	s := New(t.TempDir(), 100, 0, 0)
	// Empty body is allowed (0 <= 100); should NOT error.
	if _, err := s.Write([]byte(""), nil); err != nil {
		t.Fatalf("empty body should be allowed: %v", err)
	}
	body := make([]byte, 200)
	if _, err := s.Write(body, nil); err == nil {
		t.Fatal("expected oversize error")
	}
}

func TestStore_Idempotent(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 1024, 0, 0)
	body := []byte("<dup/>")
	a1, _ := s.Write(body, map[string]any{"first": "v1"})
	a2, _ := s.Write(body, map[string]any{"first": "v2"})
	if a1.SHA256 != a2.SHA256 {
		t.Fatal("same body produced different sha")
	}
	// First-write meta is preserved; second is a no-op on the .bin
	// (do not require deterministic meta.json content here)
}

func TestStore_ExtractsURLs(t *testing.T) {
	s := New(t.TempDir(), 1024, 0, 0)
	body := []byte(`<x>see https://evil.example/loader.exe and http://c2.example/beacon</x>`)
	a, _ := s.Write(body, nil)
	urls, _ := a.Captures["embedded_urls"].([]string)
	if len(urls) != 2 {
		t.Fatalf("expected 2 urls, got %v", urls)
	}
}

func TestStore_DoesNotMutateCallerCaptures(t *testing.T) {
	s := New(t.TempDir(), 1024, 0, 0)
	captures := map[string]any{"operator_user": "pwn"}
	_, err := s.Write([]byte("body"), captures)
	if err != nil {
		t.Fatal(err)
	}
	// Caller's map must be unchanged.
	if len(captures) != 1 {
		t.Fatalf("caller captures was mutated: %v", captures)
	}
	if _, ok := captures["sha256"]; ok {
		t.Fatal("sha256 leaked into caller map")
	}
	if _, ok := captures["embedded_urls"]; ok {
		t.Fatal("embedded_urls leaked into caller map")
	}
}

func TestStore_EvictsOldestOverBudget(t *testing.T) {
	dir := t.TempDir()
	// maxFiles=2: third distinct write evicts the oldest.
	s := New(dir, 0, 0, 2)
	a1, _ := s.Write([]byte("one"), nil)
	time.Sleep(10 * time.Millisecond) // ensure distinct mtimes
	_, _ = s.Write([]byte("two"), nil)
	time.Sleep(10 * time.Millisecond)
	_, _ = s.Write([]byte("three"), nil)

	if _, err := os.Stat(filepath.Join(dir, a1.SHA256+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest .bin should have been evicted")
	}
	if _, err := os.Stat(filepath.Join(dir, a1.SHA256+".meta.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest .meta.json should have been evicted")
	}
	bins, _ := filepath.Glob(filepath.Join(dir, "*.bin"))
	if len(bins) != 2 {
		t.Fatalf("want 2 .bin remaining, got %d", len(bins))
	}
}

func TestStore_TotalBytesBudgetEvicts(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 0, 6 /*bytes*/, 0) // ~2 small bodies fit
	a1, _ := s.Write([]byte("aaaa"), nil) // 4 bytes
	time.Sleep(10 * time.Millisecond)
	_, _ = s.Write([]byte("bbbb"), nil) // 4 bytes -> total 8 > 6 -> evict a1
	if _, err := os.Stat(filepath.Join(dir, a1.SHA256+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest should be evicted under byte budget")
	}
}
