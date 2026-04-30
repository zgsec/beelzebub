package artifactstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStore_WriteCreatesArtifactAndMeta(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, 50*1024*1024)
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
	s := New(t.TempDir(), 100)
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
	s := New(dir, 1024)
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
	s := New(t.TempDir(), 1024)
	body := []byte(`<x>see https://evil.example/loader.exe and http://c2.example/beacon</x>`)
	a, _ := s.Write(body, nil)
	urls, _ := a.Captures["embedded_urls"].([]string)
	if len(urls) != 2 {
		t.Fatalf("expected 2 urls, got %v", urls)
	}
}
