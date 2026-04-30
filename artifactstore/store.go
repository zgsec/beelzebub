// Package artifactstore is the content-addressable research-artifact pipeline.
// Captured request bodies (extension uploads, MFT drops, payloads) land here
// keyed by sha256. Each artifact has a sibling meta.json with capture context.
//
// Frame: this is a research artifact pipeline, not a malware dropbox.
// No execution, no auto-analysis — just capture + record. Downstream
// tools (azazel sandbox, blog research, vault sync) read the directory.
package artifactstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const SchemaVersion = 1

var ErrOversize = errors.New("artifactstore: body exceeds maxBodyBytes")

var urlRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

type Artifact struct {
	SHA256    string
	Captured  time.Time
	Captures  map[string]any
	SizeBytes int
}

type Store struct {
	dir          string
	maxBodyBytes int
	mu           sync.Mutex // serializes writes per process; per-sha is content-addressable so collisions are no-ops
}

func New(dir string, maxBodyBytes int) *Store {
	return &Store{dir: dir, maxBodyBytes: maxBodyBytes}
}

// Write persists body atomically + writes a meta.json sibling.
// Idempotent: same body to same store is a no-op on the .bin.
func (s *Store) Write(body []byte, captures map[string]any) (Artifact, error) {
	if s.maxBodyBytes > 0 && len(body) > s.maxBodyBytes {
		return Artifact{}, ErrOversize
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	now := time.Now().UTC()

	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return Artifact{}, fmt.Errorf("mkdir: %w", err)
	}

	binPath := filepath.Join(s.dir, sha+".bin")
	metaPath := filepath.Join(s.dir, sha+".meta.json")

	s.mu.Lock()
	defer s.mu.Unlock()

	// Atomic write of .bin (skip if already exists — content-addressable).
	if _, err := os.Stat(binPath); errors.Is(err, os.ErrNotExist) {
		if err := writeAtomic(binPath, body, 0o600); err != nil {
			return Artifact{}, err
		}
	}

	// Always (re)write meta.json — captures may differ across calls.
	urls := extractURLs(body)
	if captures == nil {
		captures = map[string]any{}
	}
	captures["embedded_urls"] = urls
	captures["schema_version"] = SchemaVersion
	captures["sha256"] = sha
	captures["captured_at"] = now.Format(time.RFC3339Nano)
	captures["size_bytes"] = len(body)
	metaBytes, err := json.MarshalIndent(captures, "", "  ")
	if err != nil {
		return Artifact{}, fmt.Errorf("meta marshal: %w", err)
	}
	if err := writeAtomic(metaPath, metaBytes, 0o600); err != nil {
		return Artifact{}, err
	}
	return Artifact{
		SHA256:    sha,
		Captured:  now,
		Captures:  captures,
		SizeBytes: len(body),
	}, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func extractURLs(body []byte) []string {
	matches := urlRe.FindAll(body, -1)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		s := string(m)
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
