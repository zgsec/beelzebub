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
	"sort"
	"strings"
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
	dir           string
	maxBodyBytes  int
	maxTotalBytes int
	maxFiles      int
	mu            sync.Mutex // serializes writes per process; per-sha is content-addressable so collisions are no-ops
}

func New(dir string, maxBodyBytes, maxTotalBytes, maxFiles int) *Store {
	return &Store{dir: dir, maxBodyBytes: maxBodyBytes, maxTotalBytes: maxTotalBytes, maxFiles: maxFiles}
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
	enriched := make(map[string]any, len(captures)+5)
	for k, v := range captures {
		enriched[k] = v
	}
	enriched["embedded_urls"] = urls
	enriched["schema_version"] = SchemaVersion
	enriched["sha256"] = sha
	enriched["captured_at"] = now.Format(time.RFC3339Nano)
	enriched["size_bytes"] = len(body)
	metaBytes, err := json.MarshalIndent(enriched, "", "  ")
	if err != nil {
		return Artifact{}, fmt.Errorf("meta marshal: %w", err)
	}
	if err := writeAtomic(metaPath, metaBytes, 0o600); err != nil {
		return Artifact{}, err
	}
	s.enforceBudget()
	return Artifact{
		SHA256:    sha,
		Captured:  now,
		Captures:  enriched,
		SizeBytes: len(body),
	}, nil
}

// enforceBudget evicts oldest artifacts (FIFO by mtime) when the store exceeds
// its file-count or total-byte budget. Best-effort: never fails the caller.
// Caller must hold s.mu.
func (s *Store) enforceBudget() {
	if s.maxTotalBytes <= 0 && s.maxFiles <= 0 {
		return
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	type binFile struct {
		sha  string
		size int64
		mod  time.Time
	}
	var bins []binFile
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		bins = append(bins, binFile{strings.TrimSuffix(e.Name(), ".bin"), info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(bins, func(i, j int) bool { return bins[i].mod.Before(bins[j].mod) }) // oldest first
	for len(bins) > 0 &&
		((s.maxTotalBytes > 0 && total > int64(s.maxTotalBytes)) ||
			(s.maxFiles > 0 && len(bins) > s.maxFiles)) {
		oldest := bins[0]
		bins = bins[1:]
		_ = os.Remove(filepath.Join(s.dir, oldest.sha+".bin"))
		_ = os.Remove(filepath.Join(s.dir, oldest.sha+".meta.json"))
		total -= oldest.size
	}
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".artifact-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // cleanup if rename never happens
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
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
