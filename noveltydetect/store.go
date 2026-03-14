package noveltydetect

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// StoreStats contains summary statistics of the fingerprint store.
type StoreStats struct {
	Commands   int `json:"commands"`
	CredPairs  int `json:"cred_pairs"`
	Paths      int `json:"paths"`
	ToolSeqs   int `json:"tool_seqs"`
	UserAgents int `json:"user_agents"`
}

// FingerprintStore tracks observed session fingerprints for novelty detection.
// Thread-safe via sync.RWMutex. Uses truncated SHA-256 hashes as map keys
// to bound memory usage regardless of input length.
type FingerprintStore struct {
	mu         sync.RWMutex
	commands   map[string]time.Time // normalized cmd hash -> last seen
	credPairs  map[string]time.Time // "user:pass" hash -> last seen
	paths      map[string]time.Time // normalized path hash -> last seen
	toolSeqs   map[string]time.Time // "tool1|tool2|tool3" hash -> last seen
	userAgents map[string]time.Time // UA hash -> last seen
}

// NewStore creates a new empty FingerprintStore.
func NewStore() *FingerprintStore {
	return &FingerprintStore{
		commands:   make(map[string]time.Time),
		credPairs:  make(map[string]time.Time),
		paths:      make(map[string]time.Time),
		toolSeqs:   make(map[string]time.Time),
		userAgents: make(map[string]time.Time),
	}
}

// hash returns a truncated SHA-256 (16 bytes hex) of the input.
func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:16])
}

// normalizeCommand lowercases and trims a command for fingerprinting.
func normalizeCommand(cmd string) string {
	return strings.ToLower(strings.TrimSpace(cmd))
}

// normalizePath lowercases a path for fingerprinting.
func normalizePath(path string) string {
	return strings.ToLower(strings.TrimSpace(path))
}

// RecordCommand records a command as seen and returns whether it was new.
func (s *FingerprintStore) RecordCommand(cmd string) bool {
	key := hash(normalizeCommand(cmd))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := s.commands[key]
	s.commands[key] = time.Now()
	return !known
}

// IsCommandKnown returns true if the command has been seen before.
func (s *FingerprintStore) IsCommandKnown(cmd string) bool {
	key := hash(normalizeCommand(cmd))
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, known := s.commands[key]
	return known
}

// RecordCredPair records a credential pair as seen and returns whether it was new.
func (s *FingerprintStore) RecordCredPair(user, pass string) bool {
	key := hash(user + ":" + pass)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := s.credPairs[key]
	s.credPairs[key] = time.Now()
	return !known
}

// IsCredPairKnown returns true if the credential pair has been seen before.
func (s *FingerprintStore) IsCredPairKnown(user, pass string) bool {
	key := hash(user + ":" + pass)
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, known := s.credPairs[key]
	return known
}

// RecordPath records an HTTP path as seen and returns whether it was new.
func (s *FingerprintStore) RecordPath(path string) bool {
	key := hash(normalizePath(path))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := s.paths[key]
	s.paths[key] = time.Now()
	return !known
}

// IsPathKnown returns true if the path has been seen before.
func (s *FingerprintStore) IsPathKnown(path string) bool {
	key := hash(normalizePath(path))
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, known := s.paths[key]
	return known
}

// RecordToolSequence records a tool call sequence as seen and returns whether it was new.
func (s *FingerprintStore) RecordToolSequence(tools []string) bool {
	key := hash(strings.Join(tools, "|"))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := s.toolSeqs[key]
	s.toolSeqs[key] = time.Now()
	return !known
}

// IsToolSequenceKnown returns true if the tool sequence has been seen before.
func (s *FingerprintStore) IsToolSequenceKnown(tools []string) bool {
	key := hash(strings.Join(tools, "|"))
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, known := s.toolSeqs[key]
	return known
}

// RecordUserAgent records a user agent as seen and returns whether it was new.
func (s *FingerprintStore) RecordUserAgent(ua string) bool {
	key := hash(strings.ToLower(strings.TrimSpace(ua)))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := s.userAgents[key]
	s.userAgents[key] = time.Now()
	return !known
}

// IsUserAgentKnown returns true if the user agent has been seen before.
func (s *FingerprintStore) IsUserAgentKnown(ua string) bool {
	key := hash(strings.ToLower(strings.TrimSpace(ua)))
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, known := s.userAgents[key]
	return known
}

// Clean removes entries older than maxAge from all maps.
func (s *FingerprintStore) Clean(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for k, t := range s.commands {
		if t.Before(cutoff) {
			delete(s.commands, k)
			removed++
		}
	}
	for k, t := range s.credPairs {
		if t.Before(cutoff) {
			delete(s.credPairs, k)
			removed++
		}
	}
	for k, t := range s.paths {
		if t.Before(cutoff) {
			delete(s.paths, k)
			removed++
		}
	}
	for k, t := range s.toolSeqs {
		if t.Before(cutoff) {
			delete(s.toolSeqs, k)
			removed++
		}
	}
	for k, t := range s.userAgents {
		if t.Before(cutoff) {
			delete(s.userAgents, k)
			removed++
		}
	}
	return removed
}

// Stats returns summary statistics.
func (s *FingerprintStore) Stats() StoreStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return StoreStats{
		Commands:   len(s.commands),
		CredPairs:  len(s.credPairs),
		Paths:      len(s.paths),
		ToolSeqs:   len(s.toolSeqs),
		UserAgents: len(s.userAgents),
	}
}
