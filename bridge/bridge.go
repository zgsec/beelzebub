package bridge

import (
	"sync"
	"time"
)

// Credential represents a credential discovered via any protocol.
type Credential struct {
	Source  string    // "ssh", "http", "mcp"
	Type   string    // "aws_key", "db_password", "api_token"
	Key    string
	Value  string
	FoundAt time.Time
}

// ProtocolBridge enables cross-protocol state sharing.
// Credentials or flags set from one protocol handler are visible to others.
type ProtocolBridge struct {
	mu              sync.RWMutex
	discoveredCreds map[string][]Credential         // IP → credentials
	sessionFlags    map[string]map[string]time.Time  // IP → flag → when set (v8: timestamp for gap computation)
}

// NewBridge creates an initialized ProtocolBridge.
func NewBridge() *ProtocolBridge {
	return &ProtocolBridge{
		discoveredCreds: make(map[string][]Credential),
		sessionFlags:    make(map[string]map[string]time.Time),
	}
}

// RecordDiscovery records that an IP discovered a credential via a protocol.
func (pb *ProtocolBridge) RecordDiscovery(ip, source, credType, key, value string) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.discoveredCreds[ip] = append(pb.discoveredCreds[ip], Credential{
		Source:  source,
		Type:    credType,
		Key:     key,
		Value:   value,
		FoundAt: time.Now(),
	})
}

// HasDiscovered checks if an IP has found credentials of a specific type.
func (pb *ProtocolBridge) HasDiscovered(ip, credType string) bool {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	for _, c := range pb.discoveredCreds[ip] {
		if c.Type == credType {
			return true
		}
	}
	return false
}

// GetDiscoveries returns all credentials discovered by an IP.
func (pb *ProtocolBridge) GetDiscoveries(ip string) []Credential {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	creds := pb.discoveredCreds[ip]
	result := make([]Credential, len(creds))
	copy(result, creds)
	return result
}

// SetFlag marks that an IP has achieved something (e.g., "ssh_authenticated").
// Stores the timestamp for cross-protocol gap computation.
func (pb *ProtocolBridge) SetFlag(ip, flag string) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.sessionFlags[ip] == nil {
		pb.sessionFlags[ip] = make(map[string]time.Time)
	}
	pb.sessionFlags[ip][flag] = time.Now()
}

// HasFlag checks if an IP has a specific flag.
func (pb *ProtocolBridge) HasFlag(ip, flag string) bool {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	_, ok := pb.sessionFlags[ip][flag]
	return ok
}

// GetFlags returns all flag names for an IP.
func (pb *ProtocolBridge) GetFlags(ip string) []string {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	var flags []string
	for f := range pb.sessionFlags[ip] {
		flags = append(flags, f)
	}
	return flags
}

// LastActivity returns the most recent flag-set or credential-discovery timestamp
// for an IP. Returns zero time if no activity recorded. Used by agent detection
// to compute CrossProtocolGapMs — the time between activity on one protocol and
// the first event on another.
func (pb *ProtocolBridge) LastActivity(ip string) time.Time {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	var latest time.Time
	for _, t := range pb.sessionFlags[ip] {
		if t.After(latest) {
			latest = t
		}
	}
	for _, c := range pb.discoveredCreds[ip] {
		if c.FoundAt.After(latest) {
			latest = c.FoundAt
		}
	}
	return latest
}

// Clean removes all state for IPs not seen since maxAge. An IP is considered
// "active" if its newest credential discovery OR its newest session flag is
// after the cutoff; otherwise both maps are pruned for that IP.
//
// Pre-fix this only iterated discoveredCreds and pruned both maps in lockstep,
// which meant any IP that set flags without ever recording a credential
// discovery (a common pattern: every authenticated SSH session sets the
// `ssh_authenticated` flag, but most of them never trigger checkCredentialDiscovery)
// stayed in sessionFlags forever — an unbounded memory leak in long-lived sensors.
func (pb *ProtocolBridge) Clean(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// Build the union of IPs across both maps so we don't miss flag-only IPs.
	ips := make(map[string]struct{}, len(pb.discoveredCreds)+len(pb.sessionFlags))
	for ip := range pb.discoveredCreds {
		ips[ip] = struct{}{}
	}
	for ip := range pb.sessionFlags {
		ips[ip] = struct{}{}
	}

	for ip := range ips {
		var latest time.Time
		if creds := pb.discoveredCreds[ip]; len(creds) > 0 {
			latest = creds[len(creds)-1].FoundAt
		}
		for _, t := range pb.sessionFlags[ip] {
			if t.After(latest) {
				latest = t
			}
		}
		if latest.IsZero() || latest.Before(cutoff) {
			delete(pb.discoveredCreds, ip)
			delete(pb.sessionFlags, ip)
		}
	}
}
