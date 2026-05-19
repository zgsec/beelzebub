package bridge

import (
	"sync"
	"time"
)

// maxCredsPerIP caps the per-IP credential history. Without this cap, an
// attacker pounding a single IP with credential-shaped payloads (e.g.
// repeated SSH-login probes that all match the AWS-key regex) would grow
// the per-IP slice without bound. The HasDiscovered() lookup short-circuits
// on first match so duplicates after the first hit are harmless to detection;
// the bound exists purely to bound memory.
//
// 100 was chosen because no realistic legitimate flow records >100 distinct
// credentials per IP — every actual credential discovery is a (source,
// type, key) triple, and the persona surface emits at most a few dozen
// distinct triples across SSH+HTTP+MCP. 100 leaves headroom while
// staying small enough that even 10k tracked IPs × 100 creds × ~120 B
// per Credential is ≈120 MB worst case (vs unbounded).
const maxCredsPerIP = 100

// Credential represents a credential discovered via any protocol.
type Credential struct {
	Source  string // "ssh", "http", "mcp"
	Type    string // "aws_key", "db_password", "api_token"
	Key     string
	Value   string
	FoundAt time.Time
}

// ProtocolBridge enables cross-protocol state sharing.
// Credentials or flags set from one protocol handler are visible to others.
type ProtocolBridge struct {
	mu              sync.RWMutex
	discoveredCreds map[string][]Credential         // IP → credentials (capped at maxCredsPerIP, FIFO-evicted)
	sessionFlags    map[string]map[string]time.Time // IP → flag → when set (v8: timestamp for gap computation)
}

// NewBridge creates an initialized ProtocolBridge.
func NewBridge() *ProtocolBridge {
	return &ProtocolBridge{
		discoveredCreds: make(map[string][]Credential),
		sessionFlags:    make(map[string]map[string]time.Time),
	}
}

// RecordDiscovery records that an IP discovered a credential via a protocol.
// The per-IP slice is capped at maxCredsPerIP entries; older entries are
// dropped FIFO when the cap is hit. This prevents an attacker from growing
// the slice without bound by spamming credential-shaped payloads from a
// single IP. The IP-keyed map itself is bounded by the periodic Clean()
// ticker (see builder/builder.go); together they cap the bridge's worst-
// case memory at maxCredsPerIP × (max active IPs in window).
func (pb *ProtocolBridge) RecordDiscovery(ip, source, credType, key, value string) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	creds := pb.discoveredCreds[ip]
	if len(creds) >= maxCredsPerIP {
		// Drop the oldest entry (FIFO). We keep the slice length stable
		// at the cap to avoid repeated grow-then-trim allocations under
		// sustained attack.
		creds = append(creds[:0], creds[len(creds)-maxCredsPerIP+1:]...)
	}
	pb.discoveredCreds[ip] = append(creds, Credential{
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
