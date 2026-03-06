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
	discoveredCreds map[string][]Credential    // IP → credentials
	sessionFlags    map[string]map[string]bool // IP → set of flags
}

// NewBridge creates an initialized ProtocolBridge.
func NewBridge() *ProtocolBridge {
	return &ProtocolBridge{
		discoveredCreds: make(map[string][]Credential),
		sessionFlags:    make(map[string]map[string]bool),
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
func (pb *ProtocolBridge) SetFlag(ip, flag string) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.sessionFlags[ip] == nil {
		pb.sessionFlags[ip] = make(map[string]bool)
	}
	pb.sessionFlags[ip][flag] = true
}

// HasFlag checks if an IP has a specific flag.
func (pb *ProtocolBridge) HasFlag(ip, flag string) bool {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	return pb.sessionFlags[ip][flag]
}

// GetFlags returns all flags for an IP.
func (pb *ProtocolBridge) GetFlags(ip string) []string {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	var flags []string
	for f := range pb.sessionFlags[ip] {
		flags = append(flags, f)
	}
	return flags
}

// Clean removes all state for IPs not seen since maxAge.
// This is a simple implementation; callers can run it periodically.
func (pb *ProtocolBridge) Clean(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	pb.mu.Lock()
	defer pb.mu.Unlock()
	for ip, creds := range pb.discoveredCreds {
		if len(creds) > 0 && creds[len(creds)-1].FoundAt.Before(cutoff) {
			delete(pb.discoveredCreds, ip)
			delete(pb.sessionFlags, ip)
		}
	}
}
