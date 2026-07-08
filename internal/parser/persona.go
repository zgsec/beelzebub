// Package parser — persona.go reads /configurations/persona.yaml at startup.
//
// The persona file is the operator's deception content: company name,
// internal domains, employee email patterns. Beelzebub reads it once and
// passes it to protocol strategies via the builder. Framework code stays
// deception-neutral; persona content lives in the bundle.
package parser

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Node mirrors the rendered node.yaml that bzb produces under persona/node.yaml
// and mounts into /configurations/node.yaml at runtime.
type Node struct {
	SchemaVersion int         `yaml:"schema_version"`
	NodeID        string      `yaml:"node_id"`
	Role          string      `yaml:"role"`
	PersonaLocal  NodePersona `yaml:"persona_local"`
	Lures         []string    `yaml:"lures"`
	CanarySlots   []string    `yaml:"canary_slots,omitempty"`
}

// NodePersona holds the runtime-visible server identity and resource data.
// Node-prefixed to avoid collision with shellemulator's own Process/Listener/NetworkConfig types.
type NodePersona struct {
	Hostname    string              `yaml:"hostname"`
	FQDN        string              `yaml:"fqdn"`
	OS          string              `yaml:"os"`
	User        string              `yaml:"user"`
	InternalIP  string              `yaml:"internal_ip"`
	UptimeDays  int                 `yaml:"uptime_days"`
	ProcessSeed string              `yaml:"process_seed"`
	Processes   []NodeProcess       `yaml:"processes,omitempty"`
	EnvVars     map[string]string   `yaml:"env_vars,omitempty"`
	Lures       map[string]string   `yaml:"lures,omitempty"`
	Filesystem  map[string][]string `yaml:"filesystem,omitempty"`
	Network     *NodeNetworkConfig  `yaml:"network,omitempty"`
	Listeners   []NodeListener      `yaml:"listeners,omitempty"`
}

// NodeProcess represents a single row in the process table (ps aux output).
type NodeProcess struct {
	PID  int    `yaml:"pid"`
	User string `yaml:"user"`
	CPU  string `yaml:"cpu"`
	Mem  string `yaml:"mem"`
	VSZ  string `yaml:"vsz"`
	RSS  string `yaml:"rss"`
	Cmd  string `yaml:"cmd"`
	Stat string `yaml:"stat"`
	Time string `yaml:"time"`
}

// NodeListener represents a listening socket entry (netstat/ss output).
type NodeListener struct {
	Proto   string `yaml:"proto"`
	Local   string `yaml:"local"`
	PID     int    `yaml:"pid"`
	Program string `yaml:"program"`
}

// NodeNetworkConfig holds network interface and routing configuration.
type NodeNetworkConfig struct {
	Interface string `yaml:"interface"`
	MAC       string `yaml:"mac"`
	IP        string `yaml:"ip"`
	Netmask   string `yaml:"netmask"`
	Broadcast string `yaml:"broadcast"`
	Gateway   string `yaml:"gateway"`
}

// LoadNode reads <dir>/node.yaml — the rendered single-node descriptor
// that bzb produces under persona/node.yaml and mounts at /configurations/node.yaml.
func LoadNode(dir string) (*Node, error) {
	data, err := os.ReadFile(filepath.Join(dir, "node.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read node.yaml: %w", err)
	}
	var n Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		return nil, fmt.Errorf("parse node.yaml: %w", err)
	}
	return &n, nil
}

// Persona mirrors the bzb-side schema. Carries only fields beelzebub uses
// at runtime; extra YAML fields are intentionally ignored so future schema
// additions don't break older binaries.
type Persona struct {
	SchemaVersion int              `yaml:"schema_version"`
	Slug          string           `yaml:"slug"`
	DisplayName   string           `yaml:"display_name"`
	Version       int              `yaml:"version"`
	Identity      PersonaIdentity  `yaml:"identity"`
	Coherence     PersonaCoherence `yaml:"coherence"`
	LLMSeed       string           `yaml:"llm_seed,omitempty"`
	// LureContent holds persona-specific key-value deception strings
	// (DB credentials, service accounts, internal hostnames, etc.)
	// so Go code stays deception-neutral and references values by key.
	LureContent map[string]string `yaml:"lure_content,omitempty"`
}

// Lure returns the value for the given key from LureContent, or "" if not set.
// Safe to call on a nil Persona.
func (p *Persona) Lure(key string) string {
	if p == nil || p.LureContent == nil {
		return ""
	}
	return p.LureContent[key]
}

// PersonaIdentity holds the canonical identity fields used by protocol handlers.
type PersonaIdentity struct {
	Industry       string `yaml:"industry"`
	Scale          string `yaml:"scale"`
	InternalDomain string `yaml:"internal_domain"`
	PublicDomain   string `yaml:"public_domain"`
	EmailPattern   string `yaml:"email_pattern"`
	Founded        int    `yaml:"founded,omitempty"`
	HQ             string `yaml:"hq,omitempty"`
}

// PersonaCoherence holds coherence/consistency data used across protocols.
type PersonaCoherence struct {
	HostsFileTemplate string              `yaml:"hosts_file_template"`
	SSHHistorySeeds   map[string][]string `yaml:"ssh_history_seeds,omitempty"`
	VaultAddr         string              `yaml:"vault_addr,omitempty"`
	// Timezone is the IANA timezone name (e.g. "Asia/Singapore", "UTC")
	// the persona "lives in". Drives wall-clock formatting on every emitted
	// timestamp that should be persona-coherent (Ollama modified_at,
	// service log timestamps, etc.). Empty = UTC.
	Timezone string `yaml:"timezone,omitempty"`
}

// LoadPersona reads <dir>/persona.yaml and returns the parsed struct.
// dir is typically "/configurations" (mounted into beelzebub at runtime).
func LoadPersona(dir string) (*Persona, error) {
	path := filepath.Join(dir, "persona.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read persona.yaml: %w", err)
	}
	var p Persona
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse persona.yaml: %w", err)
	}
	if p.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported schema_version: %d", p.SchemaVersion)
	}
	if p.Slug == "" {
		return nil, fmt.Errorf("persona.yaml missing required field: slug")
	}
	return &p, nil
}
