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
