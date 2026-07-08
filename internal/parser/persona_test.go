package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPersona(t *testing.T) {
	dir := t.TempDir()
	personaYAML := `schema_version: 1
slug: test
display_name: "Test"
version: 1
identity:
  industry: test
  scale: small
  internal_domain: int.test.local
  public_domain: test.local
`
	if err := os.WriteFile(filepath.Join(dir, "persona.yaml"),
		[]byte(personaYAML), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPersona(dir)
	if err != nil {
		t.Fatalf("LoadPersona: %v", err)
	}
	if p.Slug != "test" {
		t.Errorf("Slug = %q, want %q", p.Slug, "test")
	}
	if p.Identity.InternalDomain != "int.test.local" {
		t.Errorf("InternalDomain = %q", p.Identity.InternalDomain)
	}
}

func TestLoadPersonaMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadPersona(dir)
	if err == nil {
		t.Error("expected error for missing persona.yaml")
	}
}

func TestLoadPersonaInvalidSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	personaYAML := `schema_version: 99
slug: test
identity:
  industry: test
  scale: small
  internal_domain: x
  public_domain: y
`
	os.WriteFile(filepath.Join(dir, "persona.yaml"), []byte(personaYAML), 0644)
	_, err := LoadPersona(dir)
	if err == nil {
		t.Error("expected error for unsupported schema_version")
	}
}

func TestPersonaLureContent(t *testing.T) {
	dir := t.TempDir()
	personaYAML := `schema_version: 1
slug: test-lure
display_name: "Test Lure"
version: 1
identity:
  industry: test
  scale: small
  internal_domain: int.test.local
  public_domain: test.local
lure_content:
  db_app_user: testapp
  db_app_password: testpass123
  canary_email_sentinel: svc-sentinel@test.local
`
	if err := os.WriteFile(filepath.Join(dir, "persona.yaml"),
		[]byte(personaYAML), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPersona(dir)
	if err != nil {
		t.Fatalf("LoadPersona: %v", err)
	}
	if p.Lure("db_app_user") != "testapp" {
		t.Errorf("Lure(db_app_user) = %q, want testapp", p.Lure("db_app_user"))
	}
	if p.Lure("db_app_password") != "testpass123" {
		t.Errorf("Lure(db_app_password) = %q", p.Lure("db_app_password"))
	}
	if p.Lure("missing_key") != "" {
		t.Errorf("Lure(missing_key) should return empty string")
	}
}

func TestPersonaLureNilSafe(t *testing.T) {
	var p *Persona
	if got := p.Lure("any_key"); got != "" {
		t.Errorf("nil Persona.Lure() = %q, want empty string", got)
	}
}
