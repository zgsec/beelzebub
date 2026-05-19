package builder

import (
	"testing"

	"github.com/mariocandela/beelzebub/v3/parser"
)

func TestBuilderHoldsPersona(t *testing.T) {
	b := &Builder{}
	p := &parser.Persona{Slug: "test", Identity: parser.PersonaIdentity{InternalDomain: "x"}}
	b.SetPersona(p)
	if b.Persona() == nil {
		t.Fatal("Persona() returned nil after SetPersona")
	}
	if b.Persona().Slug != "test" {
		t.Errorf("Persona().Slug = %q, want test", b.Persona().Slug)
	}
}

func TestBuilderPersonaPropagatesToBuild(t *testing.T) {
	b := &Builder{}
	p := &parser.Persona{Slug: "built-test", Identity: parser.PersonaIdentity{InternalDomain: "int.built.test"}}
	b.SetPersona(p)
	built := b.build()
	if built.Persona() == nil {
		t.Fatal("build() did not propagate persona")
	}
	if built.Persona().Slug != "built-test" {
		t.Errorf("built.Persona().Slug = %q, want built-test", built.Persona().Slug)
	}
}

func TestBuilderNilPersonaIsAllowed(t *testing.T) {
	b := &Builder{}
	if b.Persona() != nil {
		t.Error("fresh Builder should have nil Persona()")
	}
}
