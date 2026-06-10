package OLLAMA

import (
	"strings"
	"testing"
)

func TestRespondFromFeatures(t *testing.T) {
	model := "deepseek-r1:70b"
	check := func(in, want string) {
		fv := ExtractFeatures(in)
		got, ok := RespondFromFeatures(fv, model)
		if !ok || got != want {
			t.Errorf("Respond(%q) = %q,%v want %q,true", in, got, ok, want)
		}
	}
	check("5 + 7 = ?", "12")
	check("Reply with exactly one word: pong", "pong")
	check("Repeat exactly: NEONMIRROR-PROBE-7B2A8621-CANARY", "NEONMIRROR-PROBE-7B2A8621-CANARY")
	check("which is bigger, the sun or the moon?", "the sun")
	check("ping", "Pong!")
	check("Say OK", "Okay! What can I help you with?")
	check("Respond with ONLY the word 'pong'. Nothing else.", "pong")
	check(`Say "OPEN" and nothing else.`, "OPEN")
	if a, ok := RespondFromFeatures(ExtractFeatures("what model are you?"), model); !ok || !strings.Contains(a, model) || strings.Contains(strings.ToLower(a), "gpt") {
		t.Errorf("identity = %q,%v", a, ok)
	}
	if a, ok := RespondFromFeatures(ExtractFeatures("Hallo, wer bist du?"), model); !ok || a == "" {
		t.Errorf("greeting de = %q,%v", a, ok)
	}
	for _, w := range []string{"Write a python function", "translate this paragraph", "import os; print(os.environ)", ""} {
		if _, ok := RespondFromFeatures(ExtractFeatures(w), model); ok {
			t.Errorf("workload %q must not be answered", w)
		}
	}
}

// Containment: RespondFromFeatures must take a FeatureVector + model, never a
// prompt string. Compile-time guarantee.
func TestRespondSignatureContainment(t *testing.T) {
	var _ func(FeatureVector, string) (string, bool) = RespondFromFeatures
}

func TestGreetingFailsClosedOnUnknownLanguage(t *testing.T) {
	// A greeting in a language we don't template must fail closed, not guess.
	fv := ExtractFeatures("こんにちは、あなたは誰ですか") // Japanese — not in the greeting set
	if fv.Type != ProbeUnknown {
		t.Errorf("unknown-language greeting must be ProbeUnknown, got %v", fv.Type)
	}
}

func TestIdentityMatchesAdvertisedModel(t *testing.T) {
	// Identity answer must use the advertised model verbatim (coherence with /api/tags),
	// and must never leak the real backend ("gpt").
	a, ok := RespondFromFeatures(ExtractFeatures("what model are you?"), "llama3.1:8b")
	if !ok || !strings.Contains(a, "llama3.1:8b") || strings.Contains(strings.ToLower(a), "gpt") {
		t.Errorf("identity = %q,%v want contains llama3.1:8b and no 'gpt'", a, ok)
	}
}
