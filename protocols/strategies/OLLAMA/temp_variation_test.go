package OLLAMA

import (
	"math/rand"
	"strings"
	"testing"
)

// Temperature-determinism is a statistical tell: a canned reply that is byte-identical
// at temperature>0 (no seed) outs us, but a constrained reply that VARIES also outs us.
// These tests pin Ollama's real contract exactly.

func newStrat() *OllamaStrategy { return &OllamaStrategy{rng: rand.New(rand.NewSource(1))} }

func f64(v float64) *float64 { return &v }
func iptr(v int) *int        { return &v }

// (A) PEDANTIC: a CONSTRAINED reply (echo / arith / yes-no) must NOT vary, even at
// temperature 2.0 — a real model is deterministic on a forced completion, so variation
// here would itself be a tell. This is the test a naive "randomize output" impl fails.
func TestConstrainedRepliesNeverVary(t *testing.T) {
	s := newStrat()
	cases := []struct {
		fv        FeatureVector
		canonical string
	}{
		{FeatureVector{Type: ProbeEcho, EchoToken: "pong"}, "pong"},
		{FeatureVector{Type: ProbeArith, ArithText: "2"}, "2"},
		{FeatureVector{Type: ProbeYesNo, YesNoKey: "sun_moon"}, "the sun"},
	}
	for _, c := range cases {
		for _, temp := range []float64{0, 0.8, 1.5, 2.0} {
			for i := 0; i < 20; i++ {
				if got := s.varyReply(c.fv, "llama3.1:8b", c.canonical, temp, nil); got != c.canonical {
					t.Errorf("constrained %v at temp=%.1f varied: %q != %q", c.fv.Type, temp, got, c.canonical)
				}
			}
		}
	}
}

// (B) temperature ~0 (greedy) is deterministic regardless of seed — always canonical.
func TestGreedyTempIsDeterministic(t *testing.T) {
	s := newStrat()
	fv := FeatureVector{Type: ProbeGreeting, Language: "en"}
	want := greetingVariants["en"][0]
	for i := 0; i < 20; i++ {
		if got := s.varyReply(fv, "m", want, 0.0, nil); got != want {
			t.Errorf("temp~0 must be canonical/deterministic: got %q want %q", got, want)
		}
		if got := s.varyReply(fv, "m", want, 0.0, iptr(99)); got != want {
			t.Errorf("temp~0 with seed must still be canonical: got %q", got)
		}
	}
}

// (C) temperature>0 + a fixed SEED is reproducible (same seed -> same output), as real
// Ollama guarantees. A prober who re-sends with the same seed expects identical output.
func TestSeededTempIsReproducible(t *testing.T) {
	s := newStrat()
	fv := FeatureVector{Type: ProbeGreeting, Language: "en"}
	first := s.varyReply(fv, "m", "", 1.5, iptr(42))
	for i := 0; i < 20; i++ {
		if got := s.varyReply(fv, "m", "", 1.5, iptr(42)); got != first {
			t.Errorf("same seed must reproduce: %q != %q", got, first)
		}
	}
}

// (D) temperature>0 + NO seed must VARY across calls (the actual tell we're killing),
// and every variant must come from the plausible pool (no garbage).
func TestUnseededTempVaries(t *testing.T) {
	s := newStrat()
	fv := FeatureVector{Type: ProbeGreeting, Language: "en"}
	pool := greetingVariants["en"]
	seen := map[string]bool{}
	for i := 0; i < 60; i++ {
		got := s.varyReply(fv, "m", pool[0], 1.5, nil)
		inPool := false
		for _, p := range pool {
			if got == p {
				inPool = true
			}
		}
		if !inPool {
			t.Errorf("variant %q not in the plausible pool", got)
		}
		seen[got] = true
	}
	if len(seen) < 2 {
		t.Errorf("temp>0 no-seed produced only %d distinct greeting(s) over 60 calls — still a determinism tell", len(seen))
	}
}

// (E) identity variation must still NAME the advertised model and never leak the backend.
func TestIdentityVariationNamesModelNoLeak(t *testing.T) {
	s := newStrat()
	fv := FeatureVector{Type: ProbeIdentity}
	for i := 0; i < 30; i++ {
		got := s.varyReply(fv, "deepseek-r1:70b", "", 1.5, nil)
		if !strings.Contains(got, "deepseek-r1:70b") {
			t.Errorf("identity variant dropped the model name: %q", got)
		}
		if strings.Contains(strings.ToLower(got), "gpt") || strings.Contains(strings.ToLower(got), "openai") {
			t.Errorf("identity variant leaked the backend: %q", got)
		}
	}
}
