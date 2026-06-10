package OLLAMA

import (
	"encoding/json"
	"math/rand"
	"net/http/httptest"
	"testing"
	"time"
)

// Adversarial timing tests. A capable LLMjacking actor fingerprints an endpoint by
// (1) timing the socket and comparing to the reported envelope, (2) probing twice to
// see the warm-up curve, (3) checking implied tok/s is plausible for the claimed
// model, (4) looking for unnaturally constant timing. These tests attack each vector.

func served(t *testing.T, s *OllamaStrategy, model, resp string, promptLen int) map[string]interface{} {
	t.Helper()
	rec := httptest.NewRecorder()
	s.writeOllamaChatNonStreaming(rec, model, resp, promptLen)
	var o map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		t.Fatalf("served body not JSON: %v", err)
	}
	return o
}
func ig(o map[string]interface{}, k string) int64 { return int64(o[k].(float64)) }

// (1) THE SOCKET-TIMING ATTACK: actual wall-clock must equal the reported
// total_duration. If we report 5s but answer in 200ms (or vice-versa), busted.
func TestWallClockMatchesReportedTotal(t *testing.T) {
	s := &OllamaStrategy{rng: rand.New(rand.NewSource(1))}
	model := "llama3.1:8b"
	s.modelLoadCold(model) // warm so the test runs in tens of ms
	start := time.Now()
	o := served(t, s, model, "Hello! How can I help?", 40)
	elapsed := time.Since(start)
	total := time.Duration(ig(o, "total_duration"))
	// we sleep exactly total_duration, so elapsed >= total and only scheduling slop over
	if elapsed < total-2*time.Millisecond {
		t.Errorf("answered FASTER (%v) than reported total_duration (%v) — socket-timing tell", elapsed, total)
	}
	if elapsed > total+300*time.Millisecond {
		t.Errorf("answered much SLOWER (%v) than reported total_duration (%v) — socket-timing tell", elapsed, total)
	}
}

// (1b) Envelope internal consistency must hold for ANY length (incl. when the cap
// bites) — total == load + prompt_eval + eval, always.
func TestEnvelopeConsistentAllLengths(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, model := range []string{"llama3.1:70b", "qwen2.5:14b", "llama3.1:8b"} {
		tp := timingForModel(model)
		for _, ec := range []int{0, 5, 200, 200000 /* forces the cap */} {
			for _, cold := range []bool{true, false} {
				env := capTotal(tp.durations(11, ec, 0, cold, rng), maxNonStreamWait)
				if env.Total != env.Load+env.PromptEval+env.Eval {
					t.Errorf("%s ec=%d cold=%v inconsistent: %+v", model, ec, cold, env)
				}
				if env.Total > maxNonStreamWait.Nanoseconds() {
					t.Errorf("%s ec=%d: total %d exceeds cap", model, ec, env.Total)
				}
				if env.Load <= 0 || env.PromptEval <= 0 || env.Eval <= 0 {
					t.Errorf("%s ec=%d cold=%v non-positive: %+v", model, ec, cold, env)
				}
			}
		}
		// capPre (streaming pre-token wait) must also fit and stay positive
		env := capPre(tp.durations(11, 5, 0, true, rng), maxPreTokenWait)
		if env.Load+env.PromptEval > maxPreTokenWait.Nanoseconds() {
			t.Errorf("%s capPre exceeds cap: %+v", model, env)
		}
	}
}

// (2) THE WARM-UP CURVE: the same model probed twice in quick succession must report
// a big cold load on the first hit and a small warm load on the second — the exact
// signature a prober uses to confirm a real backend. Tests the SERVED bytes.
func TestWarmupCurveOnServedBytes(t *testing.T) {
	s := &OllamaStrategy{rng: rand.New(rand.NewSource(3))}
	model := "llama3.1:8b" // cold load band 800-1500ms
	cold := served(t, s, model, "OK", 12)
	warm := served(t, s, model, "OK", 12)
	coldLoad, warmLoad := ig(cold, "load_duration"), ig(warm, "load_duration")
	if coldLoad < 400*1e6 {
		t.Errorf("first hit load_duration %dms too small to be a cold load", coldLoad/1e6)
	}
	if warmLoad > 100*1e6 {
		t.Errorf("second hit load_duration %dms too big — should be warm (~tens of ms)", warmLoad/1e6)
	}
	if coldLoad < warmLoad*8 {
		t.Errorf("warm-up curve flat: cold %d warm %d (a prober sees no load on first hit)", coldLoad, warmLoad)
	}
}

// (3) GEN-RATE PLAUSIBILITY: implied tok/s (eval_count / eval_duration) must be in a
// believable band for the claimed model size, and a bigger model must be SLOWER.
func TestGenRatePlausibleAndMonotonicInSize(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	rate := func(model string) float64 {
		env := timingForModel(model).durations(11, 100, 0, false, rng)
		return float64(100) / (float64(env.Eval) / 1e9) // tok/s
	}
	big, mid, small := rate("llama3.1:70b"), rate("qwen2.5-coder:32b"), rate("llama3.1:8b")
	if !(big < mid && mid < small) {
		t.Errorf("gen rate must increase as size shrinks: 70b=%.1f 32b=%.1f 8b=%.1f", big, mid, small)
	}
	// Bands for the emulated fast multi-GPU box (calibrated 2026-06-10): memory-
	// bound scaling anchors 70B ~18 tok/s, 32B ~38 tok/s, 8B ~130 tok/s.
	if big < 12 || big > 25 {
		t.Errorf("70b gen rate %.1f tok/s implausible for a fast-GPU 70B", big)
	}
	if mid < 28 || mid > 50 {
		t.Errorf("32b gen rate %.1f tok/s implausible for a fast-GPU 32B", mid)
	}
	if small < 90 || small > 170 {
		t.Errorf("8b gen rate %.1f tok/s implausible for a fast-GPU 8B", small)
	}
}

// (4) NO UNNATURALLY CONSTANT TIMING: warm load must jitter across calls (a fixed
// value every time is itself a tell), but stay within a tight plausible band.
func TestWarmLoadJittersWithinBand(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	tp := timingForModel("llama3.1:8b")
	seen := map[int64]bool{}
	for i := 0; i < 40; i++ {
		l := tp.durations(11, 10, 0, false, rng).Load
		if l < 15*1e6 || l > 55*1e6 {
			t.Errorf("warm load %dms outside plausible band", l/1e6)
		}
		seen[l] = true
	}
	if len(seen) < 5 {
		t.Errorf("warm load too constant across 40 calls (%d distinct) — a prober detects fixed timing", len(seen))
	}
}

// prompt_eval_count must reflect the actual prompt length (a prober can compare the
// prompt it sent to the count we report), and prompt_eval scales with it.
func TestPromptEvalCountAndScaling(t *testing.T) {
	s := &OllamaStrategy{rng: rand.New(rand.NewSource(11))}
	model := "llama3.1:8b"
	s.modelLoadCold(model)
	shortP := served(t, s, model, "ok", 20)  // ~6 prompt tokens
	longP := served(t, s, model, "ok", 4000) // ~1001 prompt tokens
	if ig(shortP, "prompt_eval_count") != 20/4+1 {
		t.Errorf("prompt_eval_count %d != promptLen-derived", ig(shortP, "prompt_eval_count"))
	}
	if ig(longP, "prompt_eval_duration") <= ig(shortP, "prompt_eval_duration") {
		t.Errorf("prompt_eval_duration not scaling with prompt length (the old 50ms tell)")
	}
}

func TestModelLoadColdWarmTransition(t *testing.T) {
	s := &OllamaStrategy{}
	if !s.modelLoadCold("llama3.1:70b") {
		t.Error("first use of a model must be COLD")
	}
	if s.modelLoadCold("llama3.1:70b") {
		t.Error("immediate reuse must be WARM")
	}
	if !s.modelLoadCold("mistral:7b") {
		t.Error("a different model must be COLD")
	}
}
