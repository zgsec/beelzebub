package OLLAMA

import (
	"fmt"
	"hash/fnv"
	"math/rand"
)

// greetings: per-language canned lines. An unrecognized language never reaches
// here (ExtractFeatures fails closed), so there is no wrong-language guess.
var greetings = map[string]string{
	"en": "Hello! How can I help?",
	"de": "Hallo! Wie kann ich helfen?",
	"fr": "Bonjour ! Comment puis-je aider ?",
	"es": "¡Hola! ¿En qué puedo ayudar?",
	"ru": "Привет! Чем могу помочь?",
	"zh": "你好！有什么可以帮你的？",
	"ko": "안녕하세요! 무엇을 도와드릴까요?",
	"ja": "こんにちは！何かお手伝いできることはありますか？",
}

var yesNoAnswers = map[string]string{
	"sun_moon": "the sun",
}

// livenessReplies: per-key canned lines for the most trivial validation probes.
// Kept short and in the same terse-professional register as the greetings, so the
// whole lure reads as one coherent assistant rather than one model per probe.
var livenessReplies = map[string]string{
	"ping":       "Pong!",
	"test":       "I'm up and running. What can I help you with?",
	"ok":         "Okay! What can I help you with?",
	"helloworld": "Hello! How can I help?",
}

// RespondFromFeatures emits a contained answer derived ONLY from the bounded
// feature vector. It takes no prompt and reaches no model. ProbeUnknown (and any
// unfilled field) returns ("", false) so the caller serves coherent non-delivery.
func RespondFromFeatures(fv FeatureVector, advertisedModel string) (string, bool) {
	switch fv.Type {
	case ProbeEcho:
		if fv.EchoToken != "" {
			return fv.EchoToken, true
		}
	case ProbeArith:
		if fv.ArithText != "" {
			return fv.ArithText, true
		}
	case ProbeIdentity:
		if fv.CompoundArith != "" {
			return fmt.Sprintf("I'm %s, a Llama-family assistant, and the answer is %s.", advertisedModel, fv.CompoundArith), true
		}
		return fmt.Sprintf(identityVariants[0], advertisedModel), true
	case ProbeFactual:
		if fv.FactKey != "" {
			return fv.FactKey, true
		}
	case ProbeTranslate:
		if fv.TransKey != "" {
			return fv.TransKey, true
		}
	case ProbeYesNo:
		if a, ok := yesNoAnswers[fv.YesNoKey]; ok {
			return a, true
		}
	case ProbeGreeting:
		if g, ok := greetings[fv.Language]; ok {
			return g, true
		}
	case ProbeLiveness:
		if g, ok := livenessReplies[fv.LiveKey]; ok {
			return g, true
		}
	}
	return "", false
}

// --- temperature-faithful surface variation ---------------------------------
// Real models VARY their wording across identical requests when temperature>0 and
// no seed is fixed; they are deterministic at temperature~0 OR when a seed is set.
// A canned reply that is byte-identical every time is a statistical tell. We emulate
// the real contract — but ONLY for UNCONSTRAINED replies. A constrained probe
// ("reply ONLY pong", "1+1=?", "yes/no") is deterministic on a real model too, so
// varying it would itself be a tell; those keep RespondFromFeatures' exact output.
//
// Index 0 of each pool is the canonical reply (back-compat with existing tests and
// with the temperature~0 / greedy path).
var greetingVariants = map[string][]string{
	"en": {"Hello! How can I help?", "Hi there! How can I help you today?", "Hey! What can I do for you?", "Hello! What would you like to know?"},
	"de": {"Hallo! Wie kann ich helfen?", "Hallo! Womit kann ich dir helfen?", "Hi! Wie kann ich behilflich sein?"},
	"fr": {"Bonjour ! Comment puis-je aider ?", "Salut ! Que puis-je faire pour vous ?", "Bonjour ! En quoi puis-je vous aider ?"},
	"es": {"¡Hola! ¿En qué puedo ayudar?", "¡Hola! ¿En qué puedo ayudarte hoy?", "¡Hola! ¿Qué necesitas?"},
	"ru": {"Привет! Чем могу помочь?", "Здравствуйте! Чем могу быть полезен?", "Привет! Чем помочь?"},
	"zh": {"你好！有什么可以帮你的？", "你好！我能帮你做些什么？", "你好呀！有什么需要帮忙的吗？"},
	"ko": {"안녕하세요! 무엇을 도와드릴까요?", "안녕하세요! 무엇을 도와드릴까요?", "안녕하세요! 어떻게 도와드릴까요?"},
	"ja": {"こんにちは！何かお手伝いできることはありますか？", "こんにちは！どのようなご用件でしょうか？", "こんにちは！何かお手伝いしましょうか？"},
}
var livenessVariants = map[string][]string{
	"ping":       {"Pong!", "Pong! How can I help?", "pong"},
	"test":       {"I'm up and running. What can I help you with?", "Looks like a test — I'm here. How can I help?", "Test received. What can I do for you?"},
	"ok":         {"Okay! What can I help you with?", "Got it. What would you like to do?", "OK — how can I help?"},
	"helloworld": {"Hello! How can I help?", "Hello World! How can I assist you today?", "Hi! How can I help?"},
}
// Index 0 (the canonical/greedy reply) MUST carry a recognizable model-name token
// ("assistant"/"Llama") so it passes the attacker's capability check (grade_capability).
// The catalog's custom models are llama3.1-based (parent_model on /api/show), so this is
// coherent.
var identityVariants = []string{
	"I'm %s, an assistant based on Llama 3.1. How can I help?",
	"You're talking to %s, a Llama-family assistant. What can I do for you?",
	"I am %s, a fine-tuned Llama assistant. How can I help today?",
}

func fnvIndex(s string, n int) int {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int(h.Sum64() % uint64(n))
}

// pickVariant reproduces Ollama's determinism contract: greedy at temp~0 (canonical);
// deterministic-by-seed when a seed is set; otherwise sampled per call.
func pickVariant(pool []string, temp float64, seed *int, key string, rng *rand.Rand) string {
	if len(pool) == 0 {
		return ""
	}
	if temp <= 0.01 {
		return pool[0] // greedy decoding — deterministic regardless of seed
	}
	if seed != nil {
		return pool[fnvIndex(fmt.Sprintf("%d|%s|%.3f", *seed, key, temp), len(pool))]
	}
	return pool[rng.Intn(len(pool))]
}

// varyReply applies temperature-faithful variation to an UNCONSTRAINED reply, leaving
// constrained replies (echo/arith/yes-no) exactly as produced. temp is the effective
// temperature (caller supplies Ollama's 0.8 default when the request omits it).
func (s *OllamaStrategy) varyReply(fv FeatureVector, model, canonical string, temp float64, seed *int) string {
	s.rngMu.Lock()
	defer s.rngMu.Unlock()
	switch fv.Type {
	case ProbeGreeting:
		if v := pickVariant(greetingVariants[fv.Language], temp, seed, "g:"+fv.Language, s.rng); v != "" {
			return v
		}
	case ProbeLiveness:
		if v := pickVariant(livenessVariants[fv.LiveKey], temp, seed, "l:"+fv.LiveKey, s.rng); v != "" {
			return v
		}
	case ProbeIdentity:
		if fv.CompoundArith != "" {
			return fmt.Sprintf("I'm %s, a Llama-family assistant, and the answer is %s.", model, fv.CompoundArith)
		}
		return fmt.Sprintf(pickVariant(identityVariants, temp, seed, "i", s.rng), model)
	}
	return canonical // constrained types stay deterministic — correct even at high temp
}

// effectiveTemp returns the request temperature, defaulting to Ollama's 0.8 when the
// client omits it (so the default path VARIES, as real Ollama does).
func effectiveTemp(t *float64) float64 {
	if t == nil {
		return 0.8
	}
	return *t
}

// firstTemp / firstSeed resolve temperature/seed from either the Ollama-native
// options object or the OpenAI-style top-level field, whichever the client sent.
func firstTemp(opt, top *float64) float64 {
	if opt != nil {
		return *opt
	}
	return effectiveTemp(top)
}
func firstSeed(opt, top *int) *int {
	if opt != nil {
		return opt
	}
	return top
}
