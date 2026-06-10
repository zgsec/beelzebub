package OLLAMA

// greetings: per-language canned lines. An unrecognized language never reaches
// here (ExtractFeatures fails closed), so there is no wrong-language guess.
var greetings = map[string]string{
	"en": "Hello! How can I help?",
	"de": "Hallo! Wie kann ich helfen?",
	"fr": "Bonjour ! Comment puis-je aider ?",
	"es": "¡Hola! ¿En qué puedo ayudar?",
	"ru": "Привет! Чем могу помочь?",
	"zh": "你好！有什么可以帮你的？",
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
		return "I am " + advertisedModel + ".", true
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
