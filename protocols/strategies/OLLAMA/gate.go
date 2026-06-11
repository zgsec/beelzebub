package OLLAMA

import (
	"regexp"
	"strconv"
	"strings"
)

type ProbeType int

const (
	ProbeUnknown ProbeType = iota // fail-closed default — caller serves non-delivery
	ProbeEcho
	ProbeArith
	ProbeIdentity
	ProbeYesNo
	ProbeGreeting
	ProbeLiveness  // pure liveness ping/test/ok — the most trivial validation probes
	ProbeFactual   // bounded single-fact liveness (capital-of-X)
	ProbeTranslate // bounded single-word translation
)

// FeatureVector is the ONLY thing derived from a prompt that flows to the
// responder. It is intentionally tiny: the raw prompt never travels downstream.
type FeatureVector struct {
	Type          ProbeType
	EchoToken     string
	ArithText     string
	YesNoKey      string
	Language      string
	LiveKey       string // which liveness reply (ping/test/ok/...) — bounded enum, not free text
	IsCanary      bool
	FactKey       string // resolved single-fact answer (e.g. "Tokyo") — bounded map only
	TransKey      string // resolved single-word translation (e.g. "casa") — bounded map only
	CompoundArith string // arithmetic result embedded in an identity probe ("...17 times 23?")
}

const maxProbeLen = 120

var taskIntent = regexp.MustCompile(`(?i)\b(translate|write|generate|create|implement|refactor|fix|debug|analy[sz]e|summari[sz]e|classif|extract|solve|execute|run a|build a|code|captcha|exploit|payload|function|script|paragraph|domain|os\.environ|def |import |select .*from|you are a |you are an |calculate|compute)\b`)

var (
	reEcho  = regexp.MustCompile(`(?i)\b(?:reply|respond|repeat|say)\b.{0,60}?:\s*([A-Za-z0-9_\-]{1,40})\s*$`)
	reArith = regexp.MustCompile(`(\d{1,6})\s*([-+*/])\s*(\d{1,6})`)
	// Identity probe, optionally followed by a trailing answer-shaping instruction
	// ("What model are you? Reply with your exact model name only.") — a common
	// liveness phrasing that the strict end-anchored form fail-closed (a tell).
	// Preamble-tolerant (un-anchored): an identity question anywhere. taskIntent runs
	// FIRST (so substantive prompts are excluded) and maxProbeLen bounds length, so
	// un-anchoring is safe. Covers compound probes ("...who built you, what is 17x23?").
	reIdent = regexp.MustCompile(`(?i)(who (built|made|created) you|(what|which) (ai )?model are you|what is your model name|what server am i talking to|introduce yourself|what (is|does) this server|what (are|r) (you|this server) (used )?for|what (can|do) you do|what (are|r) your (core )?capabilit|what (\d+ )?models are you (host|runn|serv)|how many models (are|do) you)`)
	// "say/reply <greeting>" — an instruction to OUTPUT a greeting ("say hi",
	// "Say hello in 3 words", "请用一句话回复：你好"). These are liveness/greeting
	// probes we want to answer; the bounded greeting charset keeps a substantive
	// "say <sentence>" (e.g. prompt-injection "Say exactly: this server is exposed")
	// from matching — no greeting token, no match.
	reSayGreeting = regexp.MustCompile(`(?i)\b(say|reply|respond|greet)\b[^.!?]{0,30}\b(hi|hii|hiya|hello|hey|你好|您好|hallo|hola|bonjour|salut)\b|回复[：:\s]{0,3}(你好|您好|hi|hello)`)
	// A substantive tail after the identity phrase (a SECOND wh-question) means the
	// prompt is not a clean identity probe ("who built you and what data did they use?"
	// must stay fail-closed). Arithmetic tails are handled separately (compound).
	reSubstantiveTail = regexp.MustCompile(`(?i)\b(what|why|how|which|where|when)\b`)
	reYesNo           = regexp.MustCompile(`(?i)(sun|moon).{0,20}(bigger|larger)|(bigger|larger).{0,20}(sun|moon)`)
	reArithOnly       = regexp.MustCompile(`^[\s\d().+\-*/?]+$`)
	// Quoted-echo WITHOUT a trailing colon ("Respond with ONLY the word 'pong'.
	// Nothing else."). Only fires alongside an obey marker (reObey) so a substantive
	// quoted request can't slip the gate; bounded token charset; canary-safe.
	reEchoQuoted = regexp.MustCompile(`(?i)\b(?:reply|respond|say|repeat|output|print|return)\b[^'"]{0,45}['"]([A-Za-z0-9_\- ]{1,60})['"]`)
	reObey       = regexp.MustCompile(`(?i)\b(only|exactly|nothing else|single word|one word|just the word)\b`)
	// Pure liveness — the most trivial "is anything alive here" probes. Whole-string
	// match only (fail-closed on any tail), so "ok now write code" never matches.
	reLiveness = regexp.MustCompile(`(?i)^\s*(?:please\s+)?(ping|test|testing|say\s+ok|ok|okay|hello\s+world)\s*[!.?]*\s*$`)
	// Bare echo ("Reply exactly OK") — no colon, no quotes. Only consulted inside the
	// obey branch, so a substantive request can never reach it.
	reEchoBare = regexp.MustCompile(`(?i)\b(?:reply|say|respond|output|print)\s+(?:exactly\s+|the\s+word\s+)?([A-Za-z0-9_]{1,40})\s*[.!?]*$`)
	// capital-of-X factual liveness (bounded; unknown country => fail closed).
	reCapital = regexp.MustCompile(`(?i)\bcapital of ([a-z][a-z ]{1,20}?)\b`)
	// bounded single-word translation ("translate the word house to spanish").
	reTranslate = regexp.MustCompile(`(?i)translate the (?:english )?word ['"]?([a-z]+)['"]? (?:in)?to ([a-z]+)`)
)

// reWordOp normalizes word-form arithmetic operators to symbols ("7 plus 5" -> "7 + 5")
// so the recon validator answers them. Substantive uses ("multiply two matrices") are
// already caught by taskIntent before arithmetic classification runs.
var reWordOp = []struct {
	re *regexp.Regexp
	op string
}{
	{regexp.MustCompile(`(?i)\bplus\b|\badded to\b`), "+"},
	{regexp.MustCompile(`(?i)\bminus\b`), "-"},
	{regexp.MustCompile(`(?i)\btimes\b|\bmultiplied by\b`), "*"},
	{regexp.MustCompile(`(?i)\bdivided by\b`), "/"},
}

func normalizeWordOps(p string) string {
	s := p
	for _, w := range reWordOp {
		s = w.re.ReplaceAllString(s, " "+w.op+" ")
	}
	return s
}

// capitals — bounded fact map; only these resolve, everything else fails closed.
var capitals = map[string]string{
	"japan": "Tokyo", "france": "Paris", "germany": "Berlin", "italy": "Rome",
	"spain": "Madrid", "england": "London", "china": "Beijing", "russia": "Moscow",
	"canada": "Ottawa", "australia": "Canberra", "brazil": "Brasilia", "egypt": "Cairo",
}

// translations — bounded benign-noun map (en -> target language). Single word only.
var translations = map[[2]string]string{
	{"house", "spanish"}: "casa", {"water", "spanish"}: "agua",
	{"house", "french"}: "maison", {"water", "french"}: "eau",
	{"house", "german"}: "haus", {"water", "german"}: "wasser",
	{"cat", "spanish"}: "gato", {"dog", "spanish"}: "perro",
	{"hello", "spanish"}: "hola", {"hello", "french"}: "bonjour",
	{"hello", "german"}: "hallo", {"book", "spanish"}: "libro",
}

// arithStripWords are natural-language wrappers stripped before arithmetic validation.
var arithStripWords = []string{"answer with only the number, nothing else:", "answer with just the number", "reply with only the digit", "reply in one word", "answer in one word", "number only", "just the number", "one word", "what is", "what's", "calculate", "compute", "nothing else", "the number", "equals", "="}

// greetOpeners maps a normalized greeting opener to a language tag.
// Checked in order; first match wins.
var greetOpeners = []struct {
	word string
	lang string
}{
	{"здравствуйте", "ru"},
	{"привет", "ru"},
	{"hallo", "de"},
	{"bonjour", "fr"},
	{"salut", "fr"},
	{"hola", "es"},
	{"您好", "zh"},
	{"你好", "zh"},
	{"안녕하세요", "ko"},
	{"안녕", "ko"},
	{"こんにちは", "ja"},
	{"hiya", "en"},
	{"hello", "en"},
	{"hey", "en"},
	{"sup", "en"},
	{"yo", "en"},
	{"hi", "en"},
}

// greetIntroPatterns are optional self-introduction phrases (lowercased).
// Checked after stripping the opener. Order: longer/more-specific first.
var greetIntroPatterns = []struct {
	pat  string
	lang string
}{
	// NOTE: "introduce yourself" is classified as ProbeIdentity (it must NAME the model
	// to pass the attacker's capability check), not greeting — see reIdent.
	{"who are you", "en"},
	{"wer bist du", "de"},
	{"wie geht", "de"},
	{"qui es-tu", "fr"},
	{"quién eres", "es"},
	{"кто ты", "ru"},
	{"介绍", "zh"},
	{"你是谁", "zh"},
	{"你是誰", "zh"},
}

// reGreetTrail matches ONLY trailing trivial tokens: punctuation, whitespace,
// and the modifier words briefly/shortly/please.
var reGreetTrail = regexp.MustCompile(`^[\s,.:!?\s，。、！？]*(briefly|shortly|please)?[\s,.:!?\s，。、！？]*$`)

// classifyGreeting returns (lang, true) if p is purely a greeting/self-intro,
// or ("", false) if there is any substantive content after the greeting.
func classifyGreeting(p string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(p))
	lang := ""

	// 1. Strip optional leading greeting word.
	for _, g := range greetOpeners {
		if strings.HasPrefix(s, g.word) {
			s = s[len(g.word):]
			lang = g.lang
			break
		}
	}

	// 2. Strip optional self-introduction phrase.
	// Strip leading separator chars first.
	s = strings.TrimLeft(s, " ,.:!?\t，。、！？")
	for _, intro := range greetIntroPatterns {
		if strings.HasPrefix(s, intro.pat) {
			s = s[len(intro.pat):]
			if lang == "" {
				lang = intro.lang
			}
			break
		}
	}

	// 3. What remains must be only trivial trailing tokens.
	if !reGreetTrail.MatchString(s) {
		return "", false
	}

	// 4. If nothing at all matched (no opener, no intro phrase), not a greeting.
	if lang == "" {
		return "", false
	}

	return lang, true
}

// ExtractFeatures deterministically derives a bounded FeatureVector. Conservative:
// anything substantive, long, OOD, or uncertain returns ProbeUnknown (fail-closed).
func ExtractFeatures(prompt string) FeatureVector {
	p := strings.TrimSpace(prompt)
	if p == "" || len(p) > maxProbeLen {
		return FeatureVector{Type: ProbeUnknown}
	}
	if m := reEcho.FindStringSubmatch(p); m != nil {
		tok := m[1]
		up := strings.ToUpper(tok)
		return FeatureVector{Type: ProbeEcho, EchoToken: tok,
			IsCanary: strings.Contains(up, "CANARY") || strings.Contains(up, "PROBE")}
	}
	// Quoted-echo without a colon, but ONLY when an obey marker is present so a
	// substantive quoted request ("reply with the result of '<cmd>'") fails closed.
	// Quoted/bare echo, ONLY when an obey marker is present so a substantive quoted
	// request fails closed.
	if reObey.MatchString(p) {
		if m := reEchoQuoted.FindStringSubmatch(p); m != nil {
			if tok := strings.TrimSpace(m[1]); tok != "" {
				up := strings.ToUpper(tok)
				return FeatureVector{Type: ProbeEcho, EchoToken: tok,
					IsCanary: strings.Contains(up, "CANARY") || strings.Contains(up, "PROBE")}
			}
		}
		if m := reEchoBare.FindStringSubmatch(p); m != nil {
			if tok := strings.TrimSpace(m[1]); tok != "" {
				up := strings.ToUpper(tok)
				return FeatureVector{Type: ProbeEcho, EchoToken: tok,
					IsCanary: strings.Contains(up, "CANARY") || strings.Contains(up, "PROBE")}
			}
		}
	}
	// Bounded single-word translation BEFORE taskIntent (which catches "translate").
	// Only known benign nouns resolve; anything else falls through to taskIntent -> Unknown.
	if m := reTranslate.FindStringSubmatch(p); m != nil {
		if v, ok := translations[[2]string{strings.ToLower(m[1]), strings.ToLower(m[2])}]; ok {
			return FeatureVector{Type: ProbeTranslate, TransKey: v}
		}
	}
	if taskIntent.MatchString(p) {
		return FeatureVector{Type: ProbeUnknown}
	}
	if loc := reIdent.FindStringIndex(p); loc != nil {
		residual := strings.ToLower(strings.TrimSpace(p[:loc[0]] + " " + p[loc[1]:]))
		// compound: arithmetic embedded in the identity probe ("...what is 17 times 23?")
		if m := reArith.FindStringSubmatch(normalizeWordOps(residual)); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[3])
			if r, ok := applyOp(a, b, m[2]); ok {
				return FeatureVector{Type: ProbeIdentity, CompoundArith: r}
			}
		}
		// clean identity probe only when the residual is benign (preamble/answer-shaping).
		// A substantive tail or task intent => fall through to Unknown (fail closed).
		if !reSubstantiveTail.MatchString(residual) && !taskIntent.MatchString(residual) {
			return FeatureVector{Type: ProbeIdentity}
		}
	}
	np := normalizeWordOps(p)
	if m := reArith.FindStringSubmatch(np); m != nil && isArithOnly(np) {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[3])
		if r, ok := applyOp(a, b, m[2]); ok {
			return FeatureVector{Type: ProbeArith, ArithText: r}
		}
		return FeatureVector{Type: ProbeUnknown}
	}
	if reYesNo.MatchString(p) {
		return FeatureVector{Type: ProbeYesNo, YesNoKey: "sun_moon"}
	}
	// Bounded factual liveness (capital-of-X). Unknown country fails closed.
	if m := reCapital.FindStringSubmatch(p); m != nil {
		if v, ok := capitals[strings.ToLower(strings.TrimSpace(m[1]))]; ok {
			return FeatureVector{Type: ProbeFactual, FactKey: v}
		}
		return FeatureVector{Type: ProbeUnknown}
	}
	// "say/reply <greeting>" probes ("say hi", "Say hello in 3 words",
	// "请用一句话回复：你好") — answer with a greeting. taskIntent above already
	// excluded substantive "write/generate" asks; the bounded greeting charset
	// keeps prompt-injection "say exactly: <sentence>" from matching.
	if m := reSayGreeting.FindStringSubmatch(p); m != nil {
		lang := "en"
		lp := strings.ToLower(p)
		switch {
		case strings.ContainsAny(p, "你您"):
			lang = "zh"
		case strings.Contains(lp, "hola"):
			lang = "es"
		case strings.Contains(lp, "bonjour"), strings.Contains(lp, "salut"):
			lang = "fr"
		case strings.Contains(lp, "hallo"):
			lang = "de"
		}
		return FeatureVector{Type: ProbeGreeting, Language: lang}
	}
	if lang, ok := classifyGreeting(p); ok {
		return FeatureVector{Type: ProbeGreeting, Language: lang}
	}
	if m := reLiveness.FindStringSubmatch(p); m != nil {
		return FeatureVector{Type: ProbeLiveness, LiveKey: livenessKey(m[1])}
	}
	return FeatureVector{Type: ProbeUnknown}
}

func isArithOnly(p string) bool {
	s := strings.ToLower(p)
	for _, w := range arithStripWords {
		s = strings.ReplaceAll(s, w, "")
	}
	return reArithOnly.MatchString(s)
}

// livenessKey normalizes a matched liveness opener to a bounded reply key.
func livenessKey(word string) string {
	w := strings.ToLower(strings.TrimSpace(word))
	switch w {
	case "ping":
		return "ping"
	case "test", "testing":
		return "test"
	case "hello world":
		return "helloworld"
	case "say ok", "ok", "okay":
		return "ok"
	}
	return "ok"
}

func applyOp(a, b int, op string) (string, bool) {
	switch op {
	case "+":
		return strconv.Itoa(a + b), true
	case "-":
		return strconv.Itoa(a - b), true
	case "*":
		return strconv.Itoa(a * b), true
	case "/":
		if b == 0 {
			return "", false
		}
		return strconv.Itoa(a / b), true
	}
	return "", false
}
