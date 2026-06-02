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
)

// FeatureVector is the ONLY thing derived from a prompt that flows to the
// responder. It is intentionally tiny: the raw prompt never travels downstream.
type FeatureVector struct {
	Type      ProbeType
	EchoToken string
	ArithText string
	YesNoKey  string
	Language  string
	IsCanary  bool
}

const maxProbeLen = 120

var taskIntent = regexp.MustCompile(`(?i)\b(translate|write|generate|create|implement|refactor|fix|debug|analy[sz]e|summari[sz]e|classif|extract|solve|execute|run a|build a|code|captcha|exploit|payload|function|script|paragraph|domain|os\.environ|def |import |select .*from|you are a |you are an |calculate|compute)\b`)

var (
	reEcho  = regexp.MustCompile(`(?i)\b(?:reply|respond|repeat|say)\b.{0,60}?:\s*([A-Za-z0-9_\-]{1,40})\s*$`)
	reArith = regexp.MustCompile(`(\d{1,6})\s*([-+*/])\s*(\d{1,6})`)
	reIdent = regexp.MustCompile(`(?i)^((what|which) (ai )?model are you|who (built|made|created) you|what server am i talking to)\s*\??$`)
	reYesNo = regexp.MustCompile(`(?i)(sun|moon).{0,20}(bigger|larger)|(bigger|larger).{0,20}(sun|moon)`)
)

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
	{"introduce yourself", "en"},
	{"who are you", "en"},
	{"wer bist du", "de"},
	{"wie geht", "de"},
	{"qui es-tu", "fr"},
	{"quién eres", "es"},
	{"кто ты", "ru"},
	{"介绍", "zh"},
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
		low := strings.ToLower(g.word)
		if strings.HasPrefix(s, low) {
			s = s[len(low):]
			lang = g.lang
			break
		}
	}

	// 2. Strip optional self-introduction phrase.
	// Strip leading separator chars first.
	s = strings.TrimLeft(s, " ,.:!?\t，。、！？")
	for _, intro := range greetIntroPatterns {
		low := strings.ToLower(intro.pat)
		if strings.HasPrefix(s, low) {
			s = s[len(low):]
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
	if taskIntent.MatchString(p) {
		return FeatureVector{Type: ProbeUnknown}
	}
	if reIdent.MatchString(p) {
		return FeatureVector{Type: ProbeIdentity}
	}
	if m := reArith.FindStringSubmatch(p); m != nil && isArithOnly(p) {
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
	if lang, ok := classifyGreeting(p); ok {
		return FeatureVector{Type: ProbeGreeting, Language: lang}
	}
	return FeatureVector{Type: ProbeUnknown}
}

func isArithOnly(p string) bool {
	s := strings.ToLower(p)
	for _, w := range []string{"answer with only the number, nothing else:", "what is", "what's", "calculate", "compute", "nothing else", "the number", "equals", "="} {
		s = strings.ReplaceAll(s, w, "")
	}
	return regexp.MustCompile(`^[\s\d().+\-*/?]+$`).MatchString(s)
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
