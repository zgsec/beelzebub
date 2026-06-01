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

var taskIntent = regexp.MustCompile(`(?i)\b(translate|write|generate|create|implement|refactor|fix|debug|analy[sz]e|summari[sz]e|classif|extract|solve|execute|run a|build a|code|captcha|exploit|payload|function|script|paragraph|domain|os\.environ|def |import |select .*from|you are a |you are an )\b`)

var (
	reEcho  = regexp.MustCompile(`(?i)\b(?:reply|respond|repeat|say)\b.{0,60}?:\s*([A-Za-z0-9_\-]{1,40})\s*$`)
	reArith = regexp.MustCompile(`(\d{1,6})\s*([-+*/])\s*(\d{1,6})`)
	reIdent = regexp.MustCompile(`(?i)^(what|which) (ai )?model are you\b|who (built|made|created) you|what server am i talking to|your (exact )?model name`)
	reYesNo = regexp.MustCompile(`(?i)(sun|moon).{0,20}(bigger|larger)|(bigger|larger).{0,20}(sun|moon)`)
)

var greetLang = []struct {
	re   *regexp.Regexp
	lang string
}{
	{regexp.MustCompile(`(?i)^(hallo|wer bist du|wie geht)`), "de"},
	{regexp.MustCompile(`(?i)^(bonjour|salut|qui es)`), "fr"},
	{regexp.MustCompile(`(?i)^(hola|quién eres)`), "es"},
	{regexp.MustCompile(`(?i)^(привет|здравствуй)`), "ru"},
	{regexp.MustCompile(`你好|您好|介绍`), "zh"},
	{regexp.MustCompile(`(?i)^(hi|hello|hey|yo|sup|introduce yourself)`), "en"},
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
	for _, g := range greetLang {
		if g.re.MatchString(p) {
			return FeatureVector{Type: ProbeGreeting, Language: g.lang}
		}
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
