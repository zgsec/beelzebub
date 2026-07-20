package plugins

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
)

// ResponseMirrorName is the Command.Plugin value that selects the batch-envelope
// mirror. See parser.MirrorConfig for the (generic) configuration and the HTTP
// strategy for the call site.
const ResponseMirrorName = "ResponseMirror"

const (
	defaultMirrorMaxDepth = 3
	defaultMirrorMaxTotal = 200
	defaultReflectMaxLen  = 64
)

// mirrorElem is one response-array entry. Field order (body, status, headers)
// is fixed by the struct so json.Marshal never reorders it; Body/Headers are
// RawMessage so a configured JSON object nests as an object rather than a
// string-escaped literal.
type mirrorElem struct {
	Body    json.RawMessage `json:"body"`
	Status  int             `json:"status"`
	Headers json.RawMessage `json:"headers"`
}

// MirrorRespond parses reqBody as the configured batch envelope and returns the
// assembled multiplexed response.
//
// Contract: ok=false means "not a batch we should mirror" (nil config,
// unparseable body, missing/!array request key, an over-limit count with no
// reject, or a hostile envelope that blows the recursion/element budget). The
// caller MUST then leave the response as the command's static handler — the
// plugin is strictly additive, worst case is the pre-mirror behavior.
//
// With Recurse set, a sub-request carrying its own nested request array is
// mirrored recursively (reproducing a route-confusion server). With a rule
// Reflect set, exactly one bounded, validated token from the matched
// sub-request is echoed into that element's body — the only attacker-influenced
// bytes emitted, always length-capped, optionally hex-decoded, and
// JSON-escaped. No sub-request body is executed; every structural byte is config.
func MirrorRespond(cfg *parser.MirrorConfig, reqBody []byte) (status int, body string, ok bool) {
	if cfg == nil {
		return 0, "", false
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(reqBody, &top); err != nil {
		return 0, "", false
	}
	arrRaw, exists := top[cfg.RequestKey]
	if !exists {
		return 0, "", false
	}
	subs, subsOK := decodeSubs(arrRaw)
	if !subsOK {
		return 0, "", false
	}

	max := cfg.MaxItems
	if max <= 0 {
		max = 25
	}
	if len(subs) > max {
		return rejectOr(cfg)
	}

	// Whole-envelope method guard (top level only): a real server validates the
	// sub-request method enum before dispatch, rejecting the ENTIRE batch.
	if len(cfg.AllowedMethods) > 0 {
		for _, s := range subs {
			if !methodAllowed(rawString(s[cfg.MethodField]), cfg.AllowedMethods) {
				return rejectOr(cfg)
			}
		}
	}

	maxDepth := cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = defaultMirrorMaxDepth
	}
	budget := cfg.MaxTotal
	if budget <= 0 {
		budget = defaultMirrorMaxTotal
	}

	arr, arrOK := mirrorArray(cfg, subs, 0, maxDepth, &budget)
	if !arrOK {
		return 0, "", false
	}
	// Manual wrap for the single dynamic key; json.Marshal adds no trailing newline.
	body = `{"` + cfg.ResponseKey + `":` + string(arr) + `}`
	return cfg.WrapStatus, body, true
}

// mirrorArray builds the response array for one level of sub-requests, recursing
// into nested envelopes when configured. Returns ok=false if the element budget
// is exhausted (hostile amplification) or an assembled element is not valid JSON.
func mirrorArray(cfg *parser.MirrorConfig, subs []map[string]json.RawMessage, depth, maxDepth int, budget *int) (json.RawMessage, bool) {
	elems := make([]mirrorElem, 0, len(subs))
	for _, s := range subs {
		*budget--
		if *budget < 0 {
			return nil, false
		}

		// Recursion: a sub-request whose body carries the request array is
		// re-dispatched (route-confusion behaviour) into a nested envelope.
		if cfg.Recurse != nil && depth < maxDepth {
			if nested, isNested := nestedSubs(s, cfg.RequestKey); isNested {
				inner, innerOK := mirrorArray(cfg, nested, depth+1, maxDepth, budget)
				if !innerOK {
					return nil, false
				}
				elems = append(elems, mirrorElem{
					Body:    json.RawMessage(`{"` + cfg.ResponseKey + `":` + string(inner) + `}`),
					Status:  cfg.Recurse.Status,
					Headers: rawHeaders(cfg.Recurse.Headers),
				})
				continue
			}
		}

		el, reflect := matchMirrorRule(cfg, rawString(s[cfg.PathField]), rawString(s[cfg.MethodField]))
		elemBody := el.Body
		if reflect != nil {
			elemBody = applyReflect(reflect, rawString(s[cfg.PathField]), elemBody)
		}
		elems = append(elems, mirrorElem{
			Body:    json.RawMessage(elemBody),
			Status:  el.Status,
			Headers: rawHeaders(el.Headers),
		})
	}
	arr, err := json.Marshal(elems)
	if err != nil {
		return nil, false
	}
	return arr, true
}

func rejectOr(cfg *parser.MirrorConfig) (int, string, bool) {
	if cfg.Reject != nil {
		return cfg.Reject.Status, cfg.Reject.Body, true
	}
	return 0, "", false
}

func rawHeaders(h string) json.RawMessage {
	if h == "" {
		return json.RawMessage("[]") // real servers use [] for the no-header case
	}
	return json.RawMessage(h)
}

// decodeSubs parses the request array as objects, tolerating scalar/garbage
// entries (they become empty maps → fall through to Default).
func decodeSubs(arrRaw json.RawMessage) ([]map[string]json.RawMessage, bool) {
	var raws []json.RawMessage
	if err := json.Unmarshal(arrRaw, &raws); err != nil {
		return nil, false
	}
	subs := make([]map[string]json.RawMessage, 0, len(raws))
	for _, r := range raws {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(r, &m); err != nil {
			m = map[string]json.RawMessage{} // non-object entry → empty
		}
		subs = append(subs, m)
	}
	return subs, true
}

// nestedSubs reports whether sub carries a body object exposing the request
// array, and returns those nested sub-requests.
func nestedSubs(sub map[string]json.RawMessage, requestKey string) ([]map[string]json.RawMessage, bool) {
	bodyRaw, ok := sub["body"]
	if !ok {
		return nil, false
	}
	var bodyObj map[string]json.RawMessage
	if err := json.Unmarshal(bodyRaw, &bodyObj); err != nil {
		return nil, false
	}
	arrRaw, ok := bodyObj[requestKey]
	if !ok {
		return nil, false
	}
	return decodeSubs(arrRaw)
}

// matchMirrorRule returns the first rule whose path regex (and optional method)
// matches, plus its Reflect spec (nil if none); else the Default element.
func matchMirrorRule(cfg *parser.MirrorConfig, path, method string) (parser.MirrorElement, *parser.MirrorReflect) {
	for i := range cfg.Rules {
		r := cfg.Rules[i]
		if r.PathRegex == nil || !r.PathRegex.MatchString(path) {
			continue
		}
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		return r.MirrorElement, r.Reflect
	}
	return cfg.Default, nil
}

// applyReflect extracts one capture group from path, bounds + optionally
// hex-decodes it, JSON-escapes it, and substitutes it for the placeholder in
// body. On any failure it substitutes an empty string, keeping body valid JSON.
func applyReflect(r *parser.MirrorReflect, path, body string) string {
	placeholder := r.Placeholder
	if placeholder == "" {
		placeholder = "${reflect}"
	}
	maxLen := r.MaxLen
	if maxLen <= 0 {
		maxLen = defaultReflectMaxLen
	}

	val := ""
	if r.FromRegex != nil {
		if m := r.FromRegex.FindStringSubmatch(path); len(m) >= 2 {
			val = m[1]
		}
	}
	if r.Decode == "hex" {
		if b, err := hex.DecodeString(val); err == nil {
			val = string(b)
		} else {
			val = "" // undecodable → reflect nothing rather than raw hex
		}
	}
	if len(val) > maxLen {
		val = val[:maxLen]
	}
	// JSON-escape for a string context: marshal, then strip the surrounding quotes.
	escaped, err := json.Marshal(val)
	inner := ""
	if err == nil && len(escaped) >= 2 {
		inner = string(escaped[1 : len(escaped)-1])
	}
	return strings.ReplaceAll(body, placeholder, inner)
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func methodAllowed(method string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, method) {
			return true
		}
	}
	return false
}

// evalLiteralBool decides whether a SQL boolean condition is a CONSTANT literal
// and, if so, its truth value. cond must already be URL-decoded. It is the
// fidelity boundary of the time-based oracle: we only ever answer a question
// whose both operands are constants (int or single-quoted string), so the lure
// never evaluates anything referencing real data. Anything else — identifier,
// function, subquery, AND/OR, arithmetic, mixed types, parse ambiguity — yields
// isLiteral=false (fail closed → flat response).
func evalLiteralBool(cond string) (val bool, isLiteral bool) {
	s := strings.TrimSpace(cond)
	// strip exactly one layer of wrapping parens: "(1=1)" -> "1=1"
	if len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	// bare boolean
	switch strings.ToLower(s) {
	case "true", "1":
		return true, true
	case "false", "0":
		return false, true
	}
	// comparison: find operator (longest first)
	ops := []string{"<=", ">=", "<>", "!=", "=", "<", ">"}
	for _, op := range ops {
		i := strings.Index(s, op)
		if i <= 0 || i+len(op) >= len(s) {
			continue
		}
		lhs := strings.TrimSpace(s[:i])
		rhs := strings.TrimSpace(s[i+len(op):])
		// reject if rhs itself starts another operator char (e.g. "<=" seen as "<")
		if strings.ContainsAny(rhs[:1], "=<>!") {
			return false, false
		}
		li, lok := asInt(lhs)
		ri, rok := asInt(rhs)
		if lok && rok {
			return cmpInt(li, ri, op), true
		}
		ls, lsok := asStr(lhs)
		rs, rsok := asStr(rhs)
		if lsok && rsok {
			switch op {
			case "=":
				return ls == rs, true
			case "<>", "!=":
				return ls != rs, true
			default:
				return false, false // string ordering not supported
			}
		}
		return false, false // mixed types or a non-literal operand
	}
	return false, false
}

func asInt(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}

func asStr(s string) (string, bool) {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' && strings.Count(s, "'") == 2 {
		return s[1 : len(s)-1], true
	}
	return "", false
}

func cmpInt(a, b int, op string) bool {
	switch op {
	case "=":
		return a == b
	case "<>", "!=":
		return a != b
	case "<":
		return a < b
	case ">":
		return a > b
	case "<=":
		return a <= b
	case ">=":
		return a >= b
	}
	return false
}
