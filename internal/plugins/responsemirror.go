package plugins

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
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
//
// sess is the (nil-safe) fiction-DB chain session for this source key. nil
// means "no fiction" — the boolean/forge path falls back to exactly the
// shipped evalLiteralBool/booleanElement behaviour, so every existing caller
// that passes nil sees byte-identical output. A non-nil sess additionally lets
// forgeElement answer a recognized blind-read predicate (recognizeBlindRead +
// evalBlindPredicate) when the condition isn't a literal constant.
func MirrorRespond(cfg *parser.MirrorConfig, reqBody []byte, sess *chainSession) (status int, body string, ok bool) {
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

	arr, arrOK := mirrorArray(cfg, subs, 0, maxDepth, &budget, sess)
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
func mirrorArray(cfg *parser.MirrorConfig, subs []map[string]json.RawMessage, depth, maxDepth int, budget *int, sess *chainSession) (json.RawMessage, bool) {
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
				inner, innerOK := mirrorArray(cfg, nested, depth+1, maxDepth, budget, sess)
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

		path := rawString(s[cfg.PathField])

		// Forge/boolean confirmation channel (opt-in, cfg.Forge != nil): a
		// structurally-recognized injection in this sub-request's path gets a
		// content-confirming element in place of the matched rule's static
		// body. forgeElement is a no-op (ok=false) whenever cfg.Forge is nil
		// or the path doesn't parse as an injection, so every non-injecting
		// and every Forge-disabled sub-request falls through to the exact
		// pre-existing static/reflect behaviour below, untouched.
		if fe, forged := forgeElement(cfg, path, sess); forged {
			elems = append(elems, fe)
			continue
		}

		el, reflect := matchMirrorRule(cfg, path, rawString(s[cfg.MethodField]))
		elemBody := el.Body
		if reflect != nil {
			elemBody = applyReflect(reflect, path, elemBody)
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

// reAuthorExclude pulls the author_exclude query-parameter value (up to the
// next & or end of string) out of a URL-decoded path — the wp_posts
// boolean-blind injection point exercised by booleanElement.
var reAuthorExclude = regexp.MustCompile(`(?i)[?&]author_exclude=([^&]*)`)

// forgeElement checks a sub-request's (still URL-encoded, as carried on the
// wire) path for a Forge-recognized injection and, if found, returns the
// content-confirming element to emit in place of the matched rule's static
// body. ok=false — meaning the caller must fall through to the existing
// static/reflect behaviour unchanged — whenever: cfg.Forge is nil; the
// Collection isn't the one implemented (wp_posts; compileMirror already
// rejects anything else at load time, this is a defensive belt-and-braces
// check for configs built directly rather than through the parser); the path
// fails to URL-decode; there's no UNION projection AND no author_exclude
// value; or the recognized injection itself fails to evaluate (fail closed,
// same discipline as evalLiteralBool/evalProjection). It never reimplements
// forge.go's logic, only wires extractUnionProjection / assembleForgedRow /
// booleanElement together and shapes their result into a mirrorElem.
//
// sess is the (nil-safe) fiction-DB chain session. When the author_exclude
// condition is not a literal constant (booleanElement declines) and sess !=
// nil, this additionally tries the fiction fallback: recognizeBlindRead
// identifies the read intent against the fabricated schema and
// evalBlindPredicate answers the operator's exact comparison against it,
// driving the same present/absent element booleanElement would have produced
// for a literal condition. Unrecognized or unevaluable reads fail closed
// (the pre-existing "fall through to static/reflect" behaviour), same as a
// nil sess.
func forgeElement(cfg *parser.MirrorConfig, path string, sess *chainSession) (mirrorElem, bool) {
	if cfg.Forge == nil {
		return mirrorElem{}, false
	}
	collection := cfg.Forge.Collection
	if collection == "" {
		collection = "wp_posts"
	}
	if collection != "wp_posts" {
		return mirrorElem{}, false
	}

	decoded, err := url.QueryUnescape(path)
	if err != nil {
		return mirrorElem{}, false
	}

	if cols, fields, ok := extractUnionProjection(decoded); ok {
		row, assembled := assembleForgedRow(cols, fields)
		if !assembled {
			return mirrorElem{}, false
		}
		rowJSON, err := json.Marshal(row)
		if err != nil {
			return mirrorElem{}, false
		}
		return mirrorElem{
			Body:    json.RawMessage(`[` + string(rowJSON) + `]`),
			Status:  200,
			Headers: json.RawMessage(`{"X-WP-Total":1,"X-WP-TotalPages":-1,"Allow":"GET"}`),
		}, true
	}

	if m := reAuthorExclude.FindStringSubmatch(decoded); m != nil {
		if raw, ok := booleanElement(m[1]); ok {
			var el mirrorElem
			if err := json.Unmarshal(raw, &el); err != nil {
				return mirrorElem{}, false
			}
			return el, true
		}
		// booleanElement declined — either the "<n>) AND|OR <cond> -- -"
		// wrapper didn't match, or it matched but <cond> isn't a literal
		// constant (evalLiteralBool isLiteral=false). Only the latter is a
		// fiction-fallback candidate: re-run the same wrapper strip (reBoolWrap,
		// shared with forge.go in this package) to isolate <cond>, then ask
		// the fiction DB whether it recognizes the read and can answer it.
		// sess == nil (every caller before this task, and every Layer-1 test)
		// short-circuits here, so behaviour is unchanged with no session armed.
		if sess != nil {
			if bm := reBoolWrap.FindStringSubmatch(m[1]); bm != nil {
				// stripOneParenLayer mirrors evalLiteralBool's own tolerance:
				// a boolean-blind payload conventionally double-wraps its
				// condition ("0) AND (<cond>)-- -"), and evalBlindPredicate
				// (unlike evalLiteralBool) does not strip that cosmetic layer
				// itself — without this, a real double-wrapped blind-read
				// predicate would recognize fine (recognizeBlindRead is
				// substring-based) but ALWAYS fail evalBlindPredicate's
				// top-level operator scan, silently defeating the whole
				// fallback on the exact payload shape sqlmap-style tooling
				// actually sends.
				cond := stripOneParenLayer(bm[1])
				if fv, recognized := recognizeBlindRead(cond, sess); recognized {
					if result, evalOK := evalBlindPredicate(cond, fv); evalOK {
						return booleanFictionElement(result), true
					}
				}
			}
		}
	}

	return mirrorElem{}, false
}

// booleanFictionElement builds the same present/absent batch element shape
// booleanElement (forge.go) produces for a literal condition, but driven by a
// fabricated blind-read answer instead of evalLiteralBool. Kept in this file
// (not forge.go) so the fiction-DB decision lives entirely in the file this
// task is scoped to extend; the byte shapes are pinned identical to
// booleanElement's on purpose — an operator's tool can't distinguish a
// fiction-driven confirmation from a literal-constant one.
func booleanFictionElement(result bool) mirrorElem {
	if result {
		return mirrorElem{
			Body:    json.RawMessage(`[{"id":1,"status":"publish"}]`),
			Status:  200,
			Headers: json.RawMessage(`{"X-WP-Total":1,"X-WP-TotalPages":1,"Allow":"GET"}`),
		}
	}
	return mirrorElem{
		Body:    json.RawMessage(`[]`),
		Status:  200,
		Headers: json.RawMessage(`{"X-WP-Total":0,"X-WP-TotalPages":0,"Allow":"GET"}`),
	}
}

// stripOneParenLayer removes exactly one layer of wrapping parens ("(x)" ->
// "x"), the same tolerance evalLiteralBool applies inline for a literal
// condition. A SQLi payload conventionally double-wraps its condition —
// "IF((cond),SLEEP(n),0)" / "0) AND (cond)-- -" — and the fiction-fallback
// evaluators (recognizeBlindRead/evalBlindPredicate) need that cosmetic
// layer gone before evalBlindPredicate's top-level operator scan, exactly as
// evalLiteralBool already requires for a literal comparison. Only strips
// when the FIRST and LAST bytes are '(' and ')' — a real fiction predicate's
// right-hand side is always a bare integer literal (see
// evalBlindPredicate/splitTopLevelCompare), so it never itself ends in ')',
// making this safe against accidentally eating a structural paren that
// belongs to the condition rather than to the wrapper.
func stripOneParenLayer(cond string) string {
	s := strings.TrimSpace(cond)
	if len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		return strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
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

// MaxMirrorDelayMs is the hard ceiling on any emulated time-based-oracle delay,
// enforced here and again at the HTTP call site. Also the default when
// Timing.MaxDelayMs is unset.
const MaxMirrorDelayMs = 9000

// MirrorDelayMs computes the time-based-oracle delay (ms) implied by a batch
// body, or 0. Additive and pure: it never affects the mirror body, so the
// KI-010 reflection path is untouched. It walks the same sub-requests as
// MirrorRespond (top level + one nesting level), and for each sub-request path
// (URL-encoded on the wire): tries IfRegex first — IF(<cond>,SLEEP(<n>),0),
// delaying n*1000 iff evalLiteralBool(decoded cond) is (true,true) — and only if
// IfRegex does NOT match, tries BareRegex (unconditional SLEEP(<n>)). Envelope
// delay = max over sub-requests, clamped to the cap.
//
// sess is the (nil-safe) fiction-DB chain session — see MirrorRespond's doc
// comment for the shared contract. nil reproduces the shipped
// evalLiteralBool-only behaviour exactly, so every pre-existing caller
// (passing nil) sees byte-for-byte-identical delays.
func MirrorDelayMs(cfg *parser.MirrorConfig, reqBody []byte, sess *chainSession) int {
	if cfg == nil || cfg.Timing == nil {
		return 0
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(reqBody, &top); err != nil {
		return 0
	}
	arrRaw, ok := top[cfg.RequestKey]
	if !ok {
		return 0
	}
	subs, ok := decodeSubs(arrRaw)
	if !ok {
		return 0
	}
	delay := timingWalk(cfg, subs, 0, sess)

	cap := cfg.Timing.MaxDelayMs
	if cap <= 0 || cap > MaxMirrorDelayMs {
		cap = MaxMirrorDelayMs
	}
	if delay > cap {
		delay = cap
	}
	return delay
}

// timingWalk returns the max per-sub-request delay across one level, recursing
// one nesting level (matching the observed nested-batch injection site).
func timingWalk(cfg *parser.MirrorConfig, subs []map[string]json.RawMessage, depth int, sess *chainSession) int {
	max := 0
	for _, s := range subs {
		if depth < 1 {
			if nested, isNested := nestedSubs(s, cfg.RequestKey); isNested {
				if d := timingWalk(cfg, nested, depth+1, sess); d > max {
					max = d
				}
			}
		}
		if d := sleepDelay(cfg.Timing, rawString(s[cfg.PathField]), sess); d > max {
			max = d
		}
	}
	return max
}

// sleepDelay extracts the delay a single path implies. IfRegex first (so the
// inner SLEEP of an IF form is not double-counted by BareRegex); BareRegex only
// if the IF form is absent.
//
// sess is the (nil-safe) fiction-DB chain session. When the IF condition is
// not a literal constant (evalLiteralBool isLiteral=false) and sess != nil,
// this additionally tries the fiction fallback — recognizeBlindRead +
// evalBlindPredicate — before falling through to "no bare fallthrough". A
// true fiction answer drives the same n*1000 delay branch a literal-true
// condition would; false (or unrecognized/unevaluable) stays at the existing
// flat 0. nil sess reproduces the shipped behaviour exactly.
func sleepDelay(t *parser.MirrorTiming, path string, sess *chainSession) int {
	if t.IfRegex != nil {
		if m := t.IfRegex.FindStringSubmatch(path); len(m) == 3 {
			cond, err := url.QueryUnescape(m[1])
			if err != nil {
				cond = m[1]
			}
			val, isLit := evalLiteralBool(cond)
			if !isLit && sess != nil {
				// stripOneParenLayer: see its doc comment — evalBlindPredicate,
				// unlike evalLiteralBool, does not tolerate the cosmetic
				// double-wrap a payload's IF((cond),SLEEP(n),0) form carries.
				fcond := stripOneParenLayer(cond)
				if fv, recognized := recognizeBlindRead(fcond, sess); recognized {
					if result, evalOK := evalBlindPredicate(fcond, fv); evalOK {
						val, isLit = result, true
					}
				}
			}
			if isLit && val {
				if n, err := strconv.Atoi(m[2]); err == nil {
					return n * 1000
				}
			}
			return 0 // IF matched but condition false/non-literal/unrecognized → no bare fallthrough
		}
	}
	if t.BareRegex != nil {
		if m := t.BareRegex.FindStringSubmatch(path); len(m) == 2 {
			if n, err := strconv.Atoi(m[1]); err == nil {
				return n * 1000
			}
		}
	}
	return 0
}
