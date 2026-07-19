package plugins

import (
	"encoding/hex"
	"encoding/json"
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
