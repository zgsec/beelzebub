package plugins

import (
	"encoding/json"
	"strings"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
)

// ResponseMirrorName is the Command.Plugin value that selects the batch-envelope
// mirror. See parser.MirrorConfig for the (generic) configuration and the HTTP
// strategy for the call site.
const ResponseMirrorName = "ResponseMirror"

// mirrorElem is one response-array entry. Field order (body, status, headers)
// is fixed by the struct so json.Marshal never reorders it, and Body/Headers
// are RawMessage so a configured JSON object nests as an object rather than a
// string-escaped literal. Both are pre-validated as JSON at config load
// (parser.compileMirror), so the RawMessage values are always well-formed here.
type mirrorElem struct {
	Body    json.RawMessage `json:"body"`
	Status  int             `json:"status"`
	Headers json.RawMessage `json:"headers"`
}

// MirrorRespond parses reqBody as the configured batch envelope and returns the
// assembled multiplexed response.
//
// Contract: ok=false means "this request is not a batch we should mirror"
// (nil config, unparseable body, missing/!array request key, or an
// over-limit count with no reject configured). The caller MUST then leave the
// response as the command's static handler — the plugin is strictly additive,
// so its worst case is exactly the pre-mirror behavior. ok=true returns the
// final status + body to write (either the wrapped N-element envelope, or the
// whole-envelope Reject body when a guard trips).
//
// It is deliberately flat: a sub-request's own nested body is never inspected
// or recursed, matching a patched (non-vulnerable) server. No attacker input
// is executed or reflected — every emitted byte comes from validated config.
func MirrorRespond(cfg *parser.MirrorConfig, reqBody []byte) (status int, body string, ok bool) {
	if cfg == nil {
		return 0, "", false
	}

	// Top level must be a JSON object exposing the sub-request array under RequestKey.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(reqBody, &top); err != nil {
		return 0, "", false
	}
	arrRaw, exists := top[cfg.RequestKey]
	if !exists {
		return 0, "", false
	}
	var subs []map[string]json.RawMessage
	if err := json.Unmarshal(arrRaw, &subs); err != nil {
		return 0, "", false
	}

	max := cfg.MaxItems
	if max <= 0 {
		max = 25
	}
	if len(subs) > max {
		return rejectOr(cfg, 0, "", false)
	}

	// Whole-envelope method guard: a real server validates the sub-request
	// method enum before dispatch, rejecting the ENTIRE batch (top-level 400),
	// not per element. Empty AllowedMethods disables the guard.
	if len(cfg.AllowedMethods) > 0 {
		for _, s := range subs {
			if !methodAllowed(rawString(s[cfg.MethodField]), cfg.AllowedMethods) {
				return rejectOr(cfg, 0, "", false)
			}
		}
	}

	elems := make([]mirrorElem, 0, len(subs))
	for _, s := range subs {
		el := matchMirrorRule(cfg, rawString(s[cfg.PathField]), rawString(s[cfg.MethodField]))
		headers := el.Headers
		if headers == "" {
			headers = "[]" // real servers use [] for the no-header case
		}
		elems = append(elems, mirrorElem{
			Body:    json.RawMessage(el.Body),
			Status:  el.Status,
			Headers: json.RawMessage(headers),
		})
	}

	arr, err := json.Marshal(elems)
	if err != nil {
		return 0, "", false
	}
	// Manual wrap for the single dynamic key: json.Marshal adds no trailing
	// newline (Encoder would), so this is byte-exact.
	body = `{"` + cfg.ResponseKey + `":` + string(arr) + `}`
	return cfg.WrapStatus, body, true
}

// rejectOr returns the configured whole-envelope Reject when present, else the
// provided fallthrough (typically ok=false so the caller keeps the static body).
func rejectOr(cfg *parser.MirrorConfig, s int, b string, o bool) (int, string, bool) {
	if cfg.Reject != nil {
		return cfg.Reject.Status, cfg.Reject.Body, true
	}
	return s, b, o
}

// matchMirrorRule returns the first rule whose path regex matches (and whose
// optional method matches), else the Default element.
func matchMirrorRule(cfg *parser.MirrorConfig, path, method string) parser.MirrorElement {
	for i := range cfg.Rules {
		r := cfg.Rules[i]
		if r.PathRegex == nil || !r.PathRegex.MatchString(path) {
			continue
		}
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		return r.MirrorElement
	}
	return cfg.Default
}

// rawString decodes a JSON string value, returning "" for absent/non-string.
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
