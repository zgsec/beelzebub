// Package responsesubs renders ${request.*}, ${session.*}, and ${captured.*}
// placeholders in attacker-visible response data (bodies + header values).
//
// Why a shared package:
// The HTTP strategy historically owned this rewrite, but Crestfield's
// MCP-on-port-8000 deployment exposed a wire-format gap — the MCP HTTP
// fallback path emits matchedCommand.Handler verbatim, so any
// ${request.uuid_short} placeholder authored in a YAML lure would land
// on the wire as a literal "${request.uuid_short}" string. That is
// strictly worse than the cross-fleet-identical req_a1b2c3d4 leak the
// substitution was introduced to fix (see commit 4cd06db, 2026-05-06
// conformance test).
//
// Every protocol strategy that emits YAML-authored response content
// (HTTP, MCP, OLLAMA, TCP, TELNET) calls Apply at its response-write
// boundary so authoring placeholders in YAML behaves identically
// regardless of which strategy parses the lure.
//
// Variable inventory:
//
//	${request.uuid}              — full RFC 4122 v4 UUID (uuid.New, crypto/rand)
//	${request.uuid_short}        — first 8 hex chars of the UUID, dashes stripped
//	${request.unix_ms}           — current time in unix milliseconds
//	${request.json.<path>}       — dotted-path lookup into the request body
//	                               parsed as JSON. Numbers emit unquoted, strings
//	                               quoted (via json.Marshal). Falls back to the
//	                               literal token "null" on parse error, missing
//	                               key, or nil body. Closes the MCP JSON-RPC 2.0
//	                               id-echo conformance gap (Task 3.1, 2026-05-19).
//	${session.<key>}             — looked up in sessionVars (caller-provided)
//	${captured.<key>}            — looked up in sessionVars; HTML-escaped because
//	                               captured values may originate from attacker
//	                               request bodies
//
// Safety contract:
//
//   - Apply MUST NOT mutate inputs. Strategies share matchedCommand
//     pointers across requests; in-place mutation would bake the first
//     request's UUID into every subsequent request.
//   - Consecutive calls MUST produce different output (request.uuid is
//     freshly generated each invocation).
//   - Unknown placeholders are left untouched — caller-defined session
//     keys are matched as-prefixed, not validated.
package responsesubs

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// reRequestJSON matches ${request.json.<dotted.path>} placeholders.
// Compiled once at package init — the regex is stateless and safe for
// concurrent use.
var reRequestJSON = regexp.MustCompile(`\$\{request\.json\.([a-zA-Z_][a-zA-Z0-9_.]*)\}`)

// Apply rewrites ${request.*}, ${session.*}, and ${captured.*}
// placeholders in body and each entry of headers. sessionVars is an
// optional map of caller-supplied keys; HTTP populates it from the
// per-request sessionContext (cookie, captured form fields, etc.) while
// MCP / OLLAMA / TCP / TELNET typically pass nil because they do not
// expose a stateful session context. Request-level vars work
// unconditionally regardless of sessionVars.
//
// requestBody is the raw HTTP request body (or nil for TCP/TELNET/GET
// requests). It is only parsed when the body/header template contains a
// ${request.json.*} placeholder — callers that never author those
// placeholders pay no parse cost.
//
// Keys in sessionVars use the bare suffix:
//
//	"cookie"        -> ${session.cookie}
//	"short"         -> ${session.short}
//	"capt:<key>"    -> ${captured.<key>}    (HTML-escaped)
//
// To keep the API small and avoid double-escaping, callers pass already-
// raw values for ${session.*} and raw (un-escaped) values for
// ${captured.*}; Apply does the html.EscapeString on captured values.
//
// Apply returns a new body string and a freshly-allocated headers slice.
// The input headers slice is never mutated.
func Apply(body string, headers []string, sessionVars map[string]string, requestBody []byte) (string, []string) {
	reqUUID := uuid.New().String()
	reqUUIDShort := strings.ReplaceAll(reqUUID, "-", "")[:8]
	pairs := []string{
		"${request.uuid}", reqUUID,
		"${request.uuid_short}", reqUUIDShort,
		"${request.unix_ms}", fmt.Sprintf("%d", time.Now().UnixMilli()),
	}
	for k, v := range sessionVars {
		if strings.HasPrefix(k, "capt:") {
			pairs = append(pairs, "${captured."+k[len("capt:"):]+"}", html.EscapeString(v))
			continue
		}
		pairs = append(pairs, "${session."+k+"}", v)
	}
	replacer := strings.NewReplacer(pairs...)

	newBody := replacer.Replace(body)
	newBody = applyRequestJSON(newBody, requestBody)

	if headers == nil {
		return newBody, nil
	}
	newHeaders := make([]string, len(headers))
	for i, h := range headers {
		newHeaders[i] = applyRequestJSON(replacer.Replace(h), requestBody)
	}
	return newBody, newHeaders
}

// applyRequestJSON resolves ${request.json.<dotted.path>} placeholders in s
// by parsing requestBody as JSON and walking the dotted path. Each resolved
// value is emitted as a valid JSON token (numbers unquoted, strings quoted)
// via json.Marshal so the substituted result stays syntactically valid inside
// a JSON response template. Falls back to the literal token "null" on parse
// error, missing key, non-object intermediate node, or nil requestBody.
//
// The function is a no-op (returns s unchanged) when s contains no
// ${request.json.} substring, keeping the zero-allocation fast path for
// templates that don't use this feature.
func applyRequestJSON(s string, requestBody []byte) string {
	if !strings.Contains(s, "${request.json.") {
		return s
	}
	var parsed map[string]interface{}
	if len(requestBody) > 0 {
		_ = json.Unmarshal(requestBody, &parsed) // tolerate parse errors → nil map
	}
	return reRequestJSON.ReplaceAllStringFunc(s, func(match string) string {
		m := reRequestJSON.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		path := strings.Split(m[1], ".")
		var cur interface{} = parsed
		for _, p := range path {
			mp, ok := cur.(map[string]interface{})
			if !ok {
				return "null"
			}
			v, exists := mp[p]
			if !exists {
				return "null"
			}
			cur = v
		}
		if cur == nil {
			return "null"
		}
		out, err := json.Marshal(cur)
		if err != nil {
			return "null"
		}
		return string(out)
	})
}
