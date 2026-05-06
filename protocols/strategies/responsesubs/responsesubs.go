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
//	${request.uuid}        — full RFC 4122 v4 UUID (uuid.New, crypto/rand)
//	${request.uuid_short}  — first 8 hex chars of the UUID, dashes stripped
//	${request.unix_ms}     — current time in unix milliseconds
//	${session.<key>}       — looked up in sessionVars (caller-provided)
//	${captured.<key>}      — looked up in sessionVars; HTML-escaped because
//	                         captured values may originate from attacker
//	                         request bodies
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
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Apply rewrites ${request.*}, ${session.*}, and ${captured.*}
// placeholders in body and each entry of headers. sessionVars is an
// optional map of caller-supplied keys; HTTP populates it from the
// per-request sessionContext (cookie, captured form fields, etc.) while
// MCP / OLLAMA / TCP / TELNET typically pass nil because they do not
// expose a stateful session context. Request-level vars work
// unconditionally regardless of sessionVars.
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
func Apply(body string, headers []string, sessionVars map[string]string) (string, []string) {
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
	if headers == nil {
		return newBody, nil
	}
	newHeaders := make([]string, len(headers))
	for i, h := range headers {
		newHeaders[i] = replacer.Replace(h)
	}
	return newBody, newHeaders
}
