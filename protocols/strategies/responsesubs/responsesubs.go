// Package responsesubs renders ${request.*}, ${session.*}, ${captured.*},
// and ${time.*} placeholders in attacker-visible response data (bodies +
// header values).
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
//	${request.multipart.filename}      — first filename="..." in a multipart body,
//	                               JSON-escaped for safe placement inside a "..."
//	                               JSON string (e.g. echoing an upload's name)
//	${request.multipart.filename_stem} — same filename with its final .ext removed
//	${request.multipart.ext}     — sanitized final extension incl. leading dot
//	                               parsed as JSON. Numbers emit unquoted, strings
//	                               quoted (via json.Marshal). Falls back to the
//	                               literal token "null" on parse error, missing
//	                               key, or nil body. Closes the MCP JSON-RPC 2.0
//	                               id-echo conformance gap (Task 3.1, 2026-05-19).
//	${session.<key>}             — looked up in sessionVars (caller-provided)
//	${captured.<key>}            — looked up in sessionVars; HTML-escaped because
//	                               captured values may originate from attacker
//	                               request bodies
//	${time.now}                  — current UTC time in RFC3339 format. Emits a
//	                               fresh timestamp on every call, preventing the
//	                               frozen-ISO-timestamp class of honeypot
//	                               fingerprint (5/19 audit, Task 4.1).
//	${time.ago.<N><unit>}        — current UTC time minus N units in RFC3339.
//	                               Supported units: s (seconds), m (minutes),
//	                               h (hours), d (days). Integer count only.
//	                               Example: ${time.ago.3h} → 3 hours ago.
//	                               Unknown units are left untouched.
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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// reRequestJSON matches ${request.json.<dotted.path>} placeholders.
// Compiled once at package init — the regex is stateless and safe for
// concurrent use.
var reRequestJSON = regexp.MustCompile(`\$\{request\.json\.([a-zA-Z_][a-zA-Z0-9_.]*)\}`)

// reRequestJSONStr matches ${request.json_str.<dotted.path>} — the bare-string
// sibling of reRequestJSON. Where ${request.json.*} emits a full JSON token (a
// string comes back quoted, e.g. "echo"), ${request.json_str.*} emits the resolved
// string JSON-escaped but WITHOUT the outer quotes, so a template author writes it
// inside their own quotes inside a larger string. Same bare-escaped contract as the
// ${request.multipart.filename_stem} resolver below — it lets a CVE-error lure echo
// the attacker's value verbatim into a message string the way the real product does:
//
//	"msg":"Value error, Command '${request.json_str.command}' is not in ..."
//
// renders byte-for-byte as LiteLLM's "Command 'echo' is not in ..." (CVE-2026-42271,
// invariant for every command including /bin/sh). Any ", \\ or control char in the
// value is escaped so it can neither break out of the JSON string nor inject markup.
// Missing keys, non-object intermediate nodes, and non-string values resolve to "".
var reRequestJSONStr = regexp.MustCompile(`\$\{request\.json_str\.([a-zA-Z_][a-zA-Z0-9_.]*)\}`)

// reMultipartFilename pulls the first filename="..." out of a
// multipart/form-data request body. The boundary lines carry the
// filename in the Content-Disposition header, so we can recover it from
// the raw body without needing the request Content-Type boundary param.
// Used by the ${request.multipart.*} placeholders so a file-upload lure
// (e.g. the LangFlow CVE-2026-5027 POST /api/v2/files surface) can echo
// the attacker's submitted filename — including any ../ path-traversal —
// back into its 201 response exactly as the real product does.
var reMultipartFilename = regexp.MustCompile(`(?i)filename="([^"]*)"`)

// timeAgoRE matches ${time.ago.<N><unit>} where unit is one of s/m/h/d.
// Compiled once at package init — stateless and safe for concurrent use.
var timeAgoRE = regexp.MustCompile(`\$\{time\.ago\.(\d+)([smhd])\}`)

// replaceTimeAgo is the replacement function for timeAgoRE. It is called
// once per match by ReplaceAllStringFunc. Unknown unit letters are left
// untouched so mistyped placeholders are visible in test traffic.
func replaceTimeAgo(match string) string {
	m := timeAgoRE.FindStringSubmatch(match)
	if m == nil {
		return match
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return match
	}
	var d time.Duration
	switch m[2] {
	case "s":
		d = time.Duration(n) * time.Second
	case "m":
		d = time.Duration(n) * time.Minute
	case "h":
		d = time.Duration(n) * time.Hour
	case "d":
		d = time.Duration(n) * 24 * time.Hour
	default:
		return match
	}
	return time.Now().UTC().Add(-d).Format(time.RFC3339)
}

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
	newBody = applyRequestJSONStr(newBody, requestBody)
	newBody = applyMultipart(newBody, requestBody)
	newBody = applyTime(newBody)

	if headers == nil {
		return newBody, nil
	}
	newHeaders := make([]string, len(headers))
	for i, h := range headers {
		newHeaders[i] = applyTime(applyMultipart(applyRequestJSONStr(applyRequestJSON(replacer.Replace(h), requestBody), requestBody), requestBody))
	}
	return newBody, newHeaders
}

// applyMultipart resolves the ${request.multipart.*} placeholders by
// recovering the first filename="..." from a multipart/form-data body.
// It is a no-op (returns s unchanged) when s contains no
// ${request.multipart. substring, preserving the zero-allocation fast
// path for the common case.
//
// filename / filename_stem are emitted JSON-escaped but WITHOUT the outer
// quotes, so a template author writes them inside their own quotes, e.g.
//
//	{"name":"${request.multipart.filename_stem}", ...}
//
// and any ", \\, ../ or shell metacharacters in the attacker-supplied
// filename can neither break out of the JSON string nor inject markup.
// ext is restricted to a leading dot plus [A-Za-z0-9] (capped) so it is
// always safe to concatenate after a server-generated UUID in a path.
func applyMultipart(s string, requestBody []byte) string {
	if !strings.Contains(s, "${request.multipart.") {
		return s
	}
	var filename string
	if len(requestBody) > 0 {
		if m := reMultipartFilename.FindSubmatch(requestBody); m != nil {
			filename = string(m[1])
		}
	}
	stem := filename
	ext := ""
	if dot := strings.LastIndexByte(filename, '.'); dot >= 0 {
		stem = filename[:dot]
		ext = sanitizeExt(filename[dot:])
	}
	return strings.NewReplacer(
		"${request.multipart.filename_stem}", jsonInner(stem),
		"${request.multipart.filename}", jsonInner(filename),
		"${request.multipart.ext}", ext,
	).Replace(s)
}

// jsonInner JSON-encodes v and strips the surrounding quotes, yielding a
// fragment safe to drop inside an existing "..." JSON string literal.
func jsonInner(v string) string {
	b, err := json.Marshal(v)
	if err != nil || len(b) < 2 {
		return ""
	}
	return string(b[1 : len(b)-1])
}

// sanitizeExt keeps a leading '.' followed by up to 12 alphanumeric
// characters, stopping at the first non-alphanumeric byte. This mirrors
// the real product appending the upload's extension to a UUID storage
// name while guaranteeing the result cannot escape its JSON string.
func sanitizeExt(ext string) string {
	if len(ext) == 0 || ext[0] != '.' {
		return ""
	}
	var b strings.Builder
	b.WriteByte('.')
	for i := 1; i < len(ext) && b.Len() <= 12; i++ {
		c := ext[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
		} else {
			break
		}
	}
	if b.Len() == 1 {
		return ""
	}
	return b.String()
}

// applyTime resolves ${time.now} and ${time.ago.<N><unit>} placeholders in s.
// ${time.now} emits the current UTC time in RFC3339 format. ${time.ago.<N><unit>}
// emits (now - N units) in RFC3339. The function is a no-op when s contains
// neither placeholder substring, keeping the zero-allocation fast path for
// templates that don't use time substitutions.
func applyTime(s string) string {
	if strings.Contains(s, "${time.now}") {
		s = strings.ReplaceAll(s, "${time.now}", time.Now().UTC().Format(time.RFC3339))
	}
	if strings.Contains(s, "${time.ago.") {
		s = timeAgoRE.ReplaceAllStringFunc(s, replaceTimeAgo)
	}
	return s
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

// applyRequestJSONStr resolves ${request.json_str.<dotted.path>} placeholders by
// walking the dotted path into the parsed request body and emitting the resolved
// STRING value JSON-escaped but WITHOUT the surrounding quotes — so the author wraps
// it in their own quotes inside a larger JSON string. Non-string / missing / nil
// values resolve to "" (the placeholder is meaningful only as an interpolated
// string). No-op (and zero-alloc) when s contains no ${request.json_str.} substring.
func applyRequestJSONStr(s string, requestBody []byte) string {
	if !strings.Contains(s, "${request.json_str.") {
		return s
	}
	var parsed map[string]interface{}
	if len(requestBody) > 0 {
		_ = json.Unmarshal(requestBody, &parsed) // tolerate parse errors → nil map
	}
	return reRequestJSONStr.ReplaceAllStringFunc(s, func(match string) string {
		m := reRequestJSONStr.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		path := strings.Split(m[1], ".")
		var cur interface{} = parsed
		for _, p := range path {
			mp, ok := cur.(map[string]interface{})
			if !ok {
				return ""
			}
			v, exists := mp[p]
			if !exists {
				return ""
			}
			cur = v
		}
		str, ok := cur.(string)
		if !ok {
			return "" // only strings interpolate as bare; arrays/numbers/objects → ""
		}
		b, err := json.Marshal(str) // "echo"  /  "ev\"il\\x"
		if err != nil || len(b) < 2 {
			return ""
		}
		return string(b[1 : len(b)-1]) // strip the outer quotes; inner stays JSON-escaped
	})
}
