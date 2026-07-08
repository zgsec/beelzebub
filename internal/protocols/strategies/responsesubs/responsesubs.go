// Package responsesubs renders ${request.*}, ${session.*}, ${captured.*},
// and ${time.*} placeholders in attacker-visible response data (bodies +
// header values).
//
// Why a shared package:
// The HTTP strategy historically owned this rewrite, but a persona's
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
//	${time.now}                  — current UTC time in RFC3339 format. Emits a
//	                               fresh timestamp on every call, preventing the
//	                               frozen-ISO-timestamp class of honeypot
//	                               fingerprint (5/19 audit, Task 4.1).
//	${time.now.unix}             — current unix epoch seconds as an unquoted
//	                               integer. OpenAI-compat APIs use this shape
//	                               in the `created` field of /v1/chat/completions
//	                               responses; without this, LLM-generated bodies
//	                               leak the static prompt-template placeholder
//	                               (observed 2026-05-23 in production:
//	                               `"created":1710000000` static across all
//	                               responses, an obvious honeypot fingerprint).
//	${time.ago.<N><unit>}        — current UTC time minus N units in RFC3339.
//	                               Supported units: s (seconds), m (minutes),
//	                               h (hours), d (days). Integer count only.
//	                               Example: ${time.ago.3h} → 3 hours ago.
//	                               Unknown units are left untouched.
//	${time.since.<epoch>}        — integer seconds since a unix epoch (now-epoch,
//	                               clamped ≥0). Drives advancing "seconds since
//	                               boot" fields (redis uptime_in_seconds) so a
//	                               re-probe never sees a frozen uptime.
//	${counter.<b>.<n>.<d>.<e>}   — monotonic counter b+(now-e)*n/d (int64). Stats
//	                               like total_commands_processed advance linearly
//	                               from the same boot epoch <e> as uptime, staying
//	                               internally consistent and never frozen. d≠0.
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

// timeAgoRE matches ${time.ago.<N><unit>} where unit is one of s/m/h/d.
// Compiled once at package init — stateless and safe for concurrent use.
var timeAgoRE = regexp.MustCompile(`\$\{time\.ago\.(\d+)([smhd])\}`)

// timeInRE matches ${time.in.<N><unit>} — the future-direction counterpart
// of timeAgoRE. Used for expiry-type fields (STS-token Expiration, session
// expires_at, cert renewal cutoffs) so they roll forward with wall-clock
// time instead of being frozen ISO literals that drift stale.
var timeInRE = regexp.MustCompile(`\$\{time\.in\.(\d+)([smhd])\}`)

// timeSinceRE matches ${time.since.<epoch>} → integer seconds elapsed since the
// given unix epoch (now-epoch, clamped at 0). Drives "seconds since boot" fields
// (redis uptime_in_seconds, process uptime) that must ADVANCE on every probe
// instead of being frozen at render time — re-probing a frozen uptime is a
// honeypot tell. Epoch is the persona's per-instance boot epoch.
var timeSinceRE = regexp.MustCompile(`\$\{time\.since\.(\d+)\}`)

// counterRE matches ${counter.<base>.<num>.<den>.<epoch>} → a monotonic counter
// base + (now-epoch)*num/den (integer arithmetic), so stats like
// total_commands_processed / keyspace_hits advance linearly from the same boot
// epoch as uptime, staying internally consistent (e.g. cmds == 4×uptime) while
// never frozen. den must be non-zero; all fields are integers (no float parse).
var counterRE = regexp.MustCompile(`\$\{counter\.(\d+)\.(\d+)\.(\d+)\.(\d+)\}`)

// replaceTimeAgo / replaceTimeIn share their unit parsing. Unknown unit
// letters are left untouched so mistyped placeholders are visible in test
// traffic instead of silently rendering as zero offsets.
func parseTimeUnit(n int, unit string) (time.Duration, bool) {
	switch unit {
	case "s":
		return time.Duration(n) * time.Second, true
	case "m":
		return time.Duration(n) * time.Minute, true
	case "h":
		return time.Duration(n) * time.Hour, true
	case "d":
		return time.Duration(n) * 24 * time.Hour, true
	}
	return 0, false
}

func replaceTimeAgo(match string) string {
	m := timeAgoRE.FindStringSubmatch(match)
	if m == nil {
		return match
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return match
	}
	d, ok := parseTimeUnit(n, m[2])
	if !ok {
		return match
	}
	return time.Now().UTC().Add(-d).Format(time.RFC3339)
}

func replaceTimeIn(match string) string {
	m := timeInRE.FindStringSubmatch(match)
	if m == nil {
		return match
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return match
	}
	d, ok := parseTimeUnit(n, m[2])
	if !ok {
		return match
	}
	return time.Now().UTC().Add(d).Format(time.RFC3339)
}

// replaceTimeSince resolves ${time.since.<epoch>} to (now - epoch) seconds,
// clamped at 0 so a future/misconfigured epoch never emits a negative uptime.
func replaceTimeSince(match string) string {
	m := timeSinceRE.FindStringSubmatch(match)
	if m == nil {
		return match
	}
	epoch, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return match
	}
	elapsed := time.Now().Unix() - epoch
	if elapsed < 0 {
		elapsed = 0
	}
	return strconv.FormatInt(elapsed, 10)
}

// replaceCounter resolves ${counter.<base>.<num>.<den>.<epoch>} to
// base + (now-epoch)*num/den using int64 arithmetic. Elapsed is clamped at 0;
// den==0 (or any parse failure) leaves the token untouched so the mistake is
// visible in test traffic rather than emitting a bogus number.
func replaceCounter(match string) string {
	m := counterRE.FindStringSubmatch(match)
	if m == nil {
		return match
	}
	base, e1 := strconv.ParseInt(m[1], 10, 64)
	num, e2 := strconv.ParseInt(m[2], 10, 64)
	den, e3 := strconv.ParseInt(m[3], 10, 64)
	epoch, e4 := strconv.ParseInt(m[4], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || den == 0 {
		return match
	}
	elapsed := time.Now().Unix() - epoch
	if elapsed < 0 {
		elapsed = 0
	}
	return strconv.FormatInt(base+elapsed*num/den, 10)
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
	newBody = applyTime(newBody)

	if headers == nil {
		return newBody, nil
	}
	newHeaders := make([]string, len(headers))
	for i, h := range headers {
		newHeaders[i] = applyTime(applyRequestJSON(replacer.Replace(h), requestBody))
	}
	return newBody, newHeaders
}

// applyTime resolves ${time.now}, ${time.ago.<N><unit>}, and ${time.in.<N><unit>}
// placeholders in s. ${time.now} emits the current UTC time in RFC3339 format.
// ${time.ago.<N><unit>} emits (now - N units); ${time.in.<N><unit>} emits
// (now + N units). The function is a no-op when s contains none of these
// placeholder substrings, keeping the zero-allocation fast path for templates
// that don't use time substitutions.
func applyTime(s string) string {
	// ${time.now.unix} BEFORE ${time.now} — the longer pattern must be
	// resolved first, otherwise the bare ${time.now} prefix would match
	// and leave a literal ".unix}" trailing the substituted RFC3339 stamp.
	if strings.Contains(s, "${time.now.unix}") {
		s = strings.ReplaceAll(s, "${time.now.unix}", strconv.FormatInt(time.Now().Unix(), 10))
	}
	if strings.Contains(s, "${time.now}") {
		s = strings.ReplaceAll(s, "${time.now}", time.Now().UTC().Format(time.RFC3339))
	}
	if strings.Contains(s, "${time.ago.") {
		s = timeAgoRE.ReplaceAllStringFunc(s, replaceTimeAgo)
	}
	if strings.Contains(s, "${time.in.") {
		s = timeInRE.ReplaceAllStringFunc(s, replaceTimeIn)
	}
	if strings.Contains(s, "${time.since.") {
		s = timeSinceRE.ReplaceAllStringFunc(s, replaceTimeSince)
	}
	if strings.Contains(s, "${counter.") {
		s = counterRE.ReplaceAllStringFunc(s, replaceCounter)
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
