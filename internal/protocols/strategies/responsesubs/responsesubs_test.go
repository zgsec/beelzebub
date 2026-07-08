package responsesubs

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestApply_RequestVarsUnconditional — request-level placeholders fire
// even when sessionVars is nil. This is the contract MCP / TCP / TELNET
// rely on (they do not expose a session context).
func TestApply_RequestVarsUnconditional(t *testing.T) {
	body := `{"trace_id":"${request.uuid}","ts":${request.unix_ms}}`
	headers := []string{"X-Request-Id: req_${request.uuid_short}"}
	gotBody, gotHeaders := Apply(body, headers, nil, nil)

	if strings.Contains(gotBody, "${request.uuid}") || strings.Contains(gotBody, "${request.unix_ms}") {
		t.Fatalf("request placeholders left in body: %q", gotBody)
	}
	if strings.Contains(gotHeaders[0], "${request.uuid_short}") {
		t.Fatalf("uuid_short placeholder left in header: %q", gotHeaders[0])
	}
	// uuid_short suffix is exactly 8 lowercase hex chars
	const prefix = "X-Request-Id: req_"
	if !strings.HasPrefix(gotHeaders[0], prefix) {
		t.Fatalf("header prefix unexpected: %q", gotHeaders[0])
	}
	suffix := strings.TrimPrefix(gotHeaders[0], prefix)
	if len(suffix) != 8 {
		t.Errorf("uuid_short length = %d, want 8 (got %q)", len(suffix), suffix)
	}
	for _, c := range suffix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("uuid_short non-hex char %q in %q", c, suffix)
		}
	}
}

// TestApply_VariesAcrossInvocations — consecutive calls must produce
// different request UUIDs. This catches the failure mode where a UUID
// is computed once at strategy init and frozen for every request.
func TestApply_VariesAcrossInvocations(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 5; i++ {
		body, _ := Apply("${request.uuid}", nil, nil, nil)
		if _, dup := seen[body]; dup {
			t.Fatalf("request.uuid repeated across calls: %q", body)
		}
		seen[body] = struct{}{}
	}
}

// TestApply_TimeSince — ${time.since.<epoch>} emits integer seconds elapsed,
// clamped at 0 for a future epoch. Drives redis uptime_in_seconds so it never
// reads frozen across probes.
func TestApply_TimeSince(t *testing.T) {
	epoch := time.Now().Unix() - 1000
	body, _ := Apply("${time.since."+strconv.FormatInt(epoch, 10)+"}", nil, nil, nil)
	got, err := strconv.Atoi(body)
	if err != nil {
		t.Fatalf("time.since did not resolve to an int: %q (%v)", body, err)
	}
	if got < 998 || got > 1002 {
		t.Errorf("time.since = %d, want ~1000", got)
	}
	future := strconv.FormatInt(time.Now().Unix()+5000, 10)
	if fb, _ := Apply("${time.since."+future+"}", nil, nil, nil); fb != "0" {
		t.Errorf("time.since future epoch = %q, want 0 (clamped)", fb)
	}
}

// TestApply_Counter — ${counter.<base>.<num>.<den>.<epoch>} emits
// base+(now-epoch)*num/den; integer division; a den==0 token is left untouched
// so the authoring mistake is visible instead of emitting a bogus number.
func TestApply_Counter(t *testing.T) {
	e := strconv.FormatInt(time.Now().Unix()-1000, 10)
	// base 100, 4/sec over ~1000s -> ~4100
	if got, err := strconv.Atoi(mustApply(t, "${counter.100.4.1."+e+"}")); err != nil {
		t.Fatalf("counter not an int: %v", err)
	} else if got < 4092 || got > 4108 {
		t.Errorf("counter = %d, want ~4100", got)
	}
	// integer division: base 137, 1 per 113s over ~1000s -> 137 + 8 = ~145
	if got, _ := strconv.Atoi(mustApply(t, "${counter.137.1.113."+e+"}")); got < 144 || got > 147 {
		t.Errorf("counter div = %d, want ~145", got)
	}
	if z := mustApply(t, "${counter.0.1.0.123}"); z != "${counter.0.1.0.123}" {
		t.Errorf("counter den=0 = %q, want untouched", z)
	}
}

func mustApply(t *testing.T, body string) string {
	t.Helper()
	out, _ := Apply(body, nil, nil, nil)
	return out
}

// TestApply_SessionVarsRespected — caller-supplied session.* and
// captured.* substitute correctly. session.cookie is verbatim;
// captured.role is HTML-escaped.
func TestApply_SessionVarsRespected(t *testing.T) {
	body := `cookie=${session.cookie};short=${session.short};role=${captured.role}`
	vars := map[string]string{
		"cookie":    "deadbeef00112233",
		"short":     "deadbeef",
		"capt:role": "admin",
	}
	got, _ := Apply(body, nil, vars, nil)
	if !strings.Contains(got, "cookie=deadbeef00112233") {
		t.Errorf("session.cookie missing: %q", got)
	}
	if !strings.Contains(got, "short=deadbeef") {
		t.Errorf("session.short missing: %q", got)
	}
	if !strings.Contains(got, "role=admin") {
		t.Errorf("captured.role missing: %q", got)
	}
}

// TestApply_HeadersRewrite — placeholders inside header values are
// substituted, not just bodies. Real lures put ${request.uuid_short}
// in X-Request-Id; that path must work.
func TestApply_HeadersRewrite(t *testing.T) {
	headers := []string{
		"X-Request-Id: req_${request.uuid_short}",
		"X-Trace-Id: ${request.uuid}",
		"Content-Type: application/json",
	}
	_, got := Apply("", headers, nil, nil)
	for _, h := range got {
		if strings.Contains(h, "${request.") {
			t.Fatalf("placeholder left in header: %q", h)
		}
	}
	if got[2] != "Content-Type: application/json" {
		t.Errorf("static header altered: %q", got[2])
	}
}

// TestApply_DoesNotMutateInputs — strategies share matchedCommand
// pointers across requests; if Apply mutated headers in place the
// first request's UUID would freeze into every subsequent request.
// The HTTP strategy regression that motivates this whole package is
// exactly this class of bug.
func TestApply_DoesNotMutateInputs(t *testing.T) {
	originalBody := "trace=${request.uuid}"
	originalHeaders := []string{"X-Id: ${request.uuid_short}", "Static: ok"}

	// Snapshot
	bodyCopy := originalBody
	headersCopy := append([]string(nil), originalHeaders...)

	_, _ = Apply(originalBody, originalHeaders, nil, nil)

	if originalBody != bodyCopy {
		t.Errorf("input body mutated: was %q, now %q", bodyCopy, originalBody)
	}
	for i, h := range originalHeaders {
		if h != headersCopy[i] {
			t.Errorf("input headers[%d] mutated: was %q, now %q", i, headersCopy[i], h)
		}
	}
}

// TestApply_CapturedValuesHTMLEscaped — captured.* values originate
// from attacker request bodies and MUST be HTML-escaped before being
// rendered into a response (preserves the existing HTTP-strategy
// semantic; an attacker who submits "<script>" in a captured field
// shouldn't get script tags reflected verbatim).
func TestApply_CapturedValuesHTMLEscaped(t *testing.T) {
	body := `welcome ${captured.username}`
	vars := map[string]string{
		"capt:username": `<script>alert(1)</script>`,
	}
	got, _ := Apply(body, nil, vars, nil)
	if strings.Contains(got, "<script>") {
		t.Errorf("captured value not HTML-escaped: %q", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("expected escaped <script>, got %q", got)
	}
}

// TestApply_UnknownPlaceholderUntouched — placeholders for keys we
// don't know about are left literal. This is the "fail open visible"
// contract: a typo in a YAML lure (${captured.usrname} instead of
// ${captured.username}) is observable in test traffic, not silently
// stripped to "".
func TestApply_UnknownPlaceholderUntouched(t *testing.T) {
	body := `hello ${captured.unknown_key} and ${session.unset}`
	got, _ := Apply(body, nil, nil, nil)
	if !strings.Contains(got, "${captured.unknown_key}") {
		t.Errorf("unknown captured.* placeholder altered: %q", got)
	}
	if !strings.Contains(got, "${session.unset}") {
		t.Errorf("unknown session.* placeholder altered: %q", got)
	}
}

// TestApply_NilHeadersReturnsNil — TCP/TELNET pass nil for the
// headers slice. Apply should not allocate an empty slice in that
// case; nil-in / nil-out is the contract.
func TestApply_NilHeadersReturnsNil(t *testing.T) {
	_, got := Apply("body", nil, nil, nil)
	if got != nil {
		t.Errorf("expected nil headers, got %v", got)
	}
}

// Apply MUST resolve ${request.json.<dotted.path>} by parsing the request body
// as JSON and looking up the dotted path. Numbers emit unquoted, strings quoted,
// missing/parse-error fields emit "null". Closes the MCP id-echo protocol gap.

func TestApply_RequestJSON_NumericID(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":42,"method":"initialize"}`)
	tmpl := `{"jsonrpc":"2.0","id":${request.json.id},"result":{}}`
	got, _ := Apply(tmpl, nil, nil, body)
	if !strings.Contains(got, `"id":42`) {
		t.Fatalf("expected id:42, got: %s", got)
	}
}

func TestApply_RequestJSON_StringID(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":"req-abc","method":"x"}`)
	tmpl := `{"id":${request.json.id}}`
	got, _ := Apply(tmpl, nil, nil, body)
	if !strings.Contains(got, `"id":"req-abc"`) {
		t.Fatalf("expected id:\"req-abc\", got: %s", got)
	}
}

func TestApply_RequestJSON_MissingFieldFallsBackToNull(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","method":"x"}`) // no id
	tmpl := `{"id":${request.json.id}}`
	got, _ := Apply(tmpl, nil, nil, body)
	if !strings.Contains(got, `"id":null`) {
		t.Fatalf("expected id:null fallback, got: %s", got)
	}
}

func TestApply_RequestJSON_BodyParseErrorFallsBackToNull(t *testing.T) {
	body := []byte(`not json`)
	tmpl := `{"id":${request.json.id}}`
	got, _ := Apply(tmpl, nil, nil, body)
	if !strings.Contains(got, `"id":null`) {
		t.Fatalf("expected null on parse error, got: %s", got)
	}
}

func TestApply_RequestJSON_DottedPath(t *testing.T) {
	body := []byte(`{"params":{"clientInfo":{"name":"censys-inspector"}}}`)
	tmpl := `{"echo_client":${request.json.params.clientInfo.name}}`
	got, _ := Apply(tmpl, nil, nil, body)
	if !strings.Contains(got, `"echo_client":"censys-inspector"`) {
		t.Fatalf("expected dotted lookup, got: %s", got)
	}
}

func TestApply_RequestJSON_NoBodyDoesNotPanic(t *testing.T) {
	// HTTP GET requests have no body. Apply must tolerate nil body.
	tmpl := `{"id":${request.json.id}}`
	got, _ := Apply(tmpl, nil, nil, nil)
	if !strings.Contains(got, `"id":null`) {
		t.Fatalf("expected null with nil body, got: %s", got)
	}
}

// Apply MUST resolve ${time.now} to current RFC3339 UTC.
// ${time.ago.<N><unit>} resolves to (now - N units) RFC3339 UTC.
// Closes the frozen-ISO-timestamp class of honeypot fingerprint (5/19 audit).

func TestApply_TimeNow(t *testing.T) {
	got, _ := Apply(`{"now":"${time.now}"}`, nil, nil, nil)
	if strings.Contains(got, "${time.now}") {
		t.Fatalf("unrendered: %s", got)
	}
	var parsed struct{ Now time.Time }
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("not valid JSON: %s — %v", got, err)
	}
	d := time.Since(parsed.Now)
	if d < 0 || d > 5*time.Second {
		t.Fatalf("time.now off by %v: %s", d, got)
	}
}

// ${time.now.unix} resolves to current unix epoch seconds as an unquoted
// integer — the shape OpenAI/vLLM /v1/chat/completions responses use for
// the `created` field. Closes the frozen-epoch class of honeypot fingerprint
// (5/23: gpt-4.1-mini was lazying the in-prompt substitution and emitting
// "created":1710000000 verbatim on every response).
func TestApply_TimeNowUnix(t *testing.T) {
	got, _ := Apply(`{"created":${time.now.unix}}`, nil, nil, nil)
	if strings.Contains(got, "${time.now.unix}") {
		t.Fatalf("unrendered: %s", got)
	}
	var parsed struct{ Created int64 }
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("not valid JSON: %s — %v", got, err)
	}
	now := time.Now().Unix()
	if parsed.Created < now-5 || parsed.Created > now+5 {
		t.Fatalf("time.now.unix off: got %d, want within 5s of %d (rendered: %s)",
			parsed.Created, now, got)
	}
}

// Ensure the longer ${time.now.unix} pattern is resolved BEFORE the shorter
// ${time.now} prefix — otherwise time.now would substitute first and leave
// a stray ".unix}" trailing the RFC3339 stamp.
func TestApply_TimeNowUnix_DoesNotCollideWithTimeNow(t *testing.T) {
	got, _ := Apply(`{"a":"${time.now}","b":${time.now.unix}}`, nil, nil, nil)
	if strings.Contains(got, "${time.now") {
		t.Fatalf("unrendered: %s", got)
	}
	if strings.Contains(got, ".unix}") {
		t.Fatalf("partial substitution leak: %s", got)
	}
}

func TestApply_TimeAgo_Hours(t *testing.T) {
	got, _ := Apply(`{"started":"${time.ago.3h}"}`, nil, nil, nil)
	var parsed struct{ Started time.Time }
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid JSON: %s", got)
	}
	d := time.Since(parsed.Started)
	want := 3 * time.Hour
	if d < want-5*time.Second || d > want+5*time.Second {
		t.Fatalf("time.ago.3h off: got delta %v, want ~%v (rendered: %s)", d, want, got)
	}
}

func TestApply_TimeAgo_Days(t *testing.T) {
	got, _ := Apply(`{"rotated":"${time.ago.7d}"}`, nil, nil, nil)
	var parsed struct{ Rotated time.Time }
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("invalid JSON: %s", got)
	}
	d := time.Since(parsed.Rotated)
	want := 7 * 24 * time.Hour
	if d < want-time.Minute || d > want+time.Minute {
		t.Fatalf("time.ago.7d off: got delta %v, want ~%v", d, want)
	}
}

func TestApply_TimeAgo_Seconds(t *testing.T) {
	got, _ := Apply(`{"t":"${time.ago.30s}"}`, nil, nil, nil)
	if !strings.Contains(got, "T") || !strings.HasSuffix(strings.Split(got, `"`)[3], "Z") {
		t.Fatalf("not RFC3339 UTC: %s", got)
	}
}

func TestApply_TimeAgo_Minutes(t *testing.T) {
	got, _ := Apply(`{"t":"${time.ago.45m}"}`, nil, nil, nil)
	var parsed struct{ T time.Time }
	json.Unmarshal([]byte(got), &parsed)
	want := 45 * time.Minute
	d := time.Since(parsed.T)
	if d < want-5*time.Second || d > want+5*time.Second {
		t.Fatalf("time.ago.45m off: got %v want %v", d, want)
	}
}

func TestApply_TimeAgo_UnknownDurationLeftAlone(t *testing.T) {
	// Invalid duration unit should not panic; leaving template intact is
	// acceptable. Just don't panic and don't emit garbage.
	got, _ := Apply(`{"t":"${time.ago.5x}"}`, nil, nil, nil)
	// Either left as-is or emitted as null — both acceptable; check no panic.
	_ = got
}

func TestApply_TimeAndRequestJSONComposable(t *testing.T) {
	// Verifies the new time substitution doesn't break the existing
	// ${request.json.*} from task 3.1.
	body := []byte(`{"id":7}`)
	tmpl := `{"id":${request.json.id},"now":"${time.now}"}`
	got, _ := Apply(tmpl, nil, nil, body)
	if !strings.Contains(got, `"id":7`) {
		t.Fatalf("request.json broken: %s", got)
	}
	if strings.Contains(got, "${") {
		t.Fatalf("unrendered substitution: %s", got)
	}
}

// 2026-05-20: ${time.in.<N><unit>} — future-direction counterpart of time.ago.
// Used for STS-token Expiration, session expires_at, cert renewal cutoffs so
// they roll forward with wall-clock time instead of being frozen literals.
func TestApply_TimeIn_Hours(t *testing.T) {
	got, _ := Apply(`{"expires_at":"${time.in.12h}"}`, nil, nil, nil)
	// Body wraps the ISO into a JSON string; extract.
	var resp struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("got non-JSON response: %s", got)
	}
	parsed, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q is not RFC3339: %v", resp.ExpiresAt, err)
	}
	want := 12 * time.Hour
	d := time.Until(parsed)
	if d < want-30*time.Second || d > want+30*time.Second {
		t.Fatalf("time.in.12h off: got delta %v, want ~%v", d, want)
	}
}

func TestApply_TimeIn_Days(t *testing.T) {
	got, _ := Apply(`{"renew_by":"${time.in.7d}"}`, nil, nil, nil)
	var resp struct {
		RenewBy string `json:"renew_by"`
	}
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("got non-JSON response: %s", got)
	}
	parsed, err := time.Parse(time.RFC3339, resp.RenewBy)
	if err != nil {
		t.Fatalf("renew_by %q is not RFC3339: %v", resp.RenewBy, err)
	}
	if d := time.Until(parsed); d < 7*24*time.Hour-time.Minute || d > 7*24*time.Hour+time.Minute {
		t.Fatalf("time.in.7d off: got delta %v, want ~%v", d, 7*24*time.Hour)
	}
}

func TestApply_TimeIn_Mixed_With_TimeAgo(t *testing.T) {
	// Real-world: a session lure shows last_login in the past + expires_at
	// in the future. Both placeholders must coexist without interference.
	got, _ := Apply(`{"last_login":"${time.ago.2h}","expires_at":"${time.in.12h}"}`, nil, nil, nil)
	if !strings.Contains(got, `"last_login"`) || !strings.Contains(got, `"expires_at"`) {
		t.Fatalf("missing field in mixed-substitution output: %s", got)
	}
	if strings.Contains(got, "${time.") {
		t.Fatalf("unresolved placeholder remains: %s", got)
	}
}
