package responsesubs

import (
	"strings"
	"testing"
)

// TestApply_RequestVarsUnconditional — request-level placeholders fire
// even when sessionVars is nil. This is the contract MCP / TCP / TELNET
// rely on (they do not expose a session context).
func TestApply_RequestVarsUnconditional(t *testing.T) {
	body := `{"trace_id":"${request.uuid}","ts":${request.unix_ms}}`
	headers := []string{"X-Request-Id: req_${request.uuid_short}"}
	gotBody, gotHeaders := Apply(body, headers, nil)

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
		body, _ := Apply("${request.uuid}", nil, nil)
		if _, dup := seen[body]; dup {
			t.Fatalf("request.uuid repeated across calls: %q", body)
		}
		seen[body] = struct{}{}
	}
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
	got, _ := Apply(body, nil, vars)
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
	_, got := Apply("", headers, nil)
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

	_, _ = Apply(originalBody, originalHeaders, nil)

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
	got, _ := Apply(body, nil, vars)
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
	got, _ := Apply(body, nil, nil)
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
	_, got := Apply("body", nil, nil)
	if got != nil {
		t.Errorf("expected nil headers, got %v", got)
	}
}
