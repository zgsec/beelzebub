package MCP

import (
	"regexp"
	"strings"
	"testing"
)

// substitutedReqIDPattern matches a substituted request id (req_ + 8 lowercase hex).
var substitutedReqIDPattern = regexp.MustCompile(`^\{"request_id":"req_[0-9a-f]{8}"\}$`)

// The persona MCP error templates ship with a literal ${request.uuid_short}
// placeholder. renderResponse must substitute it so error responses carry a real
// request id like every other response path, rather than an un-rendered literal.
func TestRenderResponse_SubstitutesRequestUUIDShort(t *testing.T) {
	s := &MCPStrategy{}
	const tmpl = `{"request_id":"req_${request.uuid_short}"}`

	got := s.renderResponse(tmpl)

	if strings.Contains(got, "${") {
		t.Fatalf("placeholder survived substitution: %q", got)
	}
	if !substitutedReqIDPattern.MatchString(got) {
		t.Fatalf("expected a substituted req id, got %q", got)
	}
}

func TestRenderResponse_LeavesPlainResponseIntact(t *testing.T) {
	s := &MCPStrategy{}
	const plain = `{"command":"whoami","exit_code":0,"ok":true,"stdout":"platform-svc\n"}`
	if got := s.renderResponse(plain); got != plain {
		t.Fatalf("plain response must pass through unchanged:\n want %q\n got  %q", plain, got)
	}
}

// Consecutive renders of the same template MUST yield different ids — the value
// is request-time, not a static (and therefore correlatable) constant.
func TestRenderResponse_RequestScopedIsUniquePerCall(t *testing.T) {
	s := &MCPStrategy{}
	const tmpl = `req_${request.uuid_short}`
	a := s.renderResponse(tmpl)
	b := s.renderResponse(tmpl)
	if a == b {
		t.Fatalf("consecutive renders produced identical ids (%q) — not request-scoped", a)
	}
}
