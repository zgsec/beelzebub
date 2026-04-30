package HTTP

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/artifactstore"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// captureTracer is a tracer.Tracer implementation that records every
// emitted event in-memory for test assertions.
type captureTracer struct {
	mu     sync.Mutex
	events []tracer.Event
}

func (c *captureTracer) TraceEvent(e tracer.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureTracer) last() tracer.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return tracer.Event{}
	}
	return c.events[len(c.events)-1]
}

// stubAddr lets us seed an http.Request's LocalAddrContextKey so the
// destPort extraction inside traceRequest doesn't fall over.
type stubAddr struct{ s string }

func (a *stubAddr) Network() string { return "tcp" }
func (a *stubAddr) String() string  { return a.s }

// newTestRequest builds a minimal *http.Request that traceRequest can
// process without blowing up on missing context (TeeConn, dest port).
func newTestRequest(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.42:54321"
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8888"}))
	return req.WithContext(ctx)
}

// TestTraceRequest_ResponseBodyCapturedWhenFlagOn — Threat A/H: when
// captureResponseBody=true, the served body must appear in
// event.ResponseBody verbatim, ResponseHeaders is filled, and
// ResponseBytes/ResponseTimeMs/ResponseStatusCode are set.
func TestTraceRequest_ResponseBodyCapturedWhenFlagOn(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}
	respBody := `{"id":"chatcmpl-x","model":"llama3.1:8b-instruct-q8_0",` +
		`"choices":[{"message":{"content":"llama3.1:8b-instruct-q8_0"}}]}`
	respHeaders := "Content-Type: application/json, Server: uvicorn"

	traceRequest(req, tt, cmd,
		"OpenAI-compatible inference API", "openai-compat",
		"" /* request body */, nil /* novelty store */,
		respBody, 200, respHeaders,
		true /* captureResponseBody */, 0 /* default 64KiB */, 42 /* responseTimeMs */,
		nil /* captured */, "" /* sessionKeyOverride */)

	got := tt.last()
	if got.ResponseBody != respBody {
		t.Fatalf("ResponseBody not captured.\n  want: %q\n  got:  %q", respBody, got.ResponseBody)
	}
	if got.ResponseHeaders != respHeaders {
		t.Errorf("ResponseHeaders mismatch.\n  want: %q\n  got:  %q", respHeaders, got.ResponseHeaders)
	}
	if got.ResponseBytes != int64(len(respBody)) {
		t.Errorf("ResponseBytes: want %d, got %d", len(respBody), got.ResponseBytes)
	}
	if got.ResponseTimeMs != 42 {
		t.Errorf("ResponseTimeMs: want 42, got %d", got.ResponseTimeMs)
	}
	if got.ResponseStatusCode != 200 {
		t.Errorf("ResponseStatusCode: want 200, got %d", got.ResponseStatusCode)
	}
}

// TestTraceRequest_ResponseBodyOmittedWhenFlagOff — Threat A defense in
// depth: when captureResponseBody=false (default), ResponseBody and
// ResponseHeaders must be empty, but ResponseBytes (count) and
// ResponseTimeMs are still populated.
func TestTraceRequest_ResponseBodyOmittedWhenFlagOff(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}
	respBody := "AKIAIOSFODNN7EXAMPLE leaks here when flag is off — should NOT land in ResponseBody"

	traceRequest(req, tt, cmd, "desc", "svc", "", nil,
		respBody, 200, "Content-Type: text/plain",
		false /* captureResponseBody OFF */, 0, 5,
		nil, "")

	got := tt.last()
	if got.ResponseBody != "" {
		t.Fatalf("ResponseBody must be empty when flag off; got %q", got.ResponseBody)
	}
	if got.ResponseHeaders != "" {
		t.Errorf("ResponseHeaders must be empty when flag off; got %q", got.ResponseHeaders)
	}
	if got.ResponseBytes != int64(len(respBody)) {
		t.Errorf("ResponseBytes still expected (count is harmless): want %d, got %d",
			len(respBody), got.ResponseBytes)
	}
	if got.ResponseTimeMs != 5 {
		t.Errorf("ResponseTimeMs always populated: want 5, got %d", got.ResponseTimeMs)
	}
}

// TestTraceRequest_ResponseBodyTruncatedAtMax — bounded storage:
// captureResponseBody=true with a small max truncates the body, but
// ResponseBytes still reports the FULL pre-truncation byte count.
func TestTraceRequest_ResponseBodyTruncatedAtMax(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}
	respBody := strings.Repeat("A", 500)
	maxBytes := 100

	traceRequest(req, tt, cmd, "desc", "svc", "", nil,
		respBody, 200, "Content-Type: text/plain",
		true, maxBytes, 1,
		nil, "")

	got := tt.last()
	if len(got.ResponseBody) != maxBytes {
		t.Fatalf("ResponseBody truncation: want exactly %d bytes, got %d",
			maxBytes, len(got.ResponseBody))
	}
	if got.ResponseBytes != int64(len(respBody)) {
		t.Errorf("ResponseBytes must reflect full pre-truncation size: want %d, got %d",
			len(respBody), got.ResponseBytes)
	}
}

// TestTraceRequest_DefaultMaxAppliedWhenZero — when responseBodyMaxBytes=0
// (operator left the YAML field unset), the runtime default of 64 KiB
// applies.
func TestTraceRequest_DefaultMaxAppliedWhenZero(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}
	respBody := strings.Repeat("X", 64*1024+10) // 10 bytes over default

	traceRequest(req, tt, cmd, "desc", "svc", "", nil,
		respBody, 200, "",
		true, 0 /* zero → use default 64 KiB */, 1,
		nil, "")

	got := tt.last()
	if len(got.ResponseBody) != defaultResponseBodyMaxBytes {
		t.Fatalf("default max not applied: want %d, got %d",
			defaultResponseBodyMaxBytes, len(got.ResponseBody))
	}
	if got.ResponseBytes != int64(len(respBody)) {
		t.Errorf("ResponseBytes must reflect untruncated count: want %d, got %d",
			len(respBody), got.ResponseBytes)
	}
}

// TestTraceRequest_ResponseTimeAlwaysPopulated — even when capture is OFF,
// ResponseTimeMs is populated. Universal signal, no canary leak risk.
func TestTraceRequest_ResponseTimeAlwaysPopulated(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}

	for _, capture := range []bool{true, false} {
		traceRequest(req, tt, cmd, "desc", "svc", "", nil,
			"x", 200, "", capture, 64*1024, 7,
			nil, "")
		got := tt.last()
		if got.ResponseTimeMs != 7 {
			t.Errorf("captureResponseBody=%v: ResponseTimeMs not populated (got %d)",
				capture, got.ResponseTimeMs)
		}
	}
}

// ---------------------------------------------------------------------------
// Phase 5: stateful session tests
// ---------------------------------------------------------------------------

// TestHTTP_SessionCreateSetsCookieAndCaptures verifies that sessionAction:create
// issues a Set-Cookie header, populates the cookie store, extracts sessionCapture
// regex matches from the request body, and overrides event.SessionKey to the
// cookie[:16] session key.
func TestHTTP_SessionCreateSetsCookieAndCaptures(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(10 * time.Minute)
	defer cookieStore.Stop()

	sctx := &sessionContext{
		cookieStore: cookieStore,
		cookieName:  ".ASPXAUTH",
		ttlSeconds:  600,
	}

	cmd := parser.Command{
		Name:          "screenconnect/auth_bypass",
		StatusCode:    302,
		SessionAction: "create",
		SessionCapture: map[string]string{
			"screenconnect.operator_user": `<Username>([^<]+)</Username>`,
		},
	}

	body := strings.NewReader(`<SetupWizard><Username>pwn</Username></SetupWizard>`)
	req := httptest.NewRequest(http.MethodPost, "/SetupWizard.aspx", body)
	req.RemoteAddr = "203.0.113.42:54321"
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8042"}))
	req = req.WithContext(ctx)

	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "screenconnect",
		ServiceType: "screenconnect",
		State:       &parser.State{CookieName: ".ASPXAUTH", TTLSeconds: 600},
	}

	resp, err := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx)
	if err != nil {
		t.Fatal(err)
	}

	// Set-Cookie header must be injected into resp.Headers.
	foundSetCookie := false
	for _, h := range resp.Headers {
		if strings.HasPrefix(h, "Set-Cookie:") && strings.Contains(h, ".ASPXAUTH=") {
			foundSetCookie = true
		}
	}
	if !foundSetCookie {
		t.Fatalf("missing Set-Cookie in resp.Headers: %v", resp.Headers)
	}

	// Cookie store must have exactly one live session.
	if cookieStore.Len() != 1 {
		t.Fatalf("expected 1 cookie session, got %d", cookieStore.Len())
	}

	// Tracer event must carry the captured operator_user field.
	got := tt.last()
	if got.Captured["screenconnect.operator_user"] != "pwn" {
		t.Fatalf("Captured[screenconnect.operator_user] not set correctly: %+v", got.Captured)
	}

	// SessionKey must be overridden to cookie[:16], not the default "HTTP"+ip form.
	if got.SessionKey == "HTTP203.0.113.42" || len(got.SessionKey) != 16 {
		t.Fatalf("SessionKey not overridden to cookie key: %q", got.SessionKey)
	}
}

// TestHTTP_SessionRequireRejectsUnauthed verifies that sessionAction:require
// returns 401 Unauthorized when no live session cookie is present, and that the
// tracer event still fires (recording the rejection).
func TestHTTP_SessionRequireRejectsUnauthed(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(10 * time.Minute)
	defer cookieStore.Stop()

	// sctx has no live session (sess == nil).
	sctx := &sessionContext{
		cookieStore: cookieStore,
		cookieName:  ".ASPXAUTH",
		ttlSeconds:  600,
	}

	cmd := parser.Command{
		Name:          "screenconnect/dashboard",
		StatusCode:    200,
		Handler:       "Welcome, ${captured.screenconnect.operator_user}",
		SessionAction: "require",
	}

	req := httptest.NewRequest(http.MethodGet, "/Administration", nil)
	req.RemoteAddr = "203.0.113.99:12345"
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8042"}))
	req = req.WithContext(ctx)

	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "screenconnect",
		ServiceType: "screenconnect",
		State:       &parser.State{CookieName: ".ASPXAUTH", TTLSeconds: 600},
	}

	resp, err := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", resp.StatusCode)
	}
	if resp.Body != "Unauthorized" {
		t.Fatalf("expected body %q, got %q", "Unauthorized", resp.Body)
	}
	// Tracer must still fire even on the 401 path.
	got := tt.last()
	if got.ResponseStatusCode != http.StatusUnauthorized {
		t.Fatalf("tracer event ResponseStatusCode: want 401, got %d", got.ResponseStatusCode)
	}
}

// TestHTTP_ArtifactCaptureWritesAndAddsSHA verifies that ArtifactCapture:true
// writes the request body to the artifact store and adds artifact_sha256 to the
// tracer event's Captured map. Uses t.TempDir() so no cleanup is needed.
func TestHTTP_ArtifactCaptureWritesAndAddsSHA(t *testing.T) {
	dir := t.TempDir()

	cookieStore := historystore.NewCookieSessionStore(10 * time.Minute)
	defer cookieStore.Stop()

	// Pre-create a session so sess != nil (required by ArtifactCapture path).
	sess := cookieStore.Create("203.0.113.7", "", map[string]string{"src": "test"})

	astore := artifactstore.New(dir, 0 /* no size limit */)
	sctx := &sessionContext{
		sess:          sess,
		cookieStore:   cookieStore,
		artifactStore: astore,
		cookieName:    ".ASPXAUTH",
		ttlSeconds:    600,
	}

	payload := []byte(`GET /secret HTTP/1.1\r\nHost: target\r\n\r\n`)
	cmd := parser.Command{
		Name:            "capture-payload",
		StatusCode:      200,
		Handler:         "ok",
		ArtifactCapture: true,
	}

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(string(payload)))
	req.RemoteAddr = "203.0.113.7:9999"
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8042"}))
	req = req.WithContext(ctx)

	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "capture-lure",
		ServiceType: "capture",
		State: &parser.State{
			CookieName:   ".ASPXAUTH",
			TTLSeconds:   600,
			ArtifactPath: dir,
		},
	}

	_, err := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx)
	if err != nil {
		t.Fatal(err)
	}

	// Tracer event must have artifact_sha256 set.
	got := tt.last()
	sha, ok := got.Captured["artifact_sha256"]
	if !ok || sha == "" {
		t.Fatalf("artifact_sha256 not in event.Captured: %+v", got.Captured)
	}

	// The .bin file must exist in the artifact directory.
	binPath := strings.Join([]string{dir, sha + ".bin"}, string(os.PathSeparator))
	if _, statErr := os.Stat(binPath); statErr != nil {
		t.Fatalf("artifact .bin file not found at %s: %v", binPath, statErr)
	}
}
