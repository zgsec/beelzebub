package HTTP

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mariocandela/beelzebub/v3/agentdetect"
	"github.com/mariocandela/beelzebub/v3/artifactstore"
	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/faults"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/lifecycle"
	"github.com/mariocandela/beelzebub/v3/noveltydetect"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/protocols/strategies/responsesubs"
	"github.com/mariocandela/beelzebub/v3/tracer"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// httpSessionState tracks per-IP state for agent detection on the HTTP handler.
type httpSessionState struct {
	mu       sync.Mutex
	seq      int
	timings  []int64
	lastSeen time.Time
	paths    []string // request paths for AI discovery detection
}

var (
	httpSessions     sync.Map // IP → *httpSessionState
	httpCleanupOnce  sync.Once
	httpJA4Cache     sync.Map // remoteAddr → JA4 string (per-TLS-connection, cleared on disconnect)
)

// startHTTPSessionCleanup launches a goroutine that prunes stale sessions every 5 minutes.
//
// Once-protected: the singleton is intentional — every HTTP service in
// configurations/services/ initializes the same HTTPStrategy and we only
// want one cleaner across the process. context.Background() preserves
// the previous no-shutdown behavior. When the strategy gains a lifecycle
// context, the seam is here.
func startHTTPSessionCleanup() {
	httpCleanupOnce.Do(func() {
		go lifecycle.Cleaner(context.Background(), 5*time.Minute, "http.session.cleanup", func() {
			cutoff := time.Now().Add(-30 * time.Minute)
			httpSessions.Range(func(key, value any) bool {
				state := value.(*httpSessionState)
				state.mu.Lock()
				stale := state.lastSeen.Before(cutoff)
				state.mu.Unlock()
				if stale {
					httpSessions.Delete(key)
				}
				return true
			})
		})
	})
}

var httpNoveltyCleanupOnce sync.Once

// startHTTPNoveltyCleanup launches a goroutine that periodically cleans the novelty store.
func startHTTPNoveltyCleanup(ns *noveltydetect.FingerprintStore, windowDays int) {
	if ns == nil {
		return
	}
	httpNoveltyCleanupOnce.Do(func() {
		maxAge := time.Duration(windowDays) * 24 * time.Hour
		go lifecycle.Cleaner(context.Background(), 5*time.Minute, "http.novelty.cleanup", func() {
			ns.Clean(maxAge)
		})
	})
}

// containsAIPath checks if any accumulated paths match known AI/MCP discovery patterns.
func containsAIPath(paths []string) bool {
	aiPatterns := []string{"/mcp", "/sse", "/.well-known/mcp", "/.well-known/ai-plugin",
		"/llms.txt", "/.cursor", "/api/tags", "/api/generate", "/v1/models", "/v1/chat"}
	for _, p := range paths {
		lp := strings.ToLower(p)
		for _, ai := range aiPatterns {
			if strings.Contains(lp, ai) {
				return true
			}
		}
	}
	return false
}

type HTTPStrategy struct {
	Bridge *bridge.ProtocolBridge
	Fault  *faults.Injector

	// Novelty detection (optional, nil when disabled)
	noveltyStore      *noveltydetect.FingerprintStore
	noveltyWindowDays int

	// Stateful HTTP session correlation (nil when servConf.State == nil or CookieName == "")
	cookieStore   *historystore.CookieSessionStore
	artifactStore *artifactstore.Store
}

// sessionContext bundles per-request stateful HTTP context so it can be
// threaded through buildHTTPResponse without additional globals.
type sessionContext struct {
	sess          *historystore.CookieSession      // nil if no live session for this request
	cookieStore   *historystore.CookieSessionStore // always non-nil when sctx != nil
	artifactStore *artifactstore.Store             // nil when ArtifactPath not configured
	cookieName    string                           // value of servConf.State.CookieName
	ttlSeconds    int                              // value of servConf.State.TTLSeconds

	// Cookie forgery: when the request presented a cookie that didn't
	// resolve to a live session AND the value matches a structural
	// forgery shape (JWT, hex, base64, common literal), forgedShape
	// and forgedValue carry the evidence. Both empty when no forgery
	// signal. Surfaces in trace events as Captured[svc.forged_cookie_*]
	// and overrides Handler to "<svc>/cookie_forgery".
	forgedShape string
	forgedValue string
}

type httpResponse struct {
	StatusCode int
	Headers    []string
	Body       string
}

// applyLLMOfflineResponse writes a persona-shaped error envelope into resp when
// the lure has llmOfflineResponse configured. Without llmOfflineResponse, behavior is
// identical to the legacy bare-text "500 Internal Server Error" — that
// matters for backward-compat with every non-LLM lure (CVE bait, Redis
// banner-only, etc.) and for the chat-LLM lures we haven't migrated yet.
//
// status==0 keeps the legacy 500. body=="" keeps the legacy bare text.
// Non-empty Body wins; non-zero Status wins.
func applyLLMOfflineResponse(resp *httpResponse, fb *parser.LLMOfflineResponse) {
	resp.StatusCode = 500
	resp.Body = "500 Internal Server Error"
	if fb == nil {
		return
	}
	if fb.Status != 0 {
		resp.StatusCode = fb.Status
	}
	if fb.Body != "" {
		resp.Body = fb.Body
	}
}

func (httpStrategy *HTTPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	// Novelty detection: create store if enabled in config
	if servConf.NoveltyDetection.Enabled && httpStrategy.noveltyStore == nil {
		httpStrategy.noveltyStore = noveltydetect.NewStore()
		httpStrategy.noveltyWindowDays = servConf.NoveltyDetection.WindowDays
		if httpStrategy.noveltyWindowDays <= 0 {
			httpStrategy.noveltyWindowDays = 7
		}
	}

	// Stateful HTTP: create cookie + artifact stores when configured.
	if servConf.State != nil && servConf.State.CookieName != "" {
		ttl := time.Duration(servConf.State.TTLSeconds) * time.Second
		if ttl == 0 {
			ttl = 30 * time.Minute
		}
		httpStrategy.cookieStore = historystore.NewCookieSessionStore(ttl)
		if servConf.State.ArtifactPath != "" {
			httpStrategy.artifactStore = artifactstore.New(
				servConf.State.ArtifactPath,
				servConf.State.ArtifactMaxBytes,
			)
		}
	}

	startHTTPSessionCleanup()
	startHTTPNoveltyCleanup(httpStrategy.noveltyStore, httpStrategy.noveltyWindowDays)
	serverMux := http.NewServeMux()

	serverMux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		// Build per-request session context when stateful mode is active.
		var sctx *sessionContext
		if httpStrategy.cookieStore != nil {
			sctx = &sessionContext{
				cookieStore:   httpStrategy.cookieStore,
				artifactStore: httpStrategy.artifactStore,
				cookieName:    servConf.State.CookieName,
				ttlSeconds:    servConf.State.TTLSeconds,
			}
			if c, err := request.Cookie(servConf.State.CookieName); err == nil {
				if cs, ok := httpStrategy.cookieStore.Get(c.Value); ok {
					sctx.sess = cs
				} else if shape := classifyForgedCookie(c.Value); shape != "" {
					sctx.forgedShape = shape
					// Truncate to 256 chars to bound capture cost.
					v := c.Value
					if len(v) > 256 {
						v = v[:256]
					}
					sctx.forgedValue = v
				}
			}
		}

		var matched bool
		var resp httpResponse
		var err error
		// fireTrace holds the trace-fire callback returned by buildHTTPResponse.
		// We invoke it AFTER applyLLMOfflineResponse + fault injection have
		// finalized resp, so the tracer event records what was actually written
		// to the wire — fixes the 2026-05-23 divergence where corpus showed
		// "404 Not Found!" while attackers received the configured vLLM envelope.
		var fireTrace fireTraceFunc
		for _, command := range servConf.Commands {
			var err error
			// URI regex must match. Method, when set, must also match
			// (case-insensitive). Empty Method = method-agnostic (legacy
			// behavior; existing configs that don't set Method are
			// unaffected).
			if !command.Regex.MatchString(request.RequestURI) {
				continue
			}
			if command.Method != "" && !strings.EqualFold(command.Method, request.Method) {
				continue
			}
			matched = true
			{
				resp, err, fireTrace = buildHTTPResponse(servConf, tr, command, request, httpStrategy.noveltyStore, sctx)
				if err != nil {
					log.Errorf("error building http response: %s: %v", request.RequestURI, err)
					applyLLMOfflineResponse(&resp, servConf.LLMOfflineResponse)
				}
				break
			}
		}
		// If none of the main commands matched, and we have a fallback command configured, process it here.
		// The regexp is ignored for fallback commands, as they are catch-all for any request.
		if !matched {
			command := servConf.FallbackCommand
			if command.Handler != "" || command.Plugin != "" {
				resp, err, fireTrace = buildHTTPResponse(servConf, tr, command, request, httpStrategy.noveltyStore, sctx)
				if err != nil {
					log.Errorf("error building http response: %s: %v", request.RequestURI, err)
					applyLLMOfflineResponse(&resp, servConf.LLMOfflineResponse)
				}
			}
		}
		// Fault injection: apply delay jitter and/or error faults.
		// The Fault injector is wired by builder.go from the YAML
		// faultInjection config. Delay faults sleep inside Apply()
		// (adds realistic latency). Error faults replace the response
		// with a 503 + Retry-After (simulates real service under load).
		var faultType string
		if httpStrategy.Fault != nil {
			faultResp, ft, faulted := httpStrategy.Fault.Apply()
			faultType = ft
			if faulted && ft != "delay" {
				resp.StatusCode = 503
				resp.Body = faultResp
				resp.Headers = []string{
					"Content-Type: application/json; charset=utf-8",
					"Retry-After: 5",
					"Server: " + extractServerHeader(resp.Headers),
				}
			}
		}
		_ = faultType // available for tracer event if needed

		// Fire the trace AFTER all resp modifications, so the event captures
		// the final wire values (post-fallback, post-fault-injection).
		if fireTrace != nil {
			fireTrace(&resp)
		}

		setResponseHeaders(responseWriter, resp.Headers, resp.StatusCode)
		fmt.Fprint(responseWriter, resp.Body)

	})
	go func() {
		ln, listenErr := net.Listen("tcp", servConf.Address)
		if listenErr != nil {
			log.Errorf("error during init HTTP Protocol: %v", listenErr)
			return
		}
		srv := &http.Server{
			Handler: serverMux,
			// ReadHeaderTimeout closes the Slowloris vector (a single attacker
			// dripping request-line / header bytes, holding the goroutine open).
			// 30s is generous enough that a legitimately slow probe still lands
			// while a Slowloris drip is dropped before it can pin a worker.
			// We deliberately do NOT set ReadTimeout / WriteTimeout — those
			// would break long-lived persona traffic (slow attackers, long
			// LLM-backed responses) which is intel we want to capture.
			ReadHeaderTimeout: 30 * time.Second,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, tracer.TeeConnKey, c)
			},
		}
		var err error
		if servConf.TLSKeyPath != "" && servConf.TLSCertPath != "" {
			// v8: JA4 TLS ClientHello fingerprinting via GetConfigForClient.
			// Go's stdlib parses the ClientHello and gives us the fields directly —
			// no raw byte capture needed. We store the JA4 per-IP for lookup
			// when tracing the request.
			srv.TLSConfig = &tls.Config{
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					ja4 := tracer.ComputeJA4FromClientHello(hello)
					if ja4 != "" {
						httpJA4Cache.Store(hello.Conn.RemoteAddr().String(), ja4)
					}
					return nil, nil // use default config
				},
			}
			err = srv.ServeTLS(tracer.NewTeeListener(ln, 65536, tracer.HTTPStopFunc), servConf.TLSCertPath, servConf.TLSKeyPath)
		} else {
			err = srv.Serve(tracer.NewTeeListener(ln, 65536, tracer.HTTPStopFunc))
		}
		if err != nil {
			log.Errorf("error during init HTTP Protocol: %v", err)
			return
		}
	}()

	log.WithFields(log.Fields{
		"port":     servConf.Address,
		"commands": len(servConf.Commands),
	}).Infof("Init service: %s", servConf.Description)
	return nil
}

// fireTraceFunc is invoked by the caller AFTER all post-build response
// modifications (applyLLMOfflineResponse + fault injection) so the tracer
// event reflects what was actually written to the wire — not the in-memory
// state at buildHTTPResponse's return point.
//
// Discovered 2026-05-23: when ExecuteModel failed on sensor-fra, the wire
// response was correctly the configured llmOfflineResponse envelope (curl
// received 500 + 219 bytes), but the tracer event recorded the pre-fix
// "404 Not Found!" bare-text from inside buildHTTPResponse's deferred
// trace fire. Corpus on research-1 looked like the lure was still broken
// when it wasn't. Returning the trace as a callback the caller invokes
// fixes the ordering.
type fireTraceFunc func(finalResp *httpResponse)

func buildHTTPResponse(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, command parser.Command, request *http.Request, ns *noveltydetect.FingerprintStore, sctx *sessionContext) (httpResponse, error, fireTraceFunc) {
	// v8: response timing — measure from buildHTTPResponse entry through
	// trace fire (covers static-handler + LLM plugin paths uniformly).
	// Trace fires from the caller AFTER all resp modifications complete.
	startedAt := time.Now()

	resp := httpResponse{
		Body:       command.Handler,
		Headers:    command.Headers,
		StatusCode: command.StatusCode,
	}

	// Limit body read to 1MB to prevent DoS attacks.
	// bodyBytes is reused for sessionCapture regex and artifactCapture — read only once.
	bodyBytes, err := io.ReadAll(io.LimitReader(request.Body, 1024*1024))
	body := ""
	if err == nil {
		body = string(bodyBytes)
	}

	var artifactSHA string

	// Build the trace-fire callback. Caller invokes with &resp AFTER any
	// applyLLMOfflineResponse / fault-injection mods, so the event captures
	// final wire values. Previously this ran in a defer inside buildHTTPResponse,
	// which fired before the caller could modify resp — the trace recorded
	// pre-fix values that diverged from what attackers actually received.
	//
	// v8 Phase 0 captures: ResponseBody (opt-in), ResponseHeaders (opt-in),
	// ResponseBytes (always), ResponseTimeMs (always). Gated by
	// servConf.CaptureResponseBody to keep storage cost opt-in.
	//
	// v8 Phase 5 captures: Captured map + SessionKey override for stateful services.
	fireTrace := func(finalResp *httpResponse) {
		responseTimeMs := time.Since(startedAt).Milliseconds()

		// Build the captured metadata map for the tracer event.
		eventCaptured := map[string]string{}
		if sctx != nil && sctx.sess != nil {
			for k, v := range sctx.sess.Captured {
				eventCaptured[k] = v
			}
			if len(sctx.sess.Cookie) >= 8 {
				eventCaptured["session.cookie_short"] = sctx.sess.Cookie[:8]
			}
		}
		if artifactSHA != "" {
			eventCaptured["artifact_sha256"] = artifactSHA
		}

		// Feature #6: Raw body first 8KB — captures attacker POST bodies verbatim
		// for stateful services. Gated on sctx != nil (stateless services unaffected).
		if sctx != nil && len(bodyBytes) > 0 && servConf.ServiceType != "" {
			n := len(bodyBytes)
			if n > RawBodyCapBytes {
				n = RawBodyCapBytes
			}
			eventCaptured[servConf.ServiceType+".raw_body_first_8kb"] = string(bodyBytes[:n])
		}

		// Feature #7: Referer / X-Forwarded-For / User-Agent header captures.
		// Only emit if the header is non-empty; keeps the Captured map lean for
		// stateless/uninteresting requests.
		if sctx != nil && servConf.ServiceType != "" {
			if v := request.Header.Get("Referer"); v != "" {
				eventCaptured[servConf.ServiceType+".referer"] = v
			}
			if v := request.Header.Get("X-Forwarded-For"); v != "" {
				eventCaptured[servConf.ServiceType+".xff"] = v
			}
			if v := request.UserAgent(); v != "" {
				eventCaptured[servConf.ServiceType+".user_agent_full"] = v
			}
		}

		// Feature #8: Cookie forgery — emit shape + truncated value when the
		// handler closure detected a structurally suspicious unresolved cookie.
		if sctx != nil && sctx.forgedShape != "" && servConf.ServiceType != "" {
			eventCaptured[servConf.ServiceType+".forged_cookie_shape"] = sctx.forgedShape
			eventCaptured[servConf.ServiceType+".forged_cookie_value"] = sctx.forgedValue
		}

		// Determine SessionKey override: stateful sessions use cookie[:16] for
		// cross-event correlation; stateless services keep the legacy "HTTP"+host key.
		sessionKeyOverride := ""
		if sctx != nil && sctx.sess != nil {
			sessionKeyOverride = sctx.sess.SessionKey
		}

		// Feature #8: Handler override — when forgery is detected, override the
		// tracer event's Handler to "<svc>/cookie_forgery" for downstream filtering.
		handlerOverride := ""
		if sctx != nil && sctx.forgedShape != "" && servConf.ServiceType != "" {
			handlerOverride = servConf.ServiceType + "/cookie_forgery"
		}

		traceRequest(request, tr, command, servConf.Description, servConf.ServiceType,
			body, ns, finalResp.Body, finalResp.StatusCode, strings.Join(finalResp.Headers, ", "),
			servConf.CaptureResponseBody, servConf.ResponseBodyMaxBytes, responseTimeMs,
			servConf.CaptureRequestBody, servConf.RequestBodyMaxBytes,
			nilIfEmpty(eventCaptured), sessionKeyOverride, handlerOverride)
	}

	// -------------------------------------------------------------------------
	// Stateful session logic
	// -------------------------------------------------------------------------

	// a. Enforce sessionAction:require — reject requests without a live session.
	if command.SessionAction == "require" && (sctx == nil || sctx.sess == nil) {
		resp.StatusCode = http.StatusUnauthorized
		resp.Body = "Unauthorized"
		resp.Headers = nil
		return resp, nil, fireTrace
	}

	// b. sessionAction:create — extract captures from request body + issue cookie.
	if command.SessionAction == "create" && sctx != nil {
		captured := make(map[string]string, len(command.SessionCapture))
		for key, pat := range command.SessionCapture {
			re, compileErr := regexp.Compile(pat)
			if compileErr != nil {
				log.Warnf("SessionCapture: invalid regex for key %q: %v", key, compileErr)
				continue
			}
			m := re.FindSubmatch(bodyBytes)
			if len(m) >= 2 {
				captured[key] = string(m[1])
			} else {
				captured[key] = "<missing>"
			}
		}

		host, _, splitErr := net.SplitHostPort(request.RemoteAddr)
		if splitErr != nil {
			host = request.RemoteAddr
		}

		sctx.sess = sctx.cookieStore.Create(host, request.Header.Get("X-JA4H"), captured)

		// Inject Set-Cookie into the response headers so setResponseHeaders picks it up.
		// Path=/ is required so clients (curl, browsers) send the cookie to all
		// paths under the same origin, not just the path the cookie was set from.
		// Without Path=/, curl scopes the cookie to the SetupWizard.aspx/ prefix,
		// breaking subsequent requests to /Host and /Services/...
		setCookie := fmt.Sprintf("Set-Cookie: %s=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d",
			sctx.cookieName, sctx.sess.Cookie, sctx.ttlSeconds)
		resp.Headers = append(resp.Headers, setCookie)
	}

	// c. Variable substitution on resp.Body and resp.Headers. See
	// applyResponseSubstitutions for the variable inventory + safety rules.
	// bodyBytes is passed so ${request.json.*} placeholders can be resolved
	// from the request body (e.g. echoing JSON-RPC id in lure responses).
	applyResponseSubstitutions(&resp, sctx, bodyBytes)

	// d. Artifact capture — write request body + session metadata to disk.
	if command.ArtifactCapture && sctx != nil && sctx.artifactStore != nil {
		caps := map[string]any{}
		if sctx.sess != nil {
			caps["session_key"] = sctx.sess.SessionKey
			for k, v := range sctx.sess.Captured {
				caps[k] = v
			}
		}
		if a, writeErr := sctx.artifactStore.Write(bodyBytes, caps); writeErr == nil {
			artifactSHA = a.SHA256
		}
	}

	if command.Plugin == plugins.LLMPluginName {
		llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)

		if err != nil {
			log.Errorf("error: %v", err)
			resp.Body = "404 Not Found!"
			return resp, err, fireTrace
		}

		llmHoneypot := plugins.BuildHoneypot(nil, tracer.HTTP, llmProvider, servConf)
		llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
		command := fmt.Sprintf("Method: %s, RequestURI: %s, Body: %s", request.Method, request.RequestURI, body)

		// Extract IP with fallback
		host, _, err := net.SplitHostPort(request.RemoteAddr)

		if err != nil {
			host = request.RemoteAddr
		}

		completions, err := llmHoneypotInstance.ExecuteModel(command, host)

		if err != nil {
			resp.Body = "404 Not Found!"
			return resp, fmt.Errorf("ExecuteModel error: %s, %v", command, err), fireTrace
		}

		resp.Body = completions

		// Re-run variable substitution on the LLM-generated body so prompt-
		// embedded placeholders like ${request.uuid_short} and
		// ${time.now.unix} land as real values on the wire. The first call
		// at step (c) happens BEFORE this branch overwrites resp.Body with
		// the LLM completion — so without this second pass, the chatcmpl-ID
		// and `created` timestamp ship as literal placeholder text (observed
		// 2026-05-23: `"id":"chatcmpl-RANDOM1","created":1710000000` static
		// across every /v1/chat/completions response — gpt-4.1-mini lazied
		// the in-prompt substitution and wrote the placeholder names back).
		// applyResponseSubstitutions is idempotent on already-substituted
		// text (no remaining ${...} patterns = no-op).
		applyResponseSubstitutions(&resp, sctx, bodyBytes)
	}

	return resp, nil, fireTrace
}

// nilIfEmpty returns nil if the map is empty, preserving omitempty behaviour
// on tracer.Event.Captured.
func nilIfEmpty(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	return m
}

// defaultResponseBodyMaxBytes is the truncation cap when a service config
// leaves ResponseBodyMaxBytes unset (zero). 64 KiB matches the existing
// 1 MiB request-body cap order-of-magnitude while keeping storage bounded
// for high-volume lures.
const defaultResponseBodyMaxBytes = 64 * 1024

// defaultRequestBodyMaxBytes mirrors defaultResponseBodyMaxBytes for the
// dedicated RequestBody field. Applied when CaptureRequestBody=true but
// RequestBodyMaxBytes is left at zero in the YAML.
const defaultRequestBodyMaxBytes = 64 * 1024

// RawBodyCapBytes is the maximum number of request-body bytes captured
// verbatim into the tracer event for stateful services (Feature #6).
// 8 KiB covers the vast majority of attacker payloads without blowing
// up storage for high-volume lures.
const RawBodyCapBytes = 8192

var (
	jwtRe    = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
)

// classifyForgedCookie returns a non-empty shape name for cookie values
// that look like exploit-dev forgery attempts. Empty = not suspicious.
// Used for operator profiling — distinguishing curl-with-junk vs.
// someone who built an exploit module that mints a cookie payload.
func classifyForgedCookie(value string) string {
	if value == "" {
		return ""
	}
	// Common literal bypass attempts (checked before length gate).
	switch strings.ToLower(value) {
	case "admin", "true", "1", "test", "administrator", "root":
		return "literal"
	}
	if len(value) < 16 {
		// Too short to be a plausible forgery; ignore (probably a typo/garbage).
		return ""
	}
	// JWT shape: 3 base64url segments separated by dots.
	if jwtRe.MatchString(value) {
		return "jwt"
	}
	// All-hex: operator tried hex encoding but length doesn't match a real cookie.
	if hexRe.MatchString(value) {
		return "hex"
	}
	// Base64 shape (with optional padding).
	if base64Re.MatchString(value) {
		return "base64"
	}
	return ""
}

func traceRequest(request *http.Request, tr tracer.Tracer, command parser.Command,
	HoneypotDescription, HoneypotServiceType, body string,
	ns *noveltydetect.FingerprintStore,
	responseBody string, responseStatusCode int, responseHeaders string,
	captureResponseBody bool, responseBodyMaxBytes int, responseTimeMs int64,
	captureRequestBody bool, requestBodyMaxBytes int,
	captured map[string]string, sessionKeyOverride string, handlerOverride string) {
	host, port, _ := net.SplitHostPort(request.RemoteAddr)
	// Extract destination port from the listener's local address
	destPort := ""
	if laddr, ok := request.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		destPort = tracer.ExtractPort(laddr.String())
	}
	// v8: JA4 TLS fingerprint from GetConfigForClient cache
	var ja4 string
	if v, ok := httpJA4Cache.Load(request.RemoteAddr); ok {
		ja4 = v.(string)
	}
	sessionKey := "HTTP" + host

	// Get or create per-IP session state for agent detection
	raw, _ := httpSessions.LoadOrStore(host, &httpSessionState{})
	state := raw.(*httpSessionState)
	state.mu.Lock()
	state.seq++
	seq := state.seq
	now := time.Now()
	if !state.lastSeen.IsZero() {
		delta := now.Sub(state.lastSeen).Milliseconds()
		state.timings = append(state.timings, delta)
		if len(state.timings) > 100 {
			state.timings = state.timings[len(state.timings)-100:]
		}
	}
	state.lastSeen = now
	state.paths = append(state.paths, request.RequestURI)
	if len(state.paths) > 200 {
		state.paths = state.paths[len(state.paths)-200:]
	}
	hasAIProbe := containsAIPath(state.paths)
	timings := make([]int64, len(state.timings))
	copy(timings, state.timings)
	state.mu.Unlock()

	// Agent classification
	sig := agentdetect.Signal{
		InterEventTimingsMs: timings,
		HasAIDiscoveryProbe: hasAIProbe,
	}
	verdict := agentdetect.IncrementalClassify(sig)

	// Novelty detection: record path and user agent per request
	var noveltyVerdict noveltydetect.Verdict
	if ns != nil {
		var novSig noveltydetect.Signal
		if ns.RecordPath(request.RequestURI) {
			novSig.PathsNew++
		}
		if ua := request.UserAgent(); ua != "" {
			novSig.UserAgentNew = ns.RecordUserAgent(ua)
		}
		noveltyVerdict = noveltydetect.IncrementalScore(novSig)
	}

	// Extract wire-order headers from TeeConn captured bytes, then release buffer
	var wireOrder []string
	if tc, ok := request.Context().Value(tracer.TeeConnKey).(*tracer.TeeConn); ok {
		wireOrder = tracer.ParseHeaderOrder(tc.RawBytes())
		tc.Release()
	}

	// Override SessionKey for stateful services: cookie[:16] enables cross-event
	// correlation across the cookie-session lifetime. Stateless services keep
	// the legacy "HTTP"+host key, which groups by source IP.
	if sessionKeyOverride != "" {
		sessionKey = sessionKeyOverride
	}

	event := tracer.Event{
		Msg:             "HTTP New request",
		RequestURI:      request.RequestURI,
		Protocol:        tracer.HTTP.String(),
		HTTPMethod:      request.Method,
		Body:            body,
		HostHTTPRequest: request.Host,
		UserAgent:       request.UserAgent(),
		Cookies:         mapCookiesToString(request.Cookies()),
		Headers:         mapHeaderToString(request.Header),
		HeadersMap:      request.Header,
		Status:          tracer.Stateless.String(),
		RemoteAddr:      request.RemoteAddr,
		SourceIp:        host,
		SourcePort:      port,
		ID:              uuid.New().String(),
		Description:     HoneypotDescription,
		ServiceType:     HoneypotServiceType,
		Handler:         command.Name,
		SessionKey:      sessionKey,
		Sequence:        seq,
		AgentScore:      verdict.Score,
		AgentCategory:   verdict.Category,
		AgentSignals:    verdict.SignalsString(),
		NoveltyScore:    noveltyVerdict.Score,
		NoveltyCategory: noveltyVerdict.Category,
		NoveltySignals:  noveltyVerdict.SignalsString(),
		JA4H:            tracer.ComputeJA4H(request, wireOrder),
		HeaderOrder:     strings.Join(wireOrder, ","),
		// Command mirrors the pattern used by SSH/MCP/TELNET handlers: a
		// short human-readable form of what the attacker sent. Downstream
		// exporters gate response-summary recording on Command being
		// non-empty, so populating this is what makes ResponseSummary fire
		// for HTTP lures.
		Command:         fmt.Sprintf("%s %s", request.Method, request.RequestURI),
		CommandOutput:      responseBody,
		ServicePort:        destPort,
		ResponseStatusCode: responseStatusCode,
		JA4:                ja4,
		// v8 Phase 0: response-side capture.
		// ResponseBytes is the byte count, ALWAYS set (cheap, useful for everyone).
		// ResponseTimeMs is the handler duration, ALWAYS set.
		// ResponseBody / ResponseHeaders gated by captureResponseBody flag — only
		// captured when the operator opts in for this service.
		ResponseBytes:   int64(len(responseBody)),
		ResponseTimeMs:  responseTimeMs,
		// v8 Phase 5: session capture metadata — nil when stateless (omitempty).
		Captured:        captured,
	}
	// Feature #8: Handler override — cookie_forgery events get a dedicated
	// handler label for downstream filtering / alerting.
	if handlerOverride != "" {
		event.Handler = handlerOverride
	}

	if captureResponseBody {
		maxBytes := responseBodyMaxBytes
		if maxBytes <= 0 {
			maxBytes = defaultResponseBodyMaxBytes
		}
		if len(responseBody) > maxBytes {
			event.ResponseBody = responseBody[:maxBytes]
		} else {
			event.ResponseBody = responseBody
		}
		event.ResponseHeaders = responseHeaders
	}
	if captureRequestBody {
		maxBytes := requestBodyMaxBytes
		if maxBytes <= 0 {
			maxBytes = defaultRequestBodyMaxBytes
		}
		if len(body) > maxBytes {
			event.RequestBody = body[:maxBytes]
		} else {
			event.RequestBody = body
		}
	}

	// WS-4 Slice B: hash full raw body bytes BEFORE any truncation has
	// influenced what's stored. Runs unconditionally — the hash always
	// reflects what was on the wire, regardless of whether CaptureRequestBody
	// or CaptureResponseBody is on (Slice B Q5).
	event.RequestBodySha256 = tracer.Sha256HexString(body)
	event.ResponseBodySha256 = tracer.Sha256HexString(responseBody)

	// WS-4 Slice B: parse multipart request bodies into structured parts so
	// uploaded filenames + content-types + per-part hashes are queryable
	// downstream. HTTP-only by design (Slice B Q2).
	if reqCT := request.Header.Get("Content-Type"); tracer.IsMultipartContentType(reqCT) {
		if parts := tracer.ParseMultipart(body, reqCT); len(parts) > 0 {
			event.RequestBodyParts = parts
		}
	}
	// Capture the TLS details from the request, if provided.
	if request.TLS != nil {
		event.Msg = "HTTPS New Request"
		event.TLSServerName = request.TLS.ServerName
	}
	tr.TraceEvent(event)
}

func mapHeaderToString(headers http.Header) string {
	headersString := ""

	for key := range headers {
		for _, values := range headers[key] {
			headersString += fmt.Sprintf("[Key: %s, values: %s],", key, values)
		}
	}

	return headersString
}

func mapCookiesToString(cookies []*http.Cookie) string {
	cookiesString := ""

	for _, cookie := range cookies {
		cookiesString += cookie.String()
	}

	return cookiesString
}

// applyResponseSubstitutions rewrites ${...} placeholders in resp.Body and
// every entry of resp.Headers. Thin wrapper around responsesubs.Apply that
// adapts the per-request HTTP sessionContext into the shared package's
// sessionVars map.
//
// Request-level vars (${request.*}) are always populated — every response
// gets a fresh per-request UUID + timestamp so headers like X-Request-Id
// can't be a fingerprint across requests or across sensors. UUIDs are
// generated by uuid.New (RFC 4122 v4, crypto/rand), so no XSS surface.
//
// Session-level vars (${session.*} / ${captured.*}) only fire when a live
// session exists. session.cookie / session.short are not HTML-escaped
// because the cookie is strictly hex ([0-9a-f], 64 chars) from
// historystore's crypto/rand + hex.EncodeToString. Captured values come
// from attacker request bodies and ARE escaped (responsesubs.Apply).
//
// The function is kept as a method on (*httpResponse) for backwards
// compat with the existing HTTP test suite; the actual substitution
// logic now lives in protocols/strategies/responsesubs so MCP / OLLAMA
// / TCP / TELNET share it.
func applyResponseSubstitutions(resp *httpResponse, sctx *sessionContext, reqBody []byte) {
	var sessionVars map[string]string
	if sctx != nil && sctx.sess != nil {
		sessionVars = make(map[string]string, 2+len(sctx.sess.Captured))
		short := sctx.sess.Cookie
		if len(short) > 8 {
			short = short[:8]
		}
		sessionVars["cookie"] = sctx.sess.Cookie
		sessionVars["short"] = short
		for k, v := range sctx.sess.Captured {
			sessionVars["capt:"+k] = v
		}
	}
	resp.Body, resp.Headers = responsesubs.Apply(resp.Body, resp.Headers, sessionVars, reqBody)
}

// extractServerHeader pulls the Server value from a header slice, falling back to "nginx/1.25.4".
func extractServerHeader(headers []string) string {
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "Server") {
			return strings.TrimSpace(parts[1])
		}
	}
	return "nginx/1.25.4"
}

func setResponseHeaders(responseWriter http.ResponseWriter, headers []string, statusCode int) {
	for _, headerStr := range headers {
		keyValue := strings.Split(headerStr, ":")
		if len(keyValue) > 1 {
			responseWriter.Header().Add(keyValue[0], keyValue[1])
		}
	}
	// http.StatusText(statusCode): empty string if the code is unknown.
	if len(http.StatusText(statusCode)) > 0 {
		responseWriter.WriteHeader(statusCode)
	}
}
