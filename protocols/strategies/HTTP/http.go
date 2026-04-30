package HTTP

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
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
	"github.com/mariocandela/beelzebub/v3/noveltydetect"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
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
func startHTTPSessionCleanup() {
	httpCleanupOnce.Do(func() {
		go func() {
			for {
				time.Sleep(5 * time.Minute)
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
			}
		}()
	})
}

var httpNoveltyCleanupOnce sync.Once

// startHTTPNoveltyCleanup launches a goroutine that periodically cleans the novelty store.
func startHTTPNoveltyCleanup(ns *noveltydetect.FingerprintStore, windowDays int) {
	if ns == nil {
		return
	}
	httpNoveltyCleanupOnce.Do(func() {
		go func() {
			maxAge := time.Duration(windowDays) * 24 * time.Hour
			for {
				time.Sleep(5 * time.Minute)
				ns.Clean(maxAge)
			}
		}()
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

func (httpStrategy HTTPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
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
				resp, err = buildHTTPResponse(servConf, tr, command, request, httpStrategy.noveltyStore, sctx)
				if err != nil {
					log.Errorf("error building http response: %s: %v", request.RequestURI, err)
					resp.StatusCode = 500
					resp.Body = "500 Internal Server Error"
				}
				break
			}
		}
		// If none of the main commands matched, and we have a fallback command configured, process it here.
		// The regexp is ignored for fallback commands, as they are catch-all for any request.
		if !matched {
			command := servConf.FallbackCommand
			if command.Handler != "" || command.Plugin != "" {
				resp, err = buildHTTPResponse(servConf, tr, command, request, httpStrategy.noveltyStore, sctx)
				if err != nil {
					log.Errorf("error building http response: %s: %v", request.RequestURI, err)
					resp.StatusCode = 500
					resp.Body = "500 Internal Server Error"
				}
			}
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

func buildHTTPResponse(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, command parser.Command, request *http.Request, ns *noveltydetect.FingerprintStore, sctx *sessionContext) (httpResponse, error) {
	// v8: response timing — measure from buildHTTPResponse entry through
	// deferred trace fire (covers static-handler + LLM plugin paths uniformly).
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

	// Trace AFTER the response body is finalized (including LLM-plugin generated
	// content) so tracer.Event.CommandOutput reflects what was actually served
	// to the attacker. Defer ensures the trace fires on both success and error
	// return paths. This aligns the HTTP handler with MCP/SSH/TELNET handlers,
	// which all populate CommandOutput; the HTTP omission was historical and
	// broke downstream canary/response-correlation analytics.
	//
	// v8 Phase 0 additions: ResponseBody (opt-in), ResponseHeaders (opt-in),
	// ResponseBytes (always), ResponseTimeMs (always). Gated by
	// servConf.CaptureResponseBody to keep storage cost opt-in.
	//
	// v8 Phase 5 additions: Captured map + SessionKey override for stateful services.
	defer func() {
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
			body, ns, resp.Body, resp.StatusCode, strings.Join(resp.Headers, ", "),
			servConf.CaptureResponseBody, servConf.ResponseBodyMaxBytes, responseTimeMs,
			nilIfEmpty(eventCaptured), sessionKeyOverride, handlerOverride)
	}()

	// -------------------------------------------------------------------------
	// Stateful session logic
	// -------------------------------------------------------------------------

	// a. Enforce sessionAction:require — reject requests without a live session.
	if command.SessionAction == "require" && (sctx == nil || sctx.sess == nil) {
		resp.StatusCode = http.StatusUnauthorized
		resp.Body = "Unauthorized"
		resp.Headers = nil
		return resp, nil
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
		setCookie := fmt.Sprintf("Set-Cookie: %s=%s; HttpOnly; SameSite=Lax; Max-Age=%d",
			sctx.cookieName, sctx.sess.Cookie, sctx.ttlSeconds)
		resp.Headers = append(resp.Headers, setCookie)
	}

	// c. Variable substitution on resp.Body using session data.
	if sctx != nil && sctx.sess != nil {
		short := sctx.sess.Cookie
		if len(short) > 8 {
			short = short[:8]
		}
		// Variable substitution. ${session.cookie} and ${session.short} are not
		// HTML-escaped because the cookie is strictly hex ([0-9a-f], 64 chars)
		// from historystore's crypto/rand + hex.EncodeToString — no XSS surface.
		// Captured values come from attacker request bodies, so they ARE escaped.
		pairs := []string{
			"${session.cookie}", sctx.sess.Cookie,
			"${session.short}", short,
		}
		for k, v := range sctx.sess.Captured {
			pairs = append(pairs, "${captured."+k+"}", html.EscapeString(v))
		}
		resp.Body = strings.NewReplacer(pairs...).Replace(resp.Body)
	}

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
			return resp, err
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
			return resp, fmt.Errorf("ExecuteModel error: %s, %v", command, err)
		}

		resp.Body = completions
	}

	return resp, nil
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
