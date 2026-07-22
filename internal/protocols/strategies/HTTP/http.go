package HTTP

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/agentdetect"
	"github.com/beelzebub-labs/beelzebub/v3/internal/artifactstore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/bridge"
	"github.com/beelzebub-labs/beelzebub/v3/internal/faults"
	"github.com/beelzebub-labs/beelzebub/v3/internal/historystore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/lifecycle"
	"github.com/beelzebub-labs/beelzebub/v3/internal/noveltydetect"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/responsesubs"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"

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
	httpSessions    sync.Map // IP → *httpSessionState
	httpCleanupOnce sync.Once
	httpJA4Cache    sync.Map // remoteAddr → JA4 string (per-TLS-connection, cleared on disconnect)
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

	// WP gadget-chain session store (Task 7). nil unless some command's
	// ResponseMirror config carries an enabled Chain block — see
	// findMirrorChain and its call site in Init. nil here is the gate that
	// keeps every armed-chain code path (the auth-stage routing branch and
	// the sess argument to MirrorRespond/MirrorDelayMs) a complete no-op for
	// every service that hasn't opted in.
	chainStore *plugins.ChainStore
}

// chainStoreEntryCap bounds the WP gadget-chain session store passed into
// plugins.NewChainStore — the single cap for that store; package plugins
// itself defines no cap of its own. An attacker rotating source IPs across
// chain attempts evicts old idle sessions instead of growing the map
// without bound.
const chainStoreEntryCap = 4096

// findMirrorChain scans a service's commands (main + fallback) for the
// first ResponseMirror config carrying a Chain block, so Init can decide
// whether to arm the WP gadget-chain session store for this service.
// Returns nil when no command's mirror config has Chain set — the default
// for every service that hasn't added a `chain:` key to its mirror YAML.
func findMirrorChain(servConf parser.BeelzebubServiceConfiguration) *parser.MirrorChain {
	for _, c := range servConf.Commands {
		if c.Mirror != nil && c.Mirror.Chain != nil {
			return c.Mirror.Chain
		}
	}
	if servConf.FallbackCommand.Mirror != nil && servConf.FallbackCommand.Mirror.Chain != nil {
		return servConf.FallbackCommand.Mirror.Chain
	}
	return nil
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

// commandMatches reports whether a command fires for a request: its URI regex
// must match, and its optional Method and optional BodyRegex must also match
// when set. Empty Method / nil BodyRegex = agnostic, which is the legacy
// behavior every pre-existing config relies on.
//
// Extracted rather than inlined so the matching contract is directly testable —
// a test that reimplements this logic would assert its own copy, not the code
// that actually serves requests.
func commandMatches(command parser.Command, uri, method, body string) bool {
	if command.Regex == nil || !command.Regex.MatchString(uri) {
		return false
	}
	if command.Method != "" && !strings.EqualFold(command.Method, method) {
		return false
	}
	if command.BodyRegex != nil && !command.BodyRegex.MatchString(body) {
		return false
	}
	return true
}

// anyBodyRegex reports whether any command in the service needs the request
// body for matching. When false the handler skips buffering entirely, so
// configs that don't use bodyRegex — i.e. every pre-existing one — keep the
// exact prior behavior and pay no extra allocation per request.
func anyBodyRegex(commands []parser.Command) bool {
	for _, c := range commands {
		if c.BodyRegex != nil {
			return true
		}
	}
	return false
}

// extractPluginZipPart pulls the "pluginzip" file part out of a
// multipart/form-data body — the shape poc.py's upload-plugin POST uses
// (name="pluginzip"; filename="<slug>.zip"). contentType is the request's
// raw Content-Type header value, which carries the multipart boundary as a
// parameter; body is the already-buffered (and already 1MiB-capped, see
// buildHTTPResponse's bodyBytes read) request body. Returns an error if
// contentType isn't multipart, has no boundary, the body doesn't parse, or
// no part named "pluginzip" is present — callers treat any of those as
// "not a request this stage handles" and fall through unchanged.
//
// This function only ever reads the part into memory and returns its
// bytes; it never writes them to disk itself (that's chainArtifactStore.Write,
// the sole consumer of its return value) and never opens, unzips, or
// executes anything.
func extractPluginZipPart(contentType string, body []byte) (filename string, data []byte, err error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", nil, fmt.Errorf("extractPluginZipPart: parse content-type: %w", err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return "", nil, fmt.Errorf("extractPluginZipPart: not multipart (%s)", mediaType)
	}
	boundary, ok := params["boundary"]
	if !ok || boundary == "" {
		return "", nil, fmt.Errorf("extractPluginZipPart: no multipart boundary")
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, partErr := reader.NextPart()
		if partErr == io.EOF {
			return "", nil, fmt.Errorf("extractPluginZipPart: no pluginzip part found")
		}
		if partErr != nil {
			return "", nil, fmt.Errorf("extractPluginZipPart: %w", partErr)
		}
		if part.FormName() != "pluginzip" {
			continue
		}
		zipBytes, readErr := io.ReadAll(part)
		if readErr != nil {
			return "", nil, fmt.Errorf("extractPluginZipPart: reading pluginzip part: %w", readErr)
		}
		return part.FileName(), zipBytes, nil
	}
}

// wp2ShellRestRoutePrefix and wp2ShellPrettyPathPrefix are the two shapes
// the S9 command POST against the fake shell route (registered by the S7
// plugin upload) can arrive in: poc.py's own form dispatches through
// WordPress's ?rest_route= query-string router (request.URL.Path stays
// "/"), while a pretty-permalink WordPress instance would expose the same
// REST route under /wp-json/... instead.
const (
	wp2ShellRestRoutePrefix  = "/wp2shell/v1/"
	wp2ShellPrettyPathPrefix = "/wp-json/wp2shell/v1/"
)

// isWP2ShellCommandRequest reports whether request is the exploit's S9
// command POST against the fake shell route, in either form. Neither form
// is a single, static path, so this can't be folded into the exact-match
// switch below the way S4-S8 are — it's checked separately.
func isWP2ShellCommandRequest(request *http.Request) bool {
	if request.Method != http.MethodPost {
		return false
	}
	if strings.HasPrefix(request.URL.Query().Get("rest_route"), wp2ShellRestRoutePrefix) {
		return true
	}
	return strings.HasPrefix(request.URL.Path, wp2ShellPrettyPathPrefix)
}

func (httpStrategy *HTTPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	// Bind the fault injector PER-SERVICE, here, into a local the handler
	// closure captures — exactly as servConf is captured per service below.
	//
	// httpStrategy is a SINGLE instance shared across every HTTP service, and
	// builder.go sets `.Fault = <injector>` then calls Init for each service in
	// turn. Reading httpStrategy.Fault at request time (the previous behaviour)
	// therefore used whichever service was initialised LAST, not the service the
	// request actually hit — so fault injection configured only on the LLM lure
	// (with LLM-shaped 5xx bodies) fired on unrelated HTTP lures. Capturing the
	// value now, while the shared field still holds THIS service's injector,
	// scopes faults to the service that declared them. nil = no injection.
	fault := httpStrategy.Fault

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

	// WP gadget-chain session store (Task 7): armed only when some command's
	// ResponseMirror config carries an enabled Chain block. Chain.Enabled
	// (not just Chain != nil) gates arming here, so `chain: {enabled: false}`
	// — a config that opted into the block but explicitly turned it off —
	// leaves chainStore nil same as no `chain:` key at all. compileMirror
	// has already defaulted CheckpointTTLSecs (>0) by the time Init runs, so
	// no additional zero-guard is needed here.
	if chain := findMirrorChain(servConf); chain != nil && chain.Enabled {
		httpStrategy.chainStore = plugins.NewChainStore(time.Duration(chain.CheckpointTTLSecs)*time.Second, chainStoreEntryCap)
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

		// Buffer the request body ONLY if some command actually matches on it.
		// Configs that use no bodyRegex (i.e. every pre-existing one) keep the
		// old behaviour exactly: the body stays untouched here and is read for
		// the first time inside buildHTTPResponse.
		//
		// When we do buffer, request.Body must be restored — it is a one-shot
		// stream, and buildHTTPResponse reads it downstream for sessionCapture
		// / artifactCapture. The restore happens even on a read error, so a
		// partially-drained body is never handed downstream. Bounded to 1 MiB
		// to match the limit buildHTTPResponse applies.
		reqBody := ""
		if request.Body != nil && anyBodyRegex(servConf.Commands) {
			b, _ := io.ReadAll(io.LimitReader(request.Body, 1024*1024))
			reqBody = string(b)
			request.Body = io.NopCloser(bytes.NewReader(b))
		}

		for _, command := range servConf.Commands {
			var err error
			if !commandMatches(command, request.RequestURI, request.Method, reqBody) {
				continue
			}
			matched = true
			{
				resp, err, fireTrace = buildHTTPResponse(servConf, tr, command, request, httpStrategy.noveltyStore, sctx, httpStrategy.chainStore, httpStrategy.artifactStore)
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
				resp, err, fireTrace = buildHTTPResponse(servConf, tr, command, request, httpStrategy.noveltyStore, sctx, httpStrategy.chainStore, httpStrategy.artifactStore)
				if err != nil {
					log.Errorf("error building http response: %s: %v", request.RequestURI, err)
					applyLLMOfflineResponse(&resp, servConf.LLMOfflineResponse)
				}
			}
		}
		// Fault injection: apply delay jitter and/or error faults.
		// `fault` is this service's injector, captured at Init (see top of
		// Init for why it must not be read off the shared strategy here).
		// Delay faults sleep inside Apply() (adds realistic latency). Error
		// faults replace the response with a 503 + Retry-After (simulates a
		// real service under load).
		var faultType string
		if fault != nil {
			faultResp, ft, faulted := fault.Apply()
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
// Discovered 2026-05-23: when ExecuteModel failed in production, the wire
// response was correctly the configured llmOfflineResponse envelope (curl
// received 500 + 219 bytes), but the tracer event recorded the pre-fix
// "404 Not Found!" bare-text from inside buildHTTPResponse's deferred
// trace fire. Corpus in our backend looked like the lure was still broken
// when it wasn't. Returning the trace as a callback the caller invokes
// fixes the ordering.
type fireTraceFunc func(finalResp *httpResponse)

func buildHTTPResponse(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, command parser.Command, request *http.Request, ns *noveltydetect.FingerprintStore, sctx *sessionContext, chainStore *plugins.ChainStore, chainArtifactStore *artifactstore.Store) (httpResponse, error, fireTraceFunc) {
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
	// WP gadget-chain session lookup + auth-stage routing (Task 7)
	// -------------------------------------------------------------------------

	// sess is the (nil-safe) per-source-IP chain session for this request.
	// chainStore == nil (no command's mirror config has an enabled Chain
	// block — see findMirrorChain in Init) means sess stays nil for every
	// request, which is what keeps MirrorRespond/MirrorDelayMs below and the
	// auth-stage routing that follows byte-identical to pre-Task-7 behavior.
	// Same RemoteAddr-host extraction the LLM plugin branch and traceRequest
	// already use, so the chain session is keyed on the same source identity
	// every other per-IP mechanism in this file uses.
	var sess *plugins.ChainSession
	if chainStore != nil {
		host, _, splitErr := net.SplitHostPort(request.RemoteAddr)
		if splitErr != nil {
			host = request.RemoteAddr
		}
		sess = chainStore.Get(host)
	}

	// Auth-stage routing: once the forge chain (T1-T4, driven through the
	// ResponseMirror plugin below) has minted a fabricated administrator on
	// this session, the exploit's S4-S6 reads — wp-login.php, wp-admin/
	// users.php, wp-admin/plugin-install.php — need answers that carry that
	// forged state (the auth cookie, the username, the upload nonce) instead
	// of whichever static/404 response this service's command configured
	// for those paths. ServeAuthStage itself gates on sess.adminCreated, so
	// a chain that hasn't reached that checkpoint yet (or sess == nil, i.e.
	// chainStore == nil) returns handled=false and every existing behavior
	// for these paths is untouched.
	if sess != nil {
		switch request.URL.Path {
		case "/wp-login.php", "/wp-admin/", "/wp-admin/users.php", "/wp-admin/plugin-install.php":
			if status, hdrs, authBody, handled := plugins.ServeAuthStage(request.RequestURI, sess); handled {
				resp.StatusCode = status
				resp.Body = authBody
				headers := make([]string, 0, len(hdrs))
				for k, v := range hdrs {
					headers = append(headers, k+": "+v)
				}
				resp.Headers = headers
				return resp, nil, fireTrace
			}

		// S7 (Task 8): the plugin .zip the exploit uploads once it has an
		// admin session + S6's nonce. WordPress overloads update.php for
		// dozens of unrelated admin actions via ?action=, so both the
		// method and the exact action value are checked before this branch
		// touches the request body — a GET, or a POST with any other
		// action, falls straight through to the command's ordinary
		// configured response.
		//
		// The uploaded bytes are parsed out of the multipart body and
		// handed ONLY to chainArtifactStore.Write (a content-addressable,
		// inert capture — see internal/artifactstore/store.go's package
		// doc: "a research artifact pipeline, not a malware dropbox").
		// There is no os.Open/exec/unzip anywhere on this path, and never
		// will be: the zip is never written under a name or path a
		// webserver would execute, and this function does nothing else
		// with its contents. A Write failure (including
		// artifactstore.ErrOversize) is swallowed deliberately — capture
		// is best-effort telemetry, not a gate on the exploit's forward
		// progress, so the success page below is served either way.
		//
		// plugins.ServeUploadStage re-checks sess.adminCreated itself, so
		// a request that reaches here without having cleared T4 still
		// falls through unhandled, same as the S4-S6 case above.
		//
		// Intentional two-tier contract (Task 8 review finding — do not
		// "fix" this by adding an adminCreated check to the capture below
		// to match the response gate; that would be a regression):
		//   - CAPTURE is gated only on sess != nil, i.e. it fires for ANY
		//     armed service (chainStore configured) regardless of whether
		//     this session ever reached adminCreated. Deliberately broader
		//     than the response gate: capture-first — we would rather
		//     record a plugin .zip from a source that never completed the
		//     forge chain than silently miss a backdoor drop. The artifact
		//     is inert (content-addressable storage only, never executed —
		//     see the paragraph above), so over-capturing costs nothing.
		//   - The SUCCESS/activate RESPONSE, and the uploadOpen checkpoint
		//     ServeUploadStage sets, stay scoped to sess.adminCreated —
		//     only an operator who actually completed T1-T4 gets served
		//     the S7/S8 activate-flow illusion. A capture with no matching
		//     adminCreated checkpoint still reaches chainArtifactStore.Write
		//     below, but ServeUploadStage returns handled=false and the
		//     request falls through to the command's ordinary configured
		//     response, same as any other not-yet-escalated hit here.
		case "/wp-admin/update.php":
			if request.Method == http.MethodPost && request.URL.Query().Get("action") == "upload-plugin" {
				if filename, zipBytes, parseErr := extractPluginZipPart(request.Header.Get("Content-Type"), bodyBytes); parseErr == nil {
					if chainArtifactStore != nil {
						host, _, splitErr := net.SplitHostPort(request.RemoteAddr)
						if splitErr != nil {
							host = request.RemoteAddr
						}
						_, _ = chainArtifactStore.Write(zipBytes, map[string]any{
							"stage":    "plugin_upload",
							"src_ip":   host,
							"session":  host,
							"filename": filename,
						})
					}
					if status, hdrs, uploadBody, handled := plugins.ServeUploadStage(sess, filename); handled {
						resp.StatusCode = status
						resp.Body = uploadBody
						headers := make([]string, 0, len(hdrs))
						for k, v := range hdrs {
							headers = append(headers, k+": "+v)
						}
						resp.Headers = headers
						return resp, nil, fireTrace
					}
				}
			}

		// S8 (Task 8): the activation click the exploit follows off S7's
		// "Activate Plugin" link.
		case "/wp-admin/plugins.php":
			if request.Method == http.MethodGet && request.URL.Query().Get("action") == "activate" {
				if status, hdrs, activateBody, handled := plugins.ServeActivateStage(sess); handled {
					resp.StatusCode = status
					resp.Body = activateBody
					headers := make([]string, 0, len(hdrs))
					for k, v := range hdrs {
						headers = append(headers, k+": "+v)
					}
					resp.Headers = headers
					return resp, nil, fireTrace
				}
			}
		}

		// S9 (Task 9): the first command the exploit POSTs to the fake shell
		// route its S7-uploaded plugin registers (/wp2shell/v1/<route>,
		// either the ?rest_route= query form or the /wp-json/ pretty-
		// permalink form — see isWP2ShellCommandRequest). Neither form is a
		// single static path, so it can't be a case in the switch above;
		// it's matched separately here, still inside the sess != nil guard.
		//
		// Same intentional two-tier contract as S7's upload capture (see
		// the /wp-admin/update.php case's comment above): CAPTURE is gated
		// only on sess != nil (any armed service), independent of
		// sess.uploadOpen — capture-first, so a command sent before (or
		// instead of) a completed upload is still banked as intel. The
		// RESPONSE is gated on sess.uploadOpen inside
		// plugins.ServeCommandStage itself, same pattern as
		// ServeUploadStage/ServeActivateStage above.
		//
		// The captured bytes are the raw {"c":"<base64 command>"} JSON body
		// exactly as sent, handed ONLY to chainArtifactStore.Write — never
		// base64-decoded, never passed to os/exec or a shell, never
		// interpreted at all. That's also true inside
		// plugins.ServeCommandStage: it never receives the body, only
		// sess.uploadOpen, and returns a canned JSON string.
		if isWP2ShellCommandRequest(request) {
			if chainArtifactStore != nil {
				host, _, splitErr := net.SplitHostPort(request.RemoteAddr)
				if splitErr != nil {
					host = request.RemoteAddr
				}
				_, _ = chainArtifactStore.Write(bodyBytes, map[string]any{
					"stage":   "command",
					"src_ip":  host,
					"session": host,
				})
			}
			if status, hdrs, cmdBody, handled := plugins.ServeCommandStage(sess); handled {
				resp.StatusCode = status
				resp.Body = cmdBody
				headers := make([]string, 0, len(hdrs))
				for k, v := range hdrs {
					headers = append(headers, k+": "+v)
				}
				resp.Headers = headers
				return resp, nil, fireTrace
			}
		}
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

	if command.Plugin == plugins.ResponseMirrorName && command.Mirror != nil {
		// Multiplexed batch mirror (KI-010): emit one response element per
		// sub-request so an N-in batch gets an N-out envelope instead of the
		// fixed single-element static body. bodyBytes is the already-read
		// request body (no re-read). ok==false means "not a batch we mirror"
		// — we fall through and return the configured static handler
		// unchanged, so this is strictly additive.
		// sess (Task 7): the per-source chain-session looked up above —
		// nil whenever chainStore is nil (Chain not configured for this
		// service), which reproduces the shipped literal-only oracle
		// byte-for-byte. Non-nil arms the fiction-DB blind-read fallback
		// inside MirrorRespond/MirrorDelayMs, and lets the forge chain's
		// checkpoints (seeded / admin-created) accumulate on the session so
		// the auth-stage routing above can answer S4-S6 on a later request.
		if mirrorStatus, mirrorBody, ok := plugins.MirrorRespond(command.Mirror, bodyBytes, sess); ok {
			// Time-based oracle (additive): sleep the implied delay before writing,
			// but ONLY when the batch actually dispatched (a reject returns
			// Reject.Status, not WrapStatus). Real WP rejects at validation BEFORE
			// dispatch — an instant 400 — so delaying a rejected envelope would be
			// a fidelity tell. Capped in the plugin and again here (defense in
			// depth). Inert: only literal-true conditions delay; nothing is
			// executed.
			if mirrorStatus == command.Mirror.WrapStatus {
				if d := plugins.MirrorDelayMs(command.Mirror, bodyBytes, sess); d > 0 {
					if d > plugins.MaxMirrorDelayMs {
						d = plugins.MaxMirrorDelayMs
					}
					time.Sleep(time.Duration(d) * time.Millisecond)
				}
			}
			resp.StatusCode = mirrorStatus
			resp.Body = mirrorBody
			// resp.Headers stays as the command's configured outer headers.
			return resp, nil, fireTrace
		}
	}

	if command.Plugin == plugins.MazePluginName {
		// Deterministic infinite-directory tarpit: every path resolves to an
		// Apache-style listing (more links) or realistic fabricated file
		// content. Prolongs automated crawls and exposes agent traversal/looping
		// behaviour to agentdetect/novelty. Deterministic per URL by design.
		maze := &plugins.MazeHoneypot{
			ServerVersion: servConf.ServerVersion,
			ServerName:    servConf.ServerName,
		}
		mazeResp := maze.HandleRequest(request)
		resp.StatusCode = mazeResp.StatusCode
		resp.Body = mazeResp.Body
		headers := make([]string, 0, len(mazeResp.Headers)+1)
		if mazeResp.ContentType != "" {
			headers = append(headers, "Content-Type: "+mazeResp.ContentType)
		}
		for k, v := range mazeResp.Headers {
			headers = append(headers, k+": "+v)
		}
		resp.Headers = headers
		return resp, nil, fireTrace
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
		Command:            fmt.Sprintf("%s %s", request.Method, request.RequestURI),
		CommandOutput:      responseBody,
		ServicePort:        destPort,
		ResponseStatusCode: responseStatusCode,
		JA4:                ja4,
		// v8 Phase 0: response-side capture.
		// ResponseBytes is the byte count, ALWAYS set (cheap, useful for everyone).
		// ResponseTimeMs is the handler duration, ALWAYS set.
		// ResponseBody / ResponseHeaders gated by captureResponseBody flag — only
		// captured when the operator opts in for this service.
		ResponseBytes:  int64(len(responseBody)),
		ResponseTimeMs: responseTimeMs,
		// v8 Phase 5: session capture metadata — nil when stateless (omitempty).
		Captured: captured,
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
		// Split only on the first colon: header values (URLs, error
		// messages, etc.) may legitimately contain additional colons,
		// and splitting on every colon truncated them.
		keyValue := strings.SplitN(headerStr, ":", 2)
		if len(keyValue) == 2 {
			responseWriter.Header().Add(strings.TrimSpace(keyValue[0]), strings.TrimSpace(keyValue[1]))
		}
	}
	// http.StatusText(statusCode): empty string if the code is unknown.
	if len(http.StatusText(statusCode)) > 0 {
		responseWriter.WriteHeader(statusCode)
	}
}
