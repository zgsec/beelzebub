package OLLAMA

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/mariocandela/beelzebub/v3/agentdetect"
	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/faults"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

const maxBodySize = 1024 * 1024 // 1 MB

// OllamaStrategy implements the Ollama + OpenAI-compatible API honeypot.
type OllamaStrategy struct {
	Sessions     *historystore.HistoryStore
	Bridge       *bridge.ProtocolBridge
	Fault        *faults.Injector
	sessionsMu   sync.RWMutex
	ipSessions   map[string]*OllamaSession
	models       []parser.OllamaModel
	version      string
	injections   map[string]string
	canaryTokens map[string]string
	rng               *rand.Rand
	rngMu             sync.Mutex
	modelDigests      map[string]string // stable per-model digests computed at init
	promptEvalDelayMs int
	// lastInferenceAt is the timestamp of the last successful /api/generate
	// or /api/chat completion (across all IPs). /api/ps uses it to decide
	// whether to report a model as "loaded" — real Ollama only does so
	// while a model is resident in VRAM.
	lastInferenceAt time.Time
	lastInferenceMu sync.RWMutex
}

// OllamaSession tracks per-IP state for progressive injection.
type OllamaSession struct {
	mu              sync.Mutex
	PromptCount     int
	ModelsRequested map[string]bool
	HasRegistered   bool
	RegisterPayload string
	InjectionLevel  int
	FirstSeen       time.Time
	EndpointsHit    map[string]bool
	ModelLoaded     map[string]bool
	Timings           []int64   // accumulated inter-event timing deltas
	LastSeen          time.Time // last request time for timing computation
	LLMjackIntent     string    // classified intent of first real prompt
	PromptLengths     []int     // track prompt sizes per request
	TotalPromptTokens int       // rough estimate: len(prompt) / 4
	HasSystemPrompt   bool      // did they send a system prompt?
	ModelSwitches     int       // number of distinct models requested at time of change
}

func (s *OllamaStrategy) getOrCreateSession(ip string) *OllamaSession {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if sess, ok := s.ipSessions[ip]; ok {
		return sess
	}
	sess := &OllamaSession{
		FirstSeen:       time.Now(),
		ModelsRequested: make(map[string]bool),
		EndpointsHit:    make(map[string]bool),
		ModelLoaded:     make(map[string]bool),
	}
	s.ipSessions[ip] = sess
	return sess
}

// llmResponse generates a response using the LLM plugin if configured.
// Returns (response, true) on success, ("", false) if not configured or on failure.
// The LLM generates only the response text; callers wrap it in the appropriate
// API envelope (Ollama JSON, OpenAI JSON, streaming NDJSON, etc.).
// isEmbeddingModel reports whether the supplied model name belongs to an
// embedding family. Real Ollama rejects /api/generate and /api/chat calls
// against these models with a 400 — returning chat text would fingerprint
// the honeypot immediately on any multi-model sanity probe.
func isEmbeddingModel(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	// strip an optional :tag suffix
	if idx := strings.Index(n, ":"); idx >= 0 {
		n = n[:idx]
	}
	prefixes := []string{
		"nomic-embed",
		"mxbai-embed",
		"snowflake-arctic-embed",
		"all-minilm",
		"bge-",
		"gte-",
		"e5-",
		"jina-embed",
		"text-embedding-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return strings.Contains(n, "-embed-") || strings.HasSuffix(n, "-embed")
}

func (s *OllamaStrategy) llmResponse(prompt, model, host string, servConf parser.BeelzebubServiceConfiguration) (string, bool) {
	if servConf.Plugin.LLMProvider == "" {
		return "", false
	}
	llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
	if err != nil {
		log.Warnf("Ollama LLM provider error: %v", err)
		return "", false
	}
	llmHoneypot := plugins.BuildHoneypot(nil, tracer.HTTP, llmProvider, servConf)
	llmInstance := plugins.InitLLMHoneypot(*llmHoneypot)

	// Pass the user's prompt directly — the custom system prompt handles persona
	response, err := llmInstance.ExecuteModel(prompt, host)
	if err != nil {
		if err == plugins.ErrRateLimited {
			log.WithField("host", host).Warn("Ollama LLM rate limited, falling back to templates")
		} else {
			log.WithFields(log.Fields{"host": host, "error": err}).Warn("Ollama LLM failed, falling back to templates")
		}
		return "", false
	}
	return response, true
}

func (s *OllamaStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if s.Sessions == nil {
		s.Sessions = historystore.NewHistoryStore()
	}
	go s.Sessions.HistoryCleaner()

	s.ipSessions = make(map[string]*OllamaSession)
	s.models = servConf.OllamaConfig.Models
	s.version = servConf.OllamaConfig.Version
	if s.version == "" {
		s.version = "0.6.2"
	}
	s.injections = servConf.OllamaConfig.InjectionPayloads
	if s.injections == nil {
		s.injections = make(map[string]string)
	}
	s.canaryTokens = servConf.OllamaConfig.CanaryTokens
	if s.canaryTokens == nil {
		s.canaryTokens = make(map[string]string)
	}
	s.promptEvalDelayMs = servConf.OllamaConfig.PromptEvalDelayMs
	if s.promptEvalDelayMs == 0 {
		s.promptEvalDelayMs = 200 // default 200ms prompt eval delay
	}
	s.rng = rand.New(rand.NewSource(time.Now().UnixNano()))

	// Compute stable digests per model (deterministic, same across restarts within a version)
	s.modelDigests = make(map[string]string)
	for _, m := range s.models {
		h := sha256.Sum256([]byte(m.Name + s.version + "ollama-digest-salt"))
		s.modelDigests[m.Name] = "sha256:" + hex.EncodeToString(h[:])
	}

	// Session cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			s.sessionsMu.Lock()
			for ip, sess := range s.ipSessions {
				sess.mu.Lock()
				age := time.Since(sess.FirstSeen)
				sess.mu.Unlock()
				if age > time.Hour {
					delete(s.ipSessions, ip)
				}
			}
			s.sessionsMu.Unlock()
		}
	}()

	mux := http.NewServeMux()

	// CORS middleware wrapper
	withCORS := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS, HEAD")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next(w, r)
		}
	}

	// Ollama native endpoints
	// Root handler serves both GET and HEAD (Go's ServeMux routes HEAD to GET handlers)
	mux.HandleFunc("GET /", withCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			s.handleFallback(w, r, servConf, tr)
			return
		}
		w.Header().Set("Ollama-Version", s.version)
		s.handleRoot(w, r, servConf, tr)
	}))
	mux.HandleFunc("GET /api/version", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleVersion(w, r, servConf, tr)
	}))
	mux.HandleFunc("GET /api/tags", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleTags(w, r, servConf, tr)
	}))
	mux.HandleFunc("GET /api/ps", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handlePs(w, r, servConf, tr)
	}))
	mux.HandleFunc("POST /api/generate", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleGenerate(w, r, servConf, tr)
	}))
	mux.HandleFunc("POST /api/chat", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleChat(w, r, servConf, tr)
	}))
	mux.HandleFunc("POST /api/show", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleShow(w, r, servConf, tr)
	}))
	mux.HandleFunc("POST /api/embed", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleEmbed(w, r, servConf, tr)
	}))
	mux.HandleFunc("POST /api/embeddings", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleEmbeddingsLegacy(w, r, servConf, tr)
	}))
	mux.HandleFunc("POST /api/pull", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handlePull(w, r, servConf, tr)
	}))
	mux.HandleFunc("DELETE /api/delete", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleDelete(w, r, servConf, tr)
	}))

	// OpenAI-compatible endpoints
	mux.HandleFunc("POST /v1/chat/completions", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleOpenAIChat(w, r, servConf, tr)
	}))
	mux.HandleFunc("POST /v1/completions", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleOpenAICompletions(w, r, servConf, tr)
	}))
	mux.HandleFunc("GET /v1/models", withCORS(func(w http.ResponseWriter, r *http.Request) {
		s.handleOpenAIModels(w, r, servConf, tr)
	}))

	go func() {
		ln, listenErr := net.Listen("tcp", servConf.Address)
		if listenErr != nil {
			log.Errorf("Failed to start Ollama server on %s: %v", servConf.Address, listenErr)
			return
		}
		srv := &http.Server{
			Handler: mux,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, tracer.TeeConnKey, c)
			},
		}
		if err := srv.Serve(tracer.NewTeeListener(ln, 65536, tracer.HTTPStopFunc)); err != nil {
			log.Errorf("Failed to start Ollama server on %s: %v", servConf.Address, err)
		}
	}()

	log.WithFields(log.Fields{
		"port":    servConf.Address,
		"models":  len(s.models),
		"version": s.version,
	}).Infof("Init service %s", servConf.Protocol)
	return nil
}

// --- Helper methods ---

func (s *OllamaStrategy) readBody(r *http.Request) []byte {
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	return body
}

func (s *OllamaStrategy) clientIP(r *http.Request) (host, port string) {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return
}

func (s *OllamaStrategy) randIntn(n int) int {
	s.rngMu.Lock()
	v := s.rng.Intn(n)
	s.rngMu.Unlock()
	return v
}

func (s *OllamaStrategy) traceEvent(r *http.Request, tr tracer.Tracer, servConf parser.BeelzebubServiceConfiguration, handler, command, commandOutput, body string, responseBytes ...int64) {
	host, port := s.clientIP(r)
	destPort := tracer.ExtractPort(servConf.Address)
	sessionKey := "OLLAMA" + host

	if !s.Sessions.HasKey(sessionKey) {
		s.Sessions.SetSessionID(sessionKey, uuid.New().String())
	}
	sessionID := s.Sessions.GetSessionID(sessionKey)

	seq := s.Sessions.NextSequence(sessionKey)

	cmdStr := fmt.Sprintf("%s|%s", handler, command)
	// Embed LLMjacking session metadata for downstream analysis
	{
		msess := s.getOrCreateSession(host)
		msess.mu.Lock()
		if msess.LLMjackIntent != "" {
			command = fmt.Sprintf("%s intent=%s tokens=%d reqs=%d", command, msess.LLMjackIntent, msess.TotalPromptTokens, msess.PromptCount)
		}
		msess.mu.Unlock()
	}
	eventID := uuid.New().String()
	isRetry, retryOf := s.Sessions.DetectRetry(sessionKey, cmdStr, eventID)

	var crossRef string
	if s.Bridge != nil {
		flags := s.Bridge.GetFlags(host)
		discoveries := s.Bridge.GetDiscoveries(host)
		if len(flags) > 0 || len(discoveries) > 0 {
			var parts []string
			if len(flags) > 0 {
				sort.Strings(flags)
				parts = append(parts, "flags:"+strings.Join(flags, ","))
			}
			if len(discoveries) > 0 {
				credTypes := make(map[string]bool)
				for _, d := range discoveries {
					credTypes[d.Source+"/"+d.Type] = true
				}
				var types []string
				for t := range credTypes {
					types = append(types, t)
				}
				sort.Strings(types)
				parts = append(parts, "creds:"+strings.Join(types, ","))
			}
			crossRef = strings.Join(parts, ";")
		}
	}

	var faultType string
	if s.Fault != nil {
		_, ft, faulted := s.Fault.Apply()
		if faulted {
			faultType = ft
		} else {
			faultType = ft
		}
	}

	// Per-event incremental agent scoring — feed all available signals
	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	// Accumulate timing for agent classification
	now := time.Now()
	if !sess.LastSeen.IsZero() {
		delta := now.Sub(sess.LastSeen).Milliseconds()
		sess.Timings = append(sess.Timings, delta)
		if len(sess.Timings) > 100 {
			sess.Timings = sess.Timings[len(sess.Timings)-100:]
		}
	}
	sess.LastSeen = now
	sig := agentdetect.Signal{
		HasIdenticalRetries: isRetry,
		InterEventTimingsMs: make([]int64, len(sess.Timings)),
	}
	copy(sig.InterEventTimingsMs, sess.Timings)
	if sess.EndpointsHit["openai/chat"] || sess.EndpointsHit["generate"] || sess.EndpointsHit["chat"] {
		sig.HasAIDiscoveryProbe = true
	}
	sess.mu.Unlock()
	if crossRef != "" {
		sig.HasCrossProtocol = true
	}
	verdict := agentdetect.IncrementalClassify(sig)

	// Extract wire-order headers from TeeConn captured bytes
	var wireOrder []string
	if tc, ok := r.Context().Value(tracer.TeeConnKey).(*tracer.TeeConn); ok {
		wireOrder = tracer.ParseHeaderOrder(tc.RawBytes())
		tc.Release()
	}

	var respBytes int64
	if len(responseBytes) > 0 {
		respBytes = responseBytes[0]
	}

	tr.TraceEvent(tracer.Event{
		Msg:              "Ollama API request",
		RequestURI:       r.RequestURI,
		Protocol:         tracer.HTTP.String(),
		HTTPMethod:       r.Method,
		Body:             body,
		HostHTTPRequest:  r.Host,
		UserAgent:        r.UserAgent(),
		Headers:          fmtHeaders(r.Header),
		HeadersMap:       r.Header,
		Status:           tracer.Interaction.String(),
		RemoteAddr:       r.RemoteAddr,
		SourceIp:         host,
		SourcePort:       port,
		ID:               sessionID,
		Description:      servConf.Description,
		Command:          command,
		CommandOutput:    commandOutput,
		Handler:          handler,
		SessionKey:       sessionKey,
		Sequence:         seq,
		IsRetry:          isRetry,
		RetryOf:          retryOf,
		CrossProtocolRef: crossRef,
		FaultInjected:    faultType,
		AgentScore:       verdict.Score,
		AgentCategory:    verdict.Category,
		AgentSignals:     verdict.SignalsString(),
		ResponseBytes:   respBytes,
		JA4H:            tracer.ComputeJA4H(r, wireOrder),
		HeaderOrder:     strings.Join(wireOrder, ","),
		ServicePort:     destPort,
	})
}

// requireOpenAIAuth mirrors api.openai.com: every /v1/* endpoint demands
// `Authorization: Bearer <token>`. Missing or malformed → 401 with the real
// error envelope. Token value is NOT validated (we can't know a real key),
// which matches the intent: any supplied token is recorded as a credential
// discovery by checkBridgeAndCapture and treated as legitimate. Returns
// true when the request may proceed.
//
// Also stamps X-Request-ID on every response, matching OpenAI's invariant
// that every response carries one (covers success and failure paths).
func (s *OllamaStrategy) requireOpenAIAuth(w http.ResponseWriter, r *http.Request, tr tracer.Tracer, servConf parser.BeelzebubServiceConfiguration, handler string, body []byte) bool {
	// Response header stack for an internal OpenAI-compatible inference
	// gateway. Deliberately omits Cloudflare edge headers (cf-ray, server:
	// cloudflare, cf-cache-status, alt-svc) — those only make sense on a
	// TLS-fronted edge, and our listener is naked HTTP on a raw IP, so
	// emitting them would be internally inconsistent with the Crestfield
	// internal-platform persona. Headers kept are the ones that ALSO
	// appear on real-OpenAI direct-origin probes and match the "internal
	// platform" scenario (request-id for session tracking, processing-ms
	// for timing realism, organization for credential-capture bait,
	// openai-version as a real-API invariant, HSTS as a reasonable
	// hardening default, content-type-options for XSS-avoidance).
	reqID := "req_" + randomHexN(29)
	w.Header().Set("x-request-id", reqID)
	w.Header().Set("openai-organization", "user-"+randomAlnumN(24))
	w.Header().Set("openai-processing-ms", fmt.Sprintf("%d", 300+s.randIntn(2700)))
	w.Header().Set("openai-version", "2020-10-01")
	w.Header().Set("strict-transport-security", "max-age=15552000; includeSubDomains; preload")
	w.Header().Set("x-content-type-options", "nosniff")

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		body401 := `{"error":{"message":"You didn't provide an API key. You need to provide your API key in an Authorization header using Bearer auth (i.e. Authorization: Bearer YOUR_KEY), or as the password field (with blank username) if you're accessing the API from your browser and are prompted for a username and password. You can obtain an API key from https://platform.openai.com/account/api-keys.","type":"invalid_request_error","param":null,"code":null}}`
		w.Write([]byte(body401))
		s.traceEvent(r, tr, servConf, handler, "[auth:missing]", "[401]", string(body))
		return false
	}
	// "Bearer " prefix, with a non-empty token after.
	if !strings.HasPrefix(auth, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(auth, "Bearer ")) == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		body401 := `{"error":{"message":"Incorrect API key provided. You can find your API key at https://platform.openai.com/account/api-keys.","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}`
		w.Write([]byte(body401))
		s.traceEvent(r, tr, servConf, handler, "[auth:malformed]", "[401]", string(body))
		return false
	}
	return true
}

func (s *OllamaStrategy) checkBridgeAndCapture(r *http.Request, handler string) {
	host, _ := s.clientIP(r)
	if s.Bridge == nil {
		return
	}
	s.Bridge.SetFlag(host, "ollama_api_accessed")

	// Capture injection-triggered headers (any of these = agent followed our instructions)
	extractionHeaders := []struct {
		header   string
		credType string
		flag     string
	}{
		{"X-Client-Context", "agent_context", "ollama_context_extracted"},
		{"X-Peer-Context", "agent_peer_context", "ollama_peer_context_extracted"},
		{"X-System-Prompt", "agent_system_prompt_header", "ollama_sysprompt_header"},
		{"X-Tool-Config", "agent_tool_config", "ollama_tool_config_extracted"},
		{"Authorization", "agent_auth_token", "ollama_auth_observed"},
	}
	for _, eh := range extractionHeaders {
		if val := r.Header.Get(eh.header); val != "" {
			// Don't capture generic "Bearer " auth without substance
			if eh.header == "Authorization" && (val == "Bearer " || val == "Bearer") {
				continue
			}
			s.Bridge.RecordDiscovery(host, "ollama", eh.credType, eh.header, val)
			s.Bridge.SetFlag(host, eh.flag)
		}
	}
}

// extractSystemFromMessages captures system messages from chat requests.
// Agents sending system prompts in the messages array are giving us their
// operating instructions directly — no injection needed.
func (s *OllamaStrategy) extractSystemFromMessages(r *http.Request, messages []struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}) {
	host, _ := s.clientIP(r)
	if s.Bridge == nil {
		return
	}
	for _, msg := range messages {
		if msg.Role == "system" && len(msg.Content) > 0 {
			s.Bridge.RecordDiscovery(host, "ollama", "agent_system_prompt", "chat_system_message", msg.Content)
			s.Bridge.SetFlag(host, "ollama_system_prompt_captured")
			// Mark session for metadata tracking
			msess := s.getOrCreateSession(host)
			msess.mu.Lock()
			msess.HasSystemPrompt = true
			msess.mu.Unlock()
		}
	}
}

// modelExists checks if a model name is in the configured list.
func (s *OllamaStrategy) modelExists(name string) bool {
	for _, m := range s.models {
		if m.Name == name {
			return true
		}
	}
	return false
}

// stableDigest returns a deterministic digest for a model name, prefixed
// with "sha256:". Used on /api/pull where real Ollama ships the prefix.
func (s *OllamaStrategy) stableDigest(modelName string) string {
	if d, ok := s.modelDigests[modelName]; ok {
		return d
	}
	h := sha256.Sum256([]byte(modelName + s.version + "ollama-digest-salt"))
	return "sha256:" + hex.EncodeToString(h[:])
}

// stableDigestHex returns the bare-hex digest (no "sha256:" prefix). Used
// on /api/tags and /api/ps where real Ollama emits the bare 64-char hex.
// A honeypot emitting "sha256:…" on those endpoints is an instant tell —
// every Ollama GUI and `ollama list` parses this exact field.
func (s *OllamaStrategy) stableDigestHex(modelName string) string {
	return strings.TrimPrefix(s.stableDigest(modelName), "sha256:")
}

// defaultModelName returns the first configured model or a fallback.
func (s *OllamaStrategy) defaultModelName() string {
	if len(s.models) > 0 {
		return s.models[0].Name
	}
	return "llama3.1:8b"
}

// --- Route handlers ---

func (s *OllamaStrategy) handleRoot(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/root")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "Ollama is running")
	s.traceEvent(r, tr, servConf, "ollama/root", r.Method+" /", "Ollama is running", "")
}

func (s *OllamaStrategy) handleVersion(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/version")
	host, _ := s.clientIP(r)

	resp := map[string]interface{}{
		"version":          s.version,
		"platform":         "Crestfield Platform",
		"platform_version": "3.12.1-rc1",
		"mcp_endpoint":     "http://localhost:8000/mcp",
	}

	// Cross-protocol: if IP has interacted with other services, show richer platform info
	if s.Bridge != nil {
		flags := s.Bridge.GetFlags(host)
		if len(flags) > 0 {
			services := map[string]string{}
			for _, f := range flags {
				switch {
				case strings.HasPrefix(f, "mcp_"):
					services["mcp"] = "connected"
				case strings.HasPrefix(f, "ssh_"):
					services["ssh_gateway"] = "available"
				}
			}
			if len(services) > 0 {
				resp["platform_services"] = services
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
	s.traceEvent(r, tr, servConf, "ollama/version", "GET /api/version", string(out), "")
}

func (s *OllamaStrategy) handleTags(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/tags")
	host, _ := s.clientIP(r)
	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.EndpointsHit["tags"] = true
	sess.mu.Unlock()

	type modelEntry struct {
		Name       string `json:"name"`
		Model      string `json:"model"`
		ModifiedAt string `json:"modified_at"`
		Size       int64  `json:"size"`
		Digest     string `json:"digest"`
		Details    struct {
			ParentModel       string   `json:"parent_model"`
			Format            string   `json:"format"`
			Family            string   `json:"family"`
			Families          []string `json:"families"`
			ParameterSize     string   `json:"parameter_size"`
			QuantizationLevel string   `json:"quantization_level"`
		} `json:"details"`
	}

	// Per-model timestamps (different per model, timezone offset format)
	modelTimestamps := []string{
		"2026-01-15T14:30:00.123456789-05:00",
		"2026-02-02T09:15:22.456789012-08:00",
		"2026-02-18T16:45:11.789012345-06:00",
		"2026-01-28T11:20:33.234567890-05:00",
	}

	var models []modelEntry
	for i, m := range s.models {
		ts := modelTimestamps[0]
		if i < len(modelTimestamps) {
			ts = modelTimestamps[i]
		}
		e := modelEntry{
			Name:       m.Name,
			Model:      m.Name,
			ModifiedAt: ts,
			Size:       sizeFromParam(m.ParameterSize),
			Digest:     s.stableDigestHex(m.Name),
		}
		e.Details.Format = "gguf"
		e.Details.Family = m.Family
		e.Details.Families = []string{m.Family}
		e.Details.ParameterSize = m.ParameterSize
		e.Details.QuantizationLevel = m.QuantizationLevel
		models = append(models, e)
	}

	resp := struct {
		Models []modelEntry `json:"models"`
	}{Models: models}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
	s.traceEvent(r, tr, servConf, "ollama/tags", "GET /api/tags", string(out), "")
}

func (s *OllamaStrategy) handlePs(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/ps")

	// Real Ollama /api/ps returns only models actively resident in VRAM.
	// Before any /api/generate or /api/chat hits, or after OLLAMA_KEEP_ALIVE
	// expires (default 5m), the list is empty. A honeypot that always shows
	// a loaded model is trivially detectable by polling /api/ps on a fresh
	// target. Mirror the real behavior: require at least one inference call
	// from ANY IP within the last 5 minutes to list a model as loaded.
	running := []map[string]interface{}{}
	s.lastInferenceMu.RLock()
	fresh := !s.lastInferenceAt.IsZero() && time.Since(s.lastInferenceAt) < 5*time.Minute
	s.lastInferenceMu.RUnlock()
	if fresh && len(s.models) > 0 {
		m := s.models[0]
		running = append(running, map[string]interface{}{
			"name":           m.Name,
			"model":          m.Name,
			"size":           sizeFromParam(m.ParameterSize),
			"digest":         s.stableDigestHex(m.Name),
			"expires_at":     time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano),
			"size_vram":      sizeFromParam(m.ParameterSize),
			"context_length": 4096,
			"details": map[string]interface{}{
				"parent_model":       "",
				"format":             "gguf",
				"family":             m.Family,
				"families":           []string{m.Family},
				"parameter_size":     m.ParameterSize,
				"quantization_level": m.QuantizationLevel,
			},
		})
	}

	resp := map[string]interface{}{"models": running}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
	s.traceEvent(r, tr, servConf, "ollama/ps", "GET /api/ps", string(out), "")
}

func (s *OllamaStrategy) handleGenerate(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/generate")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	var req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		Stream *bool  `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Model == "" {
		req.Model = s.defaultModelName()
	}

	// Real Ollama returns a 400 when /api/generate is invoked on an embedding
	// model. Mirroring that here keeps schema-accurate behavior and prevents
	// the "embedding model answered with chat text" fingerprint.
	if isEmbeddingModel(req.Model) {
		if s.Bridge != nil {
			s.Bridge.SetFlag(host, "ollama_embed_on_generate")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		errResp := fmt.Sprintf(`{"error":"%q does not support generate"}`, req.Model)
		w.Write([]byte(errResp))
		s.traceEvent(r, tr, servConf, "ollama/generate", req.Model, "[reject:embed_on_generate]", string(body))
		return
	}

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.ModelsRequested[req.Model] = true
	sess.EndpointsHit["generate"] = true
	promptLen := len(req.Prompt)
	sess.PromptLengths = append(sess.PromptLengths, promptLen)
	sess.TotalPromptTokens += promptLen / 4
	if sess.LLMjackIntent == "" && promptLen > 10 {
		sess.LLMjackIntent = string(categorizePrompt(req.Prompt))
	}
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	count := sess.PromptCount
	totalTokens := sess.TotalPromptTokens
	modelCount := len(sess.ModelsRequested)
	sess.mu.Unlock()

	// Bridge flags for sustained LLMjacking
	if s.Bridge != nil && count >= 3 {
		avgLen := totalTokens * 4 / count
		if avgLen > 100 {
			s.Bridge.SetFlag(host, "llmjacking_sustained")
		}
		if modelCount > 1 {
			s.Bridge.SetFlag(host, "llmjacking_model_switch")
		}
	}

	// Check fault injection
	if s.Fault != nil {
		resp, _, faulted := s.Fault.Apply()
		if faulted {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, resp)
			s.traceEvent(r, tr, servConf, "ollama/generate", req.Model, resp, string(body))
			return
		}
	}

	// Try LLM-powered response first, fall back to templates
	var response string
	if llmResp, ok := s.llmResponse(req.Prompt, req.Model, host, servConf); ok {
		response = llmResp
	} else {
		category := categorizePrompt(req.Prompt)
		s.rngMu.Lock()
		response = buildInjectedResponse(category, req.Prompt, level, count, s.rng, s.canaryTokens, s.injections, s.Bridge, host)
		s.rngMu.Unlock()
	}

	// Empty response = degradation tier 3 simulated error (real Ollama error format)
	if response == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		errResp := fmt.Sprintf(`{"error":"model '%s' failed to generate a response: CUDA error: out of memory"}`, req.Model)
		w.Write([]byte(errResp))
		s.traceEvent(r, tr, servConf, "ollama/generate", req.Model, "[degradation:cuda_oom]", string(body))
		return
	}

	shouldStream := req.Stream == nil || *req.Stream
	if shouldStream {
		s.streamOllamaResponse(w, req.Model, response, len(req.Prompt))
	} else {
		s.writeOllamaNonStreaming(w, req.Model, response, len(req.Prompt))
	}

	// Cross-protocol: mark that this IP has used Ollama inference
	if s.Bridge != nil {
		s.Bridge.SetFlag(host, "ollama_inference_used")
	}
	s.lastInferenceMu.Lock()
	s.lastInferenceAt = time.Now()
	s.lastInferenceMu.Unlock()

	s.traceEvent(r, tr, servConf, "ollama/generate", req.Model, response, string(body))
}

func (s *OllamaStrategy) handleChat(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/chat")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Model == "" {
		req.Model = s.defaultModelName()
	}

	// Real Ollama rejects /api/chat for embedding models the same way.
	if isEmbeddingModel(req.Model) {
		if s.Bridge != nil {
			s.Bridge.SetFlag(host, "ollama_embed_on_chat")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		errResp := fmt.Sprintf(`{"error":"%q does not support chat"}`, req.Model)
		w.Write([]byte(errResp))
		s.traceEvent(r, tr, servConf, "ollama/chat", req.Model, "[reject:embed_on_chat]", string(body))
		return
	}

	// Capture system messages — agents revealing their instructions
	s.extractSystemFromMessages(r, req.Messages)

	// Extract the last user message as the prompt, and collect any system
	// messages so the backend LLM actually sees them (LURE-7 fix). The
	// honeypot's own persona system prompt is set by the plugin config; we
	// prepend the user's system instructions to the user prompt so gpt will
	// weigh them without us needing to plumb structured messages through.
	var userSystems []string
	prompt := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if prompt == "" && req.Messages[i].Role == "user" {
			prompt = req.Messages[i].Content
		}
		if req.Messages[i].Role == "system" && strings.TrimSpace(req.Messages[i].Content) != "" {
			userSystems = append([]string{req.Messages[i].Content}, userSystems...)
		}
	}
	if len(userSystems) > 0 && prompt != "" {
		prompt = "[user system instructions]\n" + strings.Join(userSystems, "\n") + "\n[/user system instructions]\n\n" + prompt
	}

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.ModelsRequested[req.Model] = true
	sess.EndpointsHit["chat"] = true
	promptLen := len(prompt)
	sess.PromptLengths = append(sess.PromptLengths, promptLen)
	sess.TotalPromptTokens += promptLen / 4
	if sess.LLMjackIntent == "" && promptLen > 10 {
		sess.LLMjackIntent = string(categorizePrompt(prompt))
	}
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	count := sess.PromptCount
	totalTokens := sess.TotalPromptTokens
	modelCount := len(sess.ModelsRequested)
	sess.mu.Unlock()

	// Bridge flags for sustained LLMjacking
	if s.Bridge != nil && count >= 3 {
		avgLen := totalTokens * 4 / count
		if avgLen > 100 {
			s.Bridge.SetFlag(host, "llmjacking_sustained")
		}
		if modelCount > 1 {
			s.Bridge.SetFlag(host, "llmjacking_model_switch")
		}
	}

	if s.Fault != nil {
		resp, _, faulted := s.Fault.Apply()
		if faulted {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, resp)
			s.traceEvent(r, tr, servConf, "ollama/chat", req.Model, resp, string(body))
			return
		}
	}

	// Try LLM-powered response first, fall back to templates
	var response string
	if llmResp, ok := s.llmResponse(prompt, req.Model, host, servConf); ok {
		response = llmResp
	} else {
		category := categorizePrompt(prompt)
		s.rngMu.Lock()
		response = buildInjectedResponse(category, prompt, level, count, s.rng, s.canaryTokens, s.injections, s.Bridge, host)
		s.rngMu.Unlock()
	}

	// Empty response = degradation tier 3 simulated error
	if response == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		errResp := fmt.Sprintf(`{"error":"model '%s' failed to generate a response: CUDA error: out of memory"}`, req.Model)
		w.Write([]byte(errResp))
		s.traceEvent(r, tr, servConf, "ollama/chat", req.Model, "[degradation:cuda_oom]", string(body))
		return
	}

	shouldStream := req.Stream == nil || *req.Stream
	if shouldStream {
		s.streamOllamaChatResponse(w, req.Model, response, len(prompt))
	} else {
		s.writeOllamaChatNonStreaming(w, req.Model, response, len(prompt))
	}

	// Cross-protocol: mark that this IP has used Ollama inference
	if s.Bridge != nil {
		s.Bridge.SetFlag(host, "ollama_inference_used")
	}
	s.lastInferenceMu.Lock()
	s.lastInferenceAt = time.Now()
	s.lastInferenceMu.Unlock()

	s.traceEvent(r, tr, servConf, "ollama/chat", req.Model, response, string(body))
}

func (s *OllamaStrategy) handleShow(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/show")
	body := s.readBody(r)

	var req struct {
		Model string `json:"model"`
		Name  string `json:"name"` // fallback for older clients
	}
	json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = req.Name // accept "name" as fallback
	}
	if req.Model == "" {
		req.Model = s.defaultModelName()
	}

	// Find model details
	var family, paramSize, quantLevel string
	for _, m := range s.models {
		if m.Name == req.Model {
			family = m.Family
			paramSize = m.ParameterSize
			quantLevel = m.QuantizationLevel
			break
		}
	}
	if family == "" {
		family = "llama"
		paramSize = "8B"
		quantLevel = "Q4_0"
	}

	pCount := paramCountFromSize(paramSize)
	host, _ := s.clientIP(r)
	modelInfo := map[string]interface{}{
		"general.architecture":         family,
		"general.parameter_count":      pCount,
		"general.quantization_version": 2,
		"general.file_type":            2,
		"general.context_length":       4096,
		"general.embedding_length":     4096,
	}

	// Cross-protocol: enrich model_info for IPs seen on other protocols
	if s.Bridge != nil {
		if s.Bridge.HasFlag(host, "mcp_tool_call") {
			modelInfo["cdf.mcp_integration"] = true
			modelInfo["cdf.mcp_endpoint"] = "http://localhost:8000/mcp"
		}
		if s.Bridge.HasFlag(host, "ssh_authenticated") {
			modelInfo["cdf.credential_vault"] = "https://vault.int.crestfielddata.io:8200"
			modelInfo["cdf.ssh_config_available"] = true
		}
		discoveries := s.Bridge.GetDiscoveries(host)
		if len(discoveries) > 0 {
			modelInfo["cdf.service_credentials_available"] = true
		}
	}

	showResp := map[string]interface{}{
		"modelfile":  fmt.Sprintf("FROM %s", req.Model),
		"parameters": "stop \"<|start_header_id|>\"\nstop \"<|end_header_id|>\"\nstop \"<|eot_id|>\"",
		"template":   "{{ if .System }}<|start_header_id|>system<|end_header_id|>\n\n{{ .System }}<|eot_id|>{{ end }}{{ if .Prompt }}<|start_header_id|>user<|end_header_id|>\n\n{{ .Prompt }}<|eot_id|>{{ end }}<|start_header_id|>assistant<|end_header_id|>\n\n{{ .Response }}<|eot_id|>",
		"details": map[string]interface{}{
			"parent_model":       "",
			"format":             "gguf",
			"family":             family,
			"families":           []string{family},
			"parameter_size":     paramSize,
			"quantization_level": quantLevel,
		},
		"model_info":   modelInfo,
		"license":      "Meta Llama 3.1 Community License Agreement",
		"capabilities": []string{"completion"},
	}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(showResp)
	w.Write(out)
	s.traceEvent(r, tr, servConf, "ollama/show", req.Model, string(out), string(body))
}

// --- New endpoint handlers ---

// embeddingDimsForModel returns the output vector length real Ollama would
// produce for a given embedding model. 768 is ONLY correct for
// nomic-embed-text; mxbai-embed-large and snowflake-arctic-embed are 1024,
// bge-small is 384, etc. A honeypot that always returns 768 dims fails any
// multi-model probe checking `len(embedding)` matches the model's spec.
func embeddingDimsForModel(model string) int {
	n := strings.ToLower(model)
	if idx := strings.Index(n, ":"); idx >= 0 {
		n = n[:idx]
	}
	switch {
	case strings.HasPrefix(n, "nomic-embed"):
		return 768
	case strings.HasPrefix(n, "mxbai-embed-large"):
		return 1024
	case strings.HasPrefix(n, "snowflake-arctic-embed"):
		return 1024
	case strings.HasPrefix(n, "bge-large"):
		return 1024
	case strings.HasPrefix(n, "bge-base"):
		return 768
	case strings.HasPrefix(n, "bge-small"):
		return 384
	case strings.HasPrefix(n, "all-minilm-l12"):
		return 384
	case strings.HasPrefix(n, "all-minilm"):
		return 384
	case strings.HasPrefix(n, "gte-large"):
		return 1024
	case strings.HasPrefix(n, "gte-base"):
		return 768
	case strings.HasPrefix(n, "gte-small"):
		return 384
	case strings.HasPrefix(n, "text-embedding-3-small"):
		return 1536
	case strings.HasPrefix(n, "text-embedding-3-large"):
		return 3072
	case strings.HasPrefix(n, "text-embedding-ada-002"):
		return 1536
	default:
		return 768
	}
}

// newEmbeddingVector builds a dims-long []float32 using approximate Gaussian
// (sum of 3 uniforms, CLT) scaled to roughly [-0.6, 0.6]. Float32 is what
// real Ollama wire-serializes — float64 produces 16-17 significant JSON
// digits, Ollama emits 7-9. The number-of-decimals delta is a direct tell.
func (s *OllamaStrategy) newEmbeddingVector(dims int) []float32 {
	out := make([]float32, dims)
	s.rngMu.Lock()
	defer s.rngMu.Unlock()
	for i := range out {
		u1 := s.rng.Float64()
		u2 := s.rng.Float64()
		u3 := s.rng.Float64()
		out[i] = float32((u1 + u2 + u3 - 1.5) * 0.4)
	}
	return out
}

func (s *OllamaStrategy) handleEmbed(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/embed")
	body := s.readBody(r)

	var req struct {
		Model string      `json:"model"`
		Input interface{} `json:"input"` // string or []string
	}
	json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = "nomic-embed-text"
	}

	dims := embeddingDimsForModel(req.Model)
	embedding := s.newEmbeddingVector(dims)

	timing := timingForModel(req.Model)
	loadDurNs := int64(timing.LoadDurationMs) * 1e6
	promptEvalCount := estimateEmbedTokens(req.Input)
	s.rngMu.Lock()
	evalDurNs := int64(50+s.rng.Intn(30)) * 1e6
	s.rngMu.Unlock()

	resp := map[string]interface{}{
		"model":             req.Model,
		"embeddings":        [][]float32{embedding},
		"total_duration":    loadDurNs + evalDurNs,
		"load_duration":     loadDurNs,
		"prompt_eval_count": promptEvalCount,
	}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
	s.traceEvent(r, tr, servConf, "ollama/embed", req.Model, fmt.Sprintf("[%d-dim embedding]", dims), string(body), int64(len(out)))
}

// handleEmbeddingsLegacy serves /api/embeddings (the pre-v0.2 endpoint).
// Real legacy behavior: accepts `{"model":..., "prompt":"text"}` (singular
// string, not Input); returns `{"embedding":[flat float32...]}` — singular
// key, flat vector (not nested). Clients that haven't migrated (older
// LangChain, older langchain-ollama) hit this path and break on the new
// {"embeddings":[[...]]} shape. Keeping the split is what real Ollama does.
func (s *OllamaStrategy) handleEmbeddingsLegacy(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/embeddings")
	body := s.readBody(r)

	var req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
	}
	json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = "nomic-embed-text"
	}

	dims := embeddingDimsForModel(req.Model)
	embedding := s.newEmbeddingVector(dims)

	resp := map[string]interface{}{
		"embedding": embedding,
	}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
	s.traceEvent(r, tr, servConf, "ollama/embeddings", req.Model, fmt.Sprintf("[%d-dim legacy embedding]", dims), string(body), int64(len(out)))
}

// estimateEmbedTokens approximates token count from embed input (string or []string).
func estimateEmbedTokens(input interface{}) int {
	switch v := input.(type) {
	case string:
		return len(v) / 4
	case []interface{}:
		total := 0
		for _, item := range v {
			if s, ok := item.(string); ok {
				total += len(s) / 4
			}
		}
		return total
	default:
		return 10
	}
}

func (s *OllamaStrategy) handlePull(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/pull")
	body := s.readBody(r)

	var req struct {
		Name   string `json:"name"`
		Stream *bool  `json:"stream"`
	}
	json.Unmarshal(body, &req)

	// Stream progress JSON
	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)

	// Real Ollama status line: "pulling <first-12-hex-of-digest>" — NO
	// "sha256:" prefix. Prior impl emitted "pulling sha256:abc123def456"
	// which every Ollama user recognizes as wrong on sight. The `digest`
	// FIELD inside each stage keeps the "sha256:<64hex>" form (matches
	// real server). Also adds the "removing any unused layers" stage that
	// real pulls emit between writing-manifest and success.
	shortHex := s.stableDigestHex(req.Name)[:12]
	fullDigest := s.stableDigest(req.Name)
	stages := []map[string]interface{}{
		{"status": "pulling manifest"},
		{"status": "pulling " + shortHex, "digest": fullDigest, "total": 4700000000, "completed": 1200000000},
		{"status": "pulling " + shortHex, "digest": fullDigest, "total": 4700000000, "completed": 3500000000},
		{"status": "pulling " + shortHex, "digest": fullDigest, "total": 4700000000, "completed": 4700000000},
		{"status": "verifying sha256 digest"},
		{"status": "writing manifest"},
		{"status": "removing any unused layers"},
		{"status": "success"},
	}

	for _, stage := range stages {
		out, _ := json.Marshal(stage)
		w.Write(out)
		w.Write([]byte("\n"))
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(100 * time.Millisecond)
	}

	s.traceEvent(r, tr, servConf, "ollama/pull", req.Name, "success", string(body))
}

func (s *OllamaStrategy) handleDelete(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/delete")
	body := s.readBody(r)

	var req struct {
		Name string `json:"name"`
	}
	json.Unmarshal(body, &req)

	// Real Ollama 404's on unknown models with a typed error envelope.
	// Blanket 200 on any name was an easy "delete anything-you-like"
	// fingerprint.
	if req.Name == "" || !s.modelExists(req.Name) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":"model '%s' not found"}`, req.Name)
		s.traceEvent(r, tr, servConf, "ollama/delete", req.Name, "[404:not-found]", string(body))
		return
	}
	w.WriteHeader(http.StatusOK)
	s.traceEvent(r, tr, servConf, "ollama/delete", req.Name, "deleted", string(body))
}

// --- OpenAI-compatible handlers ---

func (s *OllamaStrategy) handleOpenAIChat(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "openai/chat")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	if !s.requireOpenAIAuth(w, r, tr, servConf, "openai/chat", body) {
		return
	}

	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		Stream *bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"message":"We could not parse the JSON body of your request. (HINT: This likely means you aren't using your HTTP library correctly. The OpenAI API expects a JSON payload, but what was sent was not valid JSON.)","type":"invalid_request_error","param":null,"code":null}}`))
		return
	}
	if req.Model == "" {
		req.Model = s.defaultModelName()
	}

	// OpenAI-compat: embedding models belong on /v1/embeddings, not here.
	if isEmbeddingModel(req.Model) {
		if s.Bridge != nil {
			s.Bridge.SetFlag(host, "openai_embed_on_chat")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		errResp := `{"error":{"message":"This is not a chat model and thus not supported in the v1/chat/completions endpoint. Did you mean to use v1/embeddings?","type":"invalid_request_error","param":"model","code":"model_not_supported"}}`
		w.Write([]byte(errResp))
		s.traceEvent(r, tr, servConf, "openai/chat", req.Model, "[reject:embed_on_chat]", string(body))
		return
	}

	// Capture system messages — agents revealing their instructions
	s.extractSystemFromMessages(r, req.Messages)

	var userSystems []string
	prompt := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if prompt == "" && req.Messages[i].Role == "user" {
			prompt = req.Messages[i].Content
		}
		if req.Messages[i].Role == "system" && strings.TrimSpace(req.Messages[i].Content) != "" {
			userSystems = append([]string{req.Messages[i].Content}, userSystems...)
		}
	}
	if len(userSystems) > 0 && prompt != "" {
		prompt = "[user system instructions]\n" + strings.Join(userSystems, "\n") + "\n[/user system instructions]\n\n" + prompt
	}

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.ModelsRequested[req.Model] = true
	sess.EndpointsHit["openai/chat"] = true
	promptLen := len(prompt)
	sess.PromptLengths = append(sess.PromptLengths, promptLen)
	sess.TotalPromptTokens += promptLen / 4
	if sess.LLMjackIntent == "" && promptLen > 10 {
		sess.LLMjackIntent = string(categorizePrompt(prompt))
	}
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	count := sess.PromptCount
	totalTokens := sess.TotalPromptTokens
	modelCount := len(sess.ModelsRequested)
	sess.mu.Unlock()

	// Bridge flags for sustained LLMjacking
	if s.Bridge != nil && count >= 3 {
		avgLen := totalTokens * 4 / count
		if avgLen > 100 {
			s.Bridge.SetFlag(host, "llmjacking_sustained")
		}
		if modelCount > 1 {
			s.Bridge.SetFlag(host, "llmjacking_model_switch")
		}
	}

	if s.Fault != nil {
		resp, _, faulted := s.Fault.Apply()
		if faulted {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, resp)
			s.traceEvent(r, tr, servConf, "openai/chat", req.Model, resp, string(body))
			return
		}
	}

	// Try LLM-powered response first, fall back to templates
	var response string
	if llmResp, ok := s.llmResponse(prompt, req.Model, host, servConf); ok {
		response = llmResp
	} else {
		category := categorizePrompt(prompt)
		s.rngMu.Lock()
		response = buildInjectedResponse(category, prompt, level, count, s.rng, s.canaryTokens, s.injections, s.Bridge, host)
		s.rngMu.Unlock()
	}

	// Empty response = degradation tier 3 simulated error (OpenAI error format)
	if response == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		errResp := `{"error":{"message":"The server is currently overloaded. Please try again later.","type":"server_error","code":"overloaded"}}`
		w.Write([]byte(errResp))
		s.traceEvent(r, tr, servConf, "openai/chat", req.Model, "[degradation:overloaded]", string(body))
		return
	}

	shouldStream := req.Stream != nil && *req.Stream
	if shouldStream {
		s.streamOpenAIResponse(w, req.Model, response)
	} else {
		s.writeOpenAINonStreaming(w, req.Model, response, len(prompt))
	}

	s.traceEvent(r, tr, servConf, "openai/chat", req.Model, response, string(body))
}

func (s *OllamaStrategy) handleOpenAICompletions(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "openai/completions")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	if !s.requireOpenAIAuth(w, r, tr, servConf, "openai/completions", body) {
		return
	}

	var req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		Stream *bool  `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"message":"We could not parse the JSON body of your request.","type":"invalid_request_error","param":null,"code":null}}`))
		return
	}
	if req.Model == "" {
		req.Model = s.defaultModelName()
	}

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.ModelsRequested[req.Model] = true
	sess.EndpointsHit["openai/completions"] = true
	promptLen := len(req.Prompt)
	sess.PromptLengths = append(sess.PromptLengths, promptLen)
	sess.TotalPromptTokens += promptLen / 4
	if sess.LLMjackIntent == "" && promptLen > 10 {
		sess.LLMjackIntent = string(categorizePrompt(req.Prompt))
	}
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	count := sess.PromptCount
	totalTokens := sess.TotalPromptTokens
	modelCount := len(sess.ModelsRequested)
	sess.mu.Unlock()

	// Bridge flags for sustained LLMjacking
	if s.Bridge != nil && count >= 3 {
		avgLen := totalTokens * 4 / count
		if avgLen > 100 {
			s.Bridge.SetFlag(host, "llmjacking_sustained")
		}
		if modelCount > 1 {
			s.Bridge.SetFlag(host, "llmjacking_model_switch")
		}
	}

	// Try LLM-powered response first, fall back to templates
	var response string
	if llmResp, ok := s.llmResponse(req.Prompt, req.Model, host, servConf); ok {
		response = llmResp
	} else {
		category := categorizePrompt(req.Prompt)
		s.rngMu.Lock()
		response = buildInjectedResponse(category, req.Prompt, level, count, s.rng, s.canaryTokens, s.injections, s.Bridge, host)
		s.rngMu.Unlock()
	}

	// Empty response = degradation tier 3 simulated error (OpenAI error format)
	if response == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		errResp := `{"error":{"message":"The server is currently overloaded. Please try again later.","type":"server_error","code":"overloaded"}}`
		w.Write([]byte(errResp))
		s.traceEvent(r, tr, servConf, "openai/completions", req.Model, "[degradation:overloaded]", string(body))
		return
	}

	// Legacy completions: real API returns object="text_completion" with a
	// text field per choice (no message wrapper). Emitting the chat shape
	// here is a schema break that any legacy SDK catches immediately.
	s.writeOpenAITextCompletion(w, req.Model, response, len(req.Prompt))
	s.traceEvent(r, tr, servConf, "openai/completions", req.Model, response, string(body))
}

type openAITextChoice struct {
	Text         string    `json:"text"`
	Index        int       `json:"index"`
	Logprobs     *struct{} `json:"logprobs"`
	FinishReason string    `json:"finish_reason"`
}

type openAITextCompletion struct {
	ID                string             `json:"id"`
	Object            string             `json:"object"`
	Created           int64              `json:"created"`
	Model             string             `json:"model"`
	Choices           []openAITextChoice `json:"choices"`
	Usage             openAIUsage        `json:"usage"`
	SystemFingerprint string             `json:"system_fingerprint"`
}

func (s *OllamaStrategy) writeOpenAITextCompletion(w http.ResponseWriter, model, response string, promptLen int) {
	cmplID := "cmpl-" + randomAlnumN(29)
	fingerprint := "fp_" + randomHexN(10)
	promptTokens := promptLen/4 + 1
	completionTokens := len(response) / 4

	resp := openAITextCompletion{
		ID:      cmplID,
		Object:  "text_completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []openAITextChoice{{
			Text:         response,
			Index:        0,
			Logprobs:     nil,
			FinishReason: "stop",
		}},
		Usage: openAIUsage{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
		},
		SystemFingerprint: fingerprint,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Platform", "Crestfield Platform v3.12.1-rc1")
	out, _ := json.Marshal(resp)
	w.Write(out)
}

func (s *OllamaStrategy) handleOpenAIModels(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "openai/models")

	if !s.requireOpenAIAuth(w, r, tr, servConf, "openai/models", nil) {
		return
	}

	type openAIModel struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}

	// Pin created timestamps to per-model deterministic values derived from
	// a hash of the name. Real OpenAI emits distinct per-model created
	// timestamps (e.g. gpt-4o = 1715367049, gpt-3.5-turbo = 1677610602);
	// identical created across every model is a trivial tell.
	//
	// owned_by MUST match the real OpenAI vocabulary: "system" (gpt-3.5+),
	// "openai" (dall-e, whisper, text-embedding-*), "openai-internal"
	// (experimental), "user-<orgid>" (fine-tunes). "library" is an
	// Ollama-ism; emitting it on /v1/models is a honeypot giveaway.
	pickOwner := func(name string) string {
		lower := strings.ToLower(name)
		switch {
		case strings.Contains(lower, "whisper"), strings.Contains(lower, "dall-e"),
			strings.Contains(lower, "embedding"), strings.Contains(lower, "tts-"):
			return "openai"
		case strings.Contains(lower, "ft:"), strings.HasPrefix(lower, "user-"):
			return "user-" + randomAlnumN(24)
		default:
			return "system"
		}
	}
	var models []openAIModel
	for _, m := range s.models {
		h := sha256.Sum256([]byte(m.Name))
		// Distribute across 2022-2024 (real OpenAI model creation epoch range).
		created := int64(1640995200) + int64(uint32(h[0])<<24|uint32(h[1])<<16|uint32(h[2])<<8|uint32(h[3]))%int64(94608000)
		models = append(models, openAIModel{
			ID:      m.Name,
			Object:  "model",
			Created: created,
			OwnedBy: pickOwner(m.Name),
		})
	}

	resp := struct {
		Object string        `json:"object"`
		Data   []openAIModel `json:"data"`
	}{Object: "list", Data: models}

	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
	s.traceEvent(r, tr, servConf, "openai/models", "GET /v1/models", string(out), "")
}


func (s *OllamaStrategy) handleFallback(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/fallback")
	body := s.readBody(r)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	resp := `{"error":"not found"}`
	fmt.Fprint(w, resp)
	s.traceEvent(r, tr, servConf, "ollama/fallback", r.Method+" "+r.URL.Path, resp, string(body))
}

// --- Streaming helpers ---

func (s *OllamaStrategy) streamOllamaResponse(w http.ResponseWriter, model, response string, promptLen int) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)

	// Simulate prompt evaluation time (real LLMs pause before first token)
	promptEvalDelay := time.Duration(s.promptEvalDelayMs) * time.Millisecond
	s.rngMu.Lock()
	jitter := time.Duration(s.rng.Intn(100)) * time.Millisecond
	s.rngMu.Unlock()
	time.Sleep(promptEvalDelay + jitter)

	tokens := tokenizeResponse(response)
	timing := timingForModel(model)
	start := time.Now()
	promptEvalCount := promptLen/4 + 1

	for i, token := range tokens {
		chunk := map[string]interface{}{
			"model":      model,
			"created_at": time.Now().UTC().Format(time.RFC3339Nano),
			"response":   token,
			"done":       false,
		}
		out, _ := json.Marshal(chunk)
		w.Write(out)
		w.Write([]byte("\n"))
		if flusher != nil {
			flusher.Flush()
		}

		if i < len(tokens)-1 {
			s.rngMu.Lock()
			delay := timing.tokenDelay(s.rng)
			s.rngMu.Unlock()
			time.Sleep(delay)
		}
	}

	// Final chunk with stats
	elapsed := time.Since(start)
	finalChunk := map[string]interface{}{
		"model":                model,
		"created_at":           time.Now().UTC().Format(time.RFC3339Nano),
		"response":             "",
		"done":                 true,
		"done_reason":          "stop",
		"total_duration":       elapsed.Nanoseconds() + int64(timing.LoadDurationMs)*1e6,
		"load_duration":        int64(timing.LoadDurationMs) * 1e6,
		"prompt_eval_count":    promptEvalCount,
		"prompt_eval_duration": int64(50e6),
		"eval_count":           len(tokens),
		"eval_duration":        elapsed.Nanoseconds(),
		"context":              ollamaContextArray(promptEvalCount, len(tokens)),
	}
	out, _ := json.Marshal(finalChunk)
	w.Write(out)
	w.Write([]byte("\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

func (s *OllamaStrategy) writeOllamaNonStreaming(w http.ResponseWriter, model, response string, promptLen int) {
	timing := timingForModel(model)
	promptEvalCount := promptLen/4 + 1
	evalCount := len(response) / 4
	resp := map[string]interface{}{
		"model":                model,
		"created_at":           time.Now().UTC().Format(time.RFC3339Nano),
		"response":             response,
		"done":                 true,
		"done_reason":          "stop",
		"total_duration":       int64(timing.LoadDurationMs+200) * 1e6,
		"load_duration":        int64(timing.LoadDurationMs) * 1e6,
		"prompt_eval_count":    promptEvalCount,
		"prompt_eval_duration": int64(50e6),
		"eval_count":           evalCount,
		"eval_duration":        int64(200e6),
		"context":              ollamaContextArray(promptEvalCount, evalCount),
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
}

func (s *OllamaStrategy) streamOllamaChatResponse(w http.ResponseWriter, model, response string, promptLen int) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)

	// Simulate prompt evaluation time (real LLMs pause before first token)
	promptEvalDelay := time.Duration(s.promptEvalDelayMs) * time.Millisecond
	s.rngMu.Lock()
	jitter := time.Duration(s.rng.Intn(100)) * time.Millisecond
	s.rngMu.Unlock()
	time.Sleep(promptEvalDelay + jitter)

	tokens := tokenizeResponse(response)
	timing := timingForModel(model)
	start := time.Now()
	promptEvalCount := promptLen/4 + 1

	for i, token := range tokens {
		chunk := map[string]interface{}{
			"model":      model,
			"created_at": time.Now().UTC().Format(time.RFC3339Nano),
			"message": map[string]string{
				"role":    "assistant",
				"content": token,
			},
			"done": false,
		}
		out, _ := json.Marshal(chunk)
		w.Write(out)
		w.Write([]byte("\n"))
		if flusher != nil {
			flusher.Flush()
		}
		if i < len(tokens)-1 {
			s.rngMu.Lock()
			delay := timing.tokenDelay(s.rng)
			s.rngMu.Unlock()
			time.Sleep(delay)
		}
	}

	elapsed := time.Since(start)
	finalChunk := map[string]interface{}{
		"model":      model,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
		"message": map[string]string{
			"role":    "assistant",
			"content": "",
		},
		"done":                 true,
		"done_reason":          "stop",
		"total_duration":       elapsed.Nanoseconds() + int64(timing.LoadDurationMs)*1e6,
		"load_duration":        int64(timing.LoadDurationMs) * 1e6,
		"prompt_eval_count":    promptEvalCount,
		"prompt_eval_duration": int64(50e6),
		"eval_count":           len(tokens),
		"eval_duration":        elapsed.Nanoseconds(),
	}
	out, _ := json.Marshal(finalChunk)
	w.Write(out)
	w.Write([]byte("\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

func (s *OllamaStrategy) writeOllamaChatNonStreaming(w http.ResponseWriter, model, response string, promptLen int) {
	timing := timingForModel(model)
	promptEvalCount := promptLen/4 + 1
	resp := map[string]interface{}{
		"model":      model,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
		"message": map[string]string{
			"role":    "assistant",
			"content": response,
		},
		"done":                 true,
		"done_reason":          "stop",
		"total_duration":       int64(timing.LoadDurationMs+200) * 1e6,
		"load_duration":        int64(timing.LoadDurationMs) * 1e6,
		"prompt_eval_count":    promptEvalCount,
		"prompt_eval_duration": int64(50e6),
		"eval_count":           len(response) / 4,
		"eval_duration":        int64(200e6),
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
}

// --- OpenAI response types --------------------------------------------------
//
// These shapes are DELIBERATE structs (not map[string]interface{}) because
// real api.openai.com uses Go-style struct marshaling with deterministic
// field ordering. A map-based response yields alphabetical field order on
// the wire, which is the single easiest Censys/Shodan banner signature.
// Field ORDER in the struct definition below is the order OpenAI emits on
// the wire — do not reorder without checking a real capture.

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	Refusal *string `json:"refusal"`
}

type openAIChatChoice struct {
	Index        int                `json:"index"`
	Message      openAIChatMessage  `json:"message"`
	Logprobs     *struct{}          `json:"logprobs"`
	FinishReason string             `json:"finish_reason"`
}

type openAIPromptTokensDetails struct {
	CachedTokens int `json:"cached_tokens"`
	AudioTokens  int `json:"audio_tokens"`
}

type openAICompletionTokensDetails struct {
	ReasoningTokens          int `json:"reasoning_tokens"`
	AudioTokens              int `json:"audio_tokens"`
	AcceptedPredictionTokens int `json:"accepted_prediction_tokens"`
	RejectedPredictionTokens int `json:"rejected_prediction_tokens"`
}

type openAIUsage struct {
	PromptTokens            int                           `json:"prompt_tokens"`
	CompletionTokens        int                           `json:"completion_tokens"`
	TotalTokens             int                           `json:"total_tokens"`
	PromptTokensDetails     openAIPromptTokensDetails     `json:"prompt_tokens_details"`
	CompletionTokensDetails openAICompletionTokensDetails `json:"completion_tokens_details"`
}

type openAIChatCompletion struct {
	ID                string             `json:"id"`
	Object            string             `json:"object"`
	Created           int64              `json:"created"`
	Model             string             `json:"model"`
	Choices           []openAIChatChoice `json:"choices"`
	Usage             openAIUsage        `json:"usage"`
	SystemFingerprint string             `json:"system_fingerprint"`
	ServiceTier       string             `json:"service_tier"`
}

type openAIChunkDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

type openAIChunkChoice struct {
	Index        int              `json:"index"`
	Delta        openAIChunkDelta `json:"delta"`
	Logprobs     *struct{}        `json:"logprobs"`
	FinishReason *string          `json:"finish_reason"`
}

type openAIChatChunk struct {
	ID                string              `json:"id"`
	Object            string              `json:"object"`
	Created           int64               `json:"created"`
	Model             string              `json:"model"`
	Choices           []openAIChunkChoice `json:"choices"`
	SystemFingerprint string              `json:"system_fingerprint"`
	ServiceTier       string              `json:"service_tier"`
}

func (s *OllamaStrategy) streamOpenAIResponse(w http.ResponseWriter, model, response string) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Header().Set("X-Platform", "Crestfield Platform v3.12.1-rc1")
	flusher, _ := w.(http.Flusher)

	// Simulate prompt evaluation time (real LLMs pause before first token)
	promptEvalDelay := time.Duration(s.promptEvalDelayMs) * time.Millisecond
	s.rngMu.Lock()
	jitter := time.Duration(s.rng.Intn(100)) * time.Millisecond
	s.rngMu.Unlock()
	time.Sleep(promptEvalDelay + jitter)

	chatID := "chatcmpl-" + randomAlnumN(29)
	tokens := tokenizeResponse(response)
	timing := timingForModel(model)
	created := time.Now().Unix()
	fingerprint := "fp_" + randomHexN(10)

	emptyContent := ""
	roleChunk := openAIChatChunk{
		ID:                chatID,
		Object:            "chat.completion.chunk",
		Created:           created,
		Model:             model,
		Choices: []openAIChunkChoice{{
			Index:        0,
			Delta:        openAIChunkDelta{Role: "assistant", Content: emptyContent},
			FinishReason: nil,
		}},
		SystemFingerprint: fingerprint,
		ServiceTier:       "default",
	}
	// Force the empty Content to serialize (omitempty would drop it, but
	// real OpenAI emits `"content":""` in the first chunk). Work around by
	// marshaling explicitly after the struct.
	roleOut, _ := json.Marshal(struct {
		openAIChatChunk
		Choices []struct {
			Index        int `json:"index"`
			Delta        struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"delta"`
			Logprobs     *struct{} `json:"logprobs"`
			FinishReason *string   `json:"finish_reason"`
		} `json:"choices"`
	}{
		openAIChatChunk: roleChunk,
		Choices: []struct {
			Index        int `json:"index"`
			Delta        struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"delta"`
			Logprobs     *struct{} `json:"logprobs"`
			FinishReason *string   `json:"finish_reason"`
		}{{
			Index: 0,
			Delta: struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			}{Role: "assistant", Content: ""},
			Logprobs:     nil,
			FinishReason: nil,
		}},
	})
	fmt.Fprintf(w, "data: %s\n\n", roleOut)
	if flusher != nil {
		flusher.Flush()
	}

	for i, token := range tokens {
		chunk := openAIChatChunk{
			ID:                chatID,
			Object:            "chat.completion.chunk",
			Created:           created,
			Model:             model,
			Choices: []openAIChunkChoice{{
				Index:        0,
				Delta:        openAIChunkDelta{Content: token},
				FinishReason: nil,
			}},
			SystemFingerprint: fingerprint,
			ServiceTier:       "default",
		}
		out, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", out)
		if flusher != nil {
			flusher.Flush()
		}
		if i < len(tokens)-1 {
			s.rngMu.Lock()
			delay := timing.tokenDelay(s.rng)
			s.rngMu.Unlock()
			time.Sleep(delay)
		}
	}

	stop := "stop"
	finalChunk := openAIChatChunk{
		ID:                chatID,
		Object:            "chat.completion.chunk",
		Created:           created,
		Model:             model,
		Choices: []openAIChunkChoice{{
			Index:        0,
			Delta:        openAIChunkDelta{},
			FinishReason: &stop,
		}},
		SystemFingerprint: fingerprint,
		ServiceTier:       "default",
	}
	out, _ := json.Marshal(finalChunk)
	fmt.Fprintf(w, "data: %s\n\n", out)
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func (s *OllamaStrategy) writeOpenAINonStreaming(w http.ResponseWriter, model, response string, promptLen int) {
	chatID := "chatcmpl-" + randomAlnumN(29)
	fingerprint := "fp_" + randomHexN(10)
	promptTokens := promptLen/4 + 1
	completionTokens := len(response) / 4

	resp := openAIChatCompletion{
		ID:      chatID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []openAIChatChoice{{
			Index: 0,
			Message: openAIChatMessage{
				Role:    "assistant",
				Content: response,
				Refusal: nil,
			},
			Logprobs:     nil,
			FinishReason: "stop",
		}},
		Usage: openAIUsage{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      promptTokens + completionTokens,
		},
		SystemFingerprint: fingerprint,
		ServiceTier:       "default",
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Platform", "Crestfield Platform v3.12.1-rc1")
	out, _ := json.Marshal(resp)
	w.Write(out)
}

// --- Utility functions ---

func fmtHeaders(headers http.Header) string {
	var b strings.Builder
	for key, values := range headers {
		for _, v := range values {
			fmt.Fprintf(&b, "[Key: %s, values: %s],", key, v)
		}
	}
	return b.String()
}

func sizeFromParam(paramSize string) int64 {
	switch strings.ToUpper(paramSize) {
	case "1.5B":
		return 1_100_000_000
	case "2.7B":
		return 1_600_000_000
	case "3B":
		return 2_000_000_000
	case "7B", "8B", "8.0B":
		return 4_700_000_000
	case "13B", "14B":
		return 8_200_000_000
	case "16B":
		return 10_200_000_000
	case "32B", "33B":
		return 20_500_000_000
	case "70B", "70.6B":
		return 42_182_029_312
	default:
		return 274_000_000 // embedding model size
	}
}

func paramCountFromSize(paramSize string) int64 {
	switch strings.ToUpper(paramSize) {
	case "1.5B":
		return 1_500_000_000
	case "2.7B":
		return 2_700_000_000
	case "3B":
		return 3_000_000_000
	case "7B":
		return 7_000_000_000
	case "8B", "8.0B":
		return 8_000_000_000
	case "13B":
		return 13_000_000_000
	case "14B":
		return 14_000_000_000
	case "16B":
		return 16_000_000_000
	case "32B", "33B":
		return 33_000_000_000
	case "70B", "70.6B":
		return 70_600_000_000
	default:
		return 137_000_000
	}
}

// jsonString returns a JSON-encoded string value.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
