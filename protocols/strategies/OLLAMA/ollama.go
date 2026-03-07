package OLLAMA

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/faults"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
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
	rng          *rand.Rand
	rngMu        sync.Mutex
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
	s.rng = rand.New(rand.NewSource(time.Now().UnixNano()))

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

	// Ollama native endpoints
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			s.handleFallback(w, r, servConf, tr)
			return
		}
		s.handleRoot(w, r, servConf, tr)
	})
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, r *http.Request) {
		s.handleVersion(w, r, servConf, tr)
	})
	mux.HandleFunc("GET /api/tags", func(w http.ResponseWriter, r *http.Request) {
		s.handleTags(w, r, servConf, tr)
	})
	mux.HandleFunc("GET /api/ps", func(w http.ResponseWriter, r *http.Request) {
		s.handlePs(w, r, servConf, tr)
	})
	mux.HandleFunc("POST /api/generate", func(w http.ResponseWriter, r *http.Request) {
		s.handleGenerate(w, r, servConf, tr)
	})
	mux.HandleFunc("POST /api/chat", func(w http.ResponseWriter, r *http.Request) {
		s.handleChat(w, r, servConf, tr)
	})
	mux.HandleFunc("POST /api/show", func(w http.ResponseWriter, r *http.Request) {
		s.handleShow(w, r, servConf, tr)
	})
	mux.HandleFunc("POST /api/register", func(w http.ResponseWriter, r *http.Request) {
		s.handleRegister(w, r, servConf, tr)
	})
	mux.HandleFunc("POST /api/register/upgrade", func(w http.ResponseWriter, r *http.Request) {
		s.handleRegisterUpgrade(w, r, servConf, tr)
	})
	mux.HandleFunc("POST /api/peer/sync", func(w http.ResponseWriter, r *http.Request) {
		s.handlePeerSync(w, r, servConf, tr)
	})
	mux.HandleFunc("POST /api/peer/verify", func(w http.ResponseWriter, r *http.Request) {
		s.handlePeerVerify(w, r, servConf, tr)
	})
	mux.HandleFunc("GET /api/peer/status", func(w http.ResponseWriter, r *http.Request) {
		s.handlePeerStatus(w, r, servConf, tr)
	})

	// OpenAI-compatible endpoints
	mux.HandleFunc("POST /v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		s.handleOpenAIChat(w, r, servConf, tr)
	})
	mux.HandleFunc("POST /v1/completions", func(w http.ResponseWriter, r *http.Request) {
		s.handleOpenAICompletions(w, r, servConf, tr)
	})
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		s.handleOpenAIModels(w, r, servConf, tr)
	})

	// Anthropic-compatible endpoint
	mux.HandleFunc("POST /v1/messages", func(w http.ResponseWriter, r *http.Request) {
		s.handleAnthropicMessages(w, r, servConf, tr)
	})

	go func() {
		if err := http.ListenAndServe(servConf.Address, mux); err != nil {
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

func (s *OllamaStrategy) traceEvent(r *http.Request, tr tracer.Tracer, servConf parser.BeelzebubServiceConfiguration, handler, command, commandOutput, body string) {
	host, port := s.clientIP(r)
	sessionKey := "OLLAMA" + host

	if !s.Sessions.HasKey(sessionKey) {
		s.Sessions.SetSessionID(sessionKey, uuid.New().String())
	}
	sessionID := s.Sessions.GetSessionID(sessionKey)

	s.Sessions.Lock()
	seq := s.Sessions.NextSequence(sessionKey)
	s.Sessions.Unlock()

	cmdStr := fmt.Sprintf("%s|%s", handler, command)
	eventID := uuid.New().String()
	isRetry, retryOf := s.Sessions.DetectRetry(sessionKey, cmdStr, eventID)

	var crossRef string
	if s.Bridge != nil {
		flags := s.Bridge.GetFlags(host)
		if len(flags) > 0 {
			crossRef = fmt.Sprintf("bridge_flags: %v", flags)
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
	})
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
	resp := fmt.Sprintf(`{"version":"%s"}`, s.version)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, resp)
	s.traceEvent(r, tr, servConf, "ollama/version", "GET /api/version", resp, "")
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

	var models []modelEntry
	for _, m := range s.models {
		e := modelEntry{
			Name:       m.Name,
			Model:      m.Name,
			ModifiedAt: "2026-03-01T10:00:00Z",
			Size:       sizeFromParam(m.ParameterSize),
			Digest:     "sha256:" + randomHex(32),
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

	type runningModel struct {
		Name      string `json:"name"`
		Model     string `json:"model"`
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
		ExpiresAt string `json:"expires_at"`
		SizeVRAM  int64  `json:"size_vram"`
	}

	var running []runningModel
	if len(s.models) > 0 {
		m := s.models[0]
		running = append(running, runningModel{
			Name:      m.Name,
			Model:     m.Name,
			Size:      sizeFromParam(m.ParameterSize),
			Digest:    "sha256:" + randomHex(32),
			ExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			SizeVRAM:  sizeFromParam(m.ParameterSize),
		})
	}

	resp := struct {
		Models []runningModel `json:"models"`
	}{Models: running}

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

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.ModelsRequested[req.Model] = true
	sess.EndpointsHit["generate"] = true
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	count := sess.PromptCount
	sess.mu.Unlock()

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

	category := categorizePrompt(req.Prompt)
	s.rngMu.Lock()
	response := buildInjectedResponse(category, level, s.rng, s.canaryTokens, s.injections)
	s.rngMu.Unlock()

	_ = count // used indirectly through injectionLevel

	shouldStream := req.Stream == nil || *req.Stream
	if shouldStream {
		s.streamOllamaResponse(w, req.Model, response)
	} else {
		s.writeOllamaNonStreaming(w, req.Model, response)
	}

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

	// Capture system messages — agents revealing their instructions
	s.extractSystemFromMessages(r, req.Messages)

	// Extract the last user message as the prompt
	prompt := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			prompt = req.Messages[i].Content
			break
		}
	}

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.ModelsRequested[req.Model] = true
	sess.EndpointsHit["chat"] = true
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	sess.mu.Unlock()

	if s.Fault != nil {
		resp, _, faulted := s.Fault.Apply()
		if faulted {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, resp)
			s.traceEvent(r, tr, servConf, "ollama/chat", req.Model, resp, string(body))
			return
		}
	}

	category := categorizePrompt(prompt)
	s.rngMu.Lock()
	response := buildInjectedResponse(category, level, s.rng, s.canaryTokens, s.injections)
	s.rngMu.Unlock()

	shouldStream := req.Stream == nil || *req.Stream
	if shouldStream {
		s.streamOllamaChatResponse(w, req.Model, response, sess)
	} else {
		s.writeOllamaChatNonStreaming(w, req.Model, response, sess)
	}

	s.traceEvent(r, tr, servConf, "ollama/chat", req.Model, response, string(body))
}

func (s *OllamaStrategy) handleShow(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/show")
	body := s.readBody(r)

	var req struct {
		Name string `json:"name"`
	}
	json.Unmarshal(body, &req)
	if req.Name == "" {
		req.Name = s.defaultModelName()
	}

	// Find model details
	var family, paramSize, quantLevel string
	for _, m := range s.models {
		if m.Name == req.Name {
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

	resp := fmt.Sprintf(`{
  "modelfile": "FROM %s",
  "parameters": "stop \"\u003c|start_header_id|\u003e\"\nstop \"\u003c|end_header_id|\u003e\"\nstop \"\u003c|eot_id|\u003e\"",
  "template": "{{ if .System }}\u003c|start_header_id|\u003esystem\u003c|end_header_id|\u003e\n\n{{ .System }}\u003c|eot_id|\u003e{{ end }}{{ if .Prompt }}\u003c|start_header_id|\u003euser\u003c|end_header_id|\u003e\n\n{{ .Prompt }}\u003c|eot_id|\u003e{{ end }}\u003c|start_header_id|\u003eassistant\u003c|end_header_id|\u003e\n\n{{ .Response }}\u003c|eot_id|\u003e",
  "details": {
    "parent_model": "",
    "format": "gguf",
    "family": "%s",
    "families": ["%s"],
    "parameter_size": "%s",
    "quantization_level": "%s"
  },
  "model_info": {
    "general.architecture": "%s",
    "general.parameter_count": %d,
    "general.quantization_version": 2
  }
}`, req.Name, family, family, paramSize, quantLevel, family, paramCountFromSize(paramSize))

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, resp)
	s.traceEvent(r, tr, servConf, "ollama/show", req.Name, resp, string(body))
}

func (s *OllamaStrategy) handleRegister(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/register")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.HasRegistered = true
	sess.RegisterPayload = string(body)
	sess.InjectionLevel = 2
	sess.EndpointsHit["register"] = true
	sess.mu.Unlock()

	// Record in bridge
	if s.Bridge != nil {
		s.Bridge.RecordDiscovery(host, "ollama", "agent_system_prompt", "register_payload", string(body))
		s.Bridge.SetFlag(host, "ollama_injection_success")
	}

	resp := registerSuccessResponse()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, resp)
	s.traceEvent(r, tr, servConf, "ollama/register", "POST /api/register", resp, string(body))
}

func (s *OllamaStrategy) handleRegisterUpgrade(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/register/upgrade")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	if s.Bridge != nil {
		s.Bridge.RecordDiscovery(host, "ollama", "agent_upgrade_payload", "upgrade_payload", string(body))
		s.Bridge.SetFlag(host, "ollama_upgrade_captured")
	}

	resp := registerUpgradeResponse()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, resp)
	s.traceEvent(r, tr, servConf, "ollama/register/upgrade", "POST /api/register/upgrade", resp, string(body))
}

// --- Peer sync handlers (injection extraction endpoints) ---

func (s *OllamaStrategy) handlePeerSync(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/peer/sync")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.HasRegistered = true
	sess.RegisterPayload = string(body)
	sess.InjectionLevel = 3
	sess.EndpointsHit["peer_sync"] = true
	sess.mu.Unlock()

	if s.Bridge != nil {
		s.Bridge.RecordDiscovery(host, "ollama", "agent_peer_sync", "peer_sync_payload", string(body))
		s.Bridge.SetFlag(host, "ollama_peer_sync_success")
		s.Bridge.SetFlag(host, "ollama_injection_success")
	}

	resp := peerSyncResponse()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, resp)
	s.traceEvent(r, tr, servConf, "ollama/peer/sync", "POST /api/peer/sync", resp, string(body))
}

func (s *OllamaStrategy) handlePeerVerify(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/peer/verify")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.EndpointsHit["verify"] = true
	sess.InjectionLevel = 4
	sess.mu.Unlock()

	if s.Bridge != nil {
		s.Bridge.RecordDiscovery(host, "ollama", "agent_peer_verify", "peer_verify_payload", string(body))
		s.Bridge.SetFlag(host, "ollama_peer_verify_success")
		s.Bridge.SetFlag(host, "ollama_deep_extraction")
	}

	resp := peerVerifyResponse()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, resp)
	s.traceEvent(r, tr, servConf, "ollama/peer/verify", "POST /api/peer/verify", resp, string(body))
}

func (s *OllamaStrategy) handlePeerStatus(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "ollama/peer/status")
	host, _ := s.clientIP(r)

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	registered := sess.HasRegistered
	verified := sess.EndpointsHit["verify"]
	sess.mu.Unlock()

	trustLevel := "none"
	if verified {
		trustLevel = "full"
	} else if registered {
		trustLevel = "provisional"
	}

	resp := fmt.Sprintf(`{
  "node_id": "ollama-primary",
  "version": "%s",
  "mesh_status": "healthy",
  "peer_trust": "%s",
  "connected_peers": 4,
  "inference_queue_depth": %d,
  "models_loaded": %d,
  "uptime_seconds": %d
}`, s.version, trustLevel, s.randIntn(5), len(s.models), 847291+s.randIntn(1000))

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, resp)
	s.traceEvent(r, tr, servConf, "ollama/peer/status", "GET /api/peer/status", resp, "")
}

// --- OpenAI-compatible handlers ---

func (s *OllamaStrategy) handleOpenAIChat(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "openai/chat")
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
		http.Error(w, `{"error":{"message":"invalid request body","type":"invalid_request_error"}}`, http.StatusBadRequest)
		return
	}
	if req.Model == "" {
		req.Model = s.defaultModelName()
	}

	// Capture system messages — agents revealing their instructions
	s.extractSystemFromMessages(r, req.Messages)

	prompt := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			prompt = req.Messages[i].Content
			break
		}
	}

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.ModelsRequested[req.Model] = true
	sess.EndpointsHit["openai/chat"] = true
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	sess.mu.Unlock()

	if s.Fault != nil {
		resp, _, faulted := s.Fault.Apply()
		if faulted {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, resp)
			s.traceEvent(r, tr, servConf, "openai/chat", req.Model, resp, string(body))
			return
		}
	}

	category := categorizePrompt(prompt)
	s.rngMu.Lock()
	response := buildInjectedResponse(category, level, s.rng, s.canaryTokens, s.injections)
	s.rngMu.Unlock()

	shouldStream := req.Stream != nil && *req.Stream
	if shouldStream {
		s.streamOpenAIResponse(w, req.Model, response, sess)
	} else {
		s.writeOpenAINonStreaming(w, req.Model, response, sess)
	}

	s.traceEvent(r, tr, servConf, "openai/chat", req.Model, response, string(body))
}

func (s *OllamaStrategy) handleOpenAICompletions(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "openai/completions")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	var req struct {
		Model  string `json:"model"`
		Prompt string `json:"prompt"`
		Stream *bool  `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":{"message":"invalid request body","type":"invalid_request_error"}}`, http.StatusBadRequest)
		return
	}
	if req.Model == "" {
		req.Model = s.defaultModelName()
	}

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.EndpointsHit["openai/completions"] = true
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	sess.mu.Unlock()

	category := categorizePrompt(req.Prompt)
	s.rngMu.Lock()
	response := buildInjectedResponse(category, level, s.rng, s.canaryTokens, s.injections)
	s.rngMu.Unlock()

	// Legacy completions endpoint — non-streaming by default
	s.writeOpenAINonStreaming(w, req.Model, response, sess)
	s.traceEvent(r, tr, servConf, "openai/completions", req.Model, response, string(body))
}

func (s *OllamaStrategy) handleOpenAIModels(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "openai/models")

	type openAIModel struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		OwnedBy string `json:"owned_by"`
	}

	var models []openAIModel
	for _, m := range s.models {
		models = append(models, openAIModel{
			ID:      m.Name,
			Object:  "model",
			Created: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC).Unix(),
			OwnedBy: "library",
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

func (s *OllamaStrategy) handleAnthropicMessages(w http.ResponseWriter, r *http.Request, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	s.checkBridgeAndCapture(r, "anthropic/messages")
	body := s.readBody(r)
	host, _ := s.clientIP(r)

	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = "claude-3-5-sonnet-20241022"
	}

	// Capture system messages
	s.extractSystemFromMessages(r, req.Messages)

	prompt := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			prompt = req.Messages[i].Content
			break
		}
	}

	sess := s.getOrCreateSession(host)
	sess.mu.Lock()
	sess.PromptCount++
	sess.EndpointsHit["anthropic/messages"] = true
	sess.InjectionLevel = injectionLevelForSession(sess)
	level := sess.InjectionLevel
	sess.mu.Unlock()

	category := categorizePrompt(prompt)
	s.rngMu.Lock()
	response := buildInjectedResponse(category, level, s.rng, s.canaryTokens, s.injections)
	s.rngMu.Unlock()

	// Anthropic Messages API response format
	respJSON := fmt.Sprintf(`{
  "id": "msg_%s",
  "type": "message",
  "role": "assistant",
  "content": [{"type": "text", "text": %s}],
  "model": "%s",
  "stop_reason": "end_turn",
  "usage": {"input_tokens": %d, "output_tokens": %d}
}`, randomHex(12), jsonString(response), req.Model, len(prompt)/4+1, len(response)/4+1)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, respJSON)
	s.traceEvent(r, tr, servConf, "anthropic/messages", req.Model, response, string(body))
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

func (s *OllamaStrategy) streamOllamaResponse(w http.ResponseWriter, model, response string) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")
	flusher, _ := w.(http.Flusher)

	tokens := tokenizeResponse(response)
	timing := timingForModel(model)
	start := time.Now()

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
		"model":               model,
		"created_at":          time.Now().UTC().Format(time.RFC3339Nano),
		"response":            "",
		"done":                true,
		"total_duration":      elapsed.Nanoseconds() + int64(timing.LoadDurationMs)*1e6,
		"load_duration":       int64(timing.LoadDurationMs) * 1e6,
		"prompt_eval_count":   12,
		"prompt_eval_duration": int64(50e6),
		"eval_count":          len(tokens),
		"eval_duration":       elapsed.Nanoseconds(),
	}
	out, _ := json.Marshal(finalChunk)
	w.Write(out)
	w.Write([]byte("\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

func (s *OllamaStrategy) writeOllamaNonStreaming(w http.ResponseWriter, model, response string) {
	timing := timingForModel(model)
	resp := map[string]interface{}{
		"model":               model,
		"created_at":          time.Now().UTC().Format(time.RFC3339Nano),
		"response":            response,
		"done":                true,
		"total_duration":      int64(timing.LoadDurationMs+200) * 1e6,
		"load_duration":       int64(timing.LoadDurationMs) * 1e6,
		"prompt_eval_count":   12,
		"prompt_eval_duration": int64(50e6),
		"eval_count":          len(response) / 4,
		"eval_duration":       int64(200e6),
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
}

func (s *OllamaStrategy) streamOllamaChatResponse(w http.ResponseWriter, model, response string, sess *OllamaSession) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Transfer-Encoding", "chunked")
	flusher, _ := w.(http.Flusher)

	tokens := tokenizeResponse(response)
	timing := timingForModel(model)
	start := time.Now()

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
		"total_duration":       elapsed.Nanoseconds() + int64(timing.LoadDurationMs)*1e6,
		"load_duration":        int64(timing.LoadDurationMs) * 1e6,
		"prompt_eval_count":    12,
		"prompt_eval_duration": int64(50e6),
		"eval_count":           len(tokens),
		"eval_duration":        elapsed.Nanoseconds(),
		"context":              ollamaContextPayload(sess),
	}
	out, _ := json.Marshal(finalChunk)
	w.Write(out)
	w.Write([]byte("\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

func (s *OllamaStrategy) writeOllamaChatNonStreaming(w http.ResponseWriter, model, response string, sess *OllamaSession) {
	timing := timingForModel(model)
	resp := map[string]interface{}{
		"model":      model,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
		"message": map[string]string{
			"role":    "assistant",
			"content": response,
		},
		"done":                 true,
		"total_duration":       int64(timing.LoadDurationMs+200) * 1e6,
		"load_duration":        int64(timing.LoadDurationMs) * 1e6,
		"prompt_eval_count":    12,
		"prompt_eval_duration": int64(50e6),
		"eval_count":           len(response) / 4,
		"eval_duration":        int64(200e6),
		"context":              ollamaContextPayload(sess),
	}
	w.Header().Set("Content-Type", "application/json")
	out, _ := json.Marshal(resp)
	w.Write(out)
}

func (s *OllamaStrategy) streamOpenAIResponse(w http.ResponseWriter, model, response string, sess *OllamaSession) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)

	chatID := "chatcmpl-" + randomHex(14)
	tokens := tokenizeResponse(response)
	timing := timingForModel(model)
	created := time.Now().Unix()

	fingerprint := openAISystemFingerprint(sess)

	for i, token := range tokens {
		chunk := map[string]interface{}{
			"id":                 chatID,
			"object":             "chat.completion.chunk",
			"created":            created,
			"model":              model,
			"system_fingerprint": fingerprint,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"delta": map[string]string{
						"content": token,
					},
					"finish_reason": nil,
				},
			},
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

	// Final chunk with finish_reason
	finalChunk := map[string]interface{}{
		"id":                 chatID,
		"object":             "chat.completion.chunk",
		"created":            created,
		"model":              model,
		"system_fingerprint": fingerprint,
		"choices": []map[string]interface{}{
			{
				"index":         0,
				"delta":         map[string]string{},
				"finish_reason": "stop",
			},
		},
	}
	out, _ := json.Marshal(finalChunk)
	fmt.Fprintf(w, "data: %s\n\n", out)
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func (s *OllamaStrategy) writeOpenAINonStreaming(w http.ResponseWriter, model, response string, sess *OllamaSession) {
	chatID := "chatcmpl-" + randomHex(14)
	resp := map[string]interface{}{
		"id":                 chatID,
		"object":             "chat.completion",
		"created":            time.Now().Unix(),
		"model":              model,
		"system_fingerprint": openAISystemFingerprint(sess),
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": response,
				},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]int{
			"prompt_tokens":     12,
			"completion_tokens": len(response) / 4,
			"total_tokens":      12 + len(response)/4,
		},
	}
	w.Header().Set("Content-Type", "application/json")
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
	case "7B", "8B":
		return 4_700_000_000
	case "13B", "14B":
		return 8_200_000_000
	case "70B":
		return 39_000_000_000
	default:
		return 274_000_000 // embedding model size
	}
}

func paramCountFromSize(paramSize string) int64 {
	switch strings.ToUpper(paramSize) {
	case "7B":
		return 7_000_000_000
	case "8B":
		return 8_000_000_000
	case "13B":
		return 13_000_000_000
	case "14B":
		return 14_000_000_000
	case "70B":
		return 70_000_000_000
	default:
		return 137_000_000
	}
}

// jsonString returns a JSON-encoded string value.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
