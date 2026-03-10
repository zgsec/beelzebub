package HTTP

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mariocandela/beelzebub/v3/agentdetect"
	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/faults"
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
}

type httpResponse struct {
	StatusCode int
	Headers    []string
	Body       string
}

func (httpStrategy HTTPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	startHTTPSessionCleanup()
	serverMux := http.NewServeMux()

	serverMux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		var matched bool
		var resp httpResponse
		var err error
		for _, command := range servConf.Commands {
			var err error
			matched = command.Regex.MatchString(request.RequestURI)
			if matched {
				resp, err = buildHTTPResponse(servConf, tr, command, request)
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
				resp, err = buildHTTPResponse(servConf, tr, command, request)
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
		var err error
		// Launch a TLS supporting server if we are supplied a TLS Key and Certificate.
		// If relative paths are supplied, they are relative to the CWD of the binary.
		// The can be self-signed, only the client will validate this (or not).
		if servConf.TLSKeyPath != "" && servConf.TLSCertPath != "" {
			err = http.ListenAndServeTLS(servConf.Address, servConf.TLSCertPath, servConf.TLSKeyPath, serverMux)
		} else {
			err = http.ListenAndServe(servConf.Address, serverMux)
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

func buildHTTPResponse(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, command parser.Command, request *http.Request) (httpResponse, error) {
	resp := httpResponse{
		Body:       command.Handler,
		Headers:    command.Headers,
		StatusCode: command.StatusCode,
	}

	// Limit body read to 1MB to prevent DoS attacks
	bodyBytes, err := io.ReadAll(io.LimitReader(request.Body, 1024*1024))
	body := ""
	if err == nil {
		body = string(bodyBytes)
	}
	traceRequest(request, tr, command, servConf.Description, body)

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

func traceRequest(request *http.Request, tr tracer.Tracer, command parser.Command, HoneypotDescription, body string) {
	host, port, _ := net.SplitHostPort(request.RemoteAddr)
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
		Handler:         command.Name,
		SessionKey:      sessionKey,
		Sequence:        seq,
		AgentScore:      verdict.Score,
		AgentCategory:   verdict.Category,
		AgentSignals:    verdict.SignalsString(),
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
