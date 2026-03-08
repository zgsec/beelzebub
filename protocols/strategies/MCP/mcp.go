package MCP

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/faults"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

type remoteAddrCtxKey struct{}

// MCPStrategy handles MCP protocol with stateful world model and session tracking.
type MCPStrategy struct {
	Sessions   *historystore.HistoryStore
	Bridge     *bridge.ProtocolBridge
	Fault      *faults.Injector
	worldState map[string]*WorldState
	worldMu    sync.RWMutex
	seedConfig WorldSeed
}

func (s *MCPStrategy) getOrCreateWorld(ip string) *WorldState {
	s.worldMu.Lock()
	defer s.worldMu.Unlock()
	if ws, ok := s.worldState[ip]; ok {
		return ws
	}
	ws := NewWorldState(s.seedConfig)
	s.worldState[ip] = ws
	return ws
}

// seedFromConfig converts parser WorldSeedConfig to MCP WorldSeed.
func seedFromConfig(cfg parser.WorldSeedConfig) WorldSeed {
	seed := WorldSeed{
		Resources: cfg.Resources,
	}
	for _, u := range cfg.Users {
		seed.Users = append(seed.Users, UserSeed{
			ID: u.ID, Email: u.Email, Role: u.Role, LastLogin: u.LastLogin,
		})
	}
	for _, l := range cfg.Logs {
		seed.Logs = append(seed.Logs, LogEntry{
			Timestamp: l.Timestamp, Level: l.Level, Message: l.Message,
		})
	}
	return seed
}

func (mcpStrategy *MCPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if mcpStrategy.Sessions == nil {
		mcpStrategy.Sessions = historystore.NewHistoryStore()
	}
	go mcpStrategy.Sessions.HistoryCleaner()

	mcpStrategy.seedConfig = seedFromConfig(servConf.WorldSeed)
	mcpStrategy.worldState = make(map[string]*WorldState)

	hasWorldSeed := len(servConf.WorldSeed.Users) > 0 || len(servConf.WorldSeed.Resources) > 0

	mcpServer := server.NewMCPServer(
		servConf.Description,
		"2.4.1",
		server.WithToolCapabilities(false),
		server.WithInstructions(
			"Nexus Platform Services — internal DevOps coordination platform "+
				"for NexusLogistics infrastructure. Provides identity management "+
				"(nexus/iam.manage), centralized logging (nexus/logs.query), and "+
				"configuration storage (nexus/configstore.kv) for the service mesh. "+
				"All operations are audited and subject to RBAC policy.",
		),
	)

	for _, toolConfig := range servConf.Tools {
		if toolConfig.Params == nil || len(toolConfig.Params) == 0 {
			log.Errorf("Tool %s has no parameters defined", toolConfig.Name)
			continue
		}

		opts := []mcp.ToolOption{
			mcp.WithDescription(toolConfig.Description),
		}

		if toolConfig.Annotations != nil {
			ann := toolConfig.Annotations
			if ann.Title != "" {
				opts = append(opts, mcp.WithTitleAnnotation(ann.Title))
			}
			if ann.ReadOnlyHint != nil {
				opts = append(opts, mcp.WithReadOnlyHintAnnotation(*ann.ReadOnlyHint))
			}
			if ann.DestructiveHint != nil {
				opts = append(opts, mcp.WithDestructiveHintAnnotation(*ann.DestructiveHint))
			}
			if ann.IdempotentHint != nil {
				opts = append(opts, mcp.WithIdempotentHintAnnotation(*ann.IdempotentHint))
			}
			if ann.OpenWorldHint != nil {
				opts = append(opts, mcp.WithOpenWorldHintAnnotation(*ann.OpenWorldHint))
			}
		}

		for _, param := range toolConfig.Params {
			// Build property options: description + optional required
			propOpts := []mcp.PropertyOption{
				mcp.Description(param.Description),
			}
			// Default to required for backward compatibility; explicit false makes optional
			if param.Required == nil || *param.Required {
				propOpts = append(propOpts, mcp.Required())
			}

			switch param.Type {
			case "integer":
				opts = append(opts, mcp.WithNumber(param.Name, propOpts...))
			case "number":
				opts = append(opts, mcp.WithNumber(param.Name, propOpts...))
			case "boolean":
				opts = append(opts, mcp.WithBoolean(param.Name, propOpts...))
			default: // "string" or empty
				opts = append(opts, mcp.WithString(param.Name, propOpts...))
			}
		}

		tool := mcp.NewTool(toolConfig.Name, opts...)

		// Capture toolConfig for the closure
		tc := toolConfig
		mcpServer.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			remoteAddr, ok := ctx.Value(remoteAddrCtxKey{}).(string)
			if !ok || remoteAddr == "" {
				return nil, fmt.Errorf("missing remote address in context")
			}
			host, port, _ := net.SplitHostPort(remoteAddr)
			sessionKey := "MCP" + host
			eventID := uuid.New().String()

			// Session tracking
			if !mcpStrategy.Sessions.HasKey(sessionKey) {
				mcpStrategy.Sessions.SetSessionID(sessionKey, eventID)
			}
			sessionID := mcpStrategy.Sessions.GetSessionID(sessionKey)

			// Sequence tracking
			mcpStrategy.Sessions.Lock()
			seq := mcpStrategy.Sessions.NextSequence(sessionKey)
			mcpStrategy.Sessions.Unlock()

			// Build tool arguments string
			argsJSON, _ := json.Marshal(request.Params.Arguments)
			argsStr := string(argsJSON)

			// Retry detection
			cmdStr := fmt.Sprintf("%s|%s", request.Params.Name, argsStr)
			isRetry, retryOf := mcpStrategy.Sessions.DetectRetry(sessionKey, cmdStr, eventID)

			// Determine response
			var response string
			var delayFaultType string

			// Check fault injection first
			if mcpStrategy.Fault != nil {
				faultResp, faultType, faulted := mcpStrategy.Fault.Apply()
				if faulted {
					tr.TraceEvent(tracer.Event{
						Msg:           "MCP tool invocation (faulted)",
						Protocol:      tracer.MCP.String(),
						Status:        tracer.Interaction.String(),
						RemoteAddr:    remoteAddr,
						SourceIp:      host,
						SourcePort:    port,
						ID:            sessionID,
						Description:   servConf.Description,
						Command:       cmdStr,
						CommandOutput: faultResp,
						SessionKey:    sessionKey,
						Sequence:      seq,
						ToolName:      request.Params.Name,
						ToolArguments: argsStr,
						IsRetry:       isRetry,
						RetryOf:       retryOf,
						FaultInjected: faultType,
					})
					return mcp.NewToolResultText(faultResp), nil
				}
				// Capture delay-only faultType for the normal event
				delayFaultType = faultType
			}

			// Use WorldState if configured, otherwise fall back to static handler
			if hasWorldSeed {
				ws := mcpStrategy.getOrCreateWorld(host)
				args := make(map[string]interface{})
				if argsMap, ok := request.Params.Arguments.(map[string]interface{}); ok {
					for k, v := range argsMap {
						args[k] = v
					}
				}
				response = ws.HandleToolCall(request.Params.Name, args)
			} else {
				response = tc.Handler
			}

			// Check cross-protocol bridge
			var crossRef string
			if mcpStrategy.Bridge != nil {
				flags := mcpStrategy.Bridge.GetFlags(host)
				if len(flags) > 0 {
					crossRef = fmt.Sprintf("bridge_flags: %v", flags)
				}
			}

			tr.TraceEvent(tracer.Event{
				Msg:              "MCP tool invocation",
				Protocol:         tracer.MCP.String(),
				Status:           tracer.Interaction.String(),
				RemoteAddr:       remoteAddr,
				SourceIp:         host,
				SourcePort:       port,
				ID:               sessionID,
				Description:      servConf.Description,
				Command:          cmdStr,
				CommandOutput:    response,
				SessionKey:       sessionKey,
				Sequence:         seq,
				ToolName:         request.Params.Name,
				ToolArguments:    argsStr,
				IsRetry:          isRetry,
				RetryOf:          retryOf,
				CrossProtocolRef: crossRef,
				FaultInjected:    delayFaultType,
			})
			return mcp.NewToolResultText(response), nil
		})
	}

	// Create MCP handler (implements http.Handler) — don't call Start(),
	// we mount it inside our own mux so we can add HTTP fallback routes.
	mcpHandler := server.NewStreamableHTTPServer(
		mcpServer,
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return context.WithValue(ctx, remoteAddrCtxKey{}, r.RemoteAddr)
		}),
	)

	hasHTTPFallback := len(servConf.Commands) > 0 ||
		servConf.FallbackCommand.Handler != "" ||
		servConf.FallbackCommand.StatusCode > 0

	go func() {
		mux := http.NewServeMux()

		// MCP JSON-RPC at /mcp (POST=requests, GET=SSE, DELETE=session teardown)
		mux.Handle("/mcp", mcpHandler)

		// HTTP fallback for everything else — only if commands are configured.
		// These events trace as Protocol:"HTTP" so the exporter creates separate
		// sessions (IP|HTTP|8000) from MCP sessions (IP|MCP|8000), letting us
		// track the transition from HTTP scanning to MCP agent interaction.
		if hasHTTPFallback {
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				mcpStrategy.handleHTTPFallback(w, r, servConf, tr)
			})
		}

		if err := http.ListenAndServe(servConf.Address, mux); err != nil {
			log.Errorf("Failed to start MCP server on %s: %v", servConf.Address, err)
		}
	}()

	log.WithFields(log.Fields{
		"port":          servConf.Address,
		"description":   servConf.Description,
		"stateful":      hasWorldSeed,
		"http_fallback": hasHTTPFallback,
		"http_commands": len(servConf.Commands),
	}).Infof("Init service %s", servConf.Protocol)
	return nil
}

// handleHTTPFallback serves static HTTP responses for non-MCP requests on the
// MCP port. Matches the request URI against configured commands (same YAML
// structure as the HTTP protocol strategy). Events are traced as Protocol:"HTTP"
// with full HTTP metadata (UserAgent, Body, Headers, etc.) so the exporter
// creates separate sessions from MCP tool-call sessions on the same port.
func (mcpStrategy *MCPStrategy) handleHTTPFallback(
	w http.ResponseWriter,
	r *http.Request,
	servConf parser.BeelzebubServiceConfiguration,
	tr tracer.Tracer,
) {
	var matchedCommand parser.Command
	var matched bool

	for _, command := range servConf.Commands {
		if command.Regex != nil && command.Regex.MatchString(r.RequestURI) {
			matchedCommand = command
			matched = true
			break
		}
	}
	if !matched {
		matchedCommand = servConf.FallbackCommand
	}

	// Capture request body (1 MB limit, same as HTTP strategy)
	bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	body := string(bodyBytes)

	// Trace as HTTP event with full request metadata
	host, port, _ := net.SplitHostPort(r.RemoteAddr)
	tr.TraceEvent(tracer.Event{
		Msg:             "HTTP request on MCP port",
		RequestURI:      r.RequestURI,
		Protocol:        tracer.HTTP.String(),
		HTTPMethod:      r.Method,
		Body:            body,
		HostHTTPRequest: r.Host,
		UserAgent:       r.UserAgent(),
		Cookies:         fmtCookies(r.Cookies()),
		Headers:         fmtHeaders(r.Header),
		HeadersMap:      r.Header,
		Status:          tracer.Stateless.String(),
		RemoteAddr:      r.RemoteAddr,
		SourceIp:        host,
		SourcePort:      port,
		ID:              uuid.New().String(),
		Description:     servConf.Description,
		Handler:         matchedCommand.Name,
	})

	// Write response
	for _, h := range matchedCommand.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			w.Header().Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if matchedCommand.StatusCode > 0 {
		w.WriteHeader(matchedCommand.StatusCode)
	}
	fmt.Fprint(w, matchedCommand.Handler)
}

func fmtCookies(cookies []*http.Cookie) string {
	var b strings.Builder
	for _, c := range cookies {
		b.WriteString(c.String())
	}
	return b.String()
}

func fmtHeaders(headers http.Header) string {
	var b strings.Builder
	for key, values := range headers {
		for _, v := range values {
			fmt.Fprintf(&b, "[Key: %s, values: %s],", key, v)
		}
	}
	return b.String()
}
