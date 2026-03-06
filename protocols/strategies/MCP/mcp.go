package MCP

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
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
		"1.0.0",
		server.WithToolCapabilities(false),
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
			opts = append(opts,
				mcp.WithString(
					param.Name,
					mcp.Required(),
					mcp.Description(param.Description),
				),
			)
		}

		tool := mcp.NewTool(toolConfig.Name, opts...)

		// Capture toolConfig for the closure
		tc := toolConfig
		mcpServer.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			host, port, _ := net.SplitHostPort(ctx.Value(remoteAddrCtxKey{}).(string))
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

			// Check fault injection first
			if mcpStrategy.Fault != nil {
				if faultResp, faultType, faulted := mcpStrategy.Fault.Apply(); faulted {
					tr.TraceEvent(tracer.Event{
						Msg:           "MCP tool invocation (faulted)",
						Protocol:      tracer.MCP.String(),
						Status:        tracer.Interaction.String(),
						RemoteAddr:    ctx.Value(remoteAddrCtxKey{}).(string),
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
				RemoteAddr:       ctx.Value(remoteAddrCtxKey{}).(string),
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
			})
			return mcp.NewToolResultText(response), nil
		})
	}

	go func() {
		httpServer := server.NewStreamableHTTPServer(
			mcpServer,
			server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
				return context.WithValue(ctx, remoteAddrCtxKey{}, r.RemoteAddr)
			}),
		)
		if err := httpServer.Start(servConf.Address); err != nil {
			log.Errorf("Failed to start MCP server on %s: %v", servConf.Address, err)
			return
		}
	}()
	log.WithFields(log.Fields{
		"port":        servConf.Address,
		"description": servConf.Description,
		"stateful":    hasWorldSeed,
	}).Infof("Init service %s", servConf.Protocol)
	return nil
}
