// Command mcpsink is a minimal streamable-HTTP MCP server sink for fingerprinting
// real MCP clients. It records each client request (raw JSON-RPC, JA4H, headers,
// method sequence) and responds just-validly-enough that the client completes its
// handshake — which doubles as a fidelity probe: what a real MCP client requires
// back is exactly what our lure must emit.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/mariocandela/beelzebub/v3/tracer"
)

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func main() {
	addr := "127.0.0.1:8998"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	enc := json.NewEncoder(os.Stdout)
	var mu sync.Mutex

	srv := &http.Server{
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, tracer.TeeConnKey, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				// Some clients open a GET SSE stream for server->client messages.
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Mcp-Session-Id", "sink-session-1")
				w.WriteHeader(http.StatusOK)
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			var msg rpcMsg
			_ = json.Unmarshal(body, &msg)

			var wireOrder []string
			if tc, ok := r.Context().Value(tracer.TeeConnKey).(*tracer.TeeConn); ok {
				wireOrder = tracer.ParseHeaderOrder(tc.RawBytes())
			}
			headers := map[string]string{}
			for k, v := range r.Header {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			if r.Host != "" {
				headers["Host"] = r.Host
			}

			mu.Lock()
			_ = enc.Encode(map[string]any{
				"method":       msg.Method,
				"has_id":       len(msg.ID) > 0,
				"raw":          json.RawMessage(body),
				"ja4h":         tracer.ComputeJA4H(r, wireOrder),
				"header_order": wireOrder,
				"headers":      headers,
				"ua":           r.UserAgent(),
			})
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "sink-session-1")
			switch msg.Method {
			case "initialize":
				var p struct {
					ProtocolVersion string `json:"protocolVersion"`
				}
				_ = json.Unmarshal(msg.Params, &p)
				if p.ProtocolVersion == "" {
					p.ProtocolVersion = "2025-06-18"
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0", "id": json.RawMessage(msg.ID),
					"result": map[string]any{
						"protocolVersion": p.ProtocolVersion,
						"capabilities":    map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}},
						"serverInfo":      map[string]any{"name": "sink", "version": "0"},
					},
				})
			case "notifications/initialized", "":
				w.WriteHeader(http.StatusAccepted)
			case "tools/list":
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(msg.ID), "result": map[string]any{"tools": []any{}}})
			default:
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(msg.ID), "result": map[string]any{}})
			}
		}),
	}
	_ = srv.Serve(tracer.NewTeeListener(ln, 65536, tracer.HTTPStopFunc))
}
