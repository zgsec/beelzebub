package MCP

import (
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
)

// mcpClientInfo captures the identity a client announces in the MCP `initialize`
// handshake. This is the single richest source of client-framework attribution
// available on the MCP surface — SDKs and agent frameworks self-report their
// name and version here — so it is captured verbatim rather than inferred.
type mcpClientInfo struct {
	Name            string
	Version         string
	Title           string
	ProtocolVersion string
	Capabilities    string // compact JSON of the declared client capabilities
}

// present reports whether any identifying field was populated.
func (c mcpClientInfo) present() bool {
	return c.Name != "" || c.Version != "" || c.Title != "" ||
		c.ProtocolVersion != "" || c.Capabilities != ""
}

// extractMCPClientInfo pulls the client identity out of an initialize request.
// It is defensive: a nil request or empty fields yield a zero-value struct
// rather than panicking, so a malformed handshake never disrupts serving.
func extractMCPClientInfo(req *mcp.InitializeRequest) mcpClientInfo {
	if req == nil {
		return mcpClientInfo{}
	}
	ci := mcpClientInfo{
		Name:            req.Params.ClientInfo.Name,
		Version:         req.Params.ClientInfo.Version,
		Title:           req.Params.ClientInfo.Title,
		ProtocolVersion: req.Params.ProtocolVersion,
	}
	// Serialize declared capabilities compactly; ignore marshal errors (best-effort).
	if b, err := json.Marshal(req.Params.Capabilities); err == nil {
		s := string(b)
		// An empty capabilities object carries no signal — leave it blank.
		if s != "" && s != "{}" && s != "null" {
			ci.Capabilities = s
		}
	}
	return ci
}

// setClientInfo records the captured handshake for an IP. Concurrency-safe.
func (mcpStrategy *MCPStrategy) setClientInfo(ip string, ci mcpClientInfo) {
	mcpStrategy.clientInfoMu.Lock()
	defer mcpStrategy.clientInfoMu.Unlock()
	if mcpStrategy.clientInfo == nil {
		mcpStrategy.clientInfo = make(map[string]mcpClientInfo)
	}
	mcpStrategy.clientInfo[ip] = ci
}

// getClientInfo returns the captured handshake for an IP, if any. Concurrency-safe.
func (mcpStrategy *MCPStrategy) getClientInfo(ip string) (mcpClientInfo, bool) {
	mcpStrategy.clientInfoMu.RLock()
	defer mcpStrategy.clientInfoMu.RUnlock()
	ci, ok := mcpStrategy.clientInfo[ip]
	return ci, ok
}

// hasClientInfo reports whether a genuine MCP initialize handshake was captured
// for an IP. This is a stronger agent signal than the seq==1 heuristic because
// it reflects an actual protocol handshake rather than a positional guess.
func (mcpStrategy *MCPStrategy) hasClientInfo(ip string) bool {
	ci, ok := mcpStrategy.getClientInfo(ip)
	return ok && ci.present()
}
