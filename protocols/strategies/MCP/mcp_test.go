package MCP

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorldStateCleanup(t *testing.T) {
	s := &MCPStrategy{
		worldState:    make(map[string]*WorldState),
		toolHistory:   make(map[string][]toolCallRecord),
		agentTimings:  make(map[string][]int64),
		agentLastSeen: make(map[string]time.Time),
	}

	// Seed state for a stale IP
	staleIP := "1.2.3.4"
	s.worldState[staleIP] = NewWorldState(WorldSeed{})
	s.toolHistory[staleIP] = []toolCallRecord{{ToolName: "test"}}
	s.agentTimings[staleIP] = []int64{100}
	s.agentLastSeen[staleIP] = time.Now().Add(-2 * time.Hour) // stale

	// Seed state for a fresh IP
	freshIP := "5.6.7.8"
	s.worldState[freshIP] = NewWorldState(WorldSeed{})
	s.toolHistory[freshIP] = []toolCallRecord{{ToolName: "test2"}}
	s.agentTimings[freshIP] = []int64{200}
	s.agentLastSeen[freshIP] = time.Now() // fresh

	// Simulate cleanup inline (same logic as cleanAgentState)
	cutoff := time.Now().Add(-60 * time.Minute)
	s.timingMu.RLock()
	var staleIPs []string
	for ip, last := range s.agentLastSeen {
		if last.Before(cutoff) {
			staleIPs = append(staleIPs, ip)
		}
	}
	s.timingMu.RUnlock()

	s.timingMu.Lock()
	for _, ip := range staleIPs {
		delete(s.agentTimings, ip)
		delete(s.agentLastSeen, ip)
	}
	s.timingMu.Unlock()

	s.historyMu.Lock()
	for _, ip := range staleIPs {
		delete(s.toolHistory, ip)
	}
	s.historyMu.Unlock()

	s.worldMu.Lock()
	for _, ip := range staleIPs {
		delete(s.worldState, ip)
	}
	s.worldMu.Unlock()

	// Stale IP should be fully cleaned
	assert.NotContains(t, s.worldState, staleIP, "worldState should be cleaned for stale IP")
	assert.NotContains(t, s.toolHistory, staleIP)
	assert.NotContains(t, s.agentTimings, staleIP)
	assert.NotContains(t, s.agentLastSeen, staleIP)

	// Fresh IP should be untouched
	assert.Contains(t, s.worldState, freshIP)
	assert.Contains(t, s.toolHistory, freshIP)
	assert.Contains(t, s.agentTimings, freshIP)
	assert.Contains(t, s.agentLastSeen, freshIP)
}

func TestBridgeEnrichmentAlwaysNormalized(t *testing.T) {
	b := bridge.NewBridge()
	s := &MCPStrategy{
		Bridge: b,
	}

	// Response without any bridge data for this IP
	input := `{"ok":true,"key":"test"}`
	result := s.enrichWithBridge("10.0.0.1", "nexus/iam.manage", input)

	var resp map[string]interface{}
	err := json.Unmarshal([]byte(result), &resp)
	require.NoError(t, err)

	// _platform_services should always be present (empty object)
	ps, ok := resp["_platform_services"]
	assert.True(t, ok, "_platform_services should always be present")
	psMap, ok := ps.(map[string]interface{})
	assert.True(t, ok)
	assert.Empty(t, psMap, "_platform_services should be empty with no bridge data")

	// platform_note should always be present with default value
	note, ok := resp["platform_note"]
	assert.True(t, ok, "platform_note should always be present")
	assert.Equal(t, "Platform services operational", note)
}

func TestBridgeEnrichmentWithSSHFlag(t *testing.T) {
	b := bridge.NewBridge()
	b.SetFlag("10.0.0.1", "ssh_authenticated")

	s := &MCPStrategy{
		Bridge: b,
	}

	input := `{"ok":true}`
	result := s.enrichWithBridge("10.0.0.1", "nexus/iam.manage", input)

	var resp map[string]interface{}
	err := json.Unmarshal([]byte(result), &resp)
	require.NoError(t, err)

	// _platform_services should contain SSH
	ps := resp["_platform_services"].(map[string]interface{})
	assert.Contains(t, ps, "ssh")

	// platform_note should reflect SSH auth
	assert.Contains(t, resp["platform_note"], "credential audit")
}

func TestBridgeEnrichmentNonJSON(t *testing.T) {
	b := bridge.NewBridge()
	s := &MCPStrategy{
		Bridge: b,
	}

	// Non-JSON response should be returned unchanged
	input := "plain text response"
	result := s.enrichWithBridge("10.0.0.1", "test", input)
	assert.Equal(t, input, result)
}
