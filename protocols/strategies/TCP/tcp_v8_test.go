package TCP

import (
	"strings"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/bridge"
)

func TestClassifyTCP_MechanicalTiming(t *testing.T) {
	s := &TCPStrategy{
		agentTimings:  make(map[string][]int64),
		agentLastSeen: make(map[string]time.Time),
		agentPrevCmd:  make(map[string]string),
	}
	ip := "1.2.3.4"
	cmds := []string{"INFO", "CONFIG GET dir", "DBSIZE", "CONFIG GET dbfilename", "SAVE"}

	// Simulate tight 100ms timing
	for _, cmd := range cmds {
		s.agentLastSeen[ip] = time.Now().Add(-100 * time.Millisecond)
		s.classifyTCP(ip, cmd)
	}

	// After 5 samples with tight timing, mechanical_timing should fire
	final := s.classifyTCP(ip, "QUIT")
	if final.Score == 0 {
		t.Error("expected non-zero agent score for mechanical timing")
	}
	if !strings.Contains(final.SignalsString(), "mechanical_timing") {
		t.Errorf("expected mechanical_timing signal, got %q", final.SignalsString())
	}
}

func TestClassifyTCP_RetryDetection(t *testing.T) {
	s := &TCPStrategy{
		agentTimings:  make(map[string][]int64),
		agentLastSeen: make(map[string]time.Time),
		agentPrevCmd:  make(map[string]string),
	}
	ip := "5.6.7.8"
	s.classifyTCP(ip, "CONFIG GET dir")
	v := s.classifyTCP(ip, "CONFIG GET dir") // identical retry
	if !strings.Contains(v.SignalsString(), "identical_retries") {
		t.Errorf("expected identical_retries, got %q", v.SignalsString())
	}
}

func TestClassifyTCP_NoBridge_NoPanic(t *testing.T) {
	// TCPStrategy without bridge should not panic
	s := &TCPStrategy{}
	v := s.classifyTCP("9.8.7.6", "PING")
	_ = v // no panic = pass
}

func TestClassifyTCP_WithBridge_CrossProtocol(t *testing.T) {
	b := bridge.NewBridge()
	b.SetFlag("1.2.3.4", "mcp_tool_call")
	// Small delay so CrossProtocolGapMs > 0 (gap must be positive to fire)
	time.Sleep(2 * time.Millisecond)

	s := &TCPStrategy{
		Bridge:        b,
		agentTimings:  make(map[string][]int64),
		agentLastSeen: make(map[string]time.Time),
		agentPrevCmd:  make(map[string]string),
	}

	v := s.classifyTCP("1.2.3.4", "INFO")
	if !strings.Contains(v.SignalsString(), "cross_protocol_pivot") {
		t.Errorf("expected cross_protocol_pivot with bridge flag, got %q", v.SignalsString())
	}
}

func TestClassifyTCP_TimingRingBuffer(t *testing.T) {
	s := &TCPStrategy{
		agentTimings:  make(map[string][]int64),
		agentLastSeen: make(map[string]time.Time),
		agentPrevCmd:  make(map[string]string),
	}
	ip := "memory.test"

	// Send 200 commands — timing buffer should cap at 100
	for i := 0; i < 200; i++ {
		s.agentLastSeen[ip] = time.Now().Add(-50 * time.Millisecond)
		s.classifyTCP(ip, "PING")
	}

	s.agentMu.Lock()
	timingsLen := len(s.agentTimings[ip])
	s.agentMu.Unlock()

	if timingsLen > 100 {
		t.Errorf("timing buffer not bounded: %d entries (max 100)", timingsLen)
	}
}

func TestClassifyTCP_DifferentCommandsNotRetry(t *testing.T) {
	s := &TCPStrategy{
		agentTimings:  make(map[string][]int64),
		agentLastSeen: make(map[string]time.Time),
		agentPrevCmd:  make(map[string]string),
	}
	ip := "1.2.3.4"
	s.classifyTCP(ip, "CONFIG GET dir")
	v := s.classifyTCP(ip, "CONFIG GET dbfilename") // different command
	if strings.Contains(v.SignalsString(), "identical_retries") {
		t.Error("different commands should not trigger retry detection")
	}
}
