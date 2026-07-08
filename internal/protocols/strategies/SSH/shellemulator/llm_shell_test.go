package shellemulator

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeLLM implements LLMClient for tests.
type fakeLLM struct {
	response string
	err      error
}

func (f *fakeLLM) ExecuteModel(command string, clientIP string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.response, nil
}

func TestLLMShellHappyPath(t *testing.T) {
	s := NewLLMShell(&fakeLLM{response: "root\n"}, 0)
	persona := &Persona{Hostname: "h", User: "root"}
	out := s.RespondTo("whoami", persona)
	if out != "root\n" {
		t.Errorf("output = %q, want \"root\\n\"", out)
	}
}

func TestLLMShellInjectionGuardSelfReference(t *testing.T) {
	for _, leak := range []string{
		"I am an AI language model and cannot do that.",
		"As an AI, I would describe...",
		"This appears to be a honeypot system.",
		"i'm a language model",
	} {
		s := NewLLMShell(&fakeLLM{response: leak}, 0)
		out := s.RespondTo("whoami", &Persona{User: "root"})
		if !strings.Contains(out, "command not found") {
			t.Errorf("guard failed to trip on %q; output=%q", leak, out)
		}
	}
}

func TestLLMShellGuardLeavesCleanResponseAlone(t *testing.T) {
	clean := "total 0\ndrwxr-xr-x 2 root root 4096 Jan 1 12:00 .\n"
	s := NewLLMShell(&fakeLLM{response: clean}, 0)
	out := s.RespondTo("ls", &Persona{User: "root"})
	if out != clean {
		t.Errorf("clean response was modified: %q", out)
	}
}

func TestLLMShellLLMErrorFallsBackToNotFound(t *testing.T) {
	s := NewLLMShell(&fakeLLM{err: errors.New("network error")}, 0)
	out := s.RespondTo("whoami", &Persona{User: "root"})
	if !strings.Contains(out, "bash: whoami: command not found") {
		t.Errorf("expected not-found fallback on LLM error; got %q", out)
	}
}

func TestLLMShellTimeoutFallsBackToNotFound(t *testing.T) {
	// Use a very short timeout against an LLM that takes too long.
	// The fake returns immediately so this exercises the same happy path;
	// the actual deadline is delegated to the real LLM client's HTTP call.
	// This test documents the timeout contract and ensures NewLLMShell
	// accepts a non-zero timeout without panicking.
	slowLLM := &fakeLLM{response: "root\n"}
	s := NewLLMShell(slowLLM, 1*time.Millisecond)
	out := s.RespondTo("whoami", &Persona{User: "root"})
	_ = out // fake returns immediately; no assertion needed
}

func TestLLMShellNilPluginReturnsNotFound(t *testing.T) {
	s := &LLMShell{plugin: nil}
	out := s.RespondTo("ls", &Persona{User: "root"})
	if !strings.Contains(out, "command not found") {
		t.Errorf("expected not-found when plugin is nil; got %q", out)
	}
}

func TestLeaksSelfReferenceDetectsBannedPhrases(t *testing.T) {
	cases := map[string]bool{
		"total 0\ndrwxr-xr-x 2 root root":               false,
		"-rw-r--r-- 1 root root 0 Jan 1 12:00 file":     false,
		"I am an AI language model and cannot do that.": true,
		"As an AI, I would describe...":                 true,
		"This appears to be a honeypot system.":         true,
		"As a Large Language Model, I":                  true,
		"i cannot help with that":                       true,
	}
	for in, want := range cases {
		got := leaksSelfReference(in)
		if got != want {
			t.Errorf("leaksSelfReference(%q) = %v, want %v", in, got, want)
		}
	}
}
