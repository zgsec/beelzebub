package shellemulator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
)

type Session struct {
	User        string
	CWD         string
	CmdCount    int
	PIDOffset   int
	ShellPID    int
	LoginTime   time.Time
	FileOverlay map[string]string
	DirOverlay  map[string][]string
	Deleted     map[string]bool
}

func (s *Session) initOverlays() {
	if s.FileOverlay == nil {
		s.FileOverlay = make(map[string]string)
	}
	if s.DirOverlay == nil {
		s.DirOverlay = make(map[string][]string)
	}
	if s.Deleted == nil {
		s.Deleted = make(map[string]bool)
	}
}

type Emulator struct {
	persona  *Persona
	llmShell *LLMShell
}

// SetLLMShell wires the LLM bridge. nil disables LLM routing; falls back to stub.
func (e *Emulator) SetLLMShell(s *LLMShell) {
	e.llmShell = s
}

func NewEmulator(cfg parser.ShellEmulator) *Emulator {
	p := MergeConfig(DefaultPersona(), cfg)

	tokens := resolveTokens(cfg.CanaryTokens)
	for path, content := range p.Lures {
		p.Lures[path] = substituteTokens(content, tokens)
	}
	for key, val := range p.EnvVars {
		p.EnvVars[key] = substituteTokens(val, tokens)
	}

	uptimeDays := cfg.UptimeDays
	if uptimeDays <= 0 {
		uptimeDays = 23
	}
	p.BootTime = time.Now().Add(-time.Duration(uptimeDays) * 24 * time.Hour)

	return &Emulator{persona: p}
}

func (e *Emulator) Execute(cmd string, sess *Session) (string, bool) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", true
	}

	sess.CmdCount++
	sess.initOverlays()

	base, _ := parseCommand(cmd)
	if base == "" {
		return "", true
	}

	if e.llmShell != nil {
		return e.llmShell.RespondTo(cmd, e.persona), true
	}

	return fmt.Sprintf("bash: %s: command not found\n", base), true
}

// BuildPromptContext serializes world state for the LLM system prompt.
func (e *Emulator) BuildPromptContext() string {
	p := e.persona
	var b strings.Builder

	b.WriteString(fmt.Sprintf("SYSTEM: %s | %s | %s x86_64 | %s/24\n", p.Hostname, p.OS, p.Kernel, p.IP))

	var procs []string
	for _, proc := range p.Processes {
		name := proc.Cmd
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		if idx := strings.Index(name, " "); idx >= 0 {
			name = name[:idx]
		}
		procs = append(procs, name)
	}
	b.WriteString(fmt.Sprintf("PROCESSES: %s\n", strings.Join(procs, " ")))

	var listeners []string
	for _, l := range p.Listeners {
		listeners = append(listeners, fmt.Sprintf("%s(%s)", l.Program, l.Local))
	}
	b.WriteString(fmt.Sprintf("LISTENERS: %s\n", strings.Join(listeners, " ")))

	var envParts []string
	for k, v := range p.EnvVars {
		if k == "PATH" || k == "HOME" || k == "SHELL" || k == "LANG" || k == "TERM" || k == "LOGNAME" || k == "USER" {
			continue
		}
		envParts = append(envParts, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(envParts)
	b.WriteString(fmt.Sprintf("ENV: %s\n", strings.Join(envParts, " ")))

	var lureFiles []string
	for path := range p.Lures {
		lureFiles = append(lureFiles, path)
	}
	sort.Strings(lureFiles)
	b.WriteString(fmt.Sprintf("FILES: %s\n", strings.Join(lureFiles, " ")))

	b.WriteString(fmt.Sprintf("USERS: %s(uid=0) ubuntu(uid=1000) www-data(uid=33) postgres(uid=113) sshd(uid=110)\n", p.User))

	return b.String()
}

// parseCommand splits a command string into base command and arguments.
func parseCommand(cmd string) (string, []string) {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], fields[1:]
}

