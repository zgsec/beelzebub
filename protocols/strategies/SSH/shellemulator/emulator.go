package shellemulator

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
)

// Session tracks per-connection state.
type Session struct {
	User        string
	CWD         string
	CmdCount    int
	PIDOffset   int               // random 0-200, shifts non-system PIDs per session
	ShellPID    int               // unique shell PID per session
	LoginTime   time.Time         // when session started
	FileOverlay map[string]string // path → content (written files)
	DirOverlay  map[string][]string // dir → additional entries
	Deleted     map[string]bool   // path → true (rm'd files)
}

// initOverlays ensures overlay maps are allocated.
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

// Emulator dispatches shell commands against a persona.
//
// Phase D.2: the deterministic handler matrix has been deleted. Each command
// now returns a generic "command not found" response. D.3 will wire the LLM
// bridge here so the shell becomes context-aware and persona-driven.
type Emulator struct {
	persona *Persona
}

// NewEmulator creates an emulator from config, merging with defaults.
func NewEmulator(cfg parser.ShellEmulator) *Emulator {
	p := MergeConfig(DefaultPersona(), cfg)

	// Resolve canary tokens and substitute into persona
	tokens := resolveTokens(cfg.CanaryTokens)
	for path, content := range p.Lures {
		p.Lures[path] = substituteTokens(content, tokens)
	}
	for key, val := range p.EnvVars {
		p.EnvVars[key] = substituteTokens(val, tokens)
	}

	// Set BootTime from config UptimeDays (default 23)
	uptimeDays := cfg.UptimeDays
	if uptimeDays <= 0 {
		uptimeDays = 23
	}
	p.BootTime = time.Now().Add(-time.Duration(uptimeDays) * 24 * time.Hour)

	return &Emulator{persona: p}
}

// Execute tries to handle the command. Returns (output, true) if handled,
// or ("", false) to fall through to LLM.
//
// Phase D.2 stub: all commands return "command not found". D.3 replaces
// this with an LLM-bridge call that has full persona context.
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

	return fmt.Sprintf("bash: %s: command not found\n", base), true
}

// BuildPromptContext serializes the world state for injection into LLM system prompt.
// D.3 will consume this to ground the LLM shell responses in persona data.
func (e *Emulator) BuildPromptContext() string {
	p := e.persona
	var b strings.Builder

	b.WriteString(fmt.Sprintf("SYSTEM: %s | %s | %s x86_64 | %s/24\n", p.Hostname, p.OS, p.Kernel, p.IP))

	// Processes summary
	var procs []string
	for _, proc := range p.Processes {
		// Extract base name
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

	// Listeners
	var listeners []string
	for _, l := range p.Listeners {
		listeners = append(listeners, fmt.Sprintf("%s(%s)", l.Program, l.Local))
	}
	b.WriteString(fmt.Sprintf("LISTENERS: %s\n", strings.Join(listeners, " ")))

	// Env vars (selected)
	var envParts []string
	for k, v := range p.EnvVars {
		if k == "PATH" || k == "HOME" || k == "SHELL" || k == "LANG" || k == "TERM" || k == "LOGNAME" || k == "USER" {
			continue
		}
		envParts = append(envParts, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(envParts)
	b.WriteString(fmt.Sprintf("ENV: %s\n", strings.Join(envParts, " ")))

	// Lure files
	var lureFiles []string
	for path := range p.Lures {
		lureFiles = append(lureFiles, path)
	}
	sort.Strings(lureFiles)
	b.WriteString(fmt.Sprintf("FILES: %s\n", strings.Join(lureFiles, " ")))

	// Users from /etc/passwd
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

// resolvePath resolves a relative path against the session CWD.
func resolvePath(p string, cwd string) string {
	if p == "" {
		return cwd
	}
	_ = p // path resolution kept for D.3
	return cwd
}

// appendUnique adds an entry to a slice if not already present.
// Kept for use by D.3 session overlay writes.
func appendUnique(slice []string, entry string) []string {
	for _, s := range slice {
		if s == entry {
			return slice
		}
	}
	return append(slice, entry)
}

// formatUptime formats a duration as Linux uptime output.
// Kept for use by D.3 LLM context injection.
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%d days, %2d:%02d", days, hours, mins)
	}
	return fmt.Sprintf("%2d:%02d", hours, mins)
}
