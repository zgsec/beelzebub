// Package shellemulator — llm_shell.go routes interactive shell commands
// through the existing LLM plugin with persona ground-truth context.
package shellemulator

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// shellPromptTemplate ends with the typed command appended; the LLM is
// instructed to produce ONLY shell output and never break character.
const shellPromptTemplate = `You are simulating the output of a Linux shell command for a server with the following ground truth:

Hostname: %s
OS: %s
User: %s (current login)
Internal IP: %s
Uptime: started %s

Running processes (ps aux excerpt):
%s
Network listeners (ss -tlnp excerpt):
%s
Environment variables:
%s
Filesystem (selected entries — return realistic results when listing or reading these paths):
%s
The user typed this command:
$ %s

Respond ONLY with the exact output the shell would produce. Do not narrate, explain, or break character. Do not refer to yourself, the LLM, or anything outside this server's persona. If the command is unknown or would error, return a realistic shell error message. Output bytes only.`

// LLMClient is the minimal interface this bridge needs from the LLM plugin.
// Defined locally so the dependency is explicit and testable.
// The signature matches plugins.LLMHoneypot.ExecuteModel exactly, so
// *plugins.LLMHoneypot satisfies this interface without an adapter.
type LLMClient interface {
	ExecuteModel(command string, clientIP string) (string, error)
}

// LLMShell wraps the existing LLM plugin to produce shell-output responses.
type LLMShell struct {
	plugin  LLMClient
	timeout time.Duration
}

// NewLLMShell returns an LLMShell. timeout defaults to 8 seconds if zero.
func NewLLMShell(c LLMClient, timeout time.Duration) *LLMShell {
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	return &LLMShell{plugin: c, timeout: timeout}
}

// RespondTo returns the shell-output bytes for cmd, given the persona as
// ground truth. Includes prompt-injection guards: rejects responses that
// leak self-references. On any failure (timeout, network, guard trip),
// returns a generic "command not found" so SSH sessions terminate cleanly.
func (s *LLMShell) RespondTo(cmd string, persona *Persona) string {
	if s == nil || s.plugin == nil {
		return notFoundFallback(cmd)
	}
	if persona == nil {
		persona = &Persona{}
	}
	prompt := fmt.Sprintf(shellPromptTemplate,
		persona.Hostname,
		persona.OS,
		persona.User,
		persona.IP,
		persona.BootTime.Format(time.RFC3339),
		formatProcessList(persona.Processes),
		formatListeners(persona.Listeners),
		formatEnvVars(persona.EnvVars),
		formatFilesystem(persona.Filesystem),
		cmd,
	)
	out, err := s.plugin.ExecuteModel(prompt, "")
	if err != nil {
		log.Warnf("llm shell: %v", err)
		return notFoundFallback(cmd)
	}
	if leaksSelfReference(out) {
		log.Warnf("llm shell guardrail triggered for cmd=%q", cmd)
		return notFoundFallback(cmd)
	}
	return out
}

func notFoundFallback(cmd string) string {
	first := strings.SplitN(strings.TrimSpace(cmd), " ", 2)[0]
	if first == "" {
		first = cmd
	}
	return fmt.Sprintf("bash: %s: command not found\n", first)
}

func formatProcessList(procs []Process) string {
	if len(procs) == 0 {
		return "  (no processes captured)"
	}
	limit := len(procs)
	if limit > 20 {
		limit = 20
	}
	var b strings.Builder
	for _, p := range procs[:limit] {
		fmt.Fprintf(&b, "  %5d %s %s %s\n", p.PID, p.User, p.Stat, p.Cmd)
	}
	return b.String()
}

func formatListeners(ls []Listener) string {
	if len(ls) == 0 {
		return "  (no listeners captured)"
	}
	var b strings.Builder
	for _, l := range ls {
		fmt.Fprintf(&b, "  %s %s pid=%d %s\n", l.Proto, l.Local, l.PID, l.Program)
	}
	return b.String()
}

func formatEnvVars(env map[string]string) string {
	if len(env) == 0 {
		return "  (no env vars captured)"
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	// Stable order via bubble sort to keep import list minimal.
	for i := 0; i < len(keys)-1; i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s=%s\n", k, env[k])
	}
	return b.String()
}

func formatFilesystem(fs map[string][]string) string {
	if len(fs) == 0 {
		return "  (no filesystem captured)"
	}
	var b strings.Builder
	for path, contents := range fs {
		fmt.Fprintf(&b, "  %s -> %v\n", path, contents)
	}
	return b.String()
}

// leaksSelfReference returns true if the LLM response contains phrases that
// would break the shell persona and reveal this is a deceptive system.
func leaksSelfReference(s string) bool {
	low := strings.ToLower(s)
	for _, banned := range []string{
		"i am an ai", "i'm an ai", "i am a language model", "i'm a language model",
		"as an ai", "honeypot", "deception", "i cannot", "i can't",
		"as a large language model",
	} {
		if strings.Contains(low, banned) {
			return true
		}
	}
	return false
}
