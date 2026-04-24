package SSH

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mariocandela/beelzebub/v3/agentdetect"
	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/faults"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/noveltydetect"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/protocols/strategies/SSH/shellemulator"
	"github.com/mariocandela/beelzebub/v3/tracer"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

type SSHStrategy struct {
	Sessions *historystore.HistoryStore
	Bridge   *bridge.ProtocolBridge
	Fault    *faults.Injector

	// Shell emulator (optional, nil when disabled)
	emulator         *shellemulator.Emulator
	emulatorSessions sync.Map // IP → *shellemulator.Session

	// Agent detection timing accumulation (per-IP)
	agentMu       sync.Mutex
	agentTimings  map[string][]int64
	agentLastSeen map[string]time.Time
	agentPrevCmd  map[string]string // previous command per IP for correction detection

	// Novelty detection (optional, nil when disabled)
	noveltyStore      *noveltydetect.FingerprintStore
	noveltyWindowDays int
	noveltySignals    sync.Map // IP → *noveltydetect.Signal
}

func (sshStrategy *SSHStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if sshStrategy.Sessions == nil {
		sshStrategy.Sessions = historystore.NewHistoryStore()
	}
	if sshStrategy.agentTimings == nil {
		sshStrategy.agentTimings = make(map[string][]int64)
		sshStrategy.agentLastSeen = make(map[string]time.Time)
		sshStrategy.agentPrevCmd = make(map[string]string)
		go sshStrategy.cleanAgentState()
	}
	// Shell emulator: create if enabled in config
	if servConf.ShellEmulator.Enabled && sshStrategy.emulator == nil {
		sshStrategy.emulator = shellemulator.NewEmulator(servConf.ShellEmulator)
	}

	// Novelty detection: create store if enabled in config
	if servConf.NoveltyDetection.Enabled && sshStrategy.noveltyStore == nil {
		sshStrategy.noveltyStore = noveltydetect.NewStore()
		sshStrategy.noveltyWindowDays = servConf.NoveltyDetection.WindowDays
		if sshStrategy.noveltyWindowDays <= 0 {
			sshStrategy.noveltyWindowDays = 7
		}
	}
	go sshStrategy.Sessions.HistoryCleaner()
	go func() {
		destPort := tracer.ExtractPort(servConf.Address)
		server := &ssh.Server{
			Addr:        servConf.Address,
			MaxTimeout:  time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			Version:     servConf.ServerVersion,
			ConnCallback: func(ctx ssh.Context, conn net.Conn) net.Conn {
				tc := tracer.NewTeeConn(conn, 8192, tracer.SSHStopFunc)
				ctx.SetValue(tracer.TeeConnKey, tc)
				return tc
			},
			Handler: func(sess ssh.Session) {
				uuidSession := uuid.New()

				host, port, _ := net.SplitHostPort(sess.RemoteAddr().String())
				sessionKey := "SSH" + host + sess.User()

				// Inline SSH command
				if sess.RawCommand() != "" {
					var histories []plugins.Message
					if sshStrategy.Sessions.HasKey(sessionKey) {
						histories = sshStrategy.Sessions.Query(sessionKey)
					}
					for _, command := range servConf.Commands {
						if command.Regex.MatchString(sess.RawCommand()) {
							commandOutput := command.Handler
							if command.Plugin == plugins.LLMPluginName {
								emHandled := false
								if sshStrategy.emulator != nil {
									emSess := sshStrategy.getOrCreateEmulatorSession(host, sess.User())
									if out, ok := sshStrategy.emulator.Execute(sess.RawCommand(), emSess); ok {
										commandOutput = out
										emHandled = true
									}
								}
								if !emHandled {
									llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
									if err != nil {
										log.Errorf("error: %s", err.Error())
										commandOutput = "command not found"
										llmProvider = plugins.OpenAI
									}
									llmHoneypot := plugins.BuildHoneypot(histories, tracer.SSH, llmProvider, servConf)
									if sshStrategy.emulator != nil {
										llmHoneypot.CustomPrompt = sshStrategy.emulator.BuildPromptContext() + "\n\n" + llmHoneypot.CustomPrompt
									}
									llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
									if commandOutput, err = llmHoneypotInstance.ExecuteModel(sess.RawCommand(), host); err != nil {
										log.Errorf("error ExecuteModel: %s, %s", sess.RawCommand(), err.Error())
										commandOutput = "command not found"
									}
								}
							}
							var newEntries []plugins.Message
							newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: sess.RawCommand()})
							newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
							// Append the new entries to the store.
							sshStrategy.Sessions.Append(sessionKey, newEntries...)

							sess.Write(append([]byte(commandOutput), '\n'))

							// Record credential discoveries for raw commands
							if sshStrategy.Bridge != nil {
								checkCredentialDiscovery(sshStrategy.Bridge, host, sess.RawCommand(), commandOutput)
							}

							// Agent classification for raw commands
							rawVerdict := sshStrategy.classifySSH(host, sess.RawCommand())

							// Novelty detection for raw commands
							var rawNoveltyVerdict noveltydetect.Verdict
							if sshStrategy.noveltyStore != nil {
								sig := sshStrategy.getNoveltySignal(host)
								if sshStrategy.noveltyStore.RecordCommand(sess.RawCommand()) {
									sig.CommandsNew++
								}
								sig.CommandsTotal++
								rawNoveltyVerdict = noveltydetect.IncrementalScore(*sig)
							}

							tr.TraceEvent(tracer.Event{
								Msg:             "SSH Raw Command",
								Protocol:        tracer.SSH.String(),
								RemoteAddr:      sess.RemoteAddr().String(),
								SourceIp:        host,
								SourcePort:      port,
								Status:          tracer.Start.String(),
								ID:              uuidSession.String(),
								Environ:         strings.Join(sess.Environ(), ","),
								User:            sess.User(),
								Description:     servConf.Description,
								Command:         sess.RawCommand(),
								CommandOutput:   commandOutput,
								Handler:         command.Name,
								SessionKey:      sessionKey,
								AgentScore:      rawVerdict.Score,
								AgentCategory:   rawVerdict.Category,
								AgentSignals:    rawVerdict.SignalsString(),
								NoveltyScore:    rawNoveltyVerdict.Score,
								NoveltyCategory: rawNoveltyVerdict.Category,
								NoveltySignals:  rawNoveltyVerdict.SignalsString(),
								HASSH:           hasshFromContext(sess.Context()),
								HASSHAlgorithms: hasshAlgorithmsFromContext(sess.Context()),
								ServicePort:     destPort,
							})
							return
						}
					}
				}

				// Capture PTY metadata — terminal type and dimensions.
				// Real humans use "xterm-256color" with varied dimensions.
				// Bots typically use "vt100" or 80x24, or skip PTY entirely.
				var ptyTerm string
				var ptyWidth, ptyHeight int
				if pty, _, hasPty := sess.Pty(); hasPty {
					ptyTerm = pty.Term
					ptyWidth = pty.Window.Width
					ptyHeight = pty.Window.Height
				}

				tr.TraceEvent(tracer.Event{
					Msg:         "New SSH Terminal Session",
					Protocol:    tracer.SSH.String(),
					RemoteAddr:  sess.RemoteAddr().String(),
					SourceIp:    host,
					SourcePort:  port,
					Status:      tracer.Start.String(),
					ID:          uuidSession.String(),
					Environ:     strings.Join(sess.Environ(), ","),
					User:        sess.User(),
					Description: servConf.Description,
					SessionKey:  sessionKey,
					HASSH:            hasshFromContext(sess.Context()),
					HASSHAlgorithms:  hasshAlgorithmsFromContext(sess.Context()),
					ServicePort:      destPort,
					PTYTerm:          ptyTerm,
					PTYWidth:         ptyWidth,
					PTYHeight:        ptyHeight,
				})

				// Record SSH authentication in bridge
				if sshStrategy.Bridge != nil {
					sshStrategy.Bridge.SetFlag(host, "ssh_authenticated")
				}

				terminal := term.NewTerminal(sess, buildPrompt(sess.User(), servConf.ServerName))
				var histories []plugins.Message
				if sshStrategy.Sessions.HasKey(sessionKey) {
					histories = sshStrategy.Sessions.Query(sessionKey)
				}

				for {
					commandInput, err := terminal.ReadLine()
					if err != nil {
						break
					}
					if commandInput == "exit" {
						break
					}
					for _, command := range servConf.Commands {
						if command.Regex.MatchString(commandInput) {
							// v8: Measure response generation time for lure effectiveness research
							responseStart := time.Now()
							commandOutput := command.Handler
							if command.Plugin == plugins.LLMPluginName {
								emHandled := false
								if sshStrategy.emulator != nil {
									emSess := sshStrategy.getOrCreateEmulatorSession(host, sess.User())
									if out, ok := sshStrategy.emulator.Execute(commandInput, emSess); ok {
										commandOutput = out
										emHandled = true
									}
								}
								if !emHandled {
									llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
									if err != nil {
										log.Errorf("error: %s, fallback OpenAI", err.Error())
										llmProvider = plugins.OpenAI
									}
									llmHoneypot := plugins.BuildHoneypot(histories, tracer.SSH, llmProvider, servConf)
									if sshStrategy.emulator != nil {
										llmHoneypot.CustomPrompt = sshStrategy.emulator.BuildPromptContext() + "\n\n" + llmHoneypot.CustomPrompt
									}
									llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
									if commandOutput, err = llmHoneypotInstance.ExecuteModel(commandInput, host); err != nil {
										log.Errorf("error ExecuteModel: %s, %s", commandInput, err.Error())
										commandOutput = "command not found"
									}
								}
							}
							responseTimeMs := time.Since(responseStart).Milliseconds()
							var newEntries []plugins.Message
							newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: commandInput})
							newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
							// Stash the new entries to the store, and update the history for this running session.
							sshStrategy.Sessions.Append(sessionKey, newEntries...)
							histories = append(histories, newEntries...)

							terminal.Write(append([]byte(commandOutput), '\n'))

							// Record credential discoveries via bridge
							if sshStrategy.Bridge != nil {
								checkCredentialDiscovery(sshStrategy.Bridge, host, commandInput, commandOutput)
							}

							// Agent classification for interactive commands
							cmdVerdict := sshStrategy.classifySSH(host, commandInput)

							// Novelty detection for interactive commands
							var cmdNoveltyVerdict noveltydetect.Verdict
							if sshStrategy.noveltyStore != nil {
								sig := sshStrategy.getNoveltySignal(host)
								if sshStrategy.noveltyStore.RecordCommand(commandInput) {
									sig.CommandsNew++
								}
								sig.CommandsTotal++
								cmdNoveltyVerdict = noveltydetect.IncrementalScore(*sig)
							}

							tr.TraceEvent(tracer.Event{
								Msg:             "SSH Terminal Session Interaction",
								RemoteAddr:      sess.RemoteAddr().String(),
								SourceIp:        host,
								SourcePort:      port,
								Status:          tracer.Interaction.String(),
								Command:         commandInput,
								CommandOutput:   commandOutput,
								ID:              uuidSession.String(),
								Protocol:        tracer.SSH.String(),
								Description:     servConf.Description,
								Handler:         command.Name,
								SessionKey:      sessionKey,
								AgentScore:      cmdVerdict.Score,
								AgentCategory:   cmdVerdict.Category,
								AgentSignals:    cmdVerdict.SignalsString(),
								NoveltyScore:    cmdNoveltyVerdict.Score,
								NoveltyCategory: cmdNoveltyVerdict.Category,
								NoveltySignals:  cmdNoveltyVerdict.SignalsString(),
								ServicePort:     destPort,
								ResponseTimeMs:  responseTimeMs,
							})
							break // Inner range over commands.
						}
					}
				}

				// Novelty detection: final score on session end
				var endNoveltyVerdict noveltydetect.Verdict
				if sshStrategy.noveltyStore != nil {
					if raw, ok := sshStrategy.noveltySignals.LoadAndDelete(host); ok {
						sig := raw.(*noveltydetect.Signal)
						endNoveltyVerdict = noveltydetect.Score(*sig)
					}
				}

				tr.TraceEvent(tracer.Event{
					Msg:             "End SSH Session",
					Status:          tracer.End.String(),
					ID:              uuidSession.String(),
					Protocol:        tracer.SSH.String(),
					SessionKey:      sessionKey,
					SourceIp:        host,
					NoveltyScore:    endNoveltyVerdict.Score,
					NoveltyCategory: endNoveltyVerdict.Category,
					NoveltySignals:  endNoveltyVerdict.SignalsString(),
					ServicePort:     destPort,
				})
			},
			PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
				host, port, _ := net.SplitHostPort(ctx.RemoteAddr().String())
				fingerprint := fingerprintKey(key)
				tr.TraceEvent(tracer.Event{
					Msg:               "SSH Public Key Offered",
					Protocol:          tracer.SSH.String(),
					Status:            tracer.Stateless.String(),
					User:              ctx.User(),
					Client:            ctx.ClientVersion(),
					RemoteAddr:        ctx.RemoteAddr().String(),
					SourceIp:          host,
					SourcePort:        port,
					ID:                uuid.New().String(),
					Description:       servConf.Description,
					Command:           key.Type() + " " + fingerprint, // backward compat
					SSHKeyType:        key.Type(),
					SSHKeyFingerprint: fingerprint,
					ServicePort:       destPort,
				})
				return false // always reject, fall through to password auth
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				host, port, _ := net.SplitHostPort(ctx.RemoteAddr().String())

				// Novelty detection for credential pairs
				var authNoveltyVerdict noveltydetect.Verdict
				if sshStrategy.noveltyStore != nil {
					sig := sshStrategy.getNoveltySignal(host)
					if sshStrategy.noveltyStore.RecordCredPair(ctx.User(), password) {
						sig.CredsNew++
					}
					authNoveltyVerdict = noveltydetect.IncrementalScore(*sig)
				}

				tr.TraceEvent(tracer.Event{
					Msg:             "New SSH Login Attempt",
					Protocol:        tracer.SSH.String(),
					Status:          tracer.Stateless.String(),
					User:            ctx.User(),
					Password:        password,
					Client:          ctx.ClientVersion(),
					RemoteAddr:      ctx.RemoteAddr().String(),
					SourceIp:        host,
					SourcePort:      port,
					ID:              uuid.New().String(),
					Description:     servConf.Description,
					NoveltyScore:    authNoveltyVerdict.Score,
					NoveltyCategory: authNoveltyVerdict.Category,
					NoveltySignals:  authNoveltyVerdict.SignalsString(),
					HASSH:           hasshFromContext(ctx),
					HASSHAlgorithms: hasshAlgorithmsFromContext(ctx),
					ServicePort:     destPort,
				})
				matched, err := regexp.MatchString(servConf.PasswordRegex, password)
				if err != nil {
					log.Errorf("error regex: %s, %s", servConf.PasswordRegex, err.Error())
					return false
				}
				return matched
			},
		}
		err := server.ListenAndServe()
		if err != nil {
			log.Errorf("error during init SSH Protocol: %s", err.Error())
		}
	}()

	log.WithFields(log.Fields{
		"port":     servConf.Address,
		"commands": len(servConf.Commands),
	}).Infof("GetInstance service %s", servConf.Protocol)
	return nil
}

// cleanAgentState periodically prunes stale entries from the agent detection maps.
func (s *SSHStrategy) cleanAgentState() {
	for {
		time.Sleep(5 * time.Minute)
		cutoff := time.Now().Add(-60 * time.Minute)
		s.agentMu.Lock()
		for ip, last := range s.agentLastSeen {
			if last.Before(cutoff) {
				delete(s.agentTimings, ip)
				delete(s.agentLastSeen, ip)
				delete(s.agentPrevCmd, ip)
			}
		}
		s.agentMu.Unlock()

		// Clean novelty store if enabled
		if s.noveltyStore != nil {
			maxAge := time.Duration(s.noveltyWindowDays) * 24 * time.Hour
			s.noveltyStore.Clean(maxAge)
		}

		// Clean stale novelty signal accumulators
		s.noveltySignals.Range(func(key, _ any) bool {
			// Reuse agent lastSeen cutoff — if the IP is stale, drop its signal
			s.agentMu.Lock()
			_, alive := s.agentLastSeen[key.(string)]
			s.agentMu.Unlock()
			if !alive {
				s.noveltySignals.Delete(key)
			}
			return true
		})

		// Clean stale emulator sessions (same cutoff as agent state)
		s.emulatorSessions.Range(func(key, _ any) bool {
			s.agentMu.Lock()
			_, alive := s.agentLastSeen[key.(string)]
			s.agentMu.Unlock()
			if !alive {
				s.emulatorSessions.Delete(key)
			}
			return true
		})
	}
}

// getNoveltySignal returns the per-IP novelty signal accumulator, creating one if needed.
func (s *SSHStrategy) getNoveltySignal(ip string) *noveltydetect.Signal {
	raw, _ := s.noveltySignals.LoadOrStore(ip, &noveltydetect.Signal{})
	return raw.(*noveltydetect.Signal)
}

// classifySSH accumulates timing and builds an agent detection verdict for an SSH command.
func (s *SSHStrategy) classifySSH(ip, cmd string) agentdetect.Verdict {
	now := time.Now()
	s.agentMu.Lock()
	// Accumulate timing
	if last, ok := s.agentLastSeen[ip]; ok {
		delta := now.Sub(last).Milliseconds()
		s.agentTimings[ip] = append(s.agentTimings[ip], delta)
		if len(s.agentTimings[ip]) > 100 {
			s.agentTimings[ip] = s.agentTimings[ip][len(s.agentTimings[ip])-100:]
		}
	}
	s.agentLastSeen[ip] = now
	timings := make([]int64, len(s.agentTimings[ip]))
	copy(timings, s.agentTimings[ip])

	// Command correction detection
	prevCmd := s.agentPrevCmd[ip]
	s.agentPrevCmd[ip] = cmd
	s.agentMu.Unlock()

	sig := agentdetect.Signal{
		InterEventTimingsMs:  timings,
		HasCommandCorrection: detectCorrection(prevCmd, cmd),
	}
	// Cross-protocol: check if this IP has MCP activity
	if s.Bridge != nil {
		flags := s.Bridge.GetFlags(ip)
		for _, f := range flags {
			if f == "mcp_tool_call" || f == "ollama_api_accessed" {
				sig.HasCrossProtocol = true
				break
			}
		}
	}
	return agentdetect.IncrementalClassify(sig)
}

// detectCorrection checks if the current command is a minor correction of the previous one.
// This is a human signal — agents don't make typos.
func detectCorrection(prev, current string) bool {
	if prev == "" || current == "" || prev == current {
		return false
	}
	// Simple heuristic: if edit distance < 30% of the longer string's length, it's a correction
	maxLen := len(prev)
	if len(current) > maxLen {
		maxLen = len(current)
	}
	if maxLen == 0 {
		return false
	}
	dist := levenshtein(prev, current)
	return dist > 0 && dist*100/maxLen < 30
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// Use single-row optimization
	prev := make([]int, lb+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr := make([]int, lb+1)
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev = curr
	}
	return prev[lb]
}

// fingerprintKey returns the SHA256 fingerprint of an SSH public key in OpenSSH format.
func fingerprintKey(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// hasshCtxKey stores the computed HASSH so we compute once and release the buffer.
type hasshCtxKey struct{}

// hasshFromContext extracts the HASSH fingerprint from a session context.
// Computes from TeeConn on first call, caches the result, and releases the
// capture buffer to avoid pinning memory for the lifetime of long sessions.
type hasshAlgosCtxKey struct{} // context key for cached raw algorithm string

func hasshFromContext(ctx interface {
	Value(any) any
	SetValue(any, any)
}) string {
	// Return cached value if already computed
	if cached, ok := ctx.Value(hasshCtxKey{}).(string); ok {
		return cached
	}
	// Compute from TeeConn using ComputeHASSHFull, cache hash + algorithms, release buffer
	hassh := ""
	if tc, ok := ctx.Value(tracer.TeeConnKey).(*tracer.TeeConn); ok {
		if result := tracer.ComputeHASSHFull(tc.RawBytes()); result != nil {
			hassh = result.Hash
			ctx.SetValue(hasshAlgosCtxKey{}, result.RawInput)
		}
		tc.Release()
	}
	ctx.SetValue(hasshCtxKey{}, hassh)
	return hassh
}

// hasshAlgorithmsFromContext returns the raw KEX algorithm string (cached by hasshFromContext).
// Must be called AFTER hasshFromContext to ensure computation has happened.
func hasshAlgorithmsFromContext(ctx interface{ Value(any) any }) string {
	if cached, ok := ctx.Value(hasshAlgosCtxKey{}).(string); ok {
		return cached
	}
	return ""
}

// checkCredentialDiscovery scans command output for credential-like content and records via bridge.
func checkCredentialDiscovery(b *bridge.ProtocolBridge, ip, cmd, output string) {
	// Check for AWS credential access patterns
	if strings.Contains(cmd, ".aws/credentials") || strings.Contains(cmd, "aws_access_key") {
		if strings.Contains(output, "AKIA") || strings.Contains(output, "aws_secret") {
			b.RecordDiscovery(ip, "ssh", "aws_key", "aws_credentials", output)
			b.SetFlag(ip, "discovered_aws_credentials")
		}
	}
	// Check for SSH key access
	if strings.Contains(cmd, ".ssh/id_rsa") || strings.Contains(cmd, ".ssh/id_ed25519") {
		if strings.Contains(output, "BEGIN") {
			b.RecordDiscovery(ip, "ssh", "ssh_key", "private_key", output)
			b.SetFlag(ip, "discovered_ssh_key")
		}
	}
	// Check for database credential access
	if strings.Contains(cmd, ".env") || strings.Contains(cmd, "config") {
		if strings.Contains(output, "DB_PASSWORD") || strings.Contains(output, "DATABASE_URL") {
			b.RecordDiscovery(ip, "ssh", "db_password", "db_credentials", output)
			b.SetFlag(ip, "discovered_db_credentials")
		}
	}
	// Check for API token access
	if strings.Contains(output, "api_key") || strings.Contains(output, "api_token") || strings.Contains(output, "Bearer") {
		b.RecordDiscovery(ip, "ssh", "api_token", "api_credentials", output)
		b.SetFlag(ip, "discovered_api_token")
	}
}

// getOrCreateEmulatorSession returns the per-IP emulator session, creating one if needed.
func (s *SSHStrategy) getOrCreateEmulatorSession(ip, user string) *shellemulator.Session {
	if v, ok := s.emulatorSessions.Load(ip); ok {
		return v.(*shellemulator.Session)
	}
	sess := &shellemulator.Session{
		User:        user,
		CWD:         "/root",
		PIDOffset:   rand.Intn(200),
		ShellPID:    2891 + rand.Intn(1000),
		LoginTime:   time.Now(),
		FileOverlay: make(map[string]string),
		DirOverlay:  make(map[string][]string),
		Deleted:     make(map[string]bool),
	}
	s.emulatorSessions.Store(ip, sess)
	return sess
}

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}