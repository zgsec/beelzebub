package SSH

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/faults"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
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
}

func (sshStrategy *SSHStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if sshStrategy.Sessions == nil {
		sshStrategy.Sessions = historystore.NewHistoryStore()
	}
	go sshStrategy.Sessions.HistoryCleaner()
	go func() {
		server := &ssh.Server{
			Addr:        servConf.Address,
			MaxTimeout:  time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			Version:     servConf.ServerVersion,
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
								llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
								if err != nil {
									log.Errorf("error: %s", err.Error())
									commandOutput = "command not found"
									llmProvider = plugins.OpenAI
								}
								llmHoneypot := plugins.BuildHoneypot(histories, tracer.SSH, llmProvider, servConf)
								llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
								if commandOutput, err = llmHoneypotInstance.ExecuteModel(sess.RawCommand(), host); err != nil {
									log.Errorf("error ExecuteModel: %s, %s", sess.RawCommand(), err.Error())
									commandOutput = "command not found"
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

							tr.TraceEvent(tracer.Event{
								Msg:           "SSH Raw Command",
								Protocol:      tracer.SSH.String(),
								RemoteAddr:    sess.RemoteAddr().String(),
								SourceIp:      host,
								SourcePort:    port,
								Status:        tracer.Start.String(),
								ID:            uuidSession.String(),
								Environ:       strings.Join(sess.Environ(), ","),
								User:          sess.User(),
								Description:   servConf.Description,
								Command:       sess.RawCommand(),
								CommandOutput: commandOutput,
								Handler:       command.Name,
								SessionKey:    sessionKey,
							})
							return
						}
					}
				}

				tr.TraceEvent(tracer.Event{
					Msg:        "New SSH Terminal Session",
					Protocol:   tracer.SSH.String(),
					RemoteAddr: sess.RemoteAddr().String(),
					SourceIp:   host,
					SourcePort: port,
					Status:     tracer.Start.String(),
					ID:         uuidSession.String(),
					Environ:    strings.Join(sess.Environ(), ","),
					User:       sess.User(),
					Description: servConf.Description,
					SessionKey: sessionKey,
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
							commandOutput := command.Handler
							if command.Plugin == plugins.LLMPluginName {
								llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
								if err != nil {
									log.Errorf("error: %s, fallback OpenAI", err.Error())
									llmProvider = plugins.OpenAI
								}
								llmHoneypot := plugins.BuildHoneypot(histories, tracer.SSH, llmProvider, servConf)
								llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
								if commandOutput, err = llmHoneypotInstance.ExecuteModel(commandInput, host); err != nil {
									log.Errorf("error ExecuteModel: %s, %s", commandInput, err.Error())
									commandOutput = "command not found"
								}
							}
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

							tr.TraceEvent(tracer.Event{
								Msg:           "SSH Terminal Session Interaction",
								RemoteAddr:    sess.RemoteAddr().String(),
								SourceIp:      host,
								SourcePort:    port,
								Status:        tracer.Interaction.String(),
								Command:       commandInput,
								CommandOutput: commandOutput,
								ID:            uuidSession.String(),
								Protocol:      tracer.SSH.String(),
								Description:   servConf.Description,
								Handler:       command.Name,
								SessionKey:    sessionKey,
							})
							break // Inner range over commands.
						}
					}
				}

				tr.TraceEvent(tracer.Event{
					Msg:        "End SSH Session",
					Status:     tracer.End.String(),
					ID:         uuidSession.String(),
					Protocol:   tracer.SSH.String(),
					SessionKey: sessionKey,
					SourceIp:   host,
				})
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				host, port, _ := net.SplitHostPort(ctx.RemoteAddr().String())

				tr.TraceEvent(tracer.Event{
					Msg:         "New SSH Login Attempt",
					Protocol:    tracer.SSH.String(),
					Status:      tracer.Stateless.String(),
					User:        ctx.User(),
					Password:    password,
					Client:      ctx.ClientVersion(),
					RemoteAddr:  ctx.RemoteAddr().String(),
					SourceIp:    host,
					SourcePort:  port,
					ID:          uuid.New().String(),
					Description: servConf.Description,
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

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}