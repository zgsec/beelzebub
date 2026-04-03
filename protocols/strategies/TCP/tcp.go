package TCP

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const maxLineLength = 8192 // Prevent unbounded memory growth from binary junk or malicious input

type TCPStrategy struct {
	Sessions *historystore.HistoryStore
}

func (tcpStrategy *TCPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if tcpStrategy.Sessions == nil {
		tcpStrategy.Sessions = historystore.NewHistoryStore()
	}
	go tcpStrategy.Sessions.HistoryCleaner()

	listen, err := net.Listen("tcp", servConf.Address)
	if err != nil {
		log.Errorf("Error during init TCP Protocol: %s", err.Error())
		return err
	}

	interactive := len(servConf.Commands) > 0

	go func() {
		for {
			conn, err := listen.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("panic in TCP handler: %v", r)
					}
				}()
				c.SetDeadline(time.Now().Add(time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second))

				// Send banner exactly as configured — no appended newline.
				// Operators control the format: "8.0.32\n", "220 smtp.example.com ESMTP\r\n", or "".
				if servConf.Banner != "" {
					c.Write([]byte(servConf.Banner))
				}

				if interactive {
					handleInteractiveConnection(c, servConf, tr, tcpStrategy)
				} else {
					handleBannerOnly(c, servConf, tr)
				}
			}(conn)
		}
	}()

	mode := "banner-only"
	if interactive {
		mode = fmt.Sprintf("interactive (%d commands)", len(servConf.Commands))
	}
	log.WithFields(log.Fields{
		"port": servConf.Address,
		"mode": mode,
	}).Infof("Init service %s", servConf.Protocol)
	return nil
}

// handleBannerOnly preserves the original TCP behavior: read one buffer, log, close.
func handleBannerOnly(conn net.Conn, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	command := ""
	if n, err := conn.Read(buffer); err == nil {
		command = string(buffer[:n])
	}

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())

	tr.TraceEvent(tracer.Event{
		Msg:         "New TCP attempt",
		Protocol:    tracer.TCP.String(),
		Command:     command,
		Status:      tracer.Stateless.String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    host,
		SourcePort:  port,
		ID:          uuid.New().String(),
		Description: servConf.Description,
	})
}

// handleInteractiveConnection runs a command loop with regex matching and LLM fallback.
func handleInteractiveConnection(conn net.Conn, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, strategy *TCPStrategy) {
	defer conn.Close()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	destPort := extractPort(servConf.Address)
	deadline := time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second

	var username, password string

	// Optional authentication — only if passwordRegex is configured
	if servConf.PasswordRegex != "" {
		conn.Write([]byte("Login: "))
		var err error
		username, err = readLine(conn)
		if err != nil {
			return
		}
		username = strings.TrimSpace(username)

		conn.Write([]byte("Password: "))
		password, err = readLine(conn)
		if err != nil {
			return
		}
		password = strings.TrimSpace(password)

		// Trace auth attempt
		tr.TraceEvent(tracer.Event{
			Msg:         "TCP Login Attempt",
			Protocol:    tracer.TCP.String(),
			Status:      tracer.Stateless.String(),
			User:        username,
			Password:    password,
			RemoteAddr:  conn.RemoteAddr().String(),
			SourceIp:    host,
			SourcePort:  port,
			ID:          uuid.New().String(),
			Description: servConf.Description,
		})

		matched, err := regexp.MatchString(servConf.PasswordRegex, password)
		if err != nil || !matched {
			conn.Write([]byte("Login incorrect\r\n"))
			return
		}
		conn.Write([]byte("\r\n"))
	}

	// Session start
	sessionID := uuid.New().String()
	sessionKey := "TCP" + host + ":" + destPort
	if username != "" {
		sessionKey += ":" + username
	}

	tr.TraceEvent(tracer.Event{
		Msg:         "New TCP Session",
		Protocol:    tracer.TCP.String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    host,
		SourcePort:  port,
		Status:      tracer.Start.String(),
		ID:          sessionID,
		User:        username,
		Description: servConf.Description,
		SessionKey:  sessionKey,
	})

	// Load history for LLM context
	var histories []plugins.Message
	if strategy.Sessions.HasKey(sessionKey) {
		histories = strategy.Sessions.Query(sessionKey)
	}

	// Interactive command loop
	for {
		// Display prompt if serverName is set
		if servConf.ServerName != "" {
			if _, err := conn.Write([]byte(servConf.ServerName)); err != nil {
				break
			}
		}

		commandInput, err := readLine(conn)
		if err != nil {
			break
		}
		commandInput = strings.TrimSpace(commandInput)

		if commandInput == "" {
			continue
		}

		// Reset deadline on each successful read — keeps active sessions alive
		conn.SetDeadline(time.Now().Add(deadline))

		// Match against configured commands
		commandOutput := ""
		handlerName := "not_found"
		matched := false
		shouldQuit := false

		for _, command := range servConf.Commands {
			if command.Regex != nil && command.Regex.MatchString(commandInput) {
				matched = true
				commandOutput = command.Handler
				handlerName = command.Name
				if handlerName == "" {
					handlerName = "configured_regex"
				}

				// Check if this is a quit command — handler name "quit" or
				// command matches common exit patterns. The YAML controls this:
				// give the quit command a name: "quit" to trigger disconnect.
				if handlerName == "quit" {
					shouldQuit = true
				}

				// LLM integration
				if command.Plugin == plugins.LLMPluginName {
					llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
					if err != nil {
						log.Errorf("LLM provider error: %s, fallback OpenAI", err.Error())
						llmProvider = plugins.OpenAI
					}
					llmHoneypot := plugins.BuildHoneypot(histories, tracer.TCP, llmProvider, servConf)
					llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
					if commandOutput, err = llmHoneypotInstance.ExecuteModel(commandInput, host); err != nil {
						log.Errorf("LLM ExecuteModel error: %s, %s", commandInput, err.Error())
						commandOutput = servConf.FallbackCommand.Handler
						if commandOutput == "" {
							commandOutput = "ERROR: unknown command"
						}
					}
				}

				break
			}
		}

		if !matched {
			commandOutput = servConf.FallbackCommand.Handler
			if commandOutput == "" {
				commandOutput = "ERROR: unknown command"
			}
		}

		// Store in history for LLM context
		newEntries := []plugins.Message{
			{Role: plugins.USER.String(), Content: commandInput},
			{Role: plugins.ASSISTANT.String(), Content: commandOutput},
		}
		strategy.Sessions.Append(sessionKey, newEntries...)
		histories = append(histories, newEntries...)

		// Send response
		if commandOutput != "" {
			if _, err := conn.Write([]byte(commandOutput + "\r\n")); err != nil {
				break
			}
		}

		// Trace interaction
		tr.TraceEvent(tracer.Event{
			Msg:           "TCP Session Interaction",
			RemoteAddr:    conn.RemoteAddr().String(),
			SourceIp:      host,
			SourcePort:    port,
			Status:        tracer.Interaction.String(),
			Command:       commandInput,
			CommandOutput: commandOutput,
			ID:            sessionID,
			Protocol:      tracer.TCP.String(),
			User:          username,
			Description:   servConf.Description,
			Handler:       handlerName,
			SessionKey:    sessionKey,
		})

		if shouldQuit {
			break
		}
	}

	// Session end
	tr.TraceEvent(tracer.Event{
		Msg:        "End TCP Session",
		Status:     tracer.End.String(),
		ID:         sessionID,
		Protocol:   tracer.TCP.String(),
		SessionKey: sessionKey,
		SourceIp:   host,
	})
}

// readLine reads bytes from conn until newline or maxLineLength.
// Keeps printable ASCII and tab only — binary junk is silently dropped.
// Returns partial line on error (connection close, timeout) so partial
// input is still captured.
func readLine(conn net.Conn) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			return string(line), err
		}
		if buf[0] == '\n' {
			break
		}
		// Keep printable ASCII and tab
		if (buf[0] >= 32 && buf[0] <= 126) || buf[0] == '\t' {
			line = append(line, buf[0])
		}
		if len(line) >= maxLineLength {
			break
		}
	}
	return string(line), nil
}

// extractPort returns the port portion of an address string.
// Handles both ":3306" and "0.0.0.0:3306" formats.
func extractPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Fallback for ":3306" format which SplitHostPort handles as host="", port="3306"
		return strings.TrimPrefix(addr, ":")
	}
	return port
}
