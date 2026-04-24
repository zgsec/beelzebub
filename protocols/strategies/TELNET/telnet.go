package TELNET

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/mariocandela/beelzebub/v3/bridge"
	"github.com/mariocandela/beelzebub/v3/faults"
	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// Telnet IAC (Interpret As Command) constants
const (
	IAC               = 255 // Interpret As Command
	DO                = 253 // Do perform option
	DONT              = 254 // Don't perform option
	WILL              = 251 // Will perform option
	WONT              = 252 // Won't perform option
	SB                = 250 // Subnegotiation Begin
	SE                = 240 // Subnegotiation End
	ECHO              = 1   // Echo option
	SUPPRESS_GO_AHEAD = 3   // Suppress Go Ahead option
)

type TelnetStrategy struct {
	Sessions *historystore.HistoryStore
	Bridge   *bridge.ProtocolBridge
	Fault    *faults.Injector
}

func (telnetStrategy *TelnetStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if telnetStrategy.Sessions == nil {
		telnetStrategy.Sessions = historystore.NewHistoryStore()
	}
	go telnetStrategy.Sessions.HistoryCleaner()

	go func() {
		listener, err := net.Listen("tcp", servConf.Address)
		if err != nil {
			log.Errorf("error during init TELNET Protocol: %s", err.Error())
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Errorf("error accepting TELNET connection: %s", err.Error())
				continue
			}

			// Set deadline timeout
			conn.SetDeadline(time.Now().Add(time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second))

			go func(c net.Conn) {
				defer func() {
					if r := recover(); r != nil {
						log.Errorf("panic in TELNET handler: %v", r)
					}
				}()
				handleTelnetConnection(c, servConf, tr, telnetStrategy)
			}(conn)
		}
	}()

	log.WithFields(log.Fields{
		"port":     servConf.Address,
		"commands": len(servConf.Commands),
	}).Infof("GetInstance service %s", servConf.Protocol)
	return nil
}

func handleTelnetConnection(conn net.Conn, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, telnetStrategy *TelnetStrategy) {
	defer conn.Close()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	destPort := tracer.ExtractPort(servConf.Address)

	// Capture client telnet negotiation as a tracer event
	captureTelnetHandshake(conn, tr, host, port, servConf.Description, destPort)

	// Authentication phase
	_, err := conn.Write([]byte("\r\nlogin: "))
	if err != nil {
		return
	}

	username, err := readLine(conn)
	if err != nil {
		return
	}
	username = strings.TrimSpace(username)

	// Send password prompt with echo suppression
	_, err = conn.Write([]byte{IAC, WILL, ECHO})
	if err != nil {
		return
	}
	_, err = conn.Write([]byte("Password: "))
	if err != nil {
		return
	}

	password, err := readLine(conn)
	if err != nil {
		return
	}
	password = strings.TrimSpace(password)

	// Re-enable echo
	_, err = conn.Write([]byte{IAC, WONT, ECHO, '\r', '\n'})
	if err != nil {
		return
	}

	// Trace authentication attempt
	tr.TraceEvent(tracer.Event{
		Msg:         "New TELNET Login Attempt",
		Protocol:    tracer.TELNET.String(),
		Status:      tracer.Stateless.String(),
		User:        username,
		Password:    password,
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    host,
		SourcePort:  port,
		ID:          uuid.New().String(),
		Description: servConf.Description,
		ServicePort: destPort,
	})

	// Validate password
	matched, err := regexp.MatchString(servConf.PasswordRegex, password)
	if err != nil {
		log.Errorf("error regex: %s, %s", servConf.PasswordRegex, err.Error())
		conn.Write([]byte("Login incorrect\r\n"))
		return
	}

	if !matched {
		conn.Write([]byte("Login incorrect\r\n"))
		return
	}

	// Session phase - authenticated
	uuidSession := uuid.New()
	sessionKey := "TELNET" + host + username

	tr.TraceEvent(tracer.Event{
		Msg:         "New TELNET Terminal Session",
		Protocol:    tracer.TELNET.String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    host,
		SourcePort:  port,
		Status:      tracer.Start.String(),
		ID:          uuidSession.String(),
		User:        username,
		Description: servConf.Description,
		SessionKey:  sessionKey,
		ServicePort: destPort,
	})

	// Load history for LLM context
	var histories []plugins.Message
	if telnetStrategy.Sessions.HasKey(sessionKey) {
		histories = telnetStrategy.Sessions.Query(sessionKey)
	}

	// Interactive command loop
	for {
		// Display prompt (no newline - user types on same line)
		prompt := buildPrompt(username, servConf.ServerName)
		_, err := conn.Write([]byte(prompt))
		if err != nil {
			break
		}

		// Read command from user
		commandInput, err := readLine(conn)
		if err != nil {
			break
		}
		commandInput = strings.TrimSpace(commandInput)

		// Handle exit command
		if commandInput == "exit" {
			break
		}

		// Match command against regexes
		matched := false
		for _, command := range servConf.Commands {
			if command.Regex.MatchString(commandInput) {
				matched = true
				commandOutput := command.Handler
				handlerName := command.Name
				if handlerName == "" {
					handlerName = "configured_regex"
				}

				// LLM integration - exactly like SSH
				if command.Plugin == plugins.LLMPluginName {
					llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
					if err != nil {
						log.Errorf("error: %s, fallback OpenAI", err.Error())
						llmProvider = plugins.OpenAI
					}
					llmHoneypot := plugins.BuildHoneypot(histories, tracer.TELNET, llmProvider, servConf)
					llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
					if commandOutput, err = llmHoneypotInstance.ExecuteModel(commandInput, host); err != nil {
						log.Errorf("error ExecuteModel: %s, %s", commandInput, err.Error())
						commandOutput = "command not found"
					}
				}

				// Store command and response in history
				var newEntries []plugins.Message
				newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: commandInput})
				newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
				telnetStrategy.Sessions.Append(sessionKey, newEntries...)
				histories = append(histories, newEntries...)

				// Send response to client
				_, err := conn.Write([]byte(commandOutput + "\r\n"))
				if err != nil {
					break
				}

				// Trace interaction event
				tr.TraceEvent(tracer.Event{
					Msg:           "TELNET Terminal Session Interaction",
					RemoteAddr:    conn.RemoteAddr().String(),
					SourceIp:      host,
					SourcePort:    port,
					Status:        tracer.Interaction.String(),
					Command:       commandInput,
					CommandOutput: commandOutput,
					ID:            uuidSession.String(),
					Protocol:      tracer.TELNET.String(),
					User:          username,
					Description:   servConf.Description,
					Handler:       handlerName,
					SessionKey:    sessionKey,
					ServicePort:   destPort,
				})

				break // Found match, exit command loop
			}
		}

		// If no command matched, send "command not found"
		if !matched {
			commandOutput := "command not found"
			_, err := conn.Write([]byte(commandOutput + "\r\n"))
			if err != nil {
				break
			}

			// Still trace the interaction even for unmatched commands
			tr.TraceEvent(tracer.Event{
				Msg:           "TELNET Terminal Session Interaction",
				RemoteAddr:    conn.RemoteAddr().String(),
				SourceIp:      host,
				SourcePort:    port,
				Status:        tracer.Interaction.String(),
				Command:       commandInput,
				CommandOutput: commandOutput,
				ID:            uuidSession.String(),
				Protocol:      tracer.TELNET.String(),
				User:          username,
				Description:   servConf.Description,
				Handler:       "not_found",
				SessionKey:    sessionKey,
				ServicePort:   destPort,
			})
		}
	}

	// Trace session end
	tr.TraceEvent(tracer.Event{
		Msg:         "End TELNET Session",
		Status:      tracer.End.String(),
		ID:          uuidSession.String(),
		Protocol:    tracer.TELNET.String(),
		SessionKey:  sessionKey,
		SourceIp:    host,
		ServicePort: destPort,
	})
}

// captureTelnetHandshake reads the client's initial IAC negotiation and emits
// it as a tracer event. Different clients negotiate different options — this
// acts as a client fingerprint (e.g., real terminal vs automated script).
func captureTelnetHandshake(conn net.Conn, tr tracer.Tracer, host, port, description, destPort string) {
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	n, _ := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})

	if n == 0 {
		return
	}

	// Parse IAC sequences into human-readable summary
	summary := parseIACOptions(buf[:n])
	if summary == "" {
		return
	}

	tr.TraceEvent(tracer.Event{
		Msg:         "TELNET Client Negotiation",
		Protocol:    tracer.TELNET.String(),
		Status:      tracer.Stateless.String(),
		Command:     summary,
		SourceIp:    host,
		SourcePort:  port,
		RemoteAddr:  net.JoinHostPort(host, port),
		ID:          uuid.New().String(),
		Description: description,
		ServicePort: destPort,
	})
}

// parseIACOptions extracts telnet IAC option negotiations from raw bytes
// and returns a compact summary like "WILL:ECHO,DO:SGA,WILL:NAWS".
func parseIACOptions(data []byte) string {
	cmdNames := map[byte]string{WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}
	optNames := map[byte]string{
		1: "ECHO", 3: "SGA", 5: "STATUS", 6: "TIMING",
		24: "TTYPE", 31: "NAWS", 32: "TSPEED", 33: "RFLOW",
		34: "LINEMODE", 35: "XDISPLOC", 36: "ENVIRON", 39: "NEWENV",
	}

	var parts []string
	i := 0
	for i < len(data) {
		if data[i] != IAC {
			i++
			continue
		}
		i++
		if i >= len(data) {
			break
		}
		cmd := data[i]
		i++

		if cmd == SB {
			// Subnegotiation — skip until IAC SE
			for i < len(data)-1 {
				if data[i] == IAC && data[i+1] == SE {
					i += 2
					break
				}
				i++
			}
			continue
		}

		if cmd == WILL || cmd == WONT || cmd == DO || cmd == DONT {
			if i >= len(data) {
				break
			}
			opt := data[i]
			i++

			cmdStr := cmdNames[cmd]
			optStr := optNames[opt]
			if optStr == "" {
				optStr = fmt.Sprintf("%d", opt)
			}
			parts = append(parts, cmdStr+":"+optStr)
		}
	}

	return strings.Join(parts, ",")
}

func readLine(conn net.Conn) (string, error) {
	// Read one byte at a time until we get a newline
	var line []byte
	buf := make([]byte, 1)

	for {
		_, err := conn.Read(buf)
		if err != nil {
			return "", err
		}

		b := buf[0]

		// Skip IAC (Interpret As Command) sequences
		if b == IAC {
			if _, err := conn.Read(buf); err != nil {
				return "", err
			}
			cmd := buf[0]
			if cmd == SB {
				// Subnegotiation: skip until IAC SE
				for {
					if _, err := conn.Read(buf); err != nil {
						return "", err
					}
					if buf[0] == IAC {
						if _, err := conn.Read(buf); err != nil {
							return "", err
						}
						if buf[0] == SE {
							break
						}
					}
				}
			} else if cmd == WILL || cmd == WONT || cmd == DO || cmd == DONT {
				conn.Read(buf) // discard option byte
			}
			continue
		}

		// Check for newline
		if b == '\n' {
			break
		}

		// Only keep printable ASCII and tab, skip control bytes
		if b >= 32 && b <= 126 || b == '\t' {
			line = append(line, b)
		}
	}

	return string(line), nil
}

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}
