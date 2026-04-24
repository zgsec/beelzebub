package TCP

import (
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mariocandela/beelzebub/v3/agentdetect"
	"github.com/mariocandela/beelzebub/v3/bridge"
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
	Bridge   *bridge.ProtocolBridge

	// Per-IP timing accumulation for automation detection.
	// We collect the data here; the scoring thresholds may need tuning
	// as we learn what TCP automation looks like vs SSH/HTTP.
	agentMu       sync.Mutex
	agentTimings  map[string][]int64
	agentLastSeen map[string]time.Time
	agentPrevCmd  map[string]string
}

func (tcpStrategy *TCPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if tcpStrategy.Sessions == nil {
		tcpStrategy.Sessions = historystore.NewHistoryStore()
	}
	go tcpStrategy.Sessions.HistoryCleaner()
	go tcpStrategy.cleanAgentState()

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

				// serviceProtocol dispatch: purpose-built binary protocol
				// handlers that own the whole connection lifecycle and
				// bypass banner / interactive / banner-only entirely.
				switch servConf.ServiceProtocol {
				case "mysql-handshake-v10":
					// Per-connection rng: thread-safe by construction,
					// cheap to seed, avoids sharing a lock across
					// concurrent MySQL probes.
					localRng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
					dispatchMysqlHandshake(c, servConf, tr, localRng)
					return
				}

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
	destPort := extractPort(servConf.Address)

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
		ServicePort: destPort,
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
			ServicePort: destPort,
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
		ServicePort: destPort,
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

		var commandInput string
		var commandRawHex string // hex-escaped raw bytes, for v2 classifier (binarySafe only)
		var err error
		if servConf.BinarySafe {
			// Binary-safe path: read the full frame (multi-line CRLF-terminated)
			// then protocol-decode it to extract the command name. The decoded
			// form drives the regex matcher (so existing handlers like
			// `^(PING|ping)$` still work); the hex-escaped raw bytes are
			// stored alongside in CommandRaw for downstream protocol-aware
			// classification.
			var rawBytes []byte
			rawBytes, err = readBinaryFrame(conn, deadline)
			if err != nil && len(rawBytes) == 0 {
				break
			}
			commandRawHex = hexEscapeNonPrintable(rawBytes)
			commandInput = decodeProtocolCommand(rawBytes)
		} else {
			// Default path: printable-ASCII, newline-delimited (legacy
			// behavior, used by telnet / LLM-plugin services / etc.).
			commandInput, err = readLine(conn)
			if err != nil {
				break
			}
			commandInput = strings.TrimSpace(commandInput)
		}

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
		var matchedCommand parser.Command

		for _, command := range servConf.Commands {
			if command.Regex != nil && command.Regex.MatchString(commandInput) {
				matched = true
				matchedCommand = command
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
			matchedCommand = servConf.FallbackCommand
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

		// Send response — honor matchedCommand.ReplyFormat when set so
		// wire-protocol lures (Redis RESP2, etc.) can emit schema-correct
		// bytes from plain YAML authors. Default (empty format) keeps the
		// legacy behavior: append "\r\n" to handler string.
		wireBytes := encodeReply(matchedCommand, commandOutput)
		if len(wireBytes) > 0 {
			if _, err := conn.Write(wireBytes); err != nil {
				break
			}
		}

		// Agent classification for interactive commands
		verdict := strategy.classifyTCP(host, commandInput)

		// Trace interaction
		tr.TraceEvent(tracer.Event{
			Msg:           "TCP Session Interaction",
			RemoteAddr:    conn.RemoteAddr().String(),
			SourceIp:      host,
			SourcePort:    port,
			Status:        tracer.Interaction.String(),
			Command:       commandInput,
			CommandRaw:    commandRawHex,
			CommandOutput: commandOutput,
			ID:            sessionID,
			Protocol:      tracer.TCP.String(),
			User:          username,
			Description:   servConf.Description,
			Handler:       handlerName,
			SessionKey:    sessionKey,
			ServicePort:   destPort,
			AgentScore:    verdict.Score,
			AgentCategory: verdict.Category,
			AgentSignals:  verdict.SignalsString(),
		})

		if shouldQuit {
			break
		}
	}

	// Session end
	tr.TraceEvent(tracer.Event{
		Msg:         "End TCP Session",
		Status:      tracer.End.String(),
		ID:          sessionID,
		Protocol:    tracer.TCP.String(),
		SessionKey:  sessionKey,
		SourceIp:    host,
		ServicePort: destPort,
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

// readBinaryFrame reads bytes from conn into a single buffer until either:
//  1. A short read settles (the client stopped sending — best signal of "end
//     of one logical request" for protocols like Redis RESP that may send
//     multiple newlines per logical command),
//  2. maxLineLength bytes have been read,
//  3. The connection closes,
//  4. The deadline expires.
//
// Unlike readLine, no bytes are dropped — CR/LF and non-printable bytes
// are preserved verbatim. Caller is responsible for hex-escaping before
// storing the bytes in trace events.
//
// The "settle" detection works by setting a short read deadline after the
// first byte arrives — if no more bytes show up within ~50ms the client is
// done sending its current frame and we return what we have. This lets us
// capture multi-line RESP frames (`*1\r\n$4\r\nPING\r\n`) as a single
// logical event without conflating them with the next request.
func readBinaryFrame(conn net.Conn, sessionDeadline time.Duration) ([]byte, error) {
	const settleWindow = 50 * time.Millisecond
	buf := make([]byte, 0, 256)
	chunk := make([]byte, 256)

	// First read uses the long session deadline — we wait however long the
	// client takes to send their first byte.
	if err := conn.SetReadDeadline(time.Now().Add(sessionDeadline)); err != nil {
		return buf, err
	}
	n, err := conn.Read(chunk)
	if n > 0 {
		buf = append(buf, chunk[:n]...)
	}
	if err != nil {
		// io.EOF or timeout on the very first read — return whatever we got
		// (probably nothing) and let the caller close the loop.
		if err == io.EOF {
			return buf, err
		}
		// On timeout / other read errors with no data, propagate.
		if len(buf) == 0 {
			return buf, err
		}
	}

	// Subsequent reads use the short settle window. We keep reading until
	// the client pauses long enough that we believe the frame is complete.
	for len(buf) < maxLineLength {
		if err := conn.SetReadDeadline(time.Now().Add(settleWindow)); err != nil {
			break
		}
		n, err := conn.Read(chunk)
		if n > 0 {
			remaining := maxLineLength - len(buf)
			if n > remaining {
				n = remaining
			}
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			// Settle timeout fires here — that's the signal that the frame
			// is done. Don't propagate, just return what we collected.
			break
		}
	}

	// Restore the session-level deadline so the rest of the handler isn't
	// surprised by our short window.
	_ = conn.SetReadDeadline(time.Now().Add(sessionDeadline))
	return buf, nil
}

// hexEscapeNonPrintable returns a printable-ASCII representation of b,
// rendering each non-printable byte as \xNN. Result is safe to store in
// trace events / JSON / database TEXT columns.
func hexEscapeNonPrintable(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c >= 32 && c <= 126 && c != '\\' {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "\\x%02x", c)
		}
	}
	return sb.String()
}

// decodeProtocolCommand inspects the first byte of a captured frame and
// extracts a logical command string suitable for regex matching.
//
// Supported protocols (auto-detected from first byte):
//   - RESP (Redis): `*N\r\n$M\r\nCMD\r\n$L\r\nARG1\r\n...` → "CMD ARG1 ARG2"
//   - RESP simple/error/integer (`+OK`, `-ERR ...`, `:42`) → returned as-is, CRLF stripped
//   - HTTP-on-TCP (`GET / HTTP/1.1\r\n...`) → returned as the request line
//   - Plain ASCII text (telnet-like) → returned with CRLF stripped
//   - Binary / unknown → hex-escaped representation (so something is captured)
//
// The goal is to give the regex matcher a string that looks like the command
// the attacker intended, regardless of how the wire protocol framed it.
func decodeProtocolCommand(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	// Try RESP array (`*N\r\n$M\r\nCMD\r\n...`)
	if b[0] == '*' {
		if cmd := decodeRESPArray(b); cmd != "" {
			return cmd
		}
		// Fall through — malformed RESP, hex-escape it
	}

	// RESP simple string / error / integer / bulk-string-header — return as-is,
	// CRLF stripped.
	if b[0] == '+' || b[0] == '-' || b[0] == ':' || b[0] == '$' {
		return strings.TrimRight(string(b), "\r\n\x00")
	}

	// HTTP request line on a non-HTTP port: GET / HTTP/1.1\r\n...
	// Return just the request line.
	if isLikelyHTTP(b) {
		if i := bytesIndexCRLF(b); i > 0 {
			return string(b[:i])
		}
		return string(b)
	}

	// Plain printable ASCII (telnet, CLI banners, etc.) — strip CRLF and
	// non-printable trailing bytes.
	if isMostlyPrintable(b) {
		s := string(b)
		s = strings.TrimRight(s, "\r\n\x00 \t")
		return s
	}

	// Binary noise / unknown protocol — hex-escape it so something useful
	// reaches the trace event.
	return hexEscapeNonPrintable(b)
}

// decodeRESPArray parses a RESP array frame and returns "CMD ARG1 ARG2 ...".
// Returns empty string if the frame is malformed or truncated.
//
// Format: *N\r\n$L1\r\nARG1\r\n$L2\r\nARG2\r\n...
func decodeRESPArray(b []byte) string {
	// Read array length: *N\r\n
	if len(b) < 4 || b[0] != '*' {
		return ""
	}
	end := bytesIndexCRLF(b)
	if end < 2 {
		return ""
	}
	count := 0
	for _, c := range b[1:end] {
		if c < '0' || c > '9' {
			return ""
		}
		count = count*10 + int(c-'0')
	}
	if count <= 0 || count > 64 {
		// Sanity cap — real Redis commands rarely have >64 args
		return ""
	}

	// Walk the bulk string headers + values
	pos := end + 2 // skip CRLF
	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if pos >= len(b) || b[pos] != '$' {
			return ""
		}
		// Read bulk length: $L\r\n
		hdrEnd := bytesIndexCRLFFrom(b, pos)
		if hdrEnd < 0 {
			return ""
		}
		bulkLen := 0
		for _, c := range b[pos+1 : hdrEnd] {
			if c < '0' || c > '9' {
				return ""
			}
			bulkLen = bulkLen*10 + int(c-'0')
		}
		if bulkLen < 0 || bulkLen > maxLineLength {
			return ""
		}
		valStart := hdrEnd + 2
		valEnd := valStart + bulkLen
		if valEnd > len(b) {
			// Truncated — return what we have so far if any
			if len(parts) > 0 {
				return strings.Join(parts, " ")
			}
			return ""
		}
		parts = append(parts, string(b[valStart:valEnd]))
		pos = valEnd + 2 // skip trailing CRLF
	}
	return strings.Join(parts, " ")
}

// bytesIndexCRLF returns the index of the first \r\n sequence in b, or -1.
func bytesIndexCRLF(b []byte) int {
	for i := 0; i < len(b)-1; i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// bytesIndexCRLFFrom returns the index of the first \r\n at or after `from`, or -1.
func bytesIndexCRLFFrom(b []byte, from int) int {
	if from < 0 {
		from = 0
	}
	for i := from; i < len(b)-1; i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// isLikelyHTTP returns true if b starts with an HTTP method followed by space.
func isLikelyHTTP(b []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}
	for _, m := range methods {
		if len(b) >= len(m) && string(b[:len(m)]) == m {
			return true
		}
	}
	return false
}

// isMostlyPrintable returns true if at least 90% of bytes are printable ASCII
// or whitespace. Used to detect "this is text" vs "this is binary noise".
func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if (c >= 32 && c <= 126) || c == '\t' || c == '\n' || c == '\r' {
			printable++
		}
	}
	return printable*10 >= len(b)*9
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

// encodeReply converts a matched Command's reply into wire bytes. When
// ReplyFormat is empty the legacy behavior is preserved: `handler + "\r\n"`.
// When ReplyFormat names a protocol-specific encoding (e.g. "redis-bulk"),
// this function frames the bytes so the response is schema-correct on the
// wire — without requiring the YAML author to count RESP length prefixes.
//
// Redis RESP2 encodings supported:
//   redis-simple   "+<value>\r\n"           simple string (e.g. "+PONG")
//   redis-integer  ":<value>\r\n"           integer (value must be digits)
//   redis-error    "-<value>\r\n"           error (e.g. "-ERR unknown cmd")
//   redis-bulk     "$<len>\r\n<value>\r\n"  bulk string; value is raw,
//                                            CRLF preserved, length auto-
//                                            computed, UTF-8 safe
//   redis-nil-bulk "$-1\r\n"                nil bulk; handler ignored
//   redis-array    "*<n>\r\n" + per-entry   array of bulk strings taken
//                  bulk encoding             from ReplyBulks
func encodeReply(cmd parser.Command, value string) []byte {
	switch cmd.ReplyFormat {
	case "":
		// Legacy default: plain text + CRLF
		if value == "" {
			return nil
		}
		return []byte(value + "\r\n")
	case "redis-simple":
		return []byte("+" + value + "\r\n")
	case "redis-integer":
		return []byte(":" + value + "\r\n")
	case "redis-error":
		return []byte("-" + value + "\r\n")
	case "redis-bulk":
		return []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(value), value))
	case "redis-nil-bulk":
		return []byte("$-1\r\n")
	case "redis-raw":
		// Escape hatch for RESP shapes the typed encoders can't express
		// (nested arrays, integer elements inside arrays, HELLO's mixed
		// bulk+integer+array response). The handler string is written
		// VERBATIM — author must provide the exact RESP bytes including
		// type markers, length prefixes, and CRLF. YAML double-quoted
		// strings handle \r\n escapes; block scalars do not.
		return []byte(value)
	case "redis-array":
		var buf strings.Builder
		fmt.Fprintf(&buf, "*%d\r\n", len(cmd.ReplyBulks))
		for _, b := range cmd.ReplyBulks {
			fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(b), b)
		}
		return []byte(buf.String())
	default:
		// Unknown format: log once and fall back to plain-text framing so
		// a typo in a YAML doesn't silently drop all traffic.
		log.Warnf("tcp.encodeReply: unknown replyFormat %q, falling back to plaintext", cmd.ReplyFormat)
		return []byte(value + "\r\n")
	}
}

// classifyTCP accumulates timing and builds an agent detection verdict for a TCP command.
// The scoring uses the same agentdetect.IncrementalClassify as SSH/MCP — same signal
// definitions, same thresholds. Whether those thresholds are well-calibrated for TCP
// is an open question (Redis scanners may have different timing profiles than SSH bots).
// We collect the data now; threshold tuning happens after we have labeled TCP sessions.
func (s *TCPStrategy) classifyTCP(ip, cmd string) agentdetect.Verdict {
	now := time.Now()
	s.agentMu.Lock()

	// Lazy init (safe because Init runs before any connections)
	if s.agentTimings == nil {
		s.agentTimings = make(map[string][]int64)
		s.agentLastSeen = make(map[string]time.Time)
		s.agentPrevCmd = make(map[string]string)
	}

	// Accumulate timing (ring buffer, max 100 samples per IP)
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

	// Retry detection: exact same command repeated
	prevCmd := s.agentPrevCmd[ip]
	isRetry := prevCmd != "" && prevCmd == cmd
	s.agentPrevCmd[ip] = cmd

	s.agentMu.Unlock()

	sig := agentdetect.Signal{
		InterEventTimingsMs: timings,
		HasIdenticalRetries: isRetry,
	}

	// Cross-protocol: check bridge for activity from same IP on other protocols.
	// v8: compute CrossProtocolGapMs from bridge timestamps (was dead code).
	if s.Bridge != nil {
		flags := s.Bridge.GetFlags(ip)
		for _, f := range flags {
			if f == "mcp_tool_call" || f == "ollama_api_accessed" {
				sig.HasCrossProtocol = true
				lastAct := s.Bridge.LastActivity(ip)
				if !lastAct.IsZero() {
					sig.CrossProtocolGapMs = now.Sub(lastAct).Milliseconds()
				}
				break
			}
		}
	}

	return agentdetect.IncrementalClassify(sig)
}

// cleanAgentState periodically prunes stale entries from the agent detection maps.
func (s *TCPStrategy) cleanAgentState() {
	for {
		time.Sleep(5 * time.Minute)
		cutoff := time.Now().Add(-60 * time.Minute)
		s.agentMu.Lock()
		if s.agentLastSeen != nil {
			for ip, last := range s.agentLastSeen {
				if last.Before(cutoff) {
					delete(s.agentTimings, ip)
					delete(s.agentLastSeen, ip)
					delete(s.agentPrevCmd, ip)
				}
			}
		}
		s.agentMu.Unlock()
	}
}
