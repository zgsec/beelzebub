// Package TCP — MySQL Handshake Packet v10 binary-protocol handler.
//
// Purpose:
//   Real MySQL clients (mysql-connector-python, Go-MySQL-Driver, mysql2,
//   libmysqlclient, MariaDB Connector/J) start every connection by
//   reading a binary Handshake Packet v10 from the server. Our TCP
//   strategy's default line-oriented "banner" mode fails this on byte 1
//   (the packet length byte is misinterpreted as ASCII text).
//
// Solution:
//   When the YAML sets `serviceProtocol: "mysql-handshake-v10"`,
//   dispatchMysqlHandshake takes over the whole connection lifecycle:
//     1. Write a real Handshake Packet v10 greeting (seq_id=0) built from
//        the YAML-configured server_version + randomized thread_id + random
//        20-byte auth scramble.
//     2. Read the client's Handshake Response 41 (seq_id=1, binary frame).
//     3. Parse it to extract: username, capability_flags, charset,
//        auth_response, auth_plugin_name, database (optional), and the
//        connect_attrs map (_client_name, _client_version, _pid,
//        program_name — our single biggest intel win vs a banner-grab).
//     4. Always respond with an ERR packet (seq_id=2, error_code 1045
//        "Access denied for user 'X'@'host' (using password: YES)") —
//        we never accept auth; doing so would imply a successful login on
//        a honeypot, crossing the ethical line between observation and
//        entrapment.
//     5. Close the connection.
//
// Protocol references:
//   - Handshake v10:  https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
//   - HSR41:          https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html
//   - ERR packet:     https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_err_packet.html
//   - Capability bits: https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html

package TCP

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
	log "github.com/sirupsen/logrus"
)

// MySQL capability flag bits we advertise in the initial handshake.
// The bitmap below is what a stock MySQL 8.0.32 on Ubuntu advertises minus
// CLIENT_SSL / CLIENT_COMPRESS — setting those and then failing to do the
// upgrade handshake is itself a honeypot tell.
const (
	capClientLongPassword              uint32 = 0x00000001
	capClientFoundRows                 uint32 = 0x00000002
	capClientLongFlag                  uint32 = 0x00000004
	capClientConnectWithDB             uint32 = 0x00000008
	capClientProtocol41                uint32 = 0x00000200
	capClientInteractive               uint32 = 0x00000400
	capClientTransactions              uint32 = 0x00002000
	capClientSecureConnection          uint32 = 0x00008000
	capClientMultiStatements           uint32 = 0x00010000
	capClientMultiResults              uint32 = 0x00020000
	capClientPSMultiResults            uint32 = 0x00040000
	capClientPluginAuth                uint32 = 0x00080000
	capClientConnectAttrs              uint32 = 0x00100000
	capClientPluginAuthLenencClientData uint32 = 0x00200000
	capClientSessionTrack              uint32 = 0x00800000
	capClientDeprecateEOF              uint32 = 0x01000000

	mysqlStatusAutocommit uint16 = 0x0002

	// charset 0xff = utf8mb4_0900_ai_ci (MySQL 8.0+ default)
	mysqlCharsetUTF8MB40900 byte = 0xff

	// auth_plugin_data total length (scramble) = 20 + NUL = 21
	mysqlAuthScrambleLen int = 20
)

// MysqlHandshakeConfig carries the per-service overrides read from the
// BeelzebubServiceConfiguration. Only ServerVersion is typically set by
// the yaml; everything else has sensible defaults matching a real Ubuntu
// MySQL 8.0.32 install.
type MysqlHandshakeConfig struct {
	ServerVersion  string // e.g. "8.0.32-0ubuntu0.22.04.2"
	AuthPluginName string // default "caching_sha2_password" (MySQL 8.0)
}

// buildHandshakeV10 constructs a real Handshake Packet v10 payload.
// Returned bytes are just the PAYLOAD (no length/seq header); caller
// wraps with writeMysqlPacket.
func buildHandshakeV10(cfg MysqlHandshakeConfig, rng *rand.Rand) ([]byte, []byte) {
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "8.0.32-0ubuntu0.22.04.2"
	}
	if cfg.AuthPluginName == "" {
		cfg.AuthPluginName = "caching_sha2_password"
	}

	caps := capClientLongPassword |
		capClientFoundRows |
		capClientLongFlag |
		capClientConnectWithDB |
		capClientProtocol41 |
		capClientInteractive |
		capClientTransactions |
		capClientSecureConnection |
		capClientMultiStatements |
		capClientMultiResults |
		capClientPSMultiResults |
		capClientPluginAuth |
		capClientConnectAttrs |
		capClientPluginAuthLenencClientData |
		capClientSessionTrack |
		capClientDeprecateEOF

	// 20 random bytes for auth scramble. Real MySQL uses `openssl RAND_bytes`;
	// crypto entropy matters only if the client actually verifies a real
	// challenge, which it won't here (we always fail auth). But per-connection
	// randomness is required to avoid the "identical scramble across connects"
	// fingerprint mentioned by the audit.
	scramble := make([]byte, mysqlAuthScrambleLen)
	for i := range scramble {
		scramble[i] = byte(rng.Intn(256))
	}

	threadID := uint32(rng.Uint32())
	// thread_id = 0 is another common honeypot tell; bump to a plausible
	// small-server range if we rolled zero.
	if threadID == 0 {
		threadID = uint32(rng.Intn(50000) + 100)
	}

	var b []byte
	b = append(b, 0x0a) // protocol_version
	b = append(b, []byte(cfg.ServerVersion)...)
	b = append(b, 0x00)

	thread := make([]byte, 4)
	binary.LittleEndian.PutUint32(thread, threadID)
	b = append(b, thread...)

	// auth_plugin_data_part_1 (first 8 bytes of scramble)
	b = append(b, scramble[:8]...)
	b = append(b, 0x00) // filler

	capLow := make([]byte, 2)
	binary.LittleEndian.PutUint16(capLow, uint16(caps&0xFFFF))
	b = append(b, capLow...)

	b = append(b, mysqlCharsetUTF8MB40900)

	status := make([]byte, 2)
	binary.LittleEndian.PutUint16(status, mysqlStatusAutocommit)
	b = append(b, status...)

	capHigh := make([]byte, 2)
	binary.LittleEndian.PutUint16(capHigh, uint16((caps>>16)&0xFFFF))
	b = append(b, capHigh...)

	// auth_plugin_data_length = len(scramble) + 1 (for trailing NUL). MySQL
	// requires this value to be >= 21 when CLIENT_PLUGIN_AUTH is set.
	b = append(b, byte(mysqlAuthScrambleLen+1))

	// reserved — 10 NUL bytes
	b = append(b, make([]byte, 10)...)

	// auth_plugin_data_part_2: remainder of scramble + trailing NUL.
	// Length = max(13, auth_plugin_data_length - 8). With 20-byte scramble,
	// part_2 is 12 bytes + NUL = 13 bytes.
	b = append(b, scramble[8:]...)
	b = append(b, 0x00)

	// auth_plugin_name (NUL-terminated)
	b = append(b, []byte(cfg.AuthPluginName)...)
	b = append(b, 0x00)

	return b, scramble
}

// writeMysqlPacket writes the 4-byte packet header (3-byte LE length,
// 1-byte seq_id) followed by the payload. Split writes are explicitly
// NOT used — a single Write maps to a single TCP segment on common Linux
// kernels, matching the server's normal behavior.
func writeMysqlPacket(w io.Writer, seqID byte, payload []byte) error {
	if len(payload) > 0xFFFFFF {
		return fmt.Errorf("mysql packet too large: %d", len(payload))
	}
	header := make([]byte, 4)
	header[0] = byte(len(payload) & 0xFF)
	header[1] = byte((len(payload) >> 8) & 0xFF)
	header[2] = byte((len(payload) >> 16) & 0xFF)
	header[3] = seqID
	full := append(header, payload...)
	_, err := w.Write(full)
	return err
}

// readMysqlPacket reads one framed packet, returning seq_id + payload.
// A 1 MB hard limit prevents memory-exhaustion probes.
func readMysqlPacket(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	payloadLen := uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16
	if payloadLen > 1<<20 {
		return 0, nil, fmt.Errorf("mysql packet too large: %d", payloadLen)
	}
	seqID := header[3]
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return seqID, payload, nil
}

// buildErrPacket constructs a MySQL ERR packet payload (no header).
// CLIENT_PROTOCOL_41 is always set by modern clients so we include the
// '#' SQL-state marker + 5-byte sql_state.
func buildErrPacket(errorCode uint16, sqlState, message string) []byte {
	var b []byte
	b = append(b, 0xff)
	code := make([]byte, 2)
	binary.LittleEndian.PutUint16(code, errorCode)
	b = append(b, code...)
	b = append(b, '#')
	// sql_state must be exactly 5 ASCII chars
	if len(sqlState) != 5 {
		sqlState = "HY000"
	}
	b = append(b, []byte(sqlState)...)
	b = append(b, []byte(message)...)
	return b
}

// parsedHSR41 holds the intel we extract from the client's response.
// Every field here is a potential fingerprint or credential we want to
// record via the tracer. connect_attrs in particular is the single
// richest source — mysql-connector-python stamps `_client_name`,
// `_client_version`, `_pid`, `program_name`; `Go-MySQL-Driver` stamps
// `_runtime`, `_client_name`, `_client_version`.
type parsedHSR41 struct {
	CapabilityFlags uint32
	Charset         byte
	Username        string
	AuthResponseHex string // hex-encoded scramble response
	Database        string
	AuthPluginName  string
	ConnectAttrs    map[string]string
}

// readLenEncInt reads a MySQL length-encoded integer. Returns the value
// and the number of bytes consumed.
func readLenEncInt(b []byte, off int) (uint64, int, error) {
	if off >= len(b) {
		return 0, 0, errors.New("lenenc int: eof")
	}
	first := b[off]
	switch {
	case first < 0xfb:
		return uint64(first), 1, nil
	case first == 0xfc:
		if off+3 > len(b) {
			return 0, 0, errors.New("lenenc int: short 0xfc")
		}
		return uint64(binary.LittleEndian.Uint16(b[off+1 : off+3])), 3, nil
	case first == 0xfd:
		if off+4 > len(b) {
			return 0, 0, errors.New("lenenc int: short 0xfd")
		}
		return uint64(b[off+1]) | uint64(b[off+2])<<8 | uint64(b[off+3])<<16, 4, nil
	case first == 0xfe:
		if off+9 > len(b) {
			return 0, 0, errors.New("lenenc int: short 0xfe")
		}
		return binary.LittleEndian.Uint64(b[off+1 : off+9]), 9, nil
	default:
		return 0, 0, fmt.Errorf("lenenc int: bad marker 0x%x", first)
	}
}

func readLenEncString(b []byte, off int) (string, int, error) {
	n, consumed, err := readLenEncInt(b, off)
	if err != nil {
		return "", 0, err
	}
	end := off + consumed + int(n)
	if end > len(b) {
		return "", 0, errors.New("lenenc string: eof")
	}
	return string(b[off+consumed : end]), end - off, nil
}

func readNulString(b []byte, off int) (string, int, error) {
	for i := off; i < len(b); i++ {
		if b[i] == 0 {
			return string(b[off:i]), i - off + 1, nil
		}
	}
	return "", 0, errors.New("nul string: no terminator")
}

// parseHSR41 decodes a Handshake Response 41 payload. Any field-level
// error is non-fatal: we still emit an ERR packet and capture what we
// got. Real MySQL client responses are well-formed, so parse failures
// usually mean "this isn't actually a MySQL client" (e.g. a plain port
// scanner, a curl probe, a StartTLS hunter).
func parseHSR41(payload []byte) (parsedHSR41, error) {
	var out parsedHSR41
	out.ConnectAttrs = map[string]string{}

	if len(payload) < 32 {
		return out, errors.New("HSR41: payload too short")
	}
	out.CapabilityFlags = binary.LittleEndian.Uint32(payload[0:4])
	// max_packet_size at payload[4:8] — we don't need it
	out.Charset = payload[8]
	// 23 bytes filler at [9..32)
	off := 32

	// username (NUL-terminated)
	user, n, err := readNulString(payload, off)
	if err != nil {
		return out, err
	}
	out.Username = user
	off += n

	// auth_response — shape depends on capability flags
	if out.CapabilityFlags&capClientPluginAuthLenencClientData != 0 {
		// length-encoded
		arLen, consumed, err := readLenEncInt(payload, off)
		if err != nil {
			return out, err
		}
		off += consumed
		if off+int(arLen) > len(payload) {
			return out, errors.New("HSR41: auth_response length overruns")
		}
		out.AuthResponseHex = fmt.Sprintf("%x", payload[off:off+int(arLen)])
		off += int(arLen)
	} else if out.CapabilityFlags&capClientSecureConnection != 0 {
		// 1-byte length prefix
		if off >= len(payload) {
			return out, errors.New("HSR41: missing auth_response length")
		}
		arLen := int(payload[off])
		off++
		if off+arLen > len(payload) {
			return out, errors.New("HSR41: auth_response length overruns")
		}
		out.AuthResponseHex = fmt.Sprintf("%x", payload[off:off+arLen])
		off += arLen
	} else {
		// NUL-terminated
		ar, n, err := readNulString(payload, off)
		if err != nil {
			return out, err
		}
		out.AuthResponseHex = fmt.Sprintf("%x", []byte(ar))
		off += n
	}

	if out.CapabilityFlags&capClientConnectWithDB != 0 && off < len(payload) {
		db, n, err := readNulString(payload, off)
		if err == nil {
			out.Database = db
			off += n
		}
	}

	if out.CapabilityFlags&capClientPluginAuth != 0 && off < len(payload) {
		plug, n, err := readNulString(payload, off)
		if err == nil {
			out.AuthPluginName = plug
			off += n
		}
	}

	if out.CapabilityFlags&capClientConnectAttrs != 0 && off < len(payload) {
		// total attrs length (lenenc int), then repeated (lenenc key, lenenc value)
		total, consumed, err := readLenEncInt(payload, off)
		if err == nil {
			off += consumed
			end := off + int(total)
			if end > len(payload) {
				end = len(payload)
			}
			for off < end {
				k, kn, err := readLenEncString(payload, off)
				if err != nil {
					break
				}
				off += kn
				if off >= end {
					break
				}
				v, vn, err := readLenEncString(payload, off)
				if err != nil {
					break
				}
				out.ConnectAttrs[k] = v
				off += vn
			}
		}
	}

	return out, nil
}

// dispatchMysqlHandshake owns the entire connection lifecycle for a
// serviceProtocol:"mysql-handshake-v10" listener. Called once per accept.
func dispatchMysqlHandshake(conn net.Conn, servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, rng *rand.Rand) {
	defer conn.Close()

	deadline := time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second
	if deadline <= 0 {
		deadline = 30 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(deadline))

	sourceIP, sourcePort, _ := net.SplitHostPort(conn.RemoteAddr().String())
	sessionID := uuid.New().String()

	cfg := MysqlHandshakeConfig{
		ServerVersion:  servConf.ServerVersion,
		AuthPluginName: servConf.MysqlAuthPlugin,
	}
	if cfg.ServerVersion == "" {
		// Fall back to the yaml banner field if ServerVersion isn't set.
		cfg.ServerVersion = strings.TrimRight(servConf.Banner, "\r\n")
	}

	handshake, _ := buildHandshakeV10(cfg, rng)
	if err := writeMysqlPacket(conn, 0, handshake); err != nil {
		log.Debugf("mysql handshake: write greeting failed for %s: %v", sourceIP, err)
		tr.TraceEvent(tracer.Event{
			Msg:         "MySQL handshake (write failed)",
			Protocol:    tracer.TCP.String(),
			Status:      tracer.Stateless.String(),
			RemoteAddr:  conn.RemoteAddr().String(),
			SourceIp:    sourceIP,
			SourcePort:  sourcePort,
			ID:          sessionID,
			Description: servConf.Description,
		})
		return
	}

	// Read client Handshake Response 41
	seqID, payload, err := readMysqlPacket(conn)
	if err != nil {
		// Non-MySQL probe (TLS client hello, HTTP, banner grab): record
		// what we got and move on. No ERR packet — the client isn't
		// speaking MySQL.
		tr.TraceEvent(tracer.Event{
			Msg:         "MySQL handshake (client spoke no HSR41)",
			Protocol:    tracer.TCP.String(),
			Status:      tracer.Stateless.String(),
			RemoteAddr:  conn.RemoteAddr().String(),
			SourceIp:    sourceIP,
			SourcePort:  sourcePort,
			ID:          sessionID,
			Description: servConf.Description,
			Command:     "greeting-then-no-response",
		})
		return
	}

	parsed, parseErr := parseHSR41(payload)
	// sequence_id should be 1 on the client's response; the ERR we send
	// back is sequence_id + 1 = 2 (conventionally).
	errMsg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: YES)", parsed.Username, sourceIP)
	errPayload := buildErrPacket(1045, "28000", errMsg)
	_ = writeMysqlPacket(conn, seqID+1, errPayload)

	// Build intel string from connect_attrs (most valuable field) + username.
	var attrPairs []string
	for k, v := range parsed.ConnectAttrs {
		attrPairs = append(attrPairs, fmt.Sprintf("%s=%s", k, v))
	}
	commandStr := fmt.Sprintf("user=%s db=%s plugin=%s caps=0x%08x", parsed.Username, parsed.Database, parsed.AuthPluginName, parsed.CapabilityFlags)
	outputStr := fmt.Sprintf("ERR 1045 access denied; attrs=[%s] auth_response_sha=%s parse_err=%v",
		strings.Join(attrPairs, ","), parsed.AuthResponseHex, parseErr)

	tr.TraceEvent(tracer.Event{
		Msg:         "MySQL handshake attempt",
		Protocol:    tracer.TCP.String(),
		Status:      tracer.Interaction.String(),
		RemoteAddr:  conn.RemoteAddr().String(),
		SourceIp:    sourceIP,
		SourcePort:  sourcePort,
		ID:          sessionID,
		User:        parsed.Username,
		Description: servConf.Description,
		Handler:     "mysql-handshake-v10",
		Command:     commandStr,
		CommandOutput: outputStr,
	})
}
