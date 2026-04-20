package TCP

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildHandshakeV10_Shape(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	payload, scramble := buildHandshakeV10(MysqlHandshakeConfig{
		ServerVersion:  "8.0.32-0ubuntu0.22.04.2",
		AuthPluginName: "caching_sha2_password",
	}, rng)

	// Byte 0: protocol version
	assert.Equal(t, byte(0x0a), payload[0], "protocol version must be 0x0a")

	// server_version is NUL-terminated starting at byte 1
	nulIdx := bytes.IndexByte(payload[1:], 0)
	assert.Greater(t, nulIdx, 0, "server_version NUL terminator present")
	assert.Equal(t, "8.0.32-0ubuntu0.22.04.2", string(payload[1:1+nulIdx]))

	off := 1 + nulIdx + 1

	// thread_id: 4 bytes LE, must be non-zero
	threadID := binary.LittleEndian.Uint32(payload[off : off+4])
	assert.NotZero(t, threadID)
	off += 4

	// auth_plugin_data_part_1: 8 bytes = scramble[0:8]
	assert.Equal(t, scramble[:8], payload[off:off+8])
	off += 8

	// filler
	assert.Equal(t, byte(0x00), payload[off])
	off++

	// capability_flags low 2 bytes
	capLow := binary.LittleEndian.Uint16(payload[off : off+2])
	off += 2
	// PROTOCOL_41 bit (bit 9 of low 16) must be set
	assert.NotZero(t, capLow&uint16(capClientProtocol41), "CLIENT_PROTOCOL_41 must be advertised")

	// charset
	assert.Equal(t, mysqlCharsetUTF8MB40900, payload[off])
	off++

	// status_flags
	off += 2

	// capability_flags high 2 bytes — must include CLIENT_PLUGIN_AUTH + CLIENT_CONNECT_ATTRS
	capHigh := binary.LittleEndian.Uint16(payload[off : off+2])
	off += 2
	assert.NotZero(t, capHigh&uint16((capClientPluginAuth>>16)), "CLIENT_PLUGIN_AUTH must be advertised")
	assert.NotZero(t, capHigh&uint16((capClientConnectAttrs>>16)), "CLIENT_CONNECT_ATTRS must be advertised")

	// auth_plugin_data_length (should be 21 for our 20-byte scramble)
	assert.Equal(t, byte(mysqlAuthScrambleLen+1), payload[off])
	off++

	// 10 reserved zero bytes
	for i := 0; i < 10; i++ {
		assert.Equal(t, byte(0x00), payload[off+i], "reserved bytes must be 0x00")
	}
	off += 10

	// auth_plugin_data_part_2: scramble[8:] + NUL terminator
	assert.Equal(t, scramble[8:], payload[off:off+12])
	off += 12
	assert.Equal(t, byte(0x00), payload[off], "scramble part 2 NUL terminator")
	off++

	// auth_plugin_name
	assert.True(t, strings.HasPrefix(string(payload[off:]), "caching_sha2_password"))
	assert.Equal(t, byte(0x00), payload[len(payload)-1], "plugin name NUL terminator")
}

func TestBuildHandshakeV10_ScrambleRandomness(t *testing.T) {
	// Two successive handshake builds must produce different scrambles.
	// Identical scrambles across connects was a honeypot tell.
	rng := rand.New(rand.NewSource(1))
	_, s1 := buildHandshakeV10(MysqlHandshakeConfig{}, rng)
	_, s2 := buildHandshakeV10(MysqlHandshakeConfig{}, rng)
	assert.NotEqual(t, s1, s2, "successive scrambles must differ")
}

func TestBuildErrPacket_Shape(t *testing.T) {
	pkt := buildErrPacket(1045, "28000", "Access denied for user 'root'@'1.2.3.4' (using password: YES)")
	assert.Equal(t, byte(0xff), pkt[0], "ERR header byte")
	code := binary.LittleEndian.Uint16(pkt[1:3])
	assert.Equal(t, uint16(1045), code)
	assert.Equal(t, byte('#'), pkt[3], "SQL state marker")
	assert.Equal(t, "28000", string(pkt[4:9]))
	assert.Equal(t, "Access denied for user 'root'@'1.2.3.4' (using password: YES)", string(pkt[9:]))
}

// buildHSR41 constructs a synthetic Handshake Response 41 for parser tests.
// Mirrors what a real mysql-connector-python would send.
func buildHSR41(t *testing.T, user, database, plugin string, attrs map[string]string, useLenenc bool) []byte {
	t.Helper()
	var b []byte

	caps := capClientProtocol41 | capClientSecureConnection | capClientPluginAuth | capClientConnectAttrs
	if database != "" {
		caps |= capClientConnectWithDB
	}
	if useLenenc {
		caps |= capClientPluginAuthLenencClientData
	}

	capBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(capBytes, caps)
	b = append(b, capBytes...)
	// max_packet_size
	b = append(b, []byte{0x00, 0x00, 0x00, 0x01}...)
	// charset
	b = append(b, mysqlCharsetUTF8MB40900)
	// 23 bytes filler
	b = append(b, make([]byte, 23)...)
	// username + NUL
	b = append(b, []byte(user)...)
	b = append(b, 0x00)

	// auth_response (fake 20-byte SHA1 scramble)
	authResp := make([]byte, 20)
	for i := range authResp {
		authResp[i] = byte(i * 7)
	}
	if useLenenc {
		b = append(b, byte(len(authResp))) // lenenc int < 0xfb
		b = append(b, authResp...)
	} else {
		b = append(b, byte(len(authResp)))
		b = append(b, authResp...)
	}

	if database != "" {
		b = append(b, []byte(database)...)
		b = append(b, 0x00)
	}
	b = append(b, []byte(plugin)...)
	b = append(b, 0x00)

	// connect_attrs: [lenenc total][(lenenc k)(lenenc v)]*
	var attrBody []byte
	// ordered iteration for reproducibility
	keys := []string{"_client_name", "_client_version", "_pid", "program_name"}
	for _, k := range keys {
		v, ok := attrs[k]
		if !ok {
			continue
		}
		attrBody = append(attrBody, byte(len(k)))
		attrBody = append(attrBody, []byte(k)...)
		attrBody = append(attrBody, byte(len(v)))
		attrBody = append(attrBody, []byte(v)...)
	}
	b = append(b, byte(len(attrBody))) // lenenc-int total
	b = append(b, attrBody...)

	return b
}

func TestParseHSR41_LenencAuth(t *testing.T) {
	payload := buildHSR41(t, "root", "mysql", "caching_sha2_password", map[string]string{
		"_client_name":    "mysql-connector-python",
		"_client_version": "8.2.0",
		"_pid":            "48212",
		"program_name":    "recon.py",
	}, true)
	parsed, err := parseHSR41(payload)
	assert.NoError(t, err)
	assert.Equal(t, "root", parsed.Username)
	assert.Equal(t, "mysql", parsed.Database)
	assert.Equal(t, "caching_sha2_password", parsed.AuthPluginName)
	assert.Equal(t, "mysql-connector-python", parsed.ConnectAttrs["_client_name"])
	assert.Equal(t, "8.2.0", parsed.ConnectAttrs["_client_version"])
	assert.Equal(t, "48212", parsed.ConnectAttrs["_pid"])
	assert.Equal(t, "recon.py", parsed.ConnectAttrs["program_name"])
	assert.NotEmpty(t, parsed.AuthResponseHex)
}

func TestParseHSR41_SecureConnection(t *testing.T) {
	payload := buildHSR41(t, "admin", "", "mysql_native_password", map[string]string{
		"_client_name": "Go-MySQL-Driver",
	}, false)
	parsed, err := parseHSR41(payload)
	assert.NoError(t, err)
	assert.Equal(t, "admin", parsed.Username)
	assert.Empty(t, parsed.Database)
	assert.Equal(t, "mysql_native_password", parsed.AuthPluginName)
	assert.Equal(t, "Go-MySQL-Driver", parsed.ConnectAttrs["_client_name"])
}

func TestParseHSR41_MalformedTooShort(t *testing.T) {
	_, err := parseHSR41([]byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestReadLenEncInt(t *testing.T) {
	cases := []struct {
		name   string
		bytes  []byte
		want   uint64
		consumed int
	}{
		{"1-byte", []byte{0x5}, 5, 1},
		{"1-byte-max", []byte{0xfa}, 250, 1},
		{"2-byte", []byte{0xfc, 0x10, 0x01}, 0x0110, 3},
		{"3-byte", []byte{0xfd, 0x01, 0x02, 0x03}, 0x030201, 4},
		{"8-byte", []byte{0xfe, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}, 0x0102030405060708, 9},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, consumed, err := readLenEncInt(c.bytes, 0)
			assert.NoError(t, err)
			assert.Equal(t, c.want, got)
			assert.Equal(t, c.consumed, consumed)
		})
	}
}
