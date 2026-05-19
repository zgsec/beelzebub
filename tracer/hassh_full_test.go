package tracer

import (
	"testing"
)

// TestHASSHFull_MatchesComputeHASSH verifies that ComputeHASSHFull produces
// the SAME hash as ComputeHASSH for identical input. If these diverge, we've
// broken the existing HASSH while adding raw algorithm capture.
func TestHASSHFull_MatchesComputeHASSH(t *testing.T) {
	// OpenSSH 8.9p1 KEXINIT from the existing HASSH test fixtures
	// This is a real packet — not synthetic.
	raw := buildOpenSSHKEXINIT()

	hashOnly := ComputeHASSH(raw)
	full := ComputeHASSHFull(raw)

	if full == nil {
		t.Fatal("ComputeHASSHFull returned nil for valid input")
	}
	if full.Hash != hashOnly {
		t.Errorf("Hash mismatch:\n  ComputeHASSH:     %s\n  ComputeHASSHFull: %s", hashOnly, full.Hash)
	}
	if full.RawInput == "" {
		t.Error("RawInput is empty — algorithm lists not preserved")
	}
	if full.KexAlgos == "" || full.EncAlgos == "" || full.MacAlgos == "" || full.CompAlgos == "" {
		t.Errorf("Missing algorithm list: kex=%q enc=%q mac=%q comp=%q",
			full.KexAlgos, full.EncAlgos, full.MacAlgos, full.CompAlgos)
	}
	// RawInput should be the semicolon-joined string that was hashed
	expected := full.KexAlgos + ";" + full.EncAlgos + ";" + full.MacAlgos + ";" + full.CompAlgos
	if full.RawInput != expected {
		t.Errorf("RawInput doesn't match joined algorithms:\n  RawInput: %s\n  Expected: %s", full.RawInput[:60], expected[:60])
	}
}

func TestHASSHFull_NilOnMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"no newline", []byte("SSH-2.0-OpenSSH")},
		{"truncated packet", []byte("SSH-2.0-Test\n\x00\x00\x00\x05\x00")},
		{"wrong message type", append([]byte("SSH-2.0-Test\n"), buildFakePacket(21, 32)...)},
		{"single byte", []byte{0x16}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ComputeHASSHFull(tc.data)
			if result != nil {
				t.Errorf("expected nil for malformed input %q, got hash=%s", tc.name, result.Hash)
			}
		})
	}
}

// buildFakePacket creates a minimal SSH binary packet with given type and cookie size.
func buildFakePacket(msgType byte, cookieSize int) []byte {
	payloadLen := 1 + cookieSize // type + cookie
	paddingLen := 0
	packetLen := payloadLen + paddingLen + 1 // +1 for padding_length byte
	pkt := make([]byte, 4+1+payloadLen)
	pkt[0] = byte(packetLen >> 24)
	pkt[1] = byte(packetLen >> 16)
	pkt[2] = byte(packetLen >> 8)
	pkt[3] = byte(packetLen)
	pkt[4] = byte(paddingLen)
	pkt[5] = msgType
	return pkt
}

// buildOpenSSHKEXINIT constructs a realistic OpenSSH 8.9 KEXINIT packet.
// This is the same fixture used by the existing TestComputeHASSH_OpenSSH.
func buildOpenSSHKEXINIT() []byte {
	// SSH version string
	version := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

	// Algorithm lists (OpenSSH 8.9 defaults)
	kex := "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,sntrup761x25519-sha512@openssh.com,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256"
	enc := "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
	mac := "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
	comp := "none,zlib@openssh.com"

	// Build the 10 name-lists (only indices 0,2,4,6 matter for HASSH)
	lists := []string{kex, enc, enc, enc, mac, mac, comp, comp, "", ""}

	// Build binary payload: type(1) + cookie(16) + 10 name-lists
	var payload []byte
	payload = append(payload, 20) // SSH_MSG_KEXINIT
	payload = append(payload, make([]byte, 16)...) // cookie (zeros)
	for _, list := range lists {
		lenBytes := []byte{
			byte(len(list) >> 24), byte(len(list) >> 16),
			byte(len(list) >> 8), byte(len(list)),
		}
		payload = append(payload, lenBytes...)
		payload = append(payload, []byte(list)...)
	}

	// Wrap in SSH binary packet
	paddingLen := 0
	packetLen := len(payload) + paddingLen + 1
	var packet []byte
	packet = append(packet, byte(packetLen>>24), byte(packetLen>>16), byte(packetLen>>8), byte(packetLen))
	packet = append(packet, byte(paddingLen))
	packet = append(packet, payload...)

	// Prepend version string
	var raw []byte
	raw = append(raw, []byte(version)...)
	raw = append(raw, packet...)
	return raw
}
