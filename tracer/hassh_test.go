package tracer

import (
	"encoding/binary"
	"testing"
)

// buildKEXINIT constructs a raw SSH connection start (version + KEXINIT packet)
// for testing. This matches the RFC 4253 wire format.
func buildKEXINIT(kex, ciphersC2S, macsC2S, compC2S string) []byte {
	// Version string
	version := []byte("SSH-2.0-OpenSSH_9.6\r\n")

	// Build KEXINIT payload
	payload := []byte{20} // SSH_MSG_KEXINIT
	payload = append(payload, make([]byte, 16)...) // cookie (zeros for testing)

	// 10 name-lists: kex, hostkey, cipher_c2s, cipher_s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c, lang_c2s, lang_s2c
	nameLists := []string{
		kex,                                     // 0: kex_algorithms
		"ssh-ed25519,ssh-rsa",                   // 1: server_host_key_algorithms
		ciphersC2S,                              // 2: encryption_algorithms_client_to_server
		"aes128-ctr,aes256-ctr",                 // 3: encryption_algorithms_server_to_client
		macsC2S,                                 // 4: mac_algorithms_client_to_server
		"hmac-sha2-256,hmac-sha1",               // 5: mac_algorithms_server_to_client
		compC2S,                                 // 6: compression_algorithms_client_to_server
		"none,zlib@openssh.com",                 // 7: compression_algorithms_server_to_client
		"",                                      // 8: languages_client_to_server
		"",                                      // 9: languages_server_to_client
	}
	for _, nl := range nameLists {
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(nl)))
		payload = append(payload, lenBuf...)
		payload = append(payload, []byte(nl)...)
	}
	// first_kex_packet_follows (false) + reserved (0)
	payload = append(payload, 0, 0, 0, 0, 0)

	// Build binary packet: uint32(packet_length) + byte(padding_length) + payload + padding
	paddingLen := byte(8 - ((1 + len(payload)) % 8))
	if paddingLen < 4 {
		paddingLen += 8
	}
	pktLen := uint32(1 + len(payload) + int(paddingLen))
	pktHeader := make([]byte, 5)
	binary.BigEndian.PutUint32(pktHeader, pktLen)
	pktHeader[4] = paddingLen

	var result []byte
	result = append(result, version...)
	result = append(result, pktHeader...)
	result = append(result, payload...)
	result = append(result, make([]byte, paddingLen)...) // padding
	return result
}

func TestComputeHASSH_OpenSSH(t *testing.T) {
	raw := buildKEXINIT(
		"curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
		"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
		"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
		"none,zlib@openssh.com",
	)
	hassh := ComputeHASSH(raw)
	if hassh == "" {
		t.Fatal("expected non-empty HASSH")
	}
	if len(hassh) != 32 {
		t.Fatalf("expected 32-char MD5 hex, got %d chars: %s", len(hassh), hassh)
	}
	t.Logf("HASSH (OpenSSH-like): %s", hassh)
}

func TestComputeHASSH_Libssh(t *testing.T) {
	raw := buildKEXINIT(
		"curve25519-sha256,ecdh-sha2-nistp256",
		"aes128-ctr,aes256-ctr",
		"hmac-sha2-256,hmac-sha1",
		"none",
	)
	hassh := ComputeHASSH(raw)
	if hassh == "" {
		t.Fatal("expected non-empty HASSH")
	}
	t.Logf("HASSH (libssh-like): %s", hassh)
}

func TestComputeHASSH_DifferentClients(t *testing.T) {
	openssh := buildKEXINIT(
		"curve25519-sha256,diffie-hellman-group16-sha512",
		"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
		"umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
		"none,zlib@openssh.com",
	)
	libssh := buildKEXINIT(
		"curve25519-sha256,ecdh-sha2-nistp256",
		"aes128-ctr,aes256-ctr",
		"hmac-sha2-256,hmac-sha1",
		"none",
	)

	h1 := ComputeHASSH(openssh)
	h2 := ComputeHASSH(libssh)

	if h1 == h2 {
		t.Error("different clients produced same HASSH")
	}
	t.Logf("OpenSSH: %s", h1)
	t.Logf("libssh:  %s", h2)
}

func TestComputeHASSH_Deterministic(t *testing.T) {
	raw := buildKEXINIT(
		"curve25519-sha256",
		"aes256-ctr",
		"hmac-sha2-256",
		"none",
	)
	first := ComputeHASSH(raw)
	for i := 0; i < 100; i++ {
		if got := ComputeHASSH(raw); got != first {
			t.Fatalf("non-deterministic: run %d got %s, expected %s", i, got, first)
		}
	}
}

func TestComputeHASSH_EmptyInput(t *testing.T) {
	if h := ComputeHASSH(nil); h != "" {
		t.Errorf("expected empty for nil, got %s", h)
	}
	if h := ComputeHASSH([]byte{}); h != "" {
		t.Errorf("expected empty for empty bytes, got %s", h)
	}
	if h := ComputeHASSH([]byte("SSH-2.0-test\r\n")); h != "" {
		t.Errorf("expected empty for version-only, got %s", h)
	}
}

func TestComputeHASSH_MalformedPacket(t *testing.T) {
	// Version string + garbage
	raw := []byte("SSH-2.0-test\r\n\x00\x00\x00\x05\x01\x15garbage")
	if h := ComputeHASSH(raw); h != "" {
		t.Errorf("expected empty for malformed packet, got %s", h)
	}
}
