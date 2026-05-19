package tracer

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
)

// ComputeHASSH computes a HASSH fingerprint from raw SSH connection bytes.
//
// HASSH = MD5(kex_algorithms + ";" + encryption_c2s + ";" + mac_c2s + ";" + compression_c2s)
//
// Input: raw bytes captured from the start of the TCP connection, containing
// the client's version string followed by the SSH_MSG_KEXINIT binary packet.
//
// Returns "" on any parse error. Never panics.
//
// Spec: https://github.com/salesforce/hassh
// Wire format: RFC 4253 §7.1
func ComputeHASSH(raw []byte) string {
	// Skip version string (ends at \n)
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 || nl+6 > len(raw) {
		return ""
	}
	rest := raw[nl+1:]

	// Read binary packet header: uint32(packet_length) + byte(padding_length)
	if len(rest) < 5 {
		return ""
	}
	pktLen := binary.BigEndian.Uint32(rest[:4])
	padLen := int(rest[4])

	// Sanity checks
	if pktLen < 2 || pktLen > 35000 {
		return ""
	}
	payloadLen := int(pktLen) - padLen - 1
	if payloadLen < 18 { // type(1) + cookie(16) + at least one name-list header(4)
		return ""
	}
	if len(rest) < 5+payloadLen {
		return "" // incomplete packet
	}
	payload := rest[5 : 5+payloadLen]

	// Verify SSH_MSG_KEXINIT (type 20)
	if payload[0] != 20 {
		return ""
	}

	// Skip message type (1) + cookie (16)
	pos := 17

	// Read 10 name-lists:
	//   0: KexAlgos              → HASSH
	//   1: ServerHostKeyAlgos
	//   2: CiphersClientServer   → HASSH
	//   3: CiphersServerClient
	//   4: MACsClientServer      → HASSH
	//   5: MACsServerClient
	//   6: CompressionClientServer → HASSH
	//   7-9: remaining
	lists := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		if pos+4 > len(payload) {
			return ""
		}
		listLen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 4
		if pos+listLen > len(payload) {
			return ""
		}
		lists = append(lists, string(payload[pos:pos+listLen]))
		pos += listLen
	}

	// HASSH = MD5(kex ; enc_c2s ; mac_c2s ; comp_c2s)
	input := lists[0] + ";" + lists[2] + ";" + lists[4] + ";" + lists[6]
	hash := md5.Sum([]byte(input))
	return fmt.Sprintf("%x", hash)
}

// HASSHResult contains both the HASSH hash and the raw algorithm lists.
// The hash is the standard HASSH fingerprint. The raw lists enable:
// - Clustering by SSH library version (not just by algorithm set)
// - Distinguishing clients that share the same algorithm set but differ in preference order
// - Detecting algorithm negotiation anomalies (unusual combinations, deprecated algorithms)
type HASSHResult struct {
	Hash        string // MD5 hash (the standard HASSH fingerprint)
	RawInput    string // semicolon-joined algorithm lists (the HASSH input string before hashing)
	KexAlgos    string // kex_algorithms (index 0)
	EncAlgos    string // encryption_algorithms_client_to_server (index 2)
	MacAlgos    string // mac_algorithms_client_to_server (index 4)
	CompAlgos   string // compression_algorithms_client_to_server (index 6)
}

// ComputeHASSHFull returns both the hash and raw algorithm lists.
// Returns nil on any parse error. Never panics.
func ComputeHASSHFull(raw []byte) *HASSHResult {
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 || nl+6 > len(raw) {
		return nil
	}
	rest := raw[nl+1:]

	if len(rest) < 5 {
		return nil
	}
	packetLen := int(binary.BigEndian.Uint32(rest[:4]))
	paddingLen := int(rest[4])
	if packetLen < 2 || packetLen > 35000 {
		return nil
	}
	payload := rest[5:]
	payloadLen := packetLen - paddingLen - 1
	if payloadLen < 18 || len(payload) < payloadLen {
		return nil
	}
	payload = payload[:payloadLen]
	if payload[0] != 20 {
		return nil
	}
	pos := 17

	lists := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		if pos+4 > len(payload) {
			return nil
		}
		listLen := int(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 4
		if pos+listLen > len(payload) {
			return nil
		}
		lists = append(lists, string(payload[pos:pos+listLen]))
		pos += listLen
	}

	input := lists[0] + ";" + lists[2] + ";" + lists[4] + ";" + lists[6]
	hash := md5.Sum([]byte(input))
	return &HASSHResult{
		Hash:     fmt.Sprintf("%x", hash),
		RawInput: input,
		KexAlgos: lists[0],
		EncAlgos: lists[2],
		MacAlgos: lists[4],
		CompAlgos: lists[6],
	}
}
