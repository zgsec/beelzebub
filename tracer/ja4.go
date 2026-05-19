package tracer

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ComputeJA4FromClientHello computes a JA4 fingerprint from Go's parsed
// tls.ClientHelloInfo. This is called from GetConfigForClient during the
// TLS handshake — the stdlib has already parsed the ClientHello for us.
//
// This approach is superior to raw byte parsing because:
// 1. Go's TLS parser is battle-tested against the entire internet
// 2. No raw byte capture or TeeConn needed
// 3. ClientHelloInfo.Extensions includes the full extension type list
// 4. Zero risk of parsing bugs (we read pre-parsed struct fields)
//
// Spec: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
// Validated against FoxIO's Python reference implementation on Chromium pcap.
func ComputeJA4FromClientHello(hello *tls.ClientHelloInfo) string {
	if hello == nil {
		return ""
	}

	// Filter GREASE from ciphers and extensions
	ciphers := filterGREASE16(hello.CipherSuites)
	extensions := filterGREASE16(hello.Extensions)

	// TLS version: check SupportedVersions first (TLS 1.3), fall back to record version
	version := ja4VersionString(hello.SupportedVersions)

	// SNI flag
	sni := "i"
	if hello.ServerName != "" {
		sni = "d"
	}

	// ALPN: first and LAST character of first protocol value
	alpn := "00"
	if len(hello.SupportedProtos) > 0 {
		proto := hello.SupportedProtos[0]
		if len(proto) >= 2 {
			alpn = string(proto[0]) + string(proto[len(proto)-1])
		} else if len(proto) == 1 {
			alpn = string(proto[0]) + "0"
		}
	}

	// Cipher hash: sorted cipher IDs (no GREASE), comma-separated hex, SHA256[:12]
	cipherHash := hashSortedUint16JA4(ciphers)

	// Extension hash per FoxIO spec:
	// 1. Remove SNI (0x0000) and ALPN (0x0010) from the hash (still counted above)
	// 2. Sort remaining extension types
	// 3. Append signature algorithms in WIRE ORDER (not sorted)
	extForHash := make([]uint16, 0, len(extensions))
	for _, e := range extensions {
		if e != 0x0000 && e != 0x0010 {
			extForHash = append(extForHash, e)
		}
	}
	extStr := sortedUint16HexJA4(extForHash)

	// Signature algorithms: GREASE-filtered, WIRE ORDER (not sorted)
	if len(hello.SignatureSchemes) > 0 {
		sigParts := make([]string, 0, len(hello.SignatureSchemes))
		for _, s := range hello.SignatureSchemes {
			if !isGREASE16(uint16(s)) {
				sigParts = append(sigParts, fmt.Sprintf("%04x", uint16(s)))
			}
		}
		if len(sigParts) > 0 {
			extStr += "_" + strings.Join(sigParts, ",")
		}
	}

	extHashBytes := sha256.Sum256([]byte(extStr))
	extHash := hex.EncodeToString(extHashBytes[:])[:12]

	// Build JA4 string
	numCiphers := len(ciphers)
	if numCiphers > 99 {
		numCiphers = 99
	}
	numExts := len(extensions)
	if numExts > 99 {
		numExts = 99
	}

	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s",
		version, sni, numCiphers, numExts, alpn,
		cipherHash, extHash)
}

// --- Internal helpers (JA4-specific, avoid name collision with ja4h.go) ---

func isGREASE16(val uint16) bool {
	return (val & 0x0F0F) == 0x0A0A
}

func filterGREASE16(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !isGREASE16(v) {
			out = append(out, v)
		}
	}
	return out
}

func ja4VersionString(supportedVersions []uint16) string {
	for _, v := range supportedVersions {
		if !isGREASE16(v) {
			switch v {
			case 0x0304:
				return "13"
			case 0x0303:
				return "12"
			case 0x0302:
				return "11"
			case 0x0301:
				return "10"
			}
		}
	}
	return "00"
}

func hashSortedUint16JA4(vals []uint16) string {
	sorted := make([]uint16, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	str := sortedUint16HexJA4(sorted)
	h := sha256.Sum256([]byte(str))
	return hex.EncodeToString(h[:])[:12]
}

func sortedUint16HexJA4(vals []uint16) string {
	sorted := make([]uint16, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	parts := make([]string, len(sorted))
	for i, v := range sorted {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}
