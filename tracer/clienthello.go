package tracer

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// RawClientHello holds the JA3/JA4-relevant fields parsed directly from the WIRE
// bytes of a TLS ClientHello — not from Go's normalized tls.ClientHelloInfo,
// which does not even expose the wire legacy_version. This is what makes a
// canonical, cross-corpus-comparable JA3/JA4 possible.
type RawClientHello struct {
	LegacyVersion       uint16
	CipherSuites        []uint16
	Extensions          []uint16
	SupportedGroups     []uint16
	ECPointFormats      []uint8
	SupportedVersions   []uint16
	SignatureAlgorithms []uint16
	ALPNProtocols       []string
	ServerName          string
}

var errShortClientHello = errors.New("clienthello: truncated or malformed")

const (
	extServerName          = 0x0000
	extSupportedGroups     = 0x000a
	extECPointFormats      = 0x000b
	extSignatureAlgorithms = 0x000d
	extALPN                = 0x0010
	extSupportedVersions   = 0x002b
)

// reassembleHandshake concatenates the payloads of consecutive TLS handshake
// records (content_type 0x16) into a single handshake-layer byte stream, so a
// ClientHello fragmented across multiple TLS records (a legal, evasion-relevant
// wire shape) is parsed as one message. Stops at the first non-handshake record.
func reassembleHandshake(raw []byte) ([]byte, error) {
	var hs []byte
	for p := 0; p+5 <= len(raw); {
		if raw[p] != 0x16 { // content_type != handshake
			if len(hs) == 0 {
				return nil, errShortClientHello
			}
			break
		}
		recLen := int(binary.BigEndian.Uint16(raw[p+3 : p+5]))
		if p+5+recLen > len(raw) {
			return nil, errShortClientHello
		}
		hs = append(hs, raw[p+5:p+5+recLen]...)
		p += 5 + recLen
	}
	if len(hs) == 0 {
		return nil, errShortClientHello
	}
	return hs, nil
}

// ParseClientHello parses the JA3/JA4 inputs from the raw bytes of one or more TLS
// handshake records carrying a ClientHello. Every field length is bounds-checked
// against the buffer — the input is attacker-controlled.
func ParseClientHello(raw []byte) (*RawClientHello, error) {
	hs, err := reassembleHandshake(raw)
	if err != nil {
		return nil, err
	}

	// Handshake header: msg_type(1)=client_hello(0x01) length(3)
	if len(hs) < 4 || hs[0] != 0x01 {
		return nil, errShortClientHello
	}
	bodyLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs)-4 < bodyLen {
		return nil, errShortClientHello
	}
	body := hs[4 : 4+bodyLen]

	ch := &RawClientHello{}
	p := 0
	avail := func(n int) bool { return p+n <= len(body) }

	if !avail(2) {
		return nil, errShortClientHello
	}
	ch.LegacyVersion = binary.BigEndian.Uint16(body[p:])
	p += 2

	if !avail(32) {
		return nil, errShortClientHello
	}
	p += 32

	if !avail(1) {
		return nil, errShortClientHello
	}
	sidLen := int(body[p])
	p++
	if !avail(sidLen) {
		return nil, errShortClientHello
	}
	p += sidLen

	if !avail(2) {
		return nil, errShortClientHello
	}
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if csLen%2 != 0 || !avail(csLen) {
		return nil, errShortClientHello
	}
	for i := 0; i < csLen; i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(body[p+i:]))
	}
	p += csLen

	if !avail(1) {
		return nil, errShortClientHello
	}
	compLen := int(body[p])
	p++
	if !avail(compLen) {
		return nil, errShortClientHello
	}
	p += compLen

	if !avail(2) {
		return ch, nil // no extensions block — valid (rare, but legal)
	}
	extLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if !avail(extLen) {
		return nil, errShortClientHello
	}
	extEnd := p + extLen
	for p+4 <= extEnd {
		etype := binary.BigEndian.Uint16(body[p:])
		elen := int(binary.BigEndian.Uint16(body[p+2:]))
		p += 4
		if p+elen > extEnd {
			return nil, errShortClientHello
		}
		edata := body[p : p+elen]
		ch.Extensions = append(ch.Extensions, etype)

		switch etype {
		case extSupportedGroups:
			if len(edata) >= 2 {
				n := int(binary.BigEndian.Uint16(edata))
				for i := 2; i+2 <= 2+n && i+2 <= len(edata); i += 2 {
					ch.SupportedGroups = append(ch.SupportedGroups, binary.BigEndian.Uint16(edata[i:]))
				}
			}
		case extECPointFormats:
			if len(edata) >= 1 {
				n := int(edata[0])
				for i := 1; i <= n && i < len(edata); i++ {
					ch.ECPointFormats = append(ch.ECPointFormats, edata[i])
				}
			}
		case extSupportedVersions:
			// u8 list length + list of u16 versions
			if len(edata) >= 1 {
				n := int(edata[0])
				for i := 1; i+2 <= 1+n && i+2 <= len(edata); i += 2 {
					ch.SupportedVersions = append(ch.SupportedVersions, binary.BigEndian.Uint16(edata[i:]))
				}
			}
		case extSignatureAlgorithms:
			// u16 list length + list of u16 schemes
			if len(edata) >= 2 {
				n := int(binary.BigEndian.Uint16(edata))
				for i := 2; i+2 <= 2+n && i+2 <= len(edata); i += 2 {
					ch.SignatureAlgorithms = append(ch.SignatureAlgorithms, binary.BigEndian.Uint16(edata[i:]))
				}
			}
		case extALPN:
			// u16 protocol_name_list length + list of {u8 len + bytes}
			if len(edata) >= 2 {
				for i := 2; i < len(edata); {
					plen := int(edata[i])
					i++
					if i+plen > len(edata) {
						break
					}
					ch.ALPNProtocols = append(ch.ALPNProtocols, string(edata[i:i+plen]))
					i += plen
				}
			}
		case extServerName:
			// server_name_list: u16 len, entry: type(1)=host_name(0) + u16 len + host
			if len(edata) >= 5 && edata[2] == 0x00 {
				hlen := int(binary.BigEndian.Uint16(edata[3:]))
				if 5+hlen <= len(edata) {
					ch.ServerName = string(edata[5 : 5+hlen])
				}
			}
		}
		p += elen
	}

	return ch, nil
}

// JA3 returns the canonical pre-hash JA3 string read from the wire:
// SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats — decimal,
// '-'-joined within a field, ','-joined across fields, GREASE removed, using the
// WIRE legacy_version.
func (ch *RawClientHello) JA3() string {
	return strings.Join([]string{
		strconv.Itoa(int(ch.LegacyVersion)),
		ja3JoinUint16(filterGREASE16(ch.CipherSuites)),
		ja3JoinUint16(filterGREASE16(ch.Extensions)),
		ja3JoinUint16(filterGREASE16(ch.SupportedGroups)),
		ja3JoinUint8(ch.ECPointFormats),
	}, ",")
}

// JA4 returns the FoxIO JA4 fingerprint computed from the wire-parsed fields. It
// reuses the canonical ComputeJA4FromClientHello (the FoxIO-verified algorithm)
// so this method's correctness is purely a function of the parse.
func (ch *RawClientHello) JA4() string {
	schemes := make([]tls.SignatureScheme, len(ch.SignatureAlgorithms))
	for i, s := range ch.SignatureAlgorithms {
		schemes[i] = tls.SignatureScheme(s)
	}
	return ComputeJA4FromClientHello(&tls.ClientHelloInfo{
		CipherSuites:      ch.CipherSuites,
		Extensions:        ch.Extensions,
		SupportedVersions: ch.SupportedVersions,
		SignatureSchemes:  schemes,
		SupportedProtos:   ch.ALPNProtocols,
		ServerName:        ch.ServerName,
	})
}

// JA3Hash returns the MD5 of the canonical JA3 string — the value indexed by
// Shodan / GreyNoise / VirusTotal.
func (ch *RawClientHello) JA3Hash() string {
	sum := md5.Sum([]byte(ch.JA3()))
	return hex.EncodeToString(sum[:])
}
