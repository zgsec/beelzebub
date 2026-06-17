package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/net/http2/hpack"
)

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

var errNoH2Headers = errors.New("http2: no HEADERS frame in capture")

// HTTP2Fingerprint holds the inputs to the Akamai HTTP/2 fingerprint, parsed from
// a client's opening h2 frames (connection preface + SETTINGS / WINDOW_UPDATE /
// PRIORITY / HEADERS) captured on the DECRYPTED stream. Go's net/http2 server
// normalizes all of this away before a handler runs, so — like the TLS
// ClientHello — it must be read from the raw frame bytes.
type HTTP2Fingerprint struct {
	Settings      [][2]uint32 // (id, value) in wire order
	WindowUpdate  uint32      // connection-level (stream 0) increment
	Priorities    []string    // "streamID:exclusive:dep:weight"
	PseudoHeaders []string    // order of :method/:authority/:scheme/:path as m/a/s/p
}

// ParseHTTP2Fingerprint walks the opening HTTP/2 frames after the connection
// preface and extracts the Akamai fingerprint inputs, stopping at the first
// HEADERS frame. Every length is bounds-checked — the input is attacker-controlled.
func ParseHTTP2Fingerprint(raw []byte) (*HTTP2Fingerprint, error) {
	if !bytes.HasPrefix(raw, http2Preface) {
		return nil, errors.New("http2: missing connection preface")
	}
	p := len(http2Preface)
	fp := &HTTP2Fingerprint{}
	for p+9 <= len(raw) {
		length := int(raw[p])<<16 | int(raw[p+1])<<8 | int(raw[p+2])
		ftype := raw[p+3]
		flags := raw[p+4]
		streamID := binary.BigEndian.Uint32(raw[p+5:p+9]) & 0x7fffffff
		ps := p + 9
		if ps+length > len(raw) {
			break
		}
		payload := raw[ps : ps+length]

		switch ftype {
		case 0x4: // SETTINGS
			if flags&0x1 == 0 { // not ACK
				for i := 0; i+6 <= len(payload); i += 6 {
					id := uint32(binary.BigEndian.Uint16(payload[i:]))
					val := binary.BigEndian.Uint32(payload[i+2:])
					fp.Settings = append(fp.Settings, [2]uint32{id, val})
				}
			}
		case 0x8: // WINDOW_UPDATE — connection-level only
			if streamID == 0 && len(payload) >= 4 {
				fp.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}
		case 0x2: // PRIORITY
			if len(payload) >= 5 {
				fp.Priorities = append(fp.Priorities, formatH2Priority(streamID, payload[:5]))
			}
		case 0x1: // HEADERS
			block := payload
			if flags&0x8 != 0 && len(block) > 0 { // PADDED
				pad := int(block[0])
				block = block[1:]
				if pad <= len(block) {
					block = block[:len(block)-pad]
				}
			}
			if flags&0x20 != 0 && len(block) >= 5 { // PRIORITY in HEADERS
				fp.Priorities = append(fp.Priorities, formatH2Priority(streamID, block[:5]))
				block = block[5:]
			}
			fp.PseudoHeaders = pseudoHeaderOrder(block)
			return fp, nil
		}
		p = ps + length
	}
	return nil, errNoH2Headers
}

func formatH2Priority(streamID uint32, b []byte) string {
	dep := binary.BigEndian.Uint32(b)
	excl := dep >> 31
	dep &= 0x7fffffff
	weight := uint32(b[4]) + 1 // RFC 7540: transmitted weight is value-1
	return fmt.Sprintf("%d:%d:%d:%d", streamID, excl, dep, weight)
}

func pseudoHeaderOrder(block []byte) []string {
	var order []string
	dec := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
		switch hf.Name {
		case ":method":
			order = append(order, "m")
		case ":authority":
			order = append(order, "a")
		case ":scheme":
			order = append(order, "s")
		case ":path":
			order = append(order, "p")
		}
	})
	// Partial decode is acceptable: the pseudo-headers lead the block, so even if a
	// later field references the dynamic table we already captured their order.
	_, _ = dec.Write(block)
	return order
}

// Akamai returns the canonical Akamai HTTP/2 fingerprint:
// SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER.
func (fp *HTTP2Fingerprint) Akamai() string {
	set := make([]string, len(fp.Settings))
	for i, kv := range fp.Settings {
		set[i] = strconv.FormatUint(uint64(kv[0]), 10) + ":" + strconv.FormatUint(uint64(kv[1]), 10)
	}
	prio := "0"
	if len(fp.Priorities) > 0 {
		prio = strings.Join(fp.Priorities, ",")
	}
	return strings.Join([]string{
		strings.Join(set, ";"),
		strconv.FormatUint(uint64(fp.WindowUpdate), 10),
		prio,
		strings.Join(fp.PseudoHeaders, ","),
	}, "|")
}
