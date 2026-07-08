package TCP

import (
	"net"
	"testing"
	"unicode/utf8"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
)

type bannerCaptureTracer struct{ events []tracer.Event }

func (c *bannerCaptureTracer) TraceEvent(e tracer.Event) { c.events = append(c.events, e) }

// A binary probe against a banner-only TCP lure (a service with no `commands`)
// must retain byte-exact bytes in CommandRaw (hex-escaped), not just a
// U+FFFD-mangled Command string. Mirrors the interactive path / upstream #320.
func TestHandleBannerOnly_CapturesRawBinaryBytes(t *testing.T) {
	raw := []byte{0x00, 0xff, 0x10, 'A', 0xc3, 0x28} // invalid UTF-8
	if utf8.Valid(raw) {
		t.Fatal("fixture must be invalid UTF-8")
	}

	server, client := net.Pipe()
	go func() {
		client.Write(raw)
		client.Close()
	}()

	tr := &bannerCaptureTracer{}
	handleBannerOnly(server, parser.BeelzebubServiceConfiguration{Protocol: "tcp", Address: ":9"}, tr)

	assert.Len(t, tr.events, 1)
	assert.Equal(t, hexEscapeNonPrintable(raw), tr.events[0].CommandRaw)
}

// A valid-UTF8 banner probe needs no raw capture — Command already holds it.
func TestHandleBannerOnly_ValidUTF8LeavesRawEmpty(t *testing.T) {
	server, client := net.Pipe()
	go func() {
		client.Write([]byte("HELP\r\n"))
		client.Close()
	}()

	tr := &bannerCaptureTracer{}
	handleBannerOnly(server, parser.BeelzebubServiceConfiguration{Protocol: "tcp", Address: ":9"}, tr)

	assert.Len(t, tr.events, 1)
	assert.Equal(t, "HELP\r\n", tr.events[0].Command)
	assert.Empty(t, tr.events[0].CommandRaw)
}
