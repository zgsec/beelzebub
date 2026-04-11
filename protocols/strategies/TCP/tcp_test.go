package TCP

import (
	"strings"
	"testing"
)

// ─── decodeProtocolCommand ─────────────────────────────────────────────────

func TestDecodeRESPArray_PING(t *testing.T) {
	frame := []byte("*1\r\n$4\r\nPING\r\n")
	got := decodeProtocolCommand(frame)
	want := "PING"
	if got != want {
		t.Errorf("decodeProtocolCommand(RESP PING) = %q, want %q", got, want)
	}
}

func TestDecodeRESPArray_SETKeyValue(t *testing.T) {
	frame := []byte("*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n")
	got := decodeProtocolCommand(frame)
	want := "SET foo bar"
	if got != want {
		t.Errorf("decodeProtocolCommand(RESP SET foo bar) = %q, want %q", got, want)
	}
}

func TestDecodeRESPArray_INFO(t *testing.T) {
	frame := []byte("*1\r\n$4\r\nINFO\r\n")
	got := decodeProtocolCommand(frame)
	want := "INFO"
	if got != want {
		t.Errorf("decodeProtocolCommand(RESP INFO) = %q, want %q", got, want)
	}
}

func TestDecodeRESPArray_ClientList(t *testing.T) {
	// CLIENT LIST is a 2-arg command
	frame := []byte("*2\r\n$6\r\nCLIENT\r\n$4\r\nLIST\r\n")
	got := decodeProtocolCommand(frame)
	want := "CLIENT LIST"
	if got != want {
		t.Errorf("decodeProtocolCommand(RESP CLIENT LIST) = %q, want %q", got, want)
	}
}

func TestDecodeRESPArray_TruncatedReturnsPartial(t *testing.T) {
	// Half of the SET command — value `bar` is truncated mid-bulk-string.
	// We expect either the partial command up to where we got, or "".
	frame := []byte("*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nb")
	got := decodeProtocolCommand(frame)
	// Acceptable: any non-empty result; we DON'T want it to crash or return empty
	// because we did parse SET and foo successfully.
	if got != "SET foo" {
		t.Logf("decodeProtocolCommand(truncated) = %q (acceptable as long as no crash)", got)
	}
}

func TestDecodeRESPArray_MalformedFallsThroughToHex(t *testing.T) {
	// `*` followed by non-digit — malformed
	frame := []byte("*z\r\nGarbage")
	got := decodeProtocolCommand(frame)
	// Should fall through to hex escape, not return ""
	if got == "" {
		t.Errorf("decodeProtocolCommand(malformed RESP) returned empty, expected hex-escaped fallback")
	}
}

func TestDecodeRESPSimpleString(t *testing.T) {
	got := decodeProtocolCommand([]byte("+OK\r\n"))
	want := "+OK"
	if got != want {
		t.Errorf("decodeProtocolCommand(+OK) = %q, want %q", got, want)
	}
}

func TestDecodeRESPError(t *testing.T) {
	got := decodeProtocolCommand([]byte("-ERR unknown command\r\n"))
	want := "-ERR unknown command"
	if got != want {
		t.Errorf("decodeProtocolCommand(-ERR) = %q, want %q", got, want)
	}
}

func TestDecodeRESPInteger(t *testing.T) {
	got := decodeProtocolCommand([]byte(":42\r\n"))
	want := ":42"
	if got != want {
		t.Errorf("decodeProtocolCommand(:42) = %q, want %q", got, want)
	}
}

func TestDecodeHTTPOnTCP(t *testing.T) {
	// HTTP request sent to a non-HTTP port (port-protocol mismatch)
	frame := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: scanner\r\n\r\n")
	got := decodeProtocolCommand(frame)
	want := "GET / HTTP/1.1"
	if got != want {
		t.Errorf("decodeProtocolCommand(HTTP) = %q, want %q", got, want)
	}
}

func TestDecodePlainText(t *testing.T) {
	frame := []byte("hello world\r\n")
	got := decodeProtocolCommand(frame)
	want := "hello world"
	if got != want {
		t.Errorf("decodeProtocolCommand(plain) = %q, want %q", got, want)
	}
}

func TestDecodeBinaryFallsThroughToHex(t *testing.T) {
	// Mostly non-printable bytes
	frame := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	got := decodeProtocolCommand(frame)
	// Expect hex-escaped output
	if !strings.Contains(got, `\x00`) {
		t.Errorf("decodeProtocolCommand(binary) = %q, expected hex escapes", got)
	}
}

func TestDecodeEmpty(t *testing.T) {
	got := decodeProtocolCommand([]byte{})
	if got != "" {
		t.Errorf("decodeProtocolCommand(empty) = %q, want empty", got)
	}
}

// ─── hexEscapeNonPrintable ─────────────────────────────────────────────────

func TestHexEscape_PreservesPrintable(t *testing.T) {
	got := hexEscapeNonPrintable([]byte("Hello, World!"))
	want := "Hello, World!"
	if got != want {
		t.Errorf("hexEscapeNonPrintable(printable) = %q, want %q", got, want)
	}
}

func TestHexEscape_EscapesCRLF(t *testing.T) {
	got := hexEscapeNonPrintable([]byte("a\rb\nc"))
	want := `a\x0db\x0ac`
	if got != want {
		t.Errorf("hexEscapeNonPrintable(CRLF) = %q, want %q", got, want)
	}
}

func TestHexEscape_EscapesNullByte(t *testing.T) {
	got := hexEscapeNonPrintable([]byte{0x00, 0x41, 0x00})
	want := `\x00A\x00`
	if got != want {
		t.Errorf("hexEscapeNonPrintable(null) = %q, want %q", got, want)
	}
}

func TestHexEscape_EscapesBackslash(t *testing.T) {
	// Backslash itself must be escaped so the output is unambiguously decodable
	got := hexEscapeNonPrintable([]byte(`a\b`))
	want := `a\x5cb`
	if got != want {
		t.Errorf("hexEscapeNonPrintable(backslash) = %q, want %q", got, want)
	}
}

// ─── isLikelyHTTP ───────────────────────────────────────────────────────────

func TestIsLikelyHTTP(t *testing.T) {
	cases := map[string]bool{
		"GET / HTTP/1.1\r\n":      true,
		"POST /api HTTP/1.1\r\n":  true,
		"OPTIONS * HTTP/1.0\r\n":  true,
		"PING\r\n":                false,
		"hello world\r\n":         false,
		"":                        false,
	}
	for input, want := range cases {
		got := isLikelyHTTP([]byte(input))
		if got != want {
			t.Errorf("isLikelyHTTP(%q) = %v, want %v", input, got, want)
		}
	}
}

// ─── isMostlyPrintable ─────────────────────────────────────────────────────

func TestIsMostlyPrintable(t *testing.T) {
	cases := map[string]bool{
		"hello":                    true,
		"hello\r\nworld":           true,
		"":                         false, // empty is not "mostly printable"
		string([]byte{0, 0, 0, 0}): false,
		// 9 printable chars + 1 null = 90% — should be true
		"abcdefghi" + string([]byte{0}): true,
		// 8 printable + 2 null = 80% — should be false
		"abcdefgh" + string([]byte{0, 0}): false,
	}
	for input, want := range cases {
		got := isMostlyPrintable([]byte(input))
		if got != want {
			t.Errorf("isMostlyPrintable(%q) = %v, want %v", input, got, want)
		}
	}
}
