package TELNET

import (
	"bufio"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

type noopTracer struct{}

func (noopTracer) TraceEvent(tracer.Event) {}

// TestTELNET_CommandResponse_AppliesResponseSubstitutions — drives a
// TELNET interactive lure via loopback and asserts that
// "${request.uuid_short}" in matchedCommand.Handler is rewritten on the
// wire instead of leaking as a literal template string.
func TestTELNET_CommandResponse_AppliesResponseSubstitutions(t *testing.T) {
	servConf := parser.BeelzebubServiceConfiguration{
		Address:                "127.0.0.1:0",
		ServerName:             "honeyhost",
		PasswordRegex:          ".*", // accept any password
		DeadlineTimeoutSeconds: 5,
		Commands: []parser.Command{
			{
				Regex:   regexp.MustCompile(`^whoami$`),
				Handler: "user_${request.uuid_short}",
				Name:    "whoami",
			},
		},
	}

	// Pre-bind an ephemeral port so we know the address before Init.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	servConf.Address = probe.Addr().String()
	_ = probe.Close()

	s := &TelnetStrategy{Sessions: historystore.NewHistoryStore()}
	if err := s.Init(servConf, noopTracer{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	dial := func() string {
		conn, err := net.Dial("tcp", servConf.Address)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))

		r := bufio.NewReader(conn)
		// Drain login prompt — handshake capture happens server-side
		// during the first 100ms; the server then writes "\r\nlogin: ".
		if _, err := r.ReadString(':'); err != nil {
			t.Fatalf("read login: %v", err)
		}
		if _, err := conn.Write([]byte("alice\r\n")); err != nil {
			t.Fatalf("write user: %v", err)
		}
		// Server emits IAC WILL ECHO (3 bytes) then "Password: ".
		// Drop bytes until we see ':'.
		if _, err := r.ReadString(':'); err != nil {
			t.Fatalf("read password prompt: %v", err)
		}
		if _, err := conn.Write([]byte("hunter2\r\n")); err != nil {
			t.Fatalf("write pass: %v", err)
		}
		// Server emits IAC WONT ECHO + CRLF + prompt "alice@honeyhost:~$ ".
		if _, err := r.ReadString('$'); err != nil {
			t.Fatalf("read shell prompt: %v", err)
		}
		// Skip space after $
		if _, err := r.ReadByte(); err != nil {
			t.Fatalf("read prompt space: %v", err)
		}
		if _, err := conn.Write([]byte("whoami\r\n")); err != nil {
			t.Fatalf("write whoami: %v", err)
		}
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}

	r1 := dial()
	if strings.Contains(r1, "${request.uuid_short}") {
		t.Fatalf("placeholder left in TELNET response: %q", r1)
	}
	if !strings.HasPrefix(r1, "user_") {
		t.Fatalf("unexpected TELNET response shape: %q", r1)
	}
	suffix := strings.TrimPrefix(r1, "user_")
	if len(suffix) != 8 {
		t.Errorf("uuid_short suffix length = %d, want 8 (got %q)", len(suffix), suffix)
	}

	// Original Command.Handler must not have been mutated.
	if servConf.Commands[0].Handler != "user_${request.uuid_short}" {
		t.Errorf("Command.Handler mutated: %q", servConf.Commands[0].Handler)
	}
}
