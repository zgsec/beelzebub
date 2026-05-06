package TCP

import (
	"bufio"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

type noopTracer struct{}

func (noopTracer) TraceEvent(tracer.Event) {}

// TestTCP_InteractiveResponse_AppliesResponseSubstitutions — drives a
// TCP interactive lure via loopback and asserts that
// "${request.uuid_short}" in matchedCommand.Handler is rewritten on the
// wire instead of leaking as a literal template string. Mirrors the
// MCP/OLLAMA/TELNET wiring done in the same commit.
func TestTCP_InteractiveResponse_AppliesResponseSubstitutions(t *testing.T) {
	servConf := parser.BeelzebubServiceConfiguration{
		Address:                "127.0.0.1:0",
		DeadlineTimeoutSeconds: 5,
		Commands: []parser.Command{
			{
				Regex:   regexp.MustCompile(`^PING$`),
				Handler: "PONG req_${request.uuid_short}",
				Name:    "ping",
			},
		},
	}

	// Init binds and spawns goroutines; we need to discover the actual
	// port. Init logs the address but doesn't return the listener — so
	// pre-bind, then patch the address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	servConf.Address = ln.Addr().String()
	_ = ln.Close()

	s := &TCPStrategy{}
	if err := s.Init(servConf, noopTracer{}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Init returns synchronously after Listen; give the accept loop a
	// moment to come up.
	time.Sleep(50 * time.Millisecond)

	dial := func() string {
		conn, err := net.Dial("tcp", servConf.Address)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("PING\r\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}

	r1 := dial()
	if strings.Contains(r1, "${request.uuid_short}") {
		t.Fatalf("placeholder left in TCP response: %q", r1)
	}
	if !strings.HasPrefix(r1, "PONG req_") {
		t.Fatalf("unexpected TCP response shape: %q", r1)
	}
	suffix := strings.TrimPrefix(r1, "PONG req_")
	if len(suffix) != 8 {
		t.Errorf("uuid_short suffix length = %d, want 8 (got %q)", len(suffix), suffix)
	}

	// Second dial should produce a different UUID.
	r2 := dial()
	if r1 == r2 {
		t.Errorf("TCP emitted identical response across two dials: %q", r1)
	}

	// Original Command.Handler must not have been mutated.
	if servConf.Commands[0].Handler != "PONG req_${request.uuid_short}" {
		t.Errorf("Command.Handler mutated: %q", servConf.Commands[0].Handler)
	}
}
