package HTTP

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/tracer"
)

// oneShotConn returns data on the first Read, then EOF. Satisfies net.Conn via
// the embedded nil interface for the unused methods.
type oneShotConn struct {
	net.Conn
	data []byte
	done bool
}

func (c *oneShotConn) Read(p []byte) (int, error) {
	if c.done {
		return 0, io.EOF
	}
	c.done = true
	return copy(p, c.data), nil
}

// traceRequest must flag JA4HSorted=true when no wire-order capture is available
// (the sorted fallback path), so downstream fingerprint pivots can exclude
// non-spec hashes. With a TeeConn supplying wire order, the flag is false and
// HeaderOrder is populated.
func TestTraceRequest_JA4HSortedFlag(t *testing.T) {
	// Case 1: no TeeConn in context → sorted fallback, flagged.
	tt := &captureTracer{}
	req := newTestRequest(t)
	cmd := parser.Command{Name: "h"}
	traceRequest(req, tt, cmd, "desc", "svc", "", nil,
		"", 200, "", false, 0, 1, false, 0, nil, "", "")
	got := tt.last()
	if !got.JA4HSorted {
		t.Errorf("expected JA4HSorted=true without wire order")
	}
	if got.HeaderOrder != "" {
		t.Errorf("expected empty HeaderOrder without wire order, got %q", got.HeaderOrder)
	}

	// Case 2: TeeConn supplies wire-order bytes → not sorted, HeaderOrder set.
	raw := []byte("GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl\r\nAccept: */*\r\n\r\n")
	tc := tracer.NewTeeConn(&oneShotConn{data: raw}, 65536, tracer.HTTPStopFunc())
	if _, err := tc.Read(make([]byte, 4096)); err != nil {
		t.Fatalf("tee read: %v", err)
	}
	req2 := newTestRequest(t)
	req2 = req2.WithContext(context.WithValue(req2.Context(), tracer.TeeConnKey, tc))
	tt2 := &captureTracer{}
	traceRequest(req2, tt2, cmd, "desc", "svc", "", nil,
		"", 200, "", false, 0, 1, false, 0, nil, "", "")
	got2 := tt2.last()
	if got2.JA4HSorted {
		t.Errorf("expected JA4HSorted=false with wire order")
	}
	if got2.HeaderOrder == "" {
		t.Errorf("expected populated HeaderOrder with wire order")
	}
}

// The cookie session must record the SERVER-COMPUTED JA4H, never the
// attacker-supplied X-JA4H request header (which is trivially forgeable and
// would poison forensic correlation in PG).
func TestHTTP_SessionCreateJA4HIgnoresAttackerHeader(t *testing.T) {
	cookieStore := historystore.NewCookieSessionStore(10 * time.Minute)
	defer cookieStore.Stop()

	sctx := &sessionContext{cookieStore: cookieStore, cookieName: ".ASPXAUTH", ttlSeconds: 600}
	cmd := parser.Command{
		Name: "x/create", StatusCode: 302, SessionAction: "create",
		SessionCapture: map[string]string{"x.u": `<U>([^<]+)</U>`},
	}
	req := httptest.NewRequest(http.MethodPost, "/c", strings.NewReader(`<U>a</U>`))
	req.RemoteAddr = "203.0.113.9:5000"
	req.Header.Set("X-JA4H", "ATTACKER-INJECTED-FINGERPRINT")
	req.Proto = "HTTP/1.1"
	req = req.WithContext(context.WithValue(req.Context(),
		http.LocalAddrContextKey, net.Addr(&stubAddr{s: "127.0.0.1:8042"})))

	tt := &captureTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "x", ServiceType: "x",
		State: &parser.State{CookieName: ".ASPXAUTH", TTLSeconds: 600},
	}
	if _, err := buildHTTPResponse(servConf, tt, cmd, req, nil, sctx); err != nil {
		t.Fatal(err)
	}

	if sctx.sess == nil {
		t.Fatal("session not created")
	}
	if sctx.sess.JA4H == "ATTACKER-INJECTED-FINGERPRINT" {
		t.Fatal("cookie session stored attacker-supplied X-JA4H header")
	}
	if want := tracer.ComputeJA4H(req, nil); sctx.sess.JA4H != want {
		t.Errorf("cookie JA4H: want server-computed %q, got %q", want, sctx.sess.JA4H)
	}
}
