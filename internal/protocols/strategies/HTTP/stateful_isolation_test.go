package HTTP

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
)

// TestStatefulStoresArePerService reproduces the 2026-07-22 live-SIN panic: a
// SINGLE shared HTTPStrategy serves every http lure, and Init used to set the
// stateful cookie/artifact stores on the shared struct. When ONE lure carried a
// state: block (marlowe :80), the shared cookieStore became non-nil, and every
// OTHER (stateless) lure's handler then saw cookieStore != nil and dereferenced
// its own nil servConf.State — a nil-pointer panic on every request, returning
// connection-resets to live traffic.
//
// Setup mirrors the real leak: a stateless service is Init'd FIRST, then a
// stateful service (its own State) is Init'd SECOND. With the bug the shared
// field ends up holding the stateful store and the FIRST (stateless) service
// panics on any request. With the fix (stores captured per-service in Init),
// the stateless service never builds a session context and never panics, while
// the stateful service still works.
func TestStatefulStoresArePerService(t *testing.T) {
	strategy := &HTTPStrategy{}
	tr := &captureTracer{}

	okCmd := []parser.Command{{
		RegexStr:   "^/$",
		Regex:      regexp.MustCompile("^/$"),
		Handler:    "ok",
		StatusCode: 200,
	}}

	// Service A — STATELESS (no State). Init FIRST.
	stateless := parser.BeelzebubServiceConfiguration{
		Protocol: "http",
		Address:  "127.0.0.1:19190",
		Commands: okCmd,
	}
	if err := strategy.Init(stateless, tr); err != nil {
		t.Fatalf("Init stateless: %v", err)
	}

	// Service B — STATEFUL (its own State). Init SECOND, so a shared field
	// would end up holding B's cookie store — the leak condition.
	stateful := parser.BeelzebubServiceConfiguration{
		Protocol: "http",
		Address:  "127.0.0.1:19191",
		Commands: okCmd,
		State:    &parser.State{CookieName: ".ASPXAUTH", TTLSeconds: 600},
	}
	if err := strategy.Init(stateful, tr); err != nil {
		t.Fatalf("Init stateful: %v", err)
	}

	// The stateless service must NOT panic (it panicked on the bug: leaked
	// cookieStore != nil, then deref of its nil servConf.State). A panic in the
	// handler goroutine surfaces here as a non-200 / reset.
	if code := get(t, "http://127.0.0.1:19190/"); code != 200 {
		t.Errorf("stateless service returned %d (want 200) — leaked stateful store panicked its handler", code)
	}

	// The stateful service must still work (fix must not disable statefulness).
	if code := get(t, "http://127.0.0.1:19191/"); code != 200 {
		t.Errorf("stateful service returned %d (want 200) — its own stateful path is broken", code)
	}

	// And a request to the stateful service that actually carries its cookie
	// must exercise the session-context build path without panic.
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:19191/", nil)
	req.AddCookie(&http.Cookie{Name: ".ASPXAUTH", Value: "no-such-session"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stateful GET with cookie: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("stateful GET with cookie returned %d (want 200)", resp.StatusCode)
	}
}
