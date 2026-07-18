package HTTP

import (
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/faults"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
)

// get issues a GET and returns the status code, retrying briefly while the
// listener goroutine started by Init comes up.
func get(t *testing.T, url string) int {
	t.Helper()
	var lastErr error
	for i := 0; i < 50; i++ {
		resp, err := http.Get(url)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return resp.StatusCode
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET %s never succeeded: %v", url, lastErr)
	return 0
}

// TestFaultInjectionIsPerService reproduces the cross-service fault leak: a
// SINGLE shared HTTPStrategy serves every HTTP service, and builder.go sets
// .Fault then Init()s each service in turn. Reading httpStrategy.Fault at
// request time used whichever service was Init'd LAST, so an injector
// configured on ONE lure fired on the others.
//
// Setup mirrors the real leak: a no-fault service is Init'd first, then a
// second service with an always-on error injector. With the bug, the shared
// field ends up holding the injector and the FIRST (no-fault) service starts
// returning the second service's 5xx. With the fix (injector captured per
// service at Init), the no-fault service is never faulted and the fault
// service always is.
func TestFaultInjectionIsPerService(t *testing.T) {
	strategy := &HTTPStrategy{}
	tr := &captureTracer{}

	okCmd := []parser.Command{{
		RegexStr:   "^/$",
		Regex:      regexp.MustCompile("^/$"),
		Handler:    "ok",
		StatusCode: 200,
	}}

	// Service A — NO fault injection. Init FIRST.
	noFault := parser.BeelzebubServiceConfiguration{
		Protocol: "http",
		Address:  "127.0.0.1:19180",
		Commands: okCmd,
	}
	strategy.Fault = nil // builder sets this per service; A has none
	if err := strategy.Init(noFault, tr); err != nil {
		t.Fatalf("Init A: %v", err)
	}

	// Service B — always-error injection. Init SECOND (so the shared field
	// ends up holding B's injector — the leak condition).
	alwaysError := faults.NewInjector(faults.Config{
		Enabled:        true,
		ErrorRate:      1.0,
		ErrorResponses: []string{`{"leaked":"service-B-only"}`},
	})
	withFault := parser.BeelzebubServiceConfiguration{
		Protocol: "http",
		Address:  "127.0.0.1:19181",
		Commands: okCmd,
	}
	strategy.Fault = alwaysError
	if err := strategy.Init(withFault, tr); err != nil {
		t.Fatalf("Init B: %v", err)
	}

	// Service A (no fault) must NEVER 503 — it must not inherit B's injector.
	// This is the assertion that fails on the bug.
	if code := get(t, "http://127.0.0.1:19180/"); code == 503 {
		t.Errorf("service A (no faultInjection) returned 503 — fault leaked from service B")
	} else if code != 200 {
		t.Errorf("service A: want 200, got %d", code)
	}

	// Service B (always-error) must still 503 — the fix must not disable a
	// service's own fault injection.
	if code := get(t, "http://127.0.0.1:19181/"); code != 503 {
		t.Errorf("service B (errorRate=1.0) want 503, got %d — its own fault injection is broken", code)
	}
}
