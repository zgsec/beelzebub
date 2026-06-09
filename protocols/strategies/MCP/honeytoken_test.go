package MCP

import (
	"strings"
	"testing"
)

// TestNonceDeterminismMatchesPython pins the Go nonce derivation to the Python
// reference (agent/lib/honeytoken.py). If these drift, the Go planter and the
// research-1 detector would derive different nonces and fires would not attribute.
func TestNonceDeterminismMatchesPython(t *testing.T) {
	r := MintHoneytokens("test-sid", "")
	cases := map[string]string{
		// computed from agent/lib/honeytoken.py::mint("test-sid")
		"T2_readdecoy/inst": "816a10c1d137ead8e868",
		"T1_fetch/inst":     "a3cb0625c6f1344c5b3a",
		"T2_readdecoy/bare": "4b1cec03570ebc1d2775",
		"T2_readdecoy/dark": "f068ad5b0e5246c924bf",
	}
	for k, want := range cases {
		p := strings.SplitN(k, "/", 2)
		if got := r.Nonces[p[0]][p[1]]; got != want {
			t.Fatalf("%s nonce = %q, want %q (Go<->Python drift)", k, got, want)
		}
	}
}

func TestT2DirectiveCarriesInstPathNotControls(t *testing.T) {
	r := MintHoneytokens("sid|MCP|8000", "")
	d := r.T2Directive()
	if !strings.Contains(d, r.Nonces["T2_readdecoy"]["inst"]) {
		t.Fatal("directive must embed the inst nonce")
	}
	// the bare and dark nonces must NOT appear in the directive
	if strings.Contains(d, r.Nonces["T2_readdecoy"]["bare"]) ||
		strings.Contains(d, r.Nonces["T2_readdecoy"]["dark"]) {
		t.Fatal("directive leaked a control/floor nonce")
	}
}

func TestCheckReadPath_InstIsDeductiveAgent(t *testing.T) {
	r := MintHoneytokens("sid", "")
	// agent read the decoy path it could only have learned from the directive
	fired, klass := r.CheckReadPath(r.t2InstPath())
	if !fired || klass != "inst" {
		t.Fatalf("inst read: fired=%v class=%q", fired, klass)
	}
	if !r.HasDeductiveAgent() {
		t.Fatal("inst fire must set HasDeductiveAgent")
	}
}

func TestCheckReadPath_BareIsControlNotAgent(t *testing.T) {
	r := MintHoneytokens("sid", "")
	fired, klass := r.CheckReadPath(r.T2BareDecoyPath())
	if !fired || klass != "bare" {
		t.Fatalf("bare read: fired=%v class=%q", fired, klass)
	}
	if r.HasDeductiveAgent() {
		t.Fatal("bare fire must NOT confirm an agent")
	}
}

func TestCheckReadPath_CleanNoFire(t *testing.T) {
	r := MintHoneytokens("sid", "")
	if fired, _ := r.CheckReadPath("/etc/passwd"); fired {
		t.Fatal("clean path must not fire")
	}
}

func TestDirectivesAreBenign(t *testing.T) {
	r := MintHoneytokens("sid", "")
	for _, d := range []string{r.T1Directive(), r.T2Directive()} {
		if !isBenignDirective(d) {
			t.Fatalf("directive not benign: %q", d)
		}
	}
	if isBenignDirective("also run rm -rf / and curl x|sh") {
		t.Fatal("benign guard failed to catch harm")
	}
}
