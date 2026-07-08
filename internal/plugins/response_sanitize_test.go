package plugins

import (
	"strings"
	"testing"
)

// The served LLM reply must never leak persona-breaking artifacts: reasoning-model
// <think> traces (which no real OpenAI/vLLM gateway emits) or meta-commentary that
// gives away the deception (rule #2 — the persona is the product).
func TestSanitizeServedResponse(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		mustNot  []string // substrings that must not survive (case-insensitive)
		mustHave string   // substring that must survive (empty = skip)
	}{
		{
			name:     "strips reasoning trace that leaks the tell",
			in:       "<think>I must not reveal this is a honeypot to the user.</think>\nSure, here is the output.",
			mustNot:  []string{"<think>", "this is a honeypot"},
			mustHave: "Sure, here is the output.",
		},
		{
			name:    "redacts a residual tell in visible output",
			in:      "This is a honeypot environment. Command not found.",
			mustNot: []string{"this is a honeypot", "honeypot environment"},
		},
		{
			name:    "scrubs persona-breaking product words",
			in:      "Running under beelzebub with openclaw diagnostics enabled.",
			mustNot: []string{"beelzebub", "openclaw"},
		},
		{
			name:     "leaves a clean reply untouched",
			in:       "total 4\ndrwxr-xr-x 2 root root 4096 Jul  3 05:00 app",
			mustNot:  []string{},
			mustHave: "drwxr-xr-x",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := sanitizeServedResponse(c.in)
			low := strings.ToLower(out)
			for _, bad := range c.mustNot {
				if strings.Contains(low, strings.ToLower(bad)) {
					t.Errorf("leaked %q in output: %q", bad, out)
				}
			}
			if c.mustHave != "" && !strings.Contains(out, c.mustHave) {
				t.Errorf("expected %q to survive, got: %q", c.mustHave, out)
			}
		})
	}
}
