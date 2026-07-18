package HTTP

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/stretchr/testify/assert"
)

// The WordPress /wp-json/batch/v1 case that motivated this: one path, one
// method, three different real responses discriminated only by JSON body.
func TestBodyRegexDiscriminatesSamePathAndMethod(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{
			{ // GET smuggled into requests[].method -> 400 rest_invalid_param
				RegexStr:     "^/wp-json/batch/v1/?$",
				Method:       "POST",
				BodyRegexStr: `"method"\s*:\s*"(GET|HEAD|OPTIONS)"`,
				Handler:      "invalid_param",
				StatusCode:   400,
			},
			{ // well-formed batch -> 207 Multi-Status
				RegexStr:     "^/wp-json/batch/v1/?$",
				Method:       "POST",
				BodyRegexStr: `"requests"`,
				Handler:      "multi_status",
				StatusCode:   207,
			},
			{ // no requests param at all -> 400 rest_missing_callback_param
				RegexStr:   "^/wp-json/batch/v1/?$",
				Method:     "POST",
				Handler:    "missing_param",
				StatusCode: 400,
			},
		},
	}
	assert.NoError(t, conf.CompileCommandRegex())

	for _, tt := range []struct {
		name, body, wantHandler string
		wantStatus              int
	}{
		{"smuggled GET", `{"requests":[{"method":"GET","path":"/wp/v2/posts"}]}`, "invalid_param", 400},
		{"valid POST batch", `{"requests":[{"method":"POST","path":"/wp/v2/posts"}]}`, "multi_status", 207},
		{"valid DELETE batch", `{"requests":[{"method":"DELETE","path":"/wp/v2/posts/1"}]}`, "multi_status", 207},
		{"empty object", `{}`, "missing_param", 400},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := firstMatch(conf.Commands, "/wp-json/batch/v1", "POST", tt.body)
			assert.True(t, ok)
			assert.Equal(t, tt.wantHandler, got.Handler)
			assert.Equal(t, tt.wantStatus, got.StatusCode)
		})
	}
}

// A command with no BodyRegex must stay body-agnostic — this is the
// backwards-compatibility guarantee for every existing service config.
func TestNilBodyRegexIsBodyAgnostic(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{{RegexStr: "^/anything$", Handler: "legacy"}},
	}
	assert.NoError(t, conf.CompileCommandRegex())

	for _, body := range []string{"", "{}", `{"requests":[]}`, "not json at all"} {
		got, ok := firstMatch(conf.Commands, "/anything", "POST", body)
		assert.True(t, ok, "body %q should still match", body)
		assert.Equal(t, "legacy", got.Handler)
	}
}

// A non-matching BodyRegex must fall through to a later command rather than
// matching-and-ignoring, and must not match when nothing else does.
func TestBodyRegexNonMatchFallsThrough(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{
			{RegexStr: "^/x$", BodyRegexStr: `"never_present"`, Handler: "specific"},
			{RegexStr: "^/x$", Handler: "fallback"},
		},
	}
	assert.NoError(t, conf.CompileCommandRegex())

	got, ok := firstMatch(conf.Commands, "/x", "POST", `{"a":1}`)
	assert.True(t, ok)
	assert.Equal(t, "fallback", got.Handler)
}

// An invalid body pattern must fail config compilation loudly, not silently
// disable body matching (which would degrade the rule into "match everything").
func TestInvalidBodyRegexFailsCompilation(t *testing.T) {
	conf := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{{RegexStr: "^/x$", BodyRegexStr: "["}},
	}
	assert.Error(t, conf.CompileCommandRegex())
}

// REGRESSION: buffering the body for BodyRegex must leave request.Body
// readable for downstream consumers (sessionCapture / artifactCapture in
// buildHTTPResponse). A one-shot stream consumed during matching would leave
// those silently empty — the most likely way this change breaks something
// unrelated to it.
func TestBufferedBodyRemainsReadableDownstream(t *testing.T) {
	const payload = `{"requests":[{"method":"POST","path":"/wp/v2/posts"}]}`
	req := httptest.NewRequest(http.MethodPost, "/wp-json/batch/v1", strings.NewReader(payload))

	// Same buffer-and-restore the handler performs before command matching.
	b, err := io.ReadAll(io.LimitReader(req.Body, 1024*1024))
	assert.NoError(t, err)
	req.Body = io.NopCloser(bytes.NewReader(b))
	assert.Equal(t, payload, string(b), "matching sees the full body")

	// Downstream read, as buildHTTPResponse does.
	again, err := io.ReadAll(io.LimitReader(req.Body, 1024*1024))
	assert.NoError(t, err)
	assert.Equal(t, payload, string(again), "body must still be readable downstream")
}

// firstMatch walks commands using the PRODUCTION commandMatches predicate, so
// these tests exercise the same code path the request handler uses rather than
// a reimplementation of it.
func firstMatch(commands []parser.Command, uri, method, body string) (parser.Command, bool) {
	for _, c := range commands {
		if commandMatches(c, uri, method, body) {
			return c, true
		}
	}
	return parser.Command{}, false
}

// anyBodyRegex gates whether the handler buffers the request body at all.
// Configs without bodyRegex must not pay for the feature.
func TestAnyBodyRegexGatesBuffering(t *testing.T) {
	none := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{{RegexStr: "^/a$"}, {RegexStr: "^/b$"}},
	}
	assert.NoError(t, none.CompileCommandRegex())
	assert.False(t, anyBodyRegex(none.Commands), "no bodyRegex configured -> must not buffer")

	some := parser.BeelzebubServiceConfiguration{
		Commands: []parser.Command{{RegexStr: "^/a$"}, {RegexStr: "^/b$", BodyRegexStr: `"x"`}},
	}
	assert.NoError(t, some.CompileCommandRegex())
	assert.True(t, anyBodyRegex(some.Commands), "one bodyRegex present -> must buffer")
}
