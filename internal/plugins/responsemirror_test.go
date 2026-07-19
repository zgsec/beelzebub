package plugins

import (
	"regexp"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"gopkg.in/yaml.v3"
)

// TestMirror_YAMLRoundTrip unmarshals a mirror command straight from YAML (the
// deployment path), compiles it through the real parser, and asserts the
// plugin produces the golden bytes. This guards the yaml struct tags — a tag
// typo would pass the struct-built tests above but silently break on a real
// lure config, which is the fork's classic "unknown key ignored" failure mode.
func TestMirror_YAMLRoundTrip(t *testing.T) {
	const y = `
commands:
  - regex: "^/wp-json/batch/v1/?$"
    method: "POST"
    plugin: "ResponseMirror"
    statusCode: 207
    handler: "{}"
    mirror:
      requestKey: requests
      responseKey: responses
      wrapStatus: 207
      pathField: path
      methodField: method
      maxItems: 25
      allowedMethods: [POST, PUT, PATCH, DELETE]
      reject:
        status: 400
        body: '{"code":"rest_invalid_param"}'
      rules:
        - pathRegex: '^https?:'
          status: 400
          body: '{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}}'
          headers: '[]'
        - pathRegex: '/wp/v2/posts$'
          status: 401
          body: '{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}}'
          headers: '{"Allow":"GET"}'
        - pathRegex: '/batch/v1$'
          status: 400
          body: '{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}}'
          headers: '{"Allow":"POST"}'
      default:
        status: 404
        body: '{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}'
        headers: '[]'
`
	var conf parser.BeelzebubServiceConfiguration
	if err := yaml.Unmarshal([]byte(y), &conf); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if err := conf.CompileCommandRegex(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	m := conf.Commands[0].Mirror
	if m == nil {
		t.Fatal("mirror did not unmarshal (yaml tag mismatch on `mirror`)")
	}
	if len(m.Rules) != 3 || m.Rules[0].PathRegex == nil {
		t.Fatalf("rules did not unmarshal/compile: %+v", m.Rules)
	}
	req := `{"requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/batch/v1"}]}`
	want := `{"responses":[{"body":{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}},"status":400,"headers":[]},{"body":{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}},"status":401,"headers":{"Allow":"GET"}},{"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":{"Allow":"POST"}}]}`
	status, body, ok := MirrorRespond(m, []byte(req))
	if !ok || status != 207 || body != want {
		t.Fatalf("ok=%v status=%d\n got=%s\nwant=%s", ok, status, body, want)
	}
}

// wpMirror builds the WordPress-6.9.5 (patched) rule table used by the tests.
// The bodies/statuses/headers are the byte-exact values captured from a real
// wordpress:6.9.4 container updated to 6.9.5 (tools/oracle-diff in honeypot-
// research). Regexes are compiled here directly rather than through the parser
// so the test targets MirrorRespond's assembly precisely.
func wpMirror() *parser.MirrorConfig {
	rule := func(re, method string, status int, body, headers string) parser.MirrorRule {
		return parser.MirrorRule{
			PathRegexStr: re,
			PathRegex:    regexp.MustCompile(re),
			Method:       method,
			MirrorElement: parser.MirrorElement{
				Status: status, Body: body, Headers: headers,
			},
		}
	}
	return &parser.MirrorConfig{
		RequestKey:     "requests",
		ResponseKey:    "responses",
		WrapStatus:     207,
		PathField:      "path",
		MethodField:    "method",
		AllowedMethods: []string{"POST", "PUT", "PATCH", "DELETE"},
		Reject: &parser.MirrorReject{
			Status: 400,
			Body:   `{"code":"rest_invalid_param","message":"Invalid parameter(s): requests","data":{"status":400,"params":{"requests":"requests[0][method] is not one of POST, PUT, PATCH, and DELETE."},"details":{"requests":{"code":"rest_not_in_enum","message":"requests[0][method] is not one of POST, PUT, PATCH, and DELETE.","data":null}}}}`,
		},
		Rules: []parser.MirrorRule{
			rule(`^https?:`, "", 400, `{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}}`, `[]`),
			rule(`/wp/v2/posts$`, "", 401, `{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}}`, `{"Allow":"GET"}`),
			rule(`/wp/v2/users$`, "", 400, `{"code":"rest_missing_callback_param","message":"Missing parameter(s): username, email, password","data":{"status":400,"params":["username","email","password"]}}`, `{"Allow":"GET"}`),
			rule(`/wp/v2/block-renderer`, "", 400, `{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}}`, `[]`),
			rule(`/batch/v1$`, "", 400, `{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}}`, `{"Allow":"POST"}`),
		},
		Default: parser.MirrorElement{
			Status: 404, Body: `{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}`, Headers: `[]`,
		},
	}
}

// GOLDEN is the byte-exact body captured from patched WP 6.9.5 for a batch with
// all six top-level element types in order (Content-Length: 994).
const goldenAllTypes = `{"responses":[{"body":{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}},"status":400,"headers":[]},{"body":{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}},"status":401,"headers":{"Allow":"GET"}},{"body":{"code":"rest_missing_callback_param","message":"Missing parameter(s): username, email, password","data":{"status":400,"params":["username","email","password"]}},"status":400,"headers":{"Allow":"GET"}},{"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":[]},{"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":{"Allow":"POST"}},{"body":{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}},"status":404,"headers":[]}]}`

func TestMirror_GoldenAllTypes(t *testing.T) {
	req := `{"requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/wp/v2/users"},{"method":"POST","path":"/wp/v2/block-renderer/core/archives"},{"method":"POST","path":"/batch/v1"},{"method":"POST","path":"/wp/v2/does-not-exist"}]}`
	status, body, ok := MirrorRespond(wpMirror(), []byte(req))
	if !ok || status != 207 {
		t.Fatalf("ok=%v status=%d", ok, status)
	}
	if body != goldenAllTypes {
		t.Fatalf("body mismatch\n got: %s\nwant: %s", body, goldenAllTypes)
	}
	if len(body) != 994 {
		t.Fatalf("Content-Length: got %d want 994", len(body))
	}
}

func TestMirror_SingleElementAndNoTrailingNewline(t *testing.T) {
	status, body, ok := MirrorRespond(wpMirror(), []byte(`{"requests":[{"method":"POST","path":"/wp/v2/posts"}]}`))
	want := `{"responses":[{"body":{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}},"status":401,"headers":{"Allow":"GET"}}]}`
	if !ok || status != 207 || body != want {
		t.Fatalf("ok=%v status=%d body=%s", ok, status, body)
	}
	if body[len(body)-1] == '\n' {
		t.Fatalf("body must not end with a newline (real WP does not)")
	}
}

// The Operator A seq6 payload (also the byte-identical 31.58.244.30 body):
// nested sub-request bodies must be IGNORED (flat / patched behaviour).
func TestMirror_OperatorA_seq6_FlatIgnoresNested(t *testing.T) {
	req := `{"requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/wp/v2/block-renderer/core/archives"},{"method":"POST","path":"/batch/v1","body":{"requests":[]}}]}`
	want := `{"responses":[{"body":{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}},"status":400,"headers":[]},{"body":{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}},"status":401,"headers":{"Allow":"GET"}},{"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":[]},{"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":{"Allow":"POST"}}]}`
	status, body, ok := MirrorRespond(wpMirror(), []byte(req))
	if !ok || status != 207 || body != want {
		t.Fatalf("ok=%v status=%d\n got=%s\nwant=%s", ok, status, body, want)
	}
}

// Operator B (wp2shell) UNION payload: the nested widgets SQLi is ignored; the
// top-level shape is [scheme, /wp/v2/posts, /batch/v1].
func TestMirror_OperatorB_wp2shell(t *testing.T) {
	req := `{"requests":[{"method":"POST","path":"http://:"},{"body":{"requests":[{"method":"GET","path":"/wp/v2/widgets?author_exclude=1) UNION ALL SELECT ..."}]},"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/batch/v1"}]}`
	status, body, ok := MirrorRespond(wpMirror(), []byte(req))
	want := `{"responses":[{"body":{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}},"status":400,"headers":[]},{"body":{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}},"status":401,"headers":{"Allow":"GET"}},{"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":{"Allow":"POST"}}]}`
	if !ok || status != 207 || body != want {
		t.Fatalf("ok=%v status=%d\n got=%s\nwant=%s", ok, status, body, want)
	}
}

func TestMirror_MethodGuardRejectsWholeBatch(t *testing.T) {
	// A top-level GET is outside the enum → whole-envelope 400, not a 207.
	status, body, ok := MirrorRespond(wpMirror(), []byte(`{"requests":[{"method":"GET","path":"/wp/v2/posts"}]}`))
	if !ok || status != 400 {
		t.Fatalf("ok=%v status=%d", ok, status)
	}
	want := `{"code":"rest_invalid_param","message":"Invalid parameter(s): requests","data":{"status":400,"params":{"requests":"requests[0][method] is not one of POST, PUT, PATCH, and DELETE."},"details":{"requests":{"code":"rest_not_in_enum","message":"requests[0][method] is not one of POST, PUT, PATCH, and DELETE.","data":null}}}}`
	if body != want {
		t.Fatalf("reject body mismatch: %s", body)
	}
}

func TestMirror_FallsBackWhenNotABatch(t *testing.T) {
	// ok=false means the caller keeps the static handler — strictly additive.
	cases := []string{
		``,                              // empty
		`not json`,                      // unparseable
		`{"foo":"bar"}`,                 // no requests key
		`{"requests":"notarray"}`,       // requests not an array
		`[]`,                            // top-level array, not object
	}
	for _, c := range cases {
		if _, _, ok := MirrorRespond(wpMirror(), []byte(c)); ok {
			t.Fatalf("expected ok=false for %q", c)
		}
	}
}

func TestMirror_NilConfig(t *testing.T) {
	if _, _, ok := MirrorRespond(nil, []byte(`{"requests":[]}`)); ok {
		t.Fatalf("nil config must return ok=false")
	}
}

func TestMirror_MaxItemsGuard(t *testing.T) {
	// 26 sub-requests (> default 25) → reject (configured) fires.
	req := `{"requests":[`
	for i := 0; i < 26; i++ {
		if i > 0 {
			req += ","
		}
		req += `{"method":"POST","path":"/wp/v2/posts"}`
	}
	req += `]}`
	status, _, ok := MirrorRespond(wpMirror(), []byte(req))
	if !ok || status != 400 {
		t.Fatalf("maxItems guard: ok=%v status=%d", ok, status)
	}
}

// compileMirror runs through the real parser path to prove a config with
// invalid JSON fragments is rejected at load, not on the wire.
func TestMirror_ParserValidatesJSON(t *testing.T) {
	good := parser.BeelzebubServiceConfiguration{Commands: []parser.Command{{
		Name: "batch", Plugin: ResponseMirrorName,
		Mirror: &parser.MirrorConfig{
			RequestKey: "requests", ResponseKey: "responses", WrapStatus: 207,
			Rules:   []parser.MirrorRule{{PathRegexStr: `/x$`, MirrorElement: parser.MirrorElement{Status: 404, Body: `{"ok":true}`, Headers: `[]`}}},
			Default: parser.MirrorElement{Status: 404, Body: `{"code":"rest_no_route"}`, Headers: `[]`},
		},
	}}}
	if err := good.CompileCommandRegex(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := good
	bad.Commands = []parser.Command{{
		Name: "batch", Plugin: ResponseMirrorName,
		Mirror: &parser.MirrorConfig{
			RequestKey: "requests", ResponseKey: "responses", WrapStatus: 207,
			Default: parser.MirrorElement{Status: 404, Body: `{not valid json`, Headers: `[]`},
		},
	}}
	if err := bad.CompileCommandRegex(); err == nil {
		t.Fatalf("expected invalid-JSON body to fail config load")
	}
}
