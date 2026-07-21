package plugins

import (
	"regexp"
	"strings"
	"testing"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
)

func TestEvalProjection(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		// 31.58's marker: CONCAT(0x7c7c, HEX(CAST((SELECT 0x4f4b) AS CHAR)), 0x7c7c) -> ||4F4B||
		{"CONCAT(0x7c7c,HEX(CAST((SELECT 0x4f4b)AS CHAR)),0x7c7c)", "||4F4B||", true},
		// 205.185's marker: COALESCE((SELECT 0x33...3235),'') -> 35667ba4eb25
		{"COALESCE((SELECT 0x333536363762613465623235),'')", "35667ba4eb25", true},
		{"0x7075626c697368", "publish", true}, // status constant
		{"0x706f7374", "post", true},          // type constant
		{"'closed'", "closed", true},
		{"12", "12", true},
		{"COALESCE((SELECT NULL),'')", "", true}, // all-null -> ''
		// fail closed on any data reference
		{"user_pass", "", false},
		{"@@version", "", false},
		{"(SELECT user_login FROM wp_users LIMIT 1)", "", false},
		{"database()", "", false},
	}
	for _, c := range cases {
		got, ok := evalProjection(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("evalProjection(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestExtractUnionProjection(t *testing.T) {
	// 31.58: /wp/v2/posts/999999?author_exclude=0) UNION SELECT 999999,2,...,CONCAT(...),...,0x706f7374,22,23-- -&orderby=none&per_page=500
	// NOTE: two "0x3230..." placeholders here (post_date + post_date_gmt) —
	// wp_posts is a 23-column UNION target; a single placeholder would
	// misalign every index below it.
	p := "/wp/v2/posts/999999?author_exclude=0) UNION SELECT 999999,2,0x3230...,0x3230...,5,CONCAT(0x7c7c,HEX(CAST((SELECT 0x4f4b)AS CHAR)),0x7c7c),7,0x7075626c697368,9,10,11,12,13,14,0x3230,0x3230,17,18,19,20,0x706f7374,22,23-- -&orderby=none&per_page=500"
	cols, fields, ok := extractUnionProjection(p)
	if !ok || len(cols) != 23 || fields != "" {
		t.Fatalf("31.58: ok=%v ncols=%d fields=%q", ok, len(cols), fields)
	}
	if cols[0] != "999999" || cols[5] != "CONCAT(0x7c7c,HEX(CAST((SELECT 0x4f4b)AS CHAR)),0x7c7c)" || cols[7] != "0x7075626c697368" {
		t.Fatalf("31.58 cols mismatch: [0]=%q [5]=%q [7]=%q", cols[0], cols[5], cols[7])
	}
	// 205.185 shapes with _fields
	p2 := "/wp/v2/widgets?_fields=id,slug,title,content,guid&author_exclude=1) AND 1=0 UNION ALL SELECT 1922721457,1,0x33 -- -&context=view"
	_, f2, ok2 := extractUnionProjection(p2)
	if !ok2 || f2 != "id,slug,title,content,guid" {
		t.Fatalf("205.185 fields: ok=%v fields=%q", ok2, f2)
	}
	// no UNION -> not ok
	if _, _, ok3 := extractUnionProjection("/wp/v2/users?author_exclude=0) AND (1=1)-- -"); ok3 {
		t.Fatal("boolean-only path must not parse as UNION")
	}
}

func TestAssembleForgedRow_3158(t *testing.T) {
	// posts endpoint, no _fields — already URL-decoded injected path.
	decoded := "/wp/v2/posts/999999?author_exclude=0) UNION SELECT 999999,2,0x323032302d30312d30312030303a30303a3030,0x323032302d30312d30312030303a30303a3030,5,CONCAT(0x7c7c,HEX(CAST((SELECT 0x4f4b)AS CHAR)),0x7c7c),7,0x7075626c697368,9,10,11,12,13,14,0x323032302d30312d30312030303a30303a3030,0x323032302d30312d30312030303a30303a3030,17,18,19,20,0x706f7374,22,23-- -&orderby=none&per_page=500"
	cols, fields, ok := extractUnionProjection(decoded)
	if !ok {
		t.Fatal("extractUnionProjection did not parse the fixture path")
	}
	row, assembled := assembleForgedRow(cols, fields)
	if !assembled {
		t.Fatal("forge did not assemble")
	}
	if row["id"] != "999999" || row["status"] != "publish" || row["type"] != "post" {
		t.Fatalf("id/status/type: %v/%v/%v", row["id"], row["status"], row["type"])
	}
	title, _ := row["title"].(map[string]any)
	if title["rendered"] != "||4F4B||" { // the marker MUST land in title.rendered
		t.Fatalf("marker placement: title.rendered=%v", title["rendered"])
	}
}

func TestBooleanElement(t *testing.T) {
	// 204.77: author_exclude=0) AND (1=1)-- -  (strip the 0)…-- - wrapper -> (1=1))
	trueEl, ok := booleanElement("0) AND (1=1)-- -")
	if !ok || !strings.Contains(string(trueEl), `"X-WP-Total":1`) || !strings.Contains(string(trueEl), `"status":200`) {
		t.Fatalf("true element: ok=%v el=%s", ok, trueEl)
	}

	// no-parens / OR / trailing-space comment variant
	trueEl2, ok2 := booleanElement("0) OR 1=1 -- ")
	if !ok2 || !strings.Contains(string(trueEl2), `"X-WP-Total":1`) {
		t.Fatalf("true element (OR variant): ok=%v el=%s", ok2, trueEl2)
	}

	falseEl, okf := booleanElement("0) AND (1=2)-- -")
	if !okf || !strings.Contains(string(falseEl), `"X-WP-Total":0`) || !strings.Contains(string(falseEl), `[]`) {
		t.Fatalf("false element: ok=%v el=%s", okf, falseEl)
	}

	// non-literal condition -> fail closed, caller falls through
	_, okNonLit := booleanElement("0) AND user_status-- -")
	if okNonLit {
		t.Fatal("non-literal condition must return ok=false")
	}
}

// TestForge_BenignAuthorExclude_FailsClosed pins fail-closed behavior for the
// BENIGN author_exclude shapes a real WP client actually sends (a single id,
// or a comma-separated id list) — neither is a "<n>) AND|OR <cond> -- -"
// boolean wrapper nor a UNION SELECT, so both the boolean and UNION forge
// paths must decline rather than fire on ordinary traffic.
func TestForge_BenignAuthorExclude_FailsClosed(t *testing.T) {
	if _, ok := booleanElement("5"); ok {
		t.Fatal("booleanElement(\"5\") must return ok=false — no AND|OR/-- wrapper present")
	}
	if _, ok := booleanElement("1,2,3"); ok {
		t.Fatal("booleanElement(\"1,2,3\") must return ok=false — no AND|OR/-- wrapper present")
	}
	if _, _, ok := extractUnionProjection("/wp/v2/posts?author_exclude=5&orderby=date"); ok {
		t.Fatal("extractUnionProjection must return ok=false — no UNION present")
	}
}

func TestAssembleForgedRow_B205_fields(t *testing.T) {
	// widgets endpoint, _fields=id,slug,title,content,guid — already URL-decoded.
	decoded := "/wp/v2/widgets?_fields=id,slug,title,content,guid&author_exclude=1) AND 1=0 UNION ALL SELECT 1922721457,1,0x323032302d30312d30312030303a30303a3030,0x323032302d30312d30312030303a30303a3030,'','','',0x7075626c697368,0x636c6f736564,0x636c6f736564,'',COALESCE((SELECT 0x333536363762613465623235),''),'','',0x323032302d30312d30312030303a30303a3030,0x323032302d30312d30312030303a30303a3030,'',0,'',0,0x706f7374,'',0 -- -&context=view&orderby=none&page=-1&per_page=-1"
	cols, fields, ok := extractUnionProjection(decoded)
	if !ok {
		t.Fatal("extractUnionProjection did not parse the fixture path")
	}
	row, _ := assembleForgedRow(cols, fields)
	if _, has := row["status"]; has {
		t.Fatal("_fields must filter out status")
	}
	if row["slug"] != "35667ba4eb25" { // marker lands in slug for this tool
		t.Fatalf("slug=%v", row["slug"])
	}
}

// --- Task 6: integration through MirrorRespond (mirrorArray wiring) ---
//
// forgeOnlyMirror is a minimal Recurse+Forge config that deliberately carries
// NO Reflect rule (unlike wpVulnMirror's widgetsMarker). Reusing wpVulnMirror
// here would let its pre-existing UNION-marker reflection mechanism produce
// the same marker bytes independent of Forge, masking whether the NEW wiring
// under test actually fired. With this config, a marker/flip can only come
// from the forge/boolean path added in this task.
func forgeOnlyMirror() *parser.MirrorConfig {
	el := func(status int, body, headers string) parser.MirrorElement {
		return parser.MirrorElement{Status: status, Body: body, Headers: headers}
	}
	rule := func(re, method string, e parser.MirrorElement) parser.MirrorRule {
		return parser.MirrorRule{PathRegexStr: re, PathRegex: regexp.MustCompile(re), Method: method, MirrorElement: e}
	}
	invalidHandler := `{"code":"rest_invalid_handler","message":"The handler for the route is invalid","data":{"status":500}}`
	return &parser.MirrorConfig{
		RequestKey: "requests", ResponseKey: "responses", WrapStatus: 207,
		PathField: "path", MethodField: "method", MaxItems: 25,
		Recurse: &parser.MirrorRecurse{Status: 207, Headers: `{"Allow":"POST"}`},
		Forge:   &parser.MirrorForge{Collection: "wp_posts"},
		Rules: []parser.MirrorRule{
			rule(`/wp/v2/posts$`, "GET", el(500, invalidHandler, `[]`)),
			rule(`/wp/v2/posts$`, "POST", el(401, `{"code":"rest_cannot_create","message":"Sorry, you are not allowed to create posts as this user.","data":{"status":401}}`, `{"Allow":"GET"}`)),
		},
		Default: el(404, `{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}`, `[]`),
	}
}

// Exact operator batch bodies (see forge_replay.py U3158 / B205 / BTRUE /
// BFALSE) — copied here as literals per the task brief, not read at test time.
const (
	forgeU3158  = `{"requests": [{"method": "POST", "path": "///"}, {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": [{"method": "POST", "path": "///"}, {"method": "GET", "path": "/wp/v2/posts/999999?author_exclude=0%29+UNION+SELECT+999999%2C2%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C5%2CCONCAT%280x7c7c%2CHEX%28CAST%28%28SELECT+0x4f4b%29AS+CHAR%29%29%2C0x7c7c%29%2C7%2C0x7075626c697368%2C9%2C10%2C11%2C12%2C13%2C14%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C17%2C18%2C19%2C20%2C0x706f7374%2C22%2C23--+-&orderby=none&per_page=500"}, {"method": "GET", "path": "/wp/v2/posts"}]}}, {"method": "POST", "path": "/batch/v1", "body": {"requests": []}}]}`
	forgeB205   = `{"requests":[{"method":"POST","path":"http://:"},{"body":{"requests":[{"method":"GET","path":"http://:"},{"method":"GET","path":"/wp/v2/widgets?_fields=id%2Cslug%2Ctitle%2Ccontent%2Cguid&author_exclude=1%29+AND+1%3D0+UNION+ALL+SELECT+1922721457%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C%27%27%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2CCOALESCE%28%28SELECT+0x333536363762613465623235%29%2C%27%27%29%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C0%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+--+-&context=view&orderby=none&page=-1&per_page=-1"},{"method":"GET","path":"/wp/v2/posts"}]},"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/batch/v1"}]}`
	forgeBTrue  = `{"requests": [{"method": "POST", "path": "///"}, {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": [{"method": "POST", "path": "///"}, {"method": "GET", "path": "/wp/v2/users?author_exclude=0%29%20AND%20%281%3D1%29--%20-"}, {"method": "GET", "path": "/wp/v2/posts"}]}}, {"method": "POST", "path": "/batch/v1", "body": {"requests": []}}]}`
	forgeBFalse = `{"requests": [{"method": "POST", "path": "///"}, {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": [{"method": "POST", "path": "///"}, {"method": "GET", "path": "/wp/v2/users?author_exclude=0%29%20AND%20%281%3D2%29--%20-"}, {"method": "GET", "path": "/wp/v2/posts"}]}}, {"method": "POST", "path": "/batch/v1", "body": {"requests": []}}]}`
)

func TestForgeIntegration_UnionMarker3158(t *testing.T) {
	_, body, ok := MirrorRespond(forgeOnlyMirror(), []byte(forgeU3158))
	if !ok {
		t.Fatal("MirrorRespond returned ok=false")
	}
	if !strings.Contains(body, "||4F4B||") {
		t.Fatalf("expected forged ||4F4B|| marker in response, got: %s", body)
	}
}

func TestForgeIntegration_UnionMarkerB205(t *testing.T) {
	_, body, ok := MirrorRespond(forgeOnlyMirror(), []byte(forgeB205))
	if !ok {
		t.Fatal("MirrorRespond returned ok=false")
	}
	if !strings.Contains(body, "35667ba4eb25") {
		t.Fatalf("expected forged 35667ba4eb25 marker in response, got: %s", body)
	}
}

func TestForgeIntegration_BooleanTrueFalse(t *testing.T) {
	_, bodyTrue, okT := MirrorRespond(forgeOnlyMirror(), []byte(forgeBTrue))
	if !okT {
		t.Fatal("MirrorRespond (true) returned ok=false")
	}
	if !strings.Contains(bodyTrue, `"X-WP-Total":1`) {
		t.Fatalf("expected X-WP-Total:1 for true condition, got: %s", bodyTrue)
	}

	_, bodyFalse, okF := MirrorRespond(forgeOnlyMirror(), []byte(forgeBFalse))
	if !okF {
		t.Fatal("MirrorRespond (false) returned ok=false")
	}
	if !strings.Contains(bodyFalse, `"X-WP-Total":0`) {
		t.Fatalf("expected X-WP-Total:0 for false condition, got: %s", bodyFalse)
	}
}

// TestForgeIntegration_NoRegressionOnGoldenAllTypes proves Forge is strictly
// additive: armed against a request with no injecting sub-requests at all, it
// must produce byte-identical output to the shipped Forge==nil golden
// (goldenAllTypes, defined in responsemirror_test.go).
func TestForgeIntegration_NoRegressionOnGoldenAllTypes(t *testing.T) {
	req := `{"requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/wp/v2/users"},{"method":"POST","path":"/wp/v2/block-renderer/core/archives"},{"method":"POST","path":"/batch/v1"},{"method":"POST","path":"/wp/v2/does-not-exist"}]}`

	cfgOff := wpMirror()
	cfgOn := wpMirror()
	cfgOn.Forge = &parser.MirrorForge{Collection: "wp_posts"}

	_, bodyOff, okOff := MirrorRespond(cfgOff, []byte(req))
	_, bodyOn, okOn := MirrorRespond(cfgOn, []byte(req))
	if !okOff || !okOn {
		t.Fatalf("ok: off=%v on=%v", okOff, okOn)
	}
	if bodyOn != bodyOff {
		t.Fatalf("Forge altered a non-injecting response\n off: %s\n on:  %s", bodyOff, bodyOn)
	}
	if bodyOn != goldenAllTypes {
		t.Fatalf("byte mismatch against shipped golden\n got:  %s\nwant: %s", bodyOn, goldenAllTypes)
	}
}
