package plugins

import "testing"

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
		{"0x706f7374", "post", true},           // type constant
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
