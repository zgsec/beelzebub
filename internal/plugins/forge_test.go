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
