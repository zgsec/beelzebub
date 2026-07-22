package plugins

import "testing"

func TestEvalBlindPredicate(t *testing.T) {
	sv := fictionValue{s: "wp_posts"}     // a fictional string value
	iv := fictionValue{n: 5, isInt: true} // a fictional int value
	cases := []struct {
		cond string
		val  fictionValue
		want bool
		ok   bool
	}{
		// getscalar length probe: CHAR_LENGTH(COALESCE((subq),'')) >= N
		{"CHAR_LENGTH(COALESCE((SELECT x),'')) >= 8", sv, true, true}, // len("wp_posts")=8 >= 8
		{"CHAR_LENGTH(COALESCE((SELECT x),'')) >= 9", sv, false, true},
		// getscalar byte probe: ASCII(SUBSTRING(COALESCE((subq),''),pos,1)) >= M
		{"ASCII(SUBSTRING(COALESCE((SELECT x),''),1,1)) >= 119", sv, true, true}, // 'w'=119 >= 119
		{"ASCII(SUBSTRING(COALESCE((SELECT x),''),1,1)) >= 120", sv, false, true},
		// getint probe: COALESCE((subq),0) >= N
		{"COALESCE((SELECT x),0) >= 4", iv, true, true},
		{"COALESCE((SELECT x),0) >= 6", iv, false, true},
		// unrecognized predicate -> fail closed
		{"BENCHMARK(1000000,MD5(1)) >= 1", sv, false, false},
	}
	for _, c := range cases {
		got, ok := evalBlindPredicate(c.cond, c.val)
		if got != c.want || ok != c.ok {
			t.Errorf("evalBlindPredicate(%q) = (%v,%v), want (%v,%v)", c.cond, got, ok, c.want, c.ok)
		}
	}
}
