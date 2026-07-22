package plugins

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

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
		{"COALESCE((SELECT ID FROM x),0) >= 4", iv, true, true},
		{"COALESCE((SELECT ID FROM x),0) >= 6", iv, false, true},
		// ASCII/SUBSTRING out-of-range pos -> byte 0, still recognized
		{"ASCII(SUBSTRING(COALESCE((SELECT x),''),9,1)) >= 1", sv, false, true},
		// unrecognized predicate -> fail closed
		{"BENCHMARK(1000000,MD5(1)) >= 1", sv, false, false},
		// non-COALESCE-wrapped int-looking predicate -> unrecognized, fail
		// closed (regression guard for the reGe tightening)
		{"SLEEP(9999) >= 1", iv, false, false},
	}
	for _, c := range cases {
		got, ok := evalBlindPredicate(c.cond, c.val)
		if got != c.want || ok != c.ok {
			t.Errorf("evalBlindPredicate(%q) = (%v,%v), want (%v,%v)", c.cond, got, ok, c.want, c.ok)
		}
	}
}

// cachePostNameCond builds a cache-id blind-read predicate the same way the
// exploit's poc.py does: hash a seed string to an md5 hex digest, then
// hex-encode the ASCII bytes of that digest as the post_name literal.
func cachePostNameCond(seed string) string {
	sum := md5.Sum([]byte(seed))
	md5Hex := hex.EncodeToString(sum[:])
	postNameHex := hex.EncodeToString([]byte(md5Hex))
	return "COALESCE((SELECT ID FROM `wp_posts` WHERE post_type=0x6f656d6265645f6361636865 " +
		"AND post_name=0x" + postNameHex + " ORDER BY ID DESC LIMIT 1),0) >= 1"
}

func TestRecognizeBlindRead(t *testing.T) {
	tablePrefixCond := "COALESCE((SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES " +
		"WHERE TABLE_SCHEMA=DATABASE() AND RIGHT(TABLE_NAME,6)=0x5f706f737473 " +
		"ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1),0) >= 1"

	adminCond := "COALESCE((SELECT u.ID FROM `wp_users` u JOIN `wp_usermeta` m ON m.user_id=u.ID " +
		"WHERE m.meta_key=0x77705f6361706162696c6974696573 " +
		"AND INSTR(m.meta_value,0x733a31333a2261646d696e6973747261746f72223b623a313b)>0 " +
		"ORDER BY u.ID LIMIT 1),0) >= 1"

	cacheCondA := cachePostNameCond("https://example.com/embed/one")
	cacheCondB := cachePostNameCond("https://example.com/embed/two")
	cacheCondC := cachePostNameCond("https://example.com/embed/three")

	unrecognizedCond := "COALESCE((SELECT BENCHMARK(1000000,MD5(1))),0) >= 1"

	t.Run("table prefix", func(t *testing.T) {
		sess := newChainSession()
		got, ok := recognizeBlindRead(tablePrefixCond, sess)
		if !ok || got != (fictionValue{s: "wp_posts"}) {
			t.Fatalf("recognizeBlindRead(table prefix) = (%+v,%v), want ({s:wp_posts},true)", got, ok)
		}
	})

	t.Run("admin id", func(t *testing.T) {
		sess := newChainSession()
		got, ok := recognizeBlindRead(adminCond, sess)
		if !ok || got != (fictionValue{n: 1, isInt: true}) {
			t.Fatalf("recognizeBlindRead(admin id) = (%+v,%v), want ({n:1,isInt:true},true)", got, ok)
		}
	})

	t.Run("cache id deterministic and stable", func(t *testing.T) {
		sess := newChainSession()
		first, ok := recognizeBlindRead(cacheCondA, sess)
		if !ok || !first.isInt {
			t.Fatalf("recognizeBlindRead(cache A, 1st) = (%+v,%v), want an int value, true", first, ok)
		}
		second, ok := recognizeBlindRead(cacheCondA, sess)
		if !ok || second != first {
			t.Fatalf("recognizeBlindRead(cache A, 2nd) = (%+v,%v), want same value as 1st (%+v,true)", second, ok, first)
		}
	})

	t.Run("cache id distinct across different md5 seeds", func(t *testing.T) {
		sess := newChainSession()
		a, ok := recognizeBlindRead(cacheCondA, sess)
		if !ok {
			t.Fatalf("recognizeBlindRead(cache A) unrecognized")
		}
		b, ok := recognizeBlindRead(cacheCondB, sess)
		if !ok {
			t.Fatalf("recognizeBlindRead(cache B) unrecognized")
		}
		c, ok := recognizeBlindRead(cacheCondC, sess)
		if !ok {
			t.Fatalf("recognizeBlindRead(cache C) unrecognized")
		}
		if a == b || a == c || b == c {
			t.Fatalf("expected 3 distinct cache ids, got a=%+v b=%+v c=%+v", a, b, c)
		}
	})

	t.Run("unrecognized predicate fails closed", func(t *testing.T) {
		sess := newChainSession()
		got, ok := recognizeBlindRead(unrecognizedCond, sess)
		if ok || got != (fictionValue{}) {
			t.Fatalf("recognizeBlindRead(unrecognized) = (%+v,%v), want ({},false)", got, ok)
		}
	})
}
