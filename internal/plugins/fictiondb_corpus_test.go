package plugins

import (
	"crypto/md5"
	"encoding/hex"
	"sync"
	"testing"
)

// fictiondb_corpus_test.go is the grading oracle for evalBlindPredicate's
// broadened grammar: the technique-variation space a real blind-SQLi tool
// exercises against this vuln, not just one PoC's exact strings. Cases are
// organized by family; each documents the real-world shape it stands in
// for (sqlmap, Havij, manual operator, etc. all phrase these differently —
// the evaluator must treat them identically).
//
// Known value under test throughout:
//   sv = fictionValue{s: "wp_posts"}  -> len 8, bytes: w=119 p=112 _=95 ...
//   iv = fictionValue{n: 5, isInt: true}

var corpusSV = fictionValue{s: "wp_posts"}
var corpusIV = fictionValue{n: 5, isInt: true}

type corpusCase struct {
	name string
	cond string
	val  fictionValue
	want bool
	ok   bool
}

// corpusCases is the full probe corpus. Table-driven so both
// TestFictionCorpus and the fuzz seed corpus can reuse it.
var corpusCases = []corpusCase{
	// ---- Length family: {CHAR_LENGTH|LENGTH|OCTET_LENGTH}(<x>) <op> N ----
	{"charlen >= true", "CHAR_LENGTH(x) >= 8", corpusSV, true, true},
	{"length > false (boundary)", "LENGTH(x) > 8", corpusSV, false, true},
	{"octetlen = true", "OCTET_LENGTH(x) = 8", corpusSV, true, true},
	{"charlen < false", "CHAR_LENGTH(x) < 8", corpusSV, false, true},
	{"length <= true", "LENGTH(x) <= 8", corpusSV, true, true},
	{"octetlen <> false", "OCTET_LENGTH(x) <> 8", corpusSV, false, true},
	{"charlen != true (bigger N)", "CHAR_LENGTH(x) != 100", corpusSV, true, true},
	{"length wraps a subquery, content ignored", "LENGTH((SELECT column_name FROM information_schema.columns LIMIT 1)) >= 1", corpusSV, true, true},

	// ---- Char-code family: {ASCII|ORD}({SUBSTRING|SUBSTR|MID}(<x>,pos,1)) <op> M ----
	{"ascii/substring >= true ('w'=119)", "ASCII(SUBSTRING(x,1,1)) >= 119", corpusSV, true, true},
	{"ord/substr = true ('p'=112, pos2)", "ORD(SUBSTR(x,2,1)) = 112", corpusSV, true, true},
	{"ascii/mid > false", "ASCII(MID(x,1,1)) > 119", corpusSV, false, true},
	{"ascii/substring out-of-range pos -> byte 0", "ASCII(SUBSTRING(x,99,1)) >= 1", corpusSV, false, true},
	{"ascii/substring out-of-range pos, = 0 true", "ASCII(SUBSTRING(x,0,1)) = 0", corpusSV, true, true},
	{"ord/mid <= true", "ORD(MID(x,1,1)) <= 119", corpusSV, true, true},
	{"ascii/substr <> false (exact match)", "ASCII(SUBSTR(x,1,1)) <> 119", corpusSV, false, true},
	{"ascii/substring != true", "ASCII(SUBSTRING(x,1,1)) != 1", corpusSV, true, true},

	// ---- Int-compare family: {COALESCE|IFNULL}(...) or bare (SELECT ...) ----
	{"coalesce >= true", "COALESCE((SELECT x),0) >= 4", corpusIV, true, true},
	{"coalesce >= false", "COALESCE((SELECT x),0) >= 6", corpusIV, false, true},
	{"ifnull = true", "IFNULL((SELECT COUNT(*) FROM wp_users),0) = 5", corpusIV, true, true},
	{"ifnull <> false", "IFNULL((SELECT x),0) <> 5", corpusIV, false, true},
	{"bare select subquery >= true", "(SELECT COUNT(*) FROM wp_users) >= 5", corpusIV, true, true},
	{"bare select subquery > false", "(SELECT COUNT(*) FROM wp_users) > 5", corpusIV, false, true},
	{"bare select subquery < true", "(SELECT COUNT(*) FROM wp_users) < 6", corpusIV, true, true},
	{"coalesce <= true", "COALESCE((SELECT x),0) <= 5", corpusIV, true, true},
	{"coalesce >= true, real column read -> tightened screen must not over-reject", "COALESCE((SELECT ID FROM x),0) >= 4", corpusIV, true, true},

	// ---- Whitespace / case / URL-decoded-form variants — must evaluate
	// identically to their canonical counterparts above. ----
	{"lowercase fn name", "char_length(x) >= 8", corpusSV, true, true},
	{"mixed case fn name", "Char_Length(x) >= 8", corpusSV, true, true},
	{"space before paren (decoded '+')", "CHAR_LENGTH (x) >= 8", corpusSV, true, true},
	{"tabs/newlines around op", "CHAR_LENGTH(x)\t>=\n8", corpusSV, true, true},
	{"extra outer whitespace", "   CHAR_LENGTH(x) >= 8   ", corpusSV, true, true},
	{"lowercase ascii/substring", "ascii(substring(x,1,1)) >= 119", corpusSV, true, true},
	{"mixed case coalesce", "CoAlEsCe((SELECT x),0) >= 4", corpusIV, true, true},
	{"space-padded args", "ASCII( SUBSTRING( x , 1 , 1 ) ) >= 119", corpusSV, true, true},

	// ---- Fail-closed cases ----
	{"bare SLEEP, not wrapped", "SLEEP(9999) >= 1", corpusIV, false, false},
	{"bare BENCHMARK, not wrapped", "BENCHMARK(1000000,MD5(1)) >= 1", corpusSV, false, false},
	{"unknown function", "WEIRDFN(x) >= 1", corpusSV, false, false},
	{"bare unwrapped comparison, no function", "x >= 1", corpusIV, false, false},
	{"malformed: unbalanced open paren", "CHAR_LENGTH(x >= 8", corpusSV, false, false},
	{"malformed: unbalanced close paren", "CHAR_LENGTH(x)) >= 8", corpusSV, false, false},
	{"coalesce wrapping SLEEP -> side-effect guard", "COALESCE((SELECT SLEEP(9999)),0) >= 1", corpusIV, false, false},
	{"ifnull wrapping BENCHMARK -> side-effect guard", "IFNULL((SELECT BENCHMARK(1000000,MD5(1))),0) >= 1", corpusIV, false, false},
	{"bare select wrapping SLEEP -> side-effect guard", "(SELECT SLEEP(9999)) >= 1", corpusIV, false, false},

	// ---- Fail-closed: whitespace/comment obfuscation between a
	// side-effect function name and its '(' must NOT defeat the guard.
	// These are the exact tamper-tool shapes a WAF-evasion pass reaches
	// for first (sqlmap --tamper=space2comment and friends). ----
	{"ifnull wrapping SLEEP with space before paren -> side-effect guard", "IFNULL((SELECT SLEEP (9999)),0) >= 1", corpusIV, false, false},
	{"ifnull wrapping SLEEP with tab before paren -> side-effect guard", "IFNULL((SELECT SLEEP\t(9999)),0) >= 1", corpusIV, false, false},
	{"ifnull wrapping SLEEP with comment before paren -> side-effect guard", "IFNULL((SELECT SLEEP/**/(9999)),0) >= 1", corpusIV, false, false},
	{"coalesce wrapping BENCHMARK with space before paren -> side-effect guard", "COALESCE((SELECT BENCHMARK (1000000,MD5(1))),0) >= 1", corpusIV, false, false},
	{"coalesce wrapping GET_LOCK with comment before paren -> side-effect guard", "COALESCE((SELECT GET_LOCK/**/('a',9999)),0) >= 1", corpusIV, false, false},
	{"ifnull wrapping RELEASE_LOCK, bare -> side-effect guard", "IFNULL((SELECT RELEASE_LOCK('a')),0) >= 1", corpusIV, false, false},
	{"bare select wrapping GET_LOCK with tab before paren -> side-effect guard", "(SELECT GET_LOCK\t('a',9999)) >= 1", corpusIV, false, false},
	{"int-compare shape but val is not int", "COALESCE((SELECT x),0) >= 4", corpusSV, false, false},
	{"char-code shape missing 3rd arg", "ASCII(SUBSTRING(x,1)) >= 119", corpusSV, false, false},
	{"char-code shape non-1 length arg", "ASCII(SUBSTRING(x,1,2)) >= 119", corpusSV, false, false},
	{"empty condition", "", corpusSV, false, false},
	{"only whitespace", "   ", corpusSV, false, false},
	{"non-numeric threshold", "CHAR_LENGTH(x) >= abc", corpusSV, false, false},
	{"trailing junk after call", "CHAR_LENGTH(x)garbage >= 8", corpusSV, false, false},
}

func TestFictionCorpus(t *testing.T) {
	for _, c := range corpusCases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := evalBlindPredicate(c.cond, c.val)
			if got != c.want || ok != c.ok {
				t.Fatalf("evalBlindPredicate(%q) = (%v,%v), want (%v,%v)", c.cond, got, ok, c.want, c.ok)
			}
		})
	}
}

// TestFictionCorpus_Consistency asserts the same predicate evaluated twice
// returns the same result — the evaluator must be a pure function of
// (cond, val), never stateful or racy, so an operator can't distinguish the
// lure by re-sending an identical probe.
func TestFictionCorpus_Consistency(t *testing.T) {
	for _, c := range corpusCases {
		first, firstOK := evalBlindPredicate(c.cond, c.val)
		second, secondOK := evalBlindPredicate(c.cond, c.val)
		if first != second || firstOK != secondOK {
			t.Errorf("evalBlindPredicate(%q) not consistent: (%v,%v) then (%v,%v)", c.cond, first, firstOK, second, secondOK)
		}
	}
}

// TestEvalBlindPredicate_NoPanic feeds adversarial/malformed strings at
// evalBlindPredicate and asserts it only ever returns, never panics — the
// lure fails closed, it doesn't fail loud. Every result is fail-closed
// (false, false) is NOT asserted here (some adversarial-looking strings
// might coincidentally parse); only the no-panic property is checked.
func TestEvalBlindPredicate_NoPanic(t *testing.T) {
	adversarial := []string{
		"",
		" ",
		"(",
		")",
		"((((((((((",
		"))))))))))",
		"CHAR_LENGTH(",
		"CHAR_LENGTH()",
		"CHAR_LENGTH(x",
		"CHAR_LENGTH(x >= 8",
		"CHAR_LENGTH(x)) >= 8",
		"CHAR_LENGTH((((((((((((((((((((x)))))))))))))))))))) >= 8",
		"ASCII(SUBSTRING(x,,1)) >= 1",
		"ASCII(SUBSTRING(x,1,)) >= 1",
		"ASCII(SUBSTRING(,,)) >= 1",
		"COALESCE() >= 1",
		"COALESCE(((((((((((((((((((((((((((((((((((((((((",
		">= 8",
		"8 >=",
		">=<>!===",
		"\x00\x00\x00CHAR_LENGTH(x)\x00 >= \x008",
		"CHAR_LENGTH(x) >= 8\x00trailing-null",
		"日本語CHAR_LENGTH(x)>=8日本語",
		"CHAR_LENGTH(𝔘𝔫𝔦𝔠𝔬𝔡𝔢) >= 8",
		"ASCII(SUBSTRING(x,999999999999999999999999999999,1)) >= 1",
		"CHAR_LENGTH(x) >= 999999999999999999999999999999999999999999",
		"CHAR_LENGTH(x) >= -8",
		strRepeat("(", 5000) + "x" + strRepeat(")", 5000) + " >= 1",
		"CHAR_LENGTH(" + strRepeat("a", 10000) + ") >= 8",
		strRepeat("CHAR_LENGTH(", 2000) + "x" + strRepeat(")", 2000) + " >= 8",
		"ASCII(SUBSTRING(ASCII(SUBSTRING(x,1,1)),1,1)) >= 1",
		"CoAlEsCe((select sleep(9999)),0)>=1",
		"(select sleep(9999))>=1",
		"(SELECT)>=1",
		"()>=1",
		"( )>=1",
		"(SELECT SELECT SELECT) >= 1",
		strRepeat("random garbage bytes \xff\xfe\xfd not utf8 ", 200),
	}

	for _, s := range adversarial {
		s := s
		t.Run("", func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("evalBlindPredicate panicked on %q: %v", truncateForLog(s), r)
				}
			}()
			evalBlindPredicate(s, corpusSV)
			evalBlindPredicate(s, corpusIV)
			evalBlindPredicate(s, fictionValue{})
		})
	}
}

// FuzzEvalBlindPredicate is the fuzz counterpart: seeded from the probe
// corpus plus the adversarial no-panic list, it asserts only that
// evalBlindPredicate returns without panicking for any input the fuzzer
// discovers. Run as a seed-corpus pass: no long fuzz campaign required for
// this task, just `go test -run FuzzEvalBlindPredicate`.
func FuzzEvalBlindPredicate(f *testing.F) {
	for _, c := range corpusCases {
		f.Add(c.cond)
	}
	seeds := []string{
		"", "(", ")", "CHAR_LENGTH(x >= 8", "CHAR_LENGTH(x)) >= 8",
		"ASCII(SUBSTRING(x,1,1)) >= 119", "COALESCE((SELECT x),0) >= 4",
		"(SELECT SLEEP(9999)) >= 1", "\x00\x00", "日本語",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cond string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("evalBlindPredicate panicked on %q: %v", truncateForLog(cond), r)
			}
		}()
		evalBlindPredicate(cond, corpusSV)
		evalBlindPredicate(cond, corpusIV)
	})
}

func strRepeat(s string, n int) string {
	b := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		b = append(b, s...)
	}
	return string(b)
}

func truncateForLog(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

// ---------------------------------------------------------------------------
// TestReadIntentCorpus is the grading oracle for recognizeBlindRead's
// broadened grammar: the same three read INTENTS (table prefix, admin id,
// oEmbed cache id) phrased the way real blind-SQLi tools phrase them —
// RIGHT() vs LIKE vs SUBSTRING vs INSTR, hex vs quoted literal, whitespace
// and /* comment */ noise a WAF-evasion tamper injects — not just the one
// exact-hex shape the original exploit's poc.py happens to emit. Every
// phrasing of a given intent must resolve to the SAME fabricated value.
// ---------------------------------------------------------------------------

// md5HexOf returns the lowercase hex digest of seed, matching how the real
// gadget chain names its oEmbed cache rows (post_name = md5(url)).
func md5HexOf(seed string) string {
	sum := md5.Sum([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// hexEncodeASCII hex-encodes the ASCII bytes of s, the way a blind-SQLi
// tool avoids embedding quotes in its payload (0x-notation instead of a
// quoted string literal).
func hexEncodeASCII(s string) string {
	return hex.EncodeToString([]byte(s))
}

// cachePostNameHexCond builds a cache-id predicate using the fully
// hex-encoded phrasing (post_type and post_name both 0x-notation) — the
// exploit's own poc.py shape.
func cachePostNameHexCond(seed string) string {
	return "COALESCE((SELECT ID FROM `wp_posts` WHERE post_type=0x6f656d6265645f6361636865 " +
		"AND post_name=0x" + hexEncodeASCII(md5HexOf(seed)) + " ORDER BY ID DESC LIMIT 1),0) >= 1"
}

// cachePostNameLiteralCond builds the same cache-id predicate using plain
// quoted-literal phrasing instead of hex-notation — a tool that doesn't
// bother hex-encoding because the target doesn't filter quotes.
func cachePostNameLiteralCond(seed string) string {
	return "SELECT ID FROM wp_posts WHERE post_type='oembed_cache' " +
		"AND post_name='" + md5HexOf(seed) + "' ORDER BY ID DESC LIMIT 1"
}

// cachePostNameMixedCond builds a cache-id predicate mixing hex post_type
// with a literal post_name — tools are not internally consistent about
// which columns they bother hex-encoding.
func cachePostNameMixedCond(seed string) string {
	return "SELECT ID FROM wp_posts WHERE post_type=0x6f656d6265645f6361636865 " +
		"AND post_name='" + md5HexOf(seed) + "' ORDER BY ID DESC LIMIT 1"
}

type readIntentCase struct {
	name    string
	cond    string
	wantVal fictionValue
	wantOK  bool
}

// tablePrefixCases: every phrasing must resolve to fictionValue{s:"wp_posts"}.
var tablePrefixCases = []readIntentCase{
	{
		"RIGHT + hex (exploit's own phrasing)",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() " +
			"AND RIGHT(TABLE_NAME,6)=0x5f706f737473 LIMIT 1",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"LIKE + literal wildcard",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%_posts' LIMIT 1",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"LIKE + hex wildcard",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE 0x255f706f737473 LIMIT 1",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"INSTR + literal, against INFORMATION_SCHEMA.COLUMNS",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE INSTR(TABLE_NAME,'_posts')>0 LIMIT 1",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"INSTR + hex",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE INSTR(TABLE_NAME,0x5f706f737473)>0",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"SUBSTRING + literal",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE SUBSTRING(TABLE_NAME,-6)='_posts'",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"SUBSTR + hex",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE SUBSTR(TABLE_NAME,-6)=0x5f706f737473",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"MID + literal",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE MID(TABLE_NAME,-6)='_posts'",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"whitespace + comment obfuscation between RIGHT and its paren",
		"select table_name from information_schema.tables where right/**/( table_name , 6 )\t=\t0x5f706f737473",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"url-encoded literal quotes",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE RIGHT(TABLE_NAME,6)=%27_posts%27",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"spaced dot in INFORMATION_SCHEMA . TABLES",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA . TABLES WHERE RIGHT(TABLE_NAME,6)=0x5f706f737473",
		fictionValue{s: "wp_posts"}, true,
	},
	{
		"mixed case",
		"Select Table_Name From Information_Schema.Tables Where Right(Table_Name,6)=0x5f706f737473",
		fictionValue{s: "wp_posts"}, true,
	},
}

// adminIDCases: every phrasing must resolve to fictionValue{n:1, isInt:true}.
var adminIDCases = []readIntentCase{
	{
		"usermeta context + hex serialized marker (exploit's own phrasing)",
		"SELECT u.ID FROM `wp_users` u JOIN `wp_usermeta` m ON m.user_id=u.ID " +
			"WHERE m.meta_key=0x77705f6361706162696c6974696573 " +
			"AND INSTR(m.meta_value,0x733a31333a2261646d696e6973747261746f72223b623a313b)>0 LIMIT 1",
		fictionValue{n: 1, isInt: true}, true,
	},
	{
		"capabilities context + literal serialized marker",
		`SELECT ID FROM wp_usermeta WHERE meta_key='wp_capabilities' AND meta_value LIKE '%s:13:"administrator";b:1;%'`,
		fictionValue{n: 1, isInt: true}, true,
	},
	{
		"user_level context + INSTR against bare 'administrator'",
		"SELECT ID FROM wp_usermeta WHERE meta_key='user_level' AND INSTR(meta_value,'administrator')>0",
		fictionValue{n: 1, isInt: true}, true,
	},
	{
		"wp_user_roles context + LIKE '%administrator%'",
		"SELECT ID FROM wp_options WHERE option_name='wp_user_roles' AND option_value LIKE '%administrator%'",
		fictionValue{n: 1, isInt: true}, true,
	},
	{
		"usermeta context + url-encoded quotes in serialized literal",
		"SELECT ID FROM wp_usermeta WHERE meta_key='capabilities' AND meta_value LIKE '%s:13:%22administrator%22;b:1;%'",
		fictionValue{n: 1, isInt: true}, true,
	},
	{
		"capabilities context + hex marker with comment obfuscation",
		"select id from wp_usermeta where meta_key='capabilities' and instr/**/(meta_value,0x733a31333a2261646d696e6973747261746f72223b623a313b)>0",
		fictionValue{n: 1, isInt: true}, true,
	},
}

func TestReadIntentCorpus(t *testing.T) {
	all := append([]readIntentCase{}, tablePrefixCases...)
	all = append(all, adminIDCases...)
	for _, c := range all {
		t.Run(c.name, func(t *testing.T) {
			sess := newChainSession()
			got, ok := recognizeBlindRead(c.cond, sess)
			if got != c.wantVal || ok != c.wantOK {
				t.Fatalf("recognizeBlindRead(%q) = (%+v,%v), want (%+v,%v)", c.cond, got, ok, c.wantVal, c.wantOK)
			}
		})
	}
}

// TestReadIntentCorpus_CacheIDPhrasings asserts every phrasing of the
// cache-id read (hex/hex, literal/literal, hex/literal mixed) for the SAME
// underlying md5 resolves to the SAME fabricated id — proving the
// recognizer keys on the semantic md5, not the literal request bytes.
func TestReadIntentCorpus_CacheIDPhrasings(t *testing.T) {
	seed := "https://example.com/embed/one"
	phrasings := map[string]string{
		"hex/hex":           cachePostNameHexCond(seed),
		"literal/literal":   cachePostNameLiteralCond(seed),
		"hex/literal mixed": cachePostNameMixedCond(seed),
	}

	sess := newChainSession()
	var first fictionValue
	haveFirst := false
	for name, cond := range phrasings {
		got, ok := recognizeBlindRead(cond, sess)
		if !ok || !got.isInt {
			t.Fatalf("phrasing %s: recognizeBlindRead(%q) = (%+v,%v), want an int value, true", name, cond, got, ok)
		}
		if !haveFirst {
			first = got
			haveFirst = true
			continue
		}
		if got != first {
			t.Errorf("phrasing %s: got %+v, want same as first phrasing %+v (same underlying md5)", name, got, first)
		}
	}
}

// TestReadIntentCorpus_CacheIDDistinct asserts distinct md5s (across
// distinct phrasings, for good measure) still produce distinct ids.
func TestReadIntentCorpus_CacheIDDistinct(t *testing.T) {
	sess := newChainSession()
	a, ok := recognizeBlindRead(cachePostNameHexCond("https://example.com/embed/one"), sess)
	if !ok {
		t.Fatalf("cache A: unrecognized")
	}
	b, ok := recognizeBlindRead(cachePostNameLiteralCond("https://example.com/embed/two"), sess)
	if !ok {
		t.Fatalf("cache B: unrecognized")
	}
	c, ok := recognizeBlindRead(cachePostNameMixedCond("https://example.com/embed/three"), sess)
	if !ok {
		t.Fatalf("cache C: unrecognized")
	}
	if a == b || a == c || b == c {
		t.Fatalf("expected 3 distinct cache ids, got a=%+v b=%+v c=%+v", a, b, c)
	}
}

// TestReadIntentCorpus_FailClosed asserts reads outside the three
// recognized intents — including a plausible-looking credential read that
// must NOT be mistaken for one of them — always fail closed with no
// distinctive tell and no panic.
func TestReadIntentCorpus_FailClosed(t *testing.T) {
	cases := []string{
		// A credential read: syntactically similar (wp_users, WHERE, quoted
		// literal) but not one of the three recognized intents. Must fail
		// closed, not be swept in by an over-broad admin-context match.
		"SELECT user_pass FROM wp_users WHERE ID=1",
		"COALESCE((SELECT user_pass FROM wp_users ORDER BY ID LIMIT 1),0) >= 1",
		// A generic version probe, nothing to do with any of the three reads.
		"COALESCE((SELECT @@version),0) >= 1",
		"(SELECT @@version) >= 1",
		// INFORMATION_SCHEMA reference present but no _posts suffix filter
		// at all -> must not over-trigger the table-prefix intent.
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES LIMIT 1",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME='wp_options'",
		// usermeta context present but no administrator marker at all.
		"SELECT ID FROM wp_usermeta WHERE meta_key='nickname'",
		"SELECT ID FROM wp_usermeta WHERE meta_key='wp_capabilities' AND meta_value LIKE '%subscriber%'",
		// oembed_cache post_type present but no post_name lookup at all.
		"SELECT ID FROM wp_posts WHERE post_type='oembed_cache'",
		"SELECT ID FROM wp_posts WHERE post_type=0x6f656d6265645f6361636865",
		// Malformed / degenerate input.
		"",
		"   ",
		"SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE RIGHT(TABLE_NAME,6",
		"post_type=0x6f656d6265645f6361636865 AND post_name=0x",
		"post_type=0x6f656d6265645f6361636865 AND post_name=",
	}
	for _, cond := range cases {
		t.Run(truncateForLog(cond), func(t *testing.T) {
			sess := newChainSession()
			got, ok := recognizeBlindRead(cond, sess)
			if ok || got != (fictionValue{}) {
				t.Fatalf("recognizeBlindRead(%q) = (%+v,%v), want ({},false)", cond, got, ok)
			}
		})
	}
}

// TestReadIntentCorpus_CredentialDenylist is the regression guard for the
// credential-column doctrine gate: a blind read that co-occurs with the
// SAME usermeta/capabilities/administrator tokens intent 2 keys on, but is
// actually SELECTing a wp_users credential/PII column scoped through that
// context, must fail closed — not be misclassified as the admin-id intent.
// Intent recognition is document-wide co-occurrence, so without the
// denylist gate these are indistinguishable from a legitimate admin-id
// read; this test is what proves the gate, not just the intent grammar.
func TestReadIntentCorpus_CredentialDenylist(t *testing.T) {
	failClosedCases := []struct {
		name string
		cond string
	}{
		{
			"user_pass scoped through admin-id subquery (ID=(SELECT user_id ...))",
			"SELECT SUBSTRING(user_pass,1,1) FROM wp_users WHERE ID=(SELECT user_id FROM wp_usermeta " +
				"WHERE meta_key='capabilities' AND meta_value LIKE '%administrator%' LIMIT 1)",
		},
		{
			"user_pass scoped through admin-id join (COALESCE + JOIN-style WHERE)",
			"COALESCE((SELECT SUBSTRING(u.user_pass,1,1) FROM wp_users u, wp_usermeta m " +
				"WHERE u.ID=m.user_id AND m.meta_key='wp_capabilities' AND m.meta_value LIKE '%administrator%'),0)",
		},
		{
			"user_login scoped through admin-id context",
			"SELECT SUBSTRING(user_login,1,1) FROM wp_users u, wp_usermeta m " +
				"WHERE u.ID=m.user_id AND m.meta_key='capabilities' AND m.meta_value LIKE '%administrator%'",
		},
		{
			"user_email scoped through admin-id context",
			"SELECT ASCII(SUBSTRING(user_email,1,1)) FROM wp_users u, wp_usermeta m " +
				"WHERE u.ID=m.user_id AND m.meta_key='capabilities' AND m.meta_value LIKE '%administrator%'",
		},
		{
			"user_activation_key scoped through admin-id context",
			"SELECT SUBSTRING(user_activation_key,1,1) FROM wp_users u, wp_usermeta m " +
				"WHERE u.ID=m.user_id AND m.meta_key='capabilities' AND m.meta_value LIKE '%administrator%'",
		},
		{
			"user_url read, no admin-id context at all",
			"SELECT SUBSTRING(user_url,1,1) FROM wp_users WHERE ID=1",
		},
	}
	for _, c := range failClosedCases {
		t.Run(c.name, func(t *testing.T) {
			sess := newChainSession()
			got, ok := recognizeBlindRead(c.cond, sess)
			if ok || got != (fictionValue{}) {
				t.Fatalf("recognizeBlindRead(%q) = (%+v,%v), want ({},false) — credential read must fail closed", c.cond, got, ok)
			}
		})
	}

	// Regression guard against over-rejection: the LEGITIMATE admin-id read
	// references only u.ID / m.user_id (neither denylisted) and must still
	// resolve to the admin-id intent.
	t.Run("legitimate admin-id read still recognized (not over-rejected)", func(t *testing.T) {
		cond := `SELECT u.ID FROM wp_users u JOIN wp_usermeta m ON m.user_id=u.ID ` +
			`WHERE m.meta_key='wp_capabilities' AND INSTR(m.meta_value, 's:13:"administrator";b:1;')>0 ORDER BY u.ID LIMIT 1`
		sess := newChainSession()
		got, ok := recognizeBlindRead(cond, sess)
		want := fictionValue{n: 1, isInt: true}
		if !ok || got != want {
			t.Fatalf("recognizeBlindRead(%q) = (%+v,%v), want (%+v,true)", cond, got, ok, want)
		}
	})

	// The denylist regex must not trip on user_id/usermeta substrings that
	// legitimately appear in the admin-id read's own WHERE clause.
	t.Run("denylist does not false-positive on user_id/usermeta tokens", func(t *testing.T) {
		cond := "SELECT u.ID FROM `wp_users` u JOIN `wp_usermeta` m ON m.user_id=u.ID " +
			"WHERE m.meta_key=0x77705f6361706162696c6974696573 " +
			"AND INSTR(m.meta_value,0x733a31333a2261646d696e6973747261746f72223b623a313b)>0 LIMIT 1"
		if hasCredentialColumnRead(normalizeReadCond(cond)) {
			t.Fatalf("hasCredentialColumnRead(%q) = true, want false (user_id/usermeta must not trip the denylist)", cond)
		}
		sess := newChainSession()
		got, ok := recognizeBlindRead(cond, sess)
		want := fictionValue{n: 1, isInt: true}
		if !ok || got != want {
			t.Fatalf("recognizeBlindRead(%q) = (%+v,%v), want (%+v,true)", cond, got, ok, want)
		}
	})
}

// TestReadIntentCorpus_NoPanic feeds adversarial/malformed strings (plus
// the whole read-intent corpus, re-run) at recognizeBlindRead and asserts
// it only ever returns, never panics.
func TestReadIntentCorpus_NoPanic(t *testing.T) {
	adversarial := []string{
		"", " ", "(", ")", "((((((((((", "))))))))))",
		"post_type=0x", "post_name=0x", "post_name='", "post_type=''",
		"RIGHT(,6)=0x5f706f737473", "RIGHT(x,)=0x5f706f737473",
		"INSTR(,0x5f706f737473)", "INSTR(x,)",
		"\x00\x00\x00INFORMATION_SCHEMA.TABLES\x00RIGHT(x,6)=0x5f706f737473\x00",
		"日本語INFORMATION_SCHEMA.TABLES RIGHT(x,6)=0x5f706f737473日本語",
		"%%%%%25%2%zz%",
		strRepeat("(", 5000) + "information_schema.tables" + strRepeat(")", 5000),
		strRepeat("/**/", 2000) + "RIGHT(x,6)=0x5f706f737473",
		strRepeat("random garbage bytes \xff\xfe\xfd not utf8 ", 200),
	}
	for _, cond := range append(adversarial, func() []string {
		var conds []string
		for _, c := range tablePrefixCases {
			conds = append(conds, c.cond)
		}
		for _, c := range adminIDCases {
			conds = append(conds, c.cond)
		}
		return conds
	}()...) {
		cond := cond
		t.Run("", func(t *testing.T) {
			sess := newChainSession()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("recognizeBlindRead panicked on %q: %v", truncateForLog(cond), r)
				}
			}()
			recognizeBlindRead(cond, sess)
		})
	}
}

// TestReadIntentCorpus_ConcurrentCacheAccess exercises the T5 concurrency
// contract directly: many goroutines calling recognizeBlindRead against the
// SAME chainSession concurrently, all resolving cache-id reads (the only
// intent that touches sess.cacheIDs). Run with -race: the contract requires
// every touch of sess fields go through sess.mutate, so a violation here is
// either a data race under -race or a fatal concurrent-map panic — this
// test is only meaningful with -race enabled.
func TestReadIntentCorpus_ConcurrentCacheAccess(t *testing.T) {
	sess := newChainSession()
	const n = 64
	var wg sync.WaitGroup
	results := make([]fictionValue, n)
	oks := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Every 3rd goroutine repeats the same seed as i%3==0's peers,
			// so we also exercise the get-or-assign race, not just the
			// assign race.
			seed := "seed-" + string(rune('A'+(i%5)))
			results[i], oks[i] = recognizeBlindRead(cachePostNameHexCond(seed), sess)
		}(i)
	}
	wg.Wait()

	byMod := make(map[int]fictionValue)
	for i := 0; i < n; i++ {
		if !oks[i] {
			t.Fatalf("goroutine %d: recognizeBlindRead unrecognized", i)
		}
		m := i % 5
		if prev, seen := byMod[m]; seen {
			if prev != results[i] {
				t.Errorf("goroutine %d: same seed group %d got different ids: %+v vs %+v", i, m, results[i], prev)
			}
		} else {
			byMod[m] = results[i]
		}
	}
}
