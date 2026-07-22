package plugins

import "testing"

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
