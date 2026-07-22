package plugins

import (
	"encoding/hex"
	"hash/crc32"
	"regexp"
	"strconv"
	"strings"
)

// fictionValue is a fabricated stand-in for the row/scalar an operator's
// blind-read predicate is probing. It carries either a string or an int
// reading, never both.
type fictionValue struct {
	s     string
	n     int64
	isInt bool
}

// evalBlindPredicate evaluates an operator's blind-SQLi read predicate
// against a fabricated value, so an inert lure can answer blind reads
// consistently without decoding or executing the inner subquery.
//
// It recognizes three predicate FAMILIES, each keyed on outer shape only —
// the inner <x>/subquery content is never inspected (that's
// recognizeBlindRead's job) — and parameterized by comparison operator
// (>=, >, <, <=, =, <>/!=):
//
//   - Length family:    {CHAR_LENGTH|LENGTH|OCTET_LENGTH}(<x>) <op> N
//     Our fabricated values are ASCII, so all three length functions are
//     treated as equivalent.
//   - Char-code family: {ASCII|ORD}({SUBSTRING|SUBSTR|MID}(<x>,pos,1)) <op> M
//     Evaluates the byte at 1-based pos; out-of-range pos reads as byte 0.
//   - Int-compare family: <left> <op> N, where <left> is a scalar-value
//     wrapper — {COALESCE|IFNULL}(...) or a bare (SELECT ...) subquery —
//     evaluated against val.n (only when val.isInt). A <left> that is
//     itself (or wraps) a time/lock side-effect call — SLEEP(...),
//     BENCHMARK(...), GET_LOCK(...), RELEASE_LOCK(...), a SELECT SLEEP(...)
//     subquery, obfuscated with whitespace or a /* comment */ before the
//     '(' — never matches this family and fails closed, as defense in
//     depth alongside recognizeBlindRead's own filtering.
//
// Anything outside these shapes — including unbalanced parens, unknown
// functions, or a bare unwrapped comparison — fails closed: (false, false).
// This function never panics on adversarial input; every index is
// range-checked and every parse is linear, non-recursive.
func evalBlindPredicate(cond string, val fictionValue) (bool, bool) {
	c := strings.TrimSpace(cond)
	if c == "" {
		return false, false
	}

	left, op, numStr, ok := splitTopLevelCompare(c)
	if !ok {
		return false, false
	}
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return false, false // threshold too large/malformed to be a real int literal
	}

	// Length family: {CHAR_LENGTH|LENGTH|OCTET_LENGTH}(<x>) <op> N
	if _, ok := matchOuterFuncCall(left, "CHAR_LENGTH", "LENGTH", "OCTET_LENGTH"); ok {
		return cmpInt64(int64(len(val.s)), op, n), true
	}

	// Char-code family: {ASCII|ORD}({SUBSTRING|SUBSTR|MID}(<x>,pos,1)) <op> M
	if inner, ok := matchOuterFuncCall(left, "ASCII", "ORD"); ok {
		subInner, ok2 := matchOuterFuncCall(inner, "SUBSTRING", "SUBSTR", "MID")
		if !ok2 {
			return false, false
		}
		args := splitTopLevelArgs(subInner)
		if len(args) != 3 {
			return false, false
		}
		if strings.TrimSpace(args[2]) != "1" {
			return false, false // only the single-byte-read shape is recognized
		}
		pos, perr := strconv.Atoi(strings.TrimSpace(args[1]))
		if perr != nil {
			return false, false
		}
		var b int64
		if pos < 1 || pos > len(val.s) {
			b = 0 // out of range -> byte 0
		} else {
			b = int64(val.s[pos-1])
		}
		return cmpInt64(b, op, n), true
	}

	// Int-compare family: {COALESCE|IFNULL}(...) or bare (SELECT ...),
	// only meaningful against an int-typed fabricated value.
	if !val.isInt {
		return false, false
	}
	if inner, ok := matchOuterFuncCall(left, "COALESCE", "IFNULL"); ok {
		if containsSideEffect(inner) {
			return false, false
		}
		return cmpInt64(val.n, op, n), true
	}
	if inner, ok := matchBareSelectSubquery(left); ok {
		if containsSideEffect(inner) {
			return false, false
		}
		return cmpInt64(val.n, op, n), true
	}

	return false, false // unrecognized -> fail closed
}

// cmpInt64 applies one of the six blind-SQLi comparison operators. An
// unrecognized op string is treated as never-true rather than panicking.
// (Named distinctly from responsemirror.go's int-based cmpInt.)
func cmpInt64(a int64, op string, b int64) bool {
	switch op {
	case ">=":
		return a >= b
	case ">":
		return a > b
	case "<=":
		return a <= b
	case "<":
		return a < b
	case "=":
		return a == b
	case "<>", "!=":
		return a != b
	default:
		return false
	}
}

// splitTopLevelCompare finds the single top-level (paren-depth-0) comparison
// operator in s and splits it into (left-hand expression, operator, integer
// literal). It fails (ok=false) on unbalanced parens, on a right-hand side
// that isn't purely digits, or when no depth-0 operator/digit-tail pairing
// exists — which is exactly what happens for malformed input like
// "CHAR_LENGTH(x >= 8" (the ">= 8" never returns to depth 0).
func splitTopLevelCompare(s string) (left string, op string, numStr string, ok bool) {
	type match struct {
		idx, opLen int
		op         string
	}
	var found []match
	depth := 0

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '(' {
			depth++
			continue
		}
		if c == ')' {
			depth--
			if depth < 0 {
				return "", "", "", false // unmatched close paren
			}
			continue
		}
		if depth != 0 {
			continue
		}
		if i+1 < len(s) {
			two := s[i : i+2]
			if two == ">=" || two == "<=" || two == "<>" || two == "!=" {
				found = append(found, match{i, 2, two})
				i++
				continue
			}
		}
		if c == '=' || c == '>' || c == '<' {
			found = append(found, match{i, 1, string(c)})
		}
	}
	if depth != 0 {
		return "", "", "", false // unbalanced open paren
	}

	// Prefer the last candidate whose right-hand side is a clean integer
	// literal running to the end of the string.
	for k := len(found) - 1; k >= 0; k-- {
		m := found[k]
		lhs := strings.TrimSpace(s[:m.idx])
		rhs := strings.TrimSpace(s[m.idx+m.opLen:])
		if lhs == "" || rhs == "" || !isAllDigits(rhs) {
			continue
		}
		return lhs, m.op, rhs, true
	}
	return "", "", "", false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// matchOuterFuncCall checks whether s (already trimmed by the caller's
// context) is exactly one of names, applied as a single outer call spanning
// the whole string — e.g. "ASCII(...)" but not "ASCII(...)extra" or
// "notASCII(...)". On match it returns the raw, uninspected argument text
// between the outer parens. Matching is case-insensitive and tolerant of
// whitespace before '('. It never panics: every slice is length-guarded.
func matchOuterFuncCall(s string, names ...string) (inner string, ok bool) {
	s = strings.TrimSpace(s)
	for _, name := range names {
		if inner, ok := tryMatchFuncCall(s, name); ok {
			return inner, true
		}
	}
	return "", false
}

func tryMatchFuncCall(s, name string) (string, bool) {
	if len(s) < len(name) {
		return "", false
	}
	if !strings.EqualFold(s[:len(name)], name) {
		return "", false
	}
	rest := s[len(name):]
	i := 0
	for i < len(rest) && isSpaceByte(rest[i]) {
		i++
	}
	if i >= len(rest) || rest[i] != '(' {
		return "", false
	}

	depth := 0
	closeIdx := -1
	for j := i; j < len(rest); j++ {
		switch rest[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "", false
			}
			if depth == 0 {
				closeIdx = j
			}
		}
		if closeIdx != -1 {
			break
		}
	}
	if closeIdx == -1 {
		return "", false // never closes -> unbalanced
	}
	if strings.TrimSpace(rest[closeIdx+1:]) != "" {
		return "", false // trailing junk after the call -> not a bare outer call
	}
	return rest[i+1 : closeIdx], true
}

// matchBareSelectSubquery recognizes a scalar-value wrapper of the form
// "(SELECT ...)" — the outer parens must be a single matching pair spanning
// the whole (trimmed) string, and the immediate inner content must start
// with the SELECT keyword. Content beyond that is not inspected here.
func matchBareSelectSubquery(s string) (inner string, ok bool) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return "", false
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return "", false
			}
			if depth == 0 && i != len(s)-1 {
				return "", false // closes early -> not one bare wrapping pair
			}
		}
	}
	if depth != 0 {
		return "", false
	}
	body := strings.TrimSpace(s[1 : len(s)-1])
	lowBody := strings.ToLower(body)
	if !strings.HasPrefix(lowBody, "select") {
		return "", false
	}
	if len(lowBody) > len("select") {
		nc := lowBody[len("select")]
		if !isSpaceByte(nc) && nc != '(' {
			return "", false // e.g. "selectfoo" is not the SELECT keyword
		}
	}
	return body, true
}

// sqlBlockCommentRe matches SQL block comments (/* ... */, including the
// empty /**/), non-greedily so multiple comments in one string are stripped
// individually rather than everything between the first /* and the last */.
var sqlBlockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)

// sideEffectFuncRe matches a MySQL/MariaDB time- or lock-based side-effect
// function name immediately followed by '(', tolerating whitespace
// (including tabs/newlines) in between. Applied only after block comments
// have been stripped, so a comment inserted between the name and '(' — e.g.
// "SLEEP/**/(9999)" — collapses to "SLEEP(9999)" first and still matches.
var sideEffectFuncRe = regexp.MustCompile(`(?i)\b(SLEEP|BENCHMARK|GET_LOCK|RELEASE_LOCK)\s*\(`)

// containsSideEffect flags scalar-wrapper content that carries a
// time/lock side-effect call (SLEEP, BENCHMARK, GET_LOCK, RELEASE_LOCK)
// anywhere inside it, so the int-compare family fails closed on those even
// though content is normally ignored — defense in depth alongside
// recognizeBlindRead's own filtering. Robust to the two obfuscations a
// WAF-evasion tamper is likely to reach for first: whitespace between the
// function name and '(', and a SQL block comment (including the bare
// "/**/") in that same gap. Never panics: regexp matching on a string is
// total, and stripping comments via ReplaceAllString only ever shrinks the
// input, never grows or re-interprets it.
func containsSideEffect(s string) bool {
	return sideEffectFuncRe.MatchString(sqlBlockCommentRe.ReplaceAllString(s, ""))
}

// splitTopLevelArgs splits s on paren-depth-0 commas. Used to pull the
// (pos, length) arguments out of a SUBSTRING/SUBSTR/MID call without caring
// about commas nested inside the ignored <x> argument. Returns nil on
// unbalanced parens.
func splitTopLevelArgs(s string) []string {
	var args []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil
			}
		case ',':
			if depth == 0 {
				args = append(args, s[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil
	}
	return append(args, s[start:])
}

// ---------------------------------------------------------------------------
// recognizeBlindRead recognizes the chain's three read INTENTS by semantic
// token co-occurrence, not by one PoC's exact strings. A real blind-SQLi
// tool (sqlmap, Havij, a hand-rolled script) phrases "does this table name
// end in _posts" or "is there an administrator flag here" a dozen different
// ways — RIGHT(...,6)= vs LIKE '%...' vs SUBSTRING(...)= vs INSTR(...), hex
// literals vs quoted strings, comments/whitespace dropped in by a WAF-evasion
// tamper. The lure fails closed on anything it doesn't recognize, so a
// recognizer that only matches one phrasing silently drops every operator
// whose tool phrases the read differently. Below, each intent is recognized
// by the co-occurrence of its semantic anchors, not by a single verbatim
// signature.
// ---------------------------------------------------------------------------

// pctQuoteRe matches ONLY the two percent-encoded quote characters (%27 = ',
// %22 = "), case-insensitively. Used to loosely URL-decode a cond before
// token matching, so a tool that ships its SQL literal quotes url-encoded
// (e.g. the "_posts" marker as %27_posts%27, or the administrator marker's
// quotes as %22) still surfaces the plain-text token our regexes look for.
//
// Deliberately narrow: a generic %XX-decoder would also decode e.g. "%ad"
// inside the entirely unrelated SQL literal '%administrator%' (LIKE
// wildcard syntax) as byte 0xAD, corrupting "administrator" mid-word and
// causing a real, in-scope phrasing to fail closed. Quotes are the only
// url-encoded form the three intents need to tolerate, so only %27/%22 are
// touched — every other percent-escape (and any malformed one) passes
// through unchanged.
var pctQuoteRe = regexp.MustCompile(`(?i)%27|%22`)

func urlDecodeLoose(s string) string {
	return pctQuoteRe.ReplaceAllStringFunc(s, func(m string) string {
		if strings.EqualFold(m, "%27") {
			return "'"
		}
		return `"`
	})
}

// normalizeReadCond applies the same obfuscation-defeat discipline
// containsSideEffect uses for the side-effect screen: strip SQL block
// comments (so "RIGHT/**/(x,6)" collapses to "RIGHT(x,6)"), loosely
// URL-decode percent-escapes, then lowercase for case-insensitive token
// matching. Every step is total over any input string; this never panics.
func normalizeReadCond(cond string) string {
	stripped := sqlBlockCommentRe.ReplaceAllString(cond, "")
	decoded := urlDecodeLoose(stripped)
	return strings.ToLower(decoded)
}

// ---- Intent 1: table prefix -----------------------------------------------
//
// The tool is reading a table name ending in "_posts" out of the schema
// catalog. Recognized by: a reference to INFORMATION_SCHEMA.TABLES or
// .COLUMNS, co-occurring with a suffix filter expressed as RIGHT(...,6)=,
// LIKE '%_posts', SUBSTRING/SUBSTR/MID(...)=, or INSTR(...,'_posts') —
// matched against the hex marker 0x5f706f737473 ("_posts") or the quoted
// literal (url-encoded forms are collapsed by normalizeReadCond first).

const (
	postsSuffixHex     = "0x5f706f737473"   // hex("_posts")
	postsSuffixLikeHex = "0x255f706f737473" // hex("%_posts") — LIKE wildcard form
	postsSuffixLiteral = `'_posts'`
	postsSuffixLikeLit = `'%_posts'`
)

var (
	infoSchemaRe = regexp.MustCompile(`information_schema\s*\.\s*(tables|columns)`)

	postsRightFilterRe = regexp.MustCompile(
		`\bright\s*\([^)]*,\s*6\s*\)\s*=\s*(` + postsSuffixHex + `|` + postsSuffixLiteral + `)`)
	postsLikeFilterRe = regexp.MustCompile(
		`\blike\s*(` + postsSuffixLikeHex + `|` + postsSuffixLikeLit + `)`)
	postsSubstrFilterRe = regexp.MustCompile(
		`\b(substring|substr|mid)\s*\([^)]*\)\s*=\s*(` + postsSuffixHex + `|` + postsSuffixLiteral + `)`)
	postsInstrFilterRe = regexp.MustCompile(
		`\binstr\s*\([^,]*,\s*(` + postsSuffixHex + `|` + postsSuffixLiteral + `)\s*\)`)
)

// hasPostsSuffixFilter reports whether c (already normalized) contains any
// of the recognized phrasings of the "_posts" suffix filter. Never panics:
// regexp matching over a string is total.
func hasPostsSuffixFilter(c string) bool {
	return postsRightFilterRe.MatchString(c) ||
		postsLikeFilterRe.MatchString(c) ||
		postsSubstrFilterRe.MatchString(c) ||
		postsInstrFilterRe.MatchString(c)
}

// ---- Intent 2: administrator id --------------------------------------------
//
// The tool is reading the first administrator's user id. Recognized by: a
// reference to usermeta/capabilities/user_level/wp_user_roles, co-occurring
// with the administrator marker — the serialized-capabilities fragment
// s:13:"administrator";b:1; (hex or literal, quotes optionally
// url/hex-encoded), or a bare INSTR/LIKE probe against the word
// "administrator".

const (
	adminSerializedHex     = "0x733a31333a2261646d696e6973747261746f72223b623a313b"
	adminSerializedLiteral = `s:13:"administrator";b:1;`
)

var adminInstrLikeRe = regexp.MustCompile(`\b(instr\s*\([^)]*administrator|like\s*'%administrator%')`)

// hasAdminContext reports whether c references one of the columns/values an
// administrator-flag read is scoped against.
func hasAdminContext(c string) bool {
	return strings.Contains(c, "usermeta") ||
		strings.Contains(c, "capabilities") ||
		strings.Contains(c, "user_level") ||
		strings.Contains(c, "wp_user_roles")
}

// hasAdminMarker reports whether c carries the administrator marker in any
// recognized form.
func hasAdminMarker(c string) bool {
	return strings.Contains(c, adminSerializedHex) ||
		strings.Contains(c, adminSerializedLiteral) ||
		adminInstrLikeRe.MatchString(c)
}

// ---- Intent 3: oEmbed cache row id -----------------------------------------
//
// The tool is reading an oembed_cache post's id by its post_name md5.
// Recognized by: post_type= the oembed_cache marker (hex or literal) AND a
// post_name= lookup (hex-encoded ASCII of the md5 hex string, or the md5
// hex string itself as a quoted literal). The md5 is extracted and used as
// a stable cache key so the same underlying object — however the tool
// phrases the lookup — resolves to the same fabricated id.

const (
	oembedCacheHex     = "0x6f656d6265645f6361636865"
	oembedCacheLiteral = `'oembed_cache'`
)

var (
	postTypeOembedRe = regexp.MustCompile(
		`\bpost_type\s*=\s*(` + oembedCacheHex + `|` + oembedCacheLiteral + `)`)

	// postNameHexRe pulls the hex-encoded post_name value (itself the ASCII
	// bytes of an md5 digest) out of a cache-id read predicate, e.g.
	// "post_name=0x666f6f..." -> "666f6f...".
	postNameHexRe = regexp.MustCompile(`\bpost_name\s*=\s*0x([0-9a-f]+)`)
	// postNameLiteralRe matches the same lookup expressed as a plain quoted
	// md5-hex literal instead of a hex-encoded string: post_name='<md5hex>'.
	postNameLiteralRe = regexp.MustCompile(`\bpost_name\s*=\s*'([0-9a-f]{32})'`)
)

// extractCacheKey pulls the underlying md5 out of a post_name lookup,
// regardless of whether the tool hex-encoded it or wrote it as a quoted
// literal, so both phrasings of the same object resolve to the same cache
// key. Never panics: hex.DecodeString errors are handled, not asserted.
func extractCacheKey(c string) (string, bool) {
	if m := postNameHexRe.FindStringSubmatch(c); m != nil {
		if decoded, err := hex.DecodeString(m[1]); err == nil && len(decoded) > 0 {
			return string(decoded), true
		}
		return m[1], true // fallback: raw hex text is still a stable key
	}
	if m := postNameLiteralRe.FindStringSubmatch(c); m != nil {
		return m[1], true
	}
	return "", false
}

// recognizeBlindRead inspects an operator's blind-SQLi read predicate and
// identifies which of the three values the WP gadget chain reads via blind
// SQLi: the live table prefix, the administrator's user id, or an
// oEmbed-cache row id the chain needs to reference consistently across
// requests. Recognition is by semantic-token co-occurrence (see the three
// "Intent" sections above), tolerant of whitespace, SQL comments, case, and
// hex-vs-literal phrasing — not a single verbatim signature — so a tool
// that phrases the same read differently from the exploit's own poc.py is
// still recognized. On a match it returns a fabricated fictionValue standing
// in for the real read; the cache-id case derives a value deterministic
// per-md5 and stores the assignment on sess (inside a single sess.mutate
// call — cacheIDs is a plain map and must never be touched outside one) so
// repeat reads for the same object resolve to the same fabricated id.
// Anything that doesn't match one of the three intents fails closed:
// (fictionValue{}, false), with no distinctive error and no panic on any
// input — every regex match and index is total/guarded.
func recognizeBlindRead(cond string, sess *chainSession) (fictionValue, bool) {
	c := normalizeReadCond(cond)

	// 1. Table prefix.
	if infoSchemaRe.MatchString(c) && hasPostsSuffixFilter(c) {
		return fictionValue{s: "wp_posts"}, true
	}

	// 2. Administrator id.
	if hasAdminContext(c) && hasAdminMarker(c) {
		return fictionValue{n: 1, isInt: true}, true
	}

	// 3. oEmbed cache row id.
	if postTypeOembedRe.MatchString(c) {
		if key, ok := extractCacheKey(c); ok {
			var id int64
			sess.mutate(func(cs *chainSession) {
				if existing, ok := cs.cacheIDs[key]; ok {
					id = existing
					return
				}
				id = 100 + int64(crc32.ChecksumIEEE([]byte(key))%900)
				cs.cacheIDs[key] = id
			})
			return fictionValue{n: id, isInt: true}, true
		}
	}

	return fictionValue{}, false // unrecognized -> fail closed
}
