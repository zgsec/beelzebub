package plugins

import (
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
//     itself (or wraps) a time/side-effect call — SLEEP(...),
//     BENCHMARK(...), a SELECT SLEEP(...) subquery — never matches this
//     family and fails closed, as defense in depth alongside
//     recognizeBlindRead's own filtering.
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

// containsSideEffect flags scalar-wrapper content that carries a
// time/side-effect call (SLEEP, BENCHMARK) anywhere inside it, so the
// int-compare family fails closed on those even though content is normally
// ignored — defense in depth alongside recognizeBlindRead's own filtering.
func containsSideEffect(s string) bool {
	low := strings.ToLower(s)
	return strings.Contains(low, "sleep(") || strings.Contains(low, "benchmark(")
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

// The three blind-read signatures below are lifted verbatim from the
// exploit's own subqueries: a hex-encoded table-suffix probe against
// INFORMATION_SCHEMA.TABLES, a hex-encoded serialized-capabilities probe
// against usermeta, and a hex-encoded (post_type, post_name) lookup against
// the oEmbed cache row the chain minted. Matching is substring-based and
// case-insensitive — these are literal hex/string signatures the exploit
// emits verbatim, not a general SQL parse.
const (
	// hexPostsSuffix is 0x5f706f737473, the hex encoding of "_posts".
	hexPostsSuffix = "0x5f706f737473"
	// hexAdminFlag is the hex encoding of the serialized capabilities
	// fragment s:13:"administrator";b:1;
	hexAdminFlag = "0x733a31333a2261646d696e6973747261746f72223b623a313b"
	// hexOembedCache is the hex encoding of the post_type "oembed_cache".
	hexOembedCache = "0x6f656d6265645f6361636865"
)

// rePostName pulls the hex-encoded post_name value (itself the ASCII bytes
// of an md5 digest) out of a cache-id read predicate, e.g.
// "post_name=0x666f6f..." -> "666f6f...".
var rePostName = regexp.MustCompile(`(?i)post_name\s*=\s*0x([0-9a-f]+)`)

// recognizeBlindRead inspects an operator's blind-SQLi read predicate and
// identifies which of the three values the WP gadget chain reads via blind
// SQLi (from the exploit's own poc.py): the live table prefix, the
// administrator's user id, or one of the three oEmbed-cache row ids the
// chain needs to reference consistently across requests. On a match it
// returns a fabricated fictionValue standing in for the real read; the
// cache-id case derives a value deterministic per-md5 and stores the
// assignment on sess so repeat reads for the same object resolve to the
// same fabricated id. Anything that doesn't match one of the three exact
// signatures fails closed: (fictionValue{}, false) — this function never
// guesses at an unrecognized predicate shape.
func recognizeBlindRead(cond string, sess *chainSession) (fictionValue, bool) {
	c := strings.ToLower(cond)

	// 1. Table prefix: SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES ...
	// RIGHT(TABLE_NAME,6)=0x5f706f737473 ("_posts").
	if strings.Contains(c, "information_schema.tables") && strings.Contains(c, hexPostsSuffix) {
		return fictionValue{s: "wp_posts"}, true
	}

	// 2. Administrator id: usermeta/capabilities row carrying the serialized
	// s:13:"administrator";b:1; flag.
	if (strings.Contains(c, "usermeta") || strings.Contains(c, "capabilities")) && strings.Contains(c, hexAdminFlag) {
		return fictionValue{n: 1, isInt: true}, true
	}

	// 3. oEmbed cache row id: post_type=0x6f656d6265645f6361636865
	// ("oembed_cache") AND post_name=0x<hex-encoded md5>.
	if strings.Contains(c, hexOembedCache) {
		if m := rePostName.FindStringSubmatch(c); m != nil {
			key := m[1] // hex-encoded md5, lowercased by c already being lowercase
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
