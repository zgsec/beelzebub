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

var (
	reCharLen = regexp.MustCompile(`(?i)^\s*CHAR_LENGTH\s*\(.*\)\s*>=\s*(\d+)\s*$`)
	reAscii   = regexp.MustCompile(`(?i)^\s*ASCII\s*\(\s*SUBSTRING\s*\(.*,\s*(\d+)\s*,\s*1\s*\)\s*\)\s*>=\s*(\d+)\s*$`)
	reGe      = regexp.MustCompile(`(?i)^\s*COALESCE\s*\(.*\)\s*>=\s*(\d+)\s*$`) // getint: COALESCE((<subquery>),0) >= N
)

// evalBlindPredicate evaluates an operator's blind-SQLi read predicate
// against a fabricated value, so an inert lure can answer blind reads
// consistently without decoding or executing the inner subquery. It
// recognizes exactly three predicate shapes taken from the exploit's own
// oracle helpers (CHAR_LENGTH length probe, ASCII/SUBSTRING byte probe,
// and a generic COALESCE(...) >= N integer probe). Anything else fails
// closed: (false, false).
func evalBlindPredicate(cond string, val fictionValue) (bool, bool) {
	c := strings.TrimSpace(cond)

	if m := reCharLen.FindStringSubmatch(c); m != nil {
		n, _ := strconv.Atoi(m[1])
		return len(val.s) >= n, true
	}

	if m := reAscii.FindStringSubmatch(c); m != nil {
		pos, _ := strconv.Atoi(m[1])
		thr, _ := strconv.Atoi(m[2])
		if pos < 1 || pos > len(val.s) {
			return 0 >= thr, true // out of range -> byte 0
		}
		return int(val.s[pos-1]) >= thr, true
	}

	if val.isInt {
		if m := reGe.FindStringSubmatch(c); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			return val.n >= n, true
		}
	}

	return false, false // unrecognized -> fail closed
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
