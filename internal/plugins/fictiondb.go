package plugins

import (
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
