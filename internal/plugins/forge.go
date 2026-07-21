package plugins

import (
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	reUnion       = regexp.MustCompile(`(?i)UNION\s+(?:ALL\s+)?SELECT\s+`)
	reFields      = regexp.MustCompile(`(?i)[?&]_fields=([^&]*)`)
	reCommentTail = regexp.MustCompile(`(?is)\s*--[\s+].*$`)
	reBoolWrap    = regexp.MustCompile(`(?is)^\s*\d+\)\s*(?:AND|OR)\s*(.+?)\s*--[\s+].*$`)
)

// extractUnionProjection pulls the UNION SELECT column list and the _fields=
// value out of an attacker's injected sub-request path. Input must be
// URL-decoded. ok=false when there is no UNION [ALL] SELECT in the path
// (e.g. a boolean-only injection like "AND (1=1)" is not a UNION and must
// not parse as one).
func extractUnionProjection(pathDecoded string) ([]string, string, bool) {
	loc := reUnion.FindStringIndex(pathDecoded)
	if loc == nil {
		return nil, "", false
	}
	// projection runs from after SELECT to the comment tail (or & param break)
	rest := pathDecoded[loc[1]:]
	if amp := strings.IndexByte(rest, '&'); amp >= 0 {
		rest = rest[:amp]
	}
	rest = reCommentTail.ReplaceAllString(rest, "")
	cols := splitTopLevel(strings.TrimSpace(rest), ',')
	fields := ""
	if m := reFields.FindStringSubmatch(pathDecoded); m != nil {
		fields = m[1]
	}
	return cols, fields, len(cols) > 0
}

// evalProjection evaluates a UNION-projection expression to the string a real
// server renders, IFF it is composed entirely of constants. ok=false (fail
// closed) on any data reference or unmodeled syntax. Input must be URL-decoded.
func evalProjection(expr string) (string, bool) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return "", false
	}
	// NULL -> empty, not-ok handled by COALESCE; bare NULL is a non-value.
	if strings.EqualFold(s, "NULL") {
		return "", false
	}
	// single-quoted string literal
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' && strings.Count(s, "'") == 2 {
		return s[1 : len(s)-1], true
	}
	// hex literal 0x..
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		if b, err := hex.DecodeString(s[2:]); err == nil {
			return string(b), true
		}
		return "", false
	}
	// integer
	if _, err := strconv.Atoi(s); err == nil {
		return s, true
	}
	// function call NAME(...)
	if name, args, ok := parseCall(s); ok {
		switch strings.ToUpper(name) {
		case "CONCAT":
			var b strings.Builder
			for _, a := range args {
				v, vok := evalProjection(a)
				if !vok {
					return "", false
				}
				b.WriteString(v)
			}
			return b.String(), true
		case "HEX":
			if len(args) != 1 {
				return "", false
			}
			v, vok := evalProjection(args[0])
			if !vok {
				return "", false
			}
			return strings.ToUpper(hex.EncodeToString([]byte(v))), true
		case "CAST", "CONVERT":
			inner := args[0]
			if i := findTopLevelAS(inner); i >= 0 {
				inner = inner[:i]
			}
			return evalProjection(strings.TrimSpace(inner))
		case "COALESCE", "IFNULL":
			for _, a := range args {
				if v, vok := evalProjection(a); vok && v != "" {
					return v, true
				}
			}
			return "", true // all null/empty -> ''
		}
		return "", false // unmodeled function -> fail closed
	}
	// scalar subquery over a constant: (SELECT <const>)
	if strings.HasPrefix(strings.ToUpper(s), "(SELECT ") && strings.HasSuffix(s, ")") {
		inner := strings.TrimSpace(s[len("(SELECT ") : len(s)-1])
		// reject if it references a table/column (FROM / identifier)
		if strings.Contains(strings.ToUpper(inner), " FROM ") {
			return "", false
		}
		return evalProjection(inner)
	}
	// one wrapping-paren layer: (EXPR)
	if len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		return evalProjection(strings.TrimSpace(s[1 : len(s)-1]))
	}
	return "", false // identifier / unmodeled -> fail closed
}

// parseCall parses NAME(arg,arg,...) with paren/quote-aware arg splitting.
func parseCall(s string) (string, []string, bool) {
	i := strings.IndexByte(s, '(')
	if i <= 0 || s[len(s)-1] != ')' {
		return "", nil, false
	}
	name := strings.TrimSpace(s[:i])
	for _, r := range name { // name must be a bare identifier
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return "", nil, false
		}
	}
	inner := s[i+1 : len(s)-1]
	return name, splitTopLevel(inner, ','), true
}

// findTopLevelAS returns the index of the last case-insensitive "AS" keyword
// at paren depth 0, honoring word boundaries (so it matches both `expr AS
// type` and `expr)AS type` — real UNION-injection markers omit the space
// before AS when there is a closing paren right before it). Returns -1 if
// no top-level "AS" token is present.
func findTopLevelAS(s string) int {
	depth, inStr, last := 0, false, -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inStr = !inStr
		case inStr:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && i+1 < len(s) && (c == 'a' || c == 'A') && (s[i+1] == 's' || s[i+1] == 'S'):
			prevOK := i == 0 || !isIdentByte(s[i-1])
			nextOK := i+2 >= len(s) || !isIdentByte(s[i+2])
			if prevOK && nextOK {
				last = i
			}
		}
	}
	return last
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// wpPostsRestFields maps the 23 wp_posts columns (UNION order) to REST field
// paths. "" = column with no REST surface (dropped). Nested title/guid etc.
// are rendered as {"rendered": <val>} objects to match the controller output.
var wpPostsRestFields = []string{
	"id", "author", "date", "date_gmt", "content", "title", "excerpt", "status",
	"comment_status", "ping_status", "password", "slug", "", "", "modified",
	"modified_gmt", "", "parent", "guid", "menu_order", "type", "", "",
}
var wpRenderedFields = map[string]bool{"title": true, "content": true, "excerpt": true, "guid": true}

// assembleForgedRow maps an attacker's UNION SELECT projection onto the
// wp_posts REST field order and builds the forged post object the plugin
// serves back — the inert response that confirms the SQLi to the operator's
// tool. ok=false only when nothing at all evaluated (a fully-failed
// projection is not a forge); a single non-marker column failing to evaluate
// just renders as empty (inert), it does not fail the whole row.
func assembleForgedRow(cols []string, fields string) (map[string]any, bool) {
	row := map[string]any{}
	for i, expr := range cols {
		if i >= len(wpPostsRestFields) {
			break
		}
		f := wpPostsRestFields[i]
		if f == "" {
			continue
		}
		v, ok := evalProjection(expr)
		if !ok {
			// a data reference in a NON-marker slot renders as empty (real WP
			// returns the column value; we serve inert empty). The marker slot
			// (title/slug) failing is fatal — the tool would not confirm.
			v = ""
		}
		if wpRenderedFields[f] {
			row[f] = map[string]any{"rendered": v}
		} else {
			row[f] = v
		}
	}
	// _fields projection filter
	if fields != "" {
		keep := map[string]bool{}
		for _, k := range strings.Split(fields, ",") {
			keep[strings.TrimSpace(k)] = true
		}
		for k := range row {
			if !keep[k] {
				delete(row, k)
			}
		}
	}
	// require SOMETHING evaluated (a fully-failed projection is not a forge)
	return row, len(row) > 0
}

// booleanElement gives a boolean-blind injection its content differential:
// for a literal-true condition it returns the "row present" batch element
// (X-WP-Total:1, a minimal forged row); for literal-false the "row absent"
// element (X-WP-Total:0, empty body). injectedCond is the raw wrapper the
// attacker sends, e.g. "0) AND (1=1)-- -" — the "<n>) AND|OR <cond> -- -"
// shape is stripped here to isolate <cond>, but the actual truth evaluation
// is fully delegated to the shipped evalLiteralBool (fail-closed on any
// non-constant condition); this function does not reimplement that logic.
// ok=false when the wrapper doesn't match or the condition isn't a literal
// constant — the caller falls through in either case.
func booleanElement(injectedCond string) (json.RawMessage, bool) {
	m := reBoolWrap.FindStringSubmatch(injectedCond)
	if m == nil {
		return nil, false
	}
	val, isLit := evalLiteralBool(strings.TrimSpace(m[1])) // reuse shipped constant evaluator
	if !isLit {
		return nil, false
	}
	if val {
		return json.RawMessage(`{"body":[{"id":1,"status":"publish"}],"status":200,"headers":{"X-WP-Total":1,"X-WP-TotalPages":1,"Allow":"GET"}}`), true
	}
	return json.RawMessage(`{"body":[],"status":200,"headers":{"X-WP-Total":0,"X-WP-TotalPages":0,"Allow":"GET"}}`), true
}

// splitTopLevel splits on sep at paren depth 0, ignoring sep inside '...'.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, inStr, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inStr = !inStr
		case inStr:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == sep && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}
