package plugins

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"fmt"
	"html"
	"strings"
	"time"
)

// Admin-page templates (S4-S6) for the WP batch/v1 gadget chain. Once the
// forge stages (T1-T4) have minted a fabricated administrator on the
// session, the exploit itself never touches SQL again: it logs in over
// wp-login.php, re-reads wp-admin/users.php to confirm the account exists,
// then reads wp-admin/plugin-install.php?tab=upload to scrape an upload
// nonce before POSTing its plugin zip. These three responses are what let
// that back half of the chain believe it holds a real authenticated
// session.
//
// Structural reference only: tools/oracle-diff/wordpress-6.9.4/chain_capture.jsonl
// (seq 93 wp-login.php dashboard, seq 94 users.php, seq 95
// plugin-install.php?tab=upload) against a real WordPress 6.9.4 instance —
// captures truncated at 40KB, dominated by inline per-page CSS/font-face
// blocks that never reach the actual admin-menu/list-table markup. The
// templates below are hand-authored to the same shell (doctype, wp-toolbar
// html class, ajaxurl/pagenow JS globals, external load-styles.php /
// load-scripts.php refs instead of inlined CSS/JS, #wpadminbar +
// #adminmenu chrome, #wpbody-content > .wrap) at a few KB instead of ~90KB,
// with every host/site identifier from the capture (title, IP:port)
// replaced by a neutral placeholder — this is a public fork, and none of
// that infra detail belongs in it.
//
//go:embed templates/*.html
var adminTemplatesFS embed.FS

var (
	dashboardTemplate     = mustLoadAdminTemplate("dashboard.html")
	usersTemplate         = mustLoadAdminTemplate("users.html")
	pluginInstallTemplate = mustLoadAdminTemplate("plugin_install.html")
)

// mustLoadAdminTemplate reads an embedded template by name. The three names
// used above are baked into the binary at build time via the go:embed
// directive, so a read failure here can only mean the embed itself is
// broken (a build-time-visible condition, not a runtime one) — fail soft to
// "" rather than panic, matching the fail-soft convention
// OLLAMA/ollama_modelmeta.go's loadModelMeta already uses for baked assets:
// an empty template degrades the served page, it doesn't take the honeypot
// down.
func mustLoadAdminTemplate(name string) string {
	raw, err := adminTemplatesFS.ReadFile("templates/" + name)
	if err != nil {
		return ""
	}
	return string(raw)
}

// serveAuthStage answers the S4-S6 admin-page reads the gadget chain's
// exploit performs once it believes it holds a freshly forged
// administrator:
//
//   - S4 (wp-login.php POST, or a direct wp-admin/ hit) — sets a plausible
//     wordpress_logged_in_* cookie so the exploit's cookie jar carries
//     credentials for every subsequent request, and returns a dashboard.
//   - S5 (wp-admin/users.php) — returns a user list whose one row carries
//     sess.username, because the exploit greps the raw page for that exact
//     string and aborts if it's absent.
//   - S6 (wp-admin/plugin-install.php[?tab=upload]) — generates a fresh
//     10-hex nonce, stores it on the session (so the later upload step can
//     be checked against it), and injects it into the upload form the
//     exploit scrapes with `name="_wpnonce" value="([^"]+)"`.
//
// Every stage is gated on sess.adminCreated — the checkpoint T4's forge
// chain sets once it has actually minted the fabricated administrator — so
// an attacker who hits these paths without having driven the chain that far
// (no session, or a session that never reached adminCreated) gets
// handled=false and falls through to whatever ordinary behavior the caller
// serves for an unauthenticated admin-page request, instead of a free
// session.
func serveAuthStage(path string, sess *chainSession) (status int, headers map[string]string, body string, handled bool) {
	if sess == nil {
		return 0, nil, "", false
	}

	var adminCreated bool
	var username string
	sess.mutate(func(cs *chainSession) {
		adminCreated = cs.adminCreated
		username = cs.username
	})
	if !adminCreated {
		return 0, nil, "", false
	}

	// path may arrive with a query string attached (plugin-install.php's
	// real trigger is ?tab=upload) — every stage below matches on the path
	// component alone.
	p := path
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}

	switch p {
	case "/wp-login.php", "/wp-admin/":
		return serveLoginStage(username)
	case "/wp-admin/users.php":
		return serveUsersStage(username)
	case "/wp-admin/plugin-install.php":
		return servePluginInstallStage(sess)
	default:
		return 0, nil, "", false
	}
}

// serveLoginStage is S4: a fabricated wordpress_logged_in_* auth cookie plus
// a dashboard body. poc.py never parses this body — it proceeds straight to
// wp-admin/users.php after the login POST — so the cookie is the only part
// that has to function; the dashboard is served for realism, not because
// anything downstream inspects it.
func serveLoginStage(username string) (int, map[string]string, string, bool) {
	cookieName := "wordpress_logged_in_" + randomHexToken(4) // 8 hex chars, real WP's COOKIEHASH-derived suffix
	cookieValue := fabricateAuthCookieValue(sanitizeCookieUsername(username))
	headers := map[string]string{
		"Set-Cookie": cookieName + "=" + cookieValue + "; path=/; HttpOnly",
	}
	return 200, headers, dashboardTemplate, true
}

// sanitizeCookieUsername strips sess.username down to the charset a real WP
// username is already confined to ([A-Za-z0-9_.-], per the w2s_<hex> shape
// the forge chain mints) before it goes anywhere near a Set-Cookie value. A
// cookie value can't legally contain CR/LF (header/response splitting),
// ';' (the WordPress cookie's own attribute delimiter), or '|' (this
// cookie's own field delimiter, see fabricateAuthCookieValue) — an attacker
// who sets username to any of those on the forge path must not be able to
// inject headers or corrupt the cookie's own field structure. Unlike
// html.EscapeString (used for the S5 HTML body), escaping isn't the right
// tool for a cookie value, so this drops rather than encodes.
func sanitizeCookieUsername(username string) string {
	var b strings.Builder
	b.Grow(len(username))
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fabricateAuthCookieValue mimics the shape of a real WordPress auth
// cookie's value: username|expiration|token|hmac, pipe-delimited. Nothing
// downstream parses or validates it — the exploit's cookie jar only needs a
// value to carry — so plausibility, not cryptographic correctness, is the
// bar. Caller (serveLoginStage) is responsible for sanitizing username
// first; this function does not re-sanitize.
func fabricateAuthCookieValue(username string) string {
	expiry := time.Now().Add(48 * time.Hour).Unix()
	token := randomHexToken(20)
	hmacPart := randomHexToken(20)
	return fmt.Sprintf("%s|%d|%s|%s", username, expiry, token, hmacPart)
}

// serveUsersStage is S5: the users.php list with sess.username injected
// into the one row the exploit's raw substring check needs to see.
// sess.username is attacker-controlled all the way from the forge chain
// (T1-T4), so it's HTML-escaped before substitution — a benign w2s_<hex>
// username (alphanumeric+underscore) is unchanged by escaping, so poc.py's
// raw substring check still matches, but a username carrying HTML
// metacharacters can't break out of the table row and corrupt the rest of
// the served page.
func serveUsersStage(username string) (int, map[string]string, string, bool) {
	body := strings.ReplaceAll(usersTemplate, "{{USERNAME}}", html.EscapeString(username))
	return 200, nil, body, true
}

// servePluginInstallStage is S6: generates the 10-hex upload nonce the
// exploit scrapes with `name="_wpnonce" value="([^"]+)"`, stores it on the
// session via the mandatory mutate accessor (so a later upload step in this
// same chain can be checked against it), and injects it into the upload
// form.
func servePluginInstallStage(sess *chainSession) (int, map[string]string, string, bool) {
	nonce := randomHexToken(5) // 5 bytes -> 10 hex chars, matching a real wp_create_nonce() value
	sess.mutate(func(cs *chainSession) {
		cs.nonce = nonce
	})
	body := strings.ReplaceAll(pluginInstallTemplate, "{{NONCE}}", nonce)
	return 200, nil, body, true
}

// randomHexToken returns hex.EncodeToString of n crypto/rand bytes (2n hex
// characters). Mirrors historystore's newCookie (cookie_session_store.go);
// a crypto/rand failure is as unrecoverable here as it is there.
func randomHexToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("admintemplates: rand.Read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
