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
	dashboardTemplate      = mustLoadAdminTemplate("dashboard.html")
	usersTemplate          = mustLoadAdminTemplate("users.html")
	pluginInstallTemplate  = mustLoadAdminTemplate("plugin_install.html")
	pluginUploadTemplate   = mustLoadAdminTemplate("plugin_upload.html")
	pluginActivateTemplate = mustLoadAdminTemplate("plugin_activate.html")
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

// ServeAuthStage answers the S4-S6 admin-page reads the gadget chain's
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
func ServeAuthStage(path string, sess *ChainSession) (status int, headers map[string]string, body string, handled bool) {
	if sess == nil {
		return 0, nil, "", false
	}

	var adminCreated bool
	var username string
	sess.mutate(func(cs *ChainSession) {
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
func servePluginInstallStage(sess *ChainSession) (int, map[string]string, string, bool) {
	nonce := randomHexToken(5) // 5 bytes -> 10 hex chars, matching a real wp_create_nonce() value
	sess.mutate(func(cs *ChainSession) {
		cs.nonce = nonce
	})
	body := strings.ReplaceAll(pluginInstallTemplate, "{{NONCE}}", nonce)
	return 200, nil, body, true
}

// ServeUploadStage is S7: the plugin .zip upload the exploit POSTs to
// /wp-admin/update.php?action=upload-plugin once it has scraped S6's
// upload nonce off plugin-install.php. Gated on sess.adminCreated exactly
// like ServeAuthStage — a request that reaches here without the forge
// chain having minted the fabricated administrator gets handled=false and
// falls through to whatever ordinary behavior the caller serves for this
// path.
//
// The zip's bytes never reach this function. Capturing and storing them is
// the caller's job (internal/protocols/strategies/HTTP/http.go, via
// artifactstore.Write) precisely so this package — which only ever renders
// plausible pages from strings — has no code path that could open, unzip,
// or execute attacker-supplied bytes. All ServeUploadStage does with the
// upload is turn its filename into a plausible plugin slug.
//
// filename is the Content-Disposition filename off the multipart
// "pluginzip" part — entirely attacker-controlled — so it is sanitized
// down to a safe slug (sanitizeSlug) before it goes anywhere near the
// response body or the session. The slug is stored on the session via the
// mandatory mutate accessor (so the later S8 activate hit can echo it
// back) and injected into the install-success page's activation link,
// which poc.py scrapes with
// `href="([^"]*plugins\.php\?action=activate[^"]*)"` then
// html.unescape()s before following it.
func ServeUploadStage(sess *ChainSession, filename string) (status int, headers map[string]string, body string, handled bool) {
	if sess == nil {
		return 0, nil, "", false
	}

	var adminCreated bool
	sess.mutate(func(cs *ChainSession) {
		adminCreated = cs.adminCreated
	})
	if !adminCreated {
		return 0, nil, "", false
	}

	slug := sanitizeSlug(filename)
	nonce := randomHexToken(5) // 5 bytes -> 10 hex chars, same shape as S6's nonce

	sess.mutate(func(cs *ChainSession) {
		cs.uploadOpen = true
		cs.slug = slug
	})

	out := strings.ReplaceAll(pluginUploadTemplate, "{{SLUG}}", html.EscapeString(slug))
	out = strings.ReplaceAll(out, "{{NONCE}}", nonce)
	return 200, nil, out, true
}

// ServeActivateStage is S8: the GET the exploit follows off S7's "Activate
// Plugin" link (/wp-admin/plugins.php?action=activate&plugin=…). Gated on
// sess.uploadOpen — the checkpoint ServeUploadStage sets — so a hit to
// this path without having gone through the upload stage first (no
// session, or a session that never reached uploadOpen) gets
// handled=false. poc.py never inspects this response body (it only checks
// that following the link didn't raise), so plausibility over exactness is
// the bar here.
func ServeActivateStage(sess *ChainSession) (status int, headers map[string]string, body string, handled bool) {
	if sess == nil {
		return 0, nil, "", false
	}

	var uploadOpen bool
	var slug string
	sess.mutate(func(cs *ChainSession) {
		uploadOpen = cs.uploadOpen
		slug = cs.slug
	})
	if !uploadOpen {
		return 0, nil, "", false
	}

	out := strings.ReplaceAll(pluginActivateTemplate, "{{SLUG}}", html.EscapeString(slug))
	return 200, nil, out, true
}

// ServeCommandStage is S9: the response to the exploit's first command POST
// against the fake shell route its uploaded plugin (S7) registers —
// /wp2shell/v1/<random-route>, reached either through WordPress's
// ?rest_route= query-string dispatcher or the /wp-json/ pretty-permalink
// path (both forms are matched by the caller,
// internal/protocols/strategies/HTTP/http.go's isWP2ShellCommandRequest, not
// here). Gated on sess.uploadOpen — the checkpoint ServeUploadStage (S7)
// sets — so a command sent before any plugin was ever uploaded gets
// handled=false and falls through to whatever ordinary behavior the caller
// serves for the route.
//
// We never ran the attacker's plugin: its .zip is captured and stored
// content-addressably (ServeUploadStage's doc comment) but never
// opened/unzipped/executed, so the actual marker string the plugin embeds
// in its own response only exists inside code we never execute — there is
// no way for this function to know it. The marker returned here is
// therefore fabricated. poc.py's own marker-match check will fail against
// it and it will report failure and stop, but by then both artifacts this
// stage exists to bank are already on disk: the uploaded .zip (S7,
// ServeUploadStage) and the raw command body, which the caller captures via
// chainArtifactStore.Write BEFORE this function is even invoked. A failed
// marker check on the exploit's side costs us nothing — the capture already
// happened.
//
// This function does not decode, execute, or otherwise interpret the
// command in any way — it doesn't even receive it. It only reads
// sess.uploadOpen and returns a canned JSON string built from crypto/rand
// hex tokens plus a static, generic output line.
func ServeCommandStage(sess *ChainSession) (status int, headers map[string]string, body string, handled bool) {
	if sess == nil {
		return 0, nil, "", false
	}

	var uploadOpen bool
	sess.mutate(func(cs *ChainSession) {
		uploadOpen = cs.uploadOpen
	})
	if !uploadOpen {
		return 0, nil, "", false
	}

	// 12 bytes -> 24 hex chars: plausible length for an opaque marker
	// string, but fabricated — see the doc comment above for why we can't
	// know the real one. output is a static, generic line in the shape a
	// low-privilege web-server command (e.g. `id`) would actually produce,
	// chosen for plausibility only; it carries no real system information.
	// Both fields are our own fixed-shape trusted strings (hex digits, or a
	// constant with no quote/backslash characters), so direct
	// interpolation into the JSON literal below can't break its structure.
	marker := randomHexToken(12)
	const output = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
	respBody := fmt.Sprintf(`{"marker":"%s","output":"%s"}`, marker, output)
	headers = map[string]string{"Content-Type": "application/json"}
	return 200, headers, respBody, true
}

// sanitizeSlug turns an attacker-controlled upload filename into a safe,
// WordPress-plugin-slug-shaped string: strips a leading path component (a
// filename can't legally carry one, but nothing here trusts that), strips
// a trailing ".zip" (case-insensitive — the only extension poc.py or a
// real WordPress upload ever sends here), then drops every character
// outside [A-Za-z0-9_-] — the same charset a real WP plugin slug is
// confined to. If nothing survives that filter (an empty or
// entirely-symbolic filename), falls back to a random slug rather than
// returning "", so the activation link this feeds always carries a
// non-empty plugin path.
func sanitizeSlug(filename string) string {
	name := filename
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if len(name) >= 4 && strings.EqualFold(name[len(name)-4:], ".zip") {
		name = name[:len(name)-4]
	}

	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	slug := b.String()
	if slug == "" {
		slug = "plugin-" + randomHexToken(3)
	}
	return slug
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
