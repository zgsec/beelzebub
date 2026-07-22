package plugins

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Task 6: S4-S6 admin-page templates. Exercises serveAuthStage against the
// exploit's actual checks (poc.py): S4 needs a Set-Cookie the cookie jar
// will carry, S5 needs the raw page to contain sess.username (poc.py does
// `if username not in users_page: abort`), S6 needs
// `name="_wpnonce" value="([^"]+)"` to match and that same value must be
// readable back off the session for a later upload step to check against.
// ---------------------------------------------------------------------------

// armedAdminSession returns a chainSession that has already cleared T4's
// forge checkpoint (adminCreated=true) with the given username, i.e. the
// state serveAuthStage requires before it will answer anything.
func armedAdminSession(username string) *chainSession {
	sess := newChainSession()
	sess.mutate(func(cs *chainSession) {
		cs.adminCreated = true
		cs.username = username
	})
	return sess
}

func TestServeAuthStage_S4_LoginSetsPlausibleCookie(t *testing.T) {
	sess := armedAdminSession("w2s_probe")

	status, headers, body, handled := serveAuthStage("/wp-login.php", sess)
	if !handled {
		t.Fatalf("S4 (wp-login.php): handled = false, want true")
	}
	if status != 200 {
		t.Errorf("S4 status = %d, want 200", status)
	}
	setCookie, ok := headers["Set-Cookie"]
	if !ok {
		t.Fatalf("S4: no Set-Cookie header in %v", headers)
	}
	name := setCookie
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	if !strings.HasPrefix(name, "wordpress_logged_in_") {
		t.Errorf("Set-Cookie name = %q, want prefix wordpress_logged_in_", name)
	}
	if body == "" {
		t.Errorf("S4: dashboard body is empty")
	}

	// /wp-admin/ is documented as an equivalent S4 trigger.
	status2, headers2, _, handled2 := serveAuthStage("/wp-admin/", sess)
	if !handled2 || status2 != 200 || headers2["Set-Cookie"] == "" {
		t.Errorf("S4 (/wp-admin/): handled=%v status=%d headers=%v, want handled+200+cookie", handled2, status2, headers2)
	}
}

func TestServeAuthStage_S5_UsersPageContainsUsername(t *testing.T) {
	sess := armedAdminSession("w2s_probe")

	status, _, body, handled := serveAuthStage("/wp-admin/users.php", sess)
	if !handled {
		t.Fatalf("S5: handled = false, want true")
	}
	if status != 200 {
		t.Errorf("S5 status = %d, want 200", status)
	}
	if !strings.Contains(body, "w2s_probe") {
		t.Errorf("S5 body does not contain the session username w2s_probe")
	}
}

var wpNonceRe = regexp.MustCompile(`name="_wpnonce" value="([0-9a-f]{10})"`)

func TestServeAuthStage_S6_PluginInstallNonceMatchesAndPersists(t *testing.T) {
	sess := armedAdminSession("w2s_probe")

	// Real trigger carries the tab=upload query string.
	status, _, body, handled := serveAuthStage("/wp-admin/plugin-install.php?tab=upload", sess)
	if !handled {
		t.Fatalf("S6: handled = false, want true")
	}
	if status != 200 {
		t.Errorf("S6 status = %d, want 200", status)
	}

	m := wpNonceRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("S6 body does not match name=\"_wpnonce\" value=\"([0-9a-f]{10})\"; body: %s", body)
	}
	bodyNonce := m[1]

	var storedNonce string
	sess.mutate(func(cs *chainSession) {
		storedNonce = cs.nonce
	})
	if storedNonce == "" {
		t.Fatalf("S6: sess.nonce was never set")
	}
	if storedNonce != bodyNonce {
		t.Errorf("S6: sess.nonce = %q, body nonce = %q, want equal", storedNonce, bodyNonce)
	}
}

// maliciousUsername is a username that carries HTML metacharacters and
// Set-Cookie-hostile characters (';', '|', CR/LF) in one shot, chosen to
// break out of the S5 users.php table-row markup and, if unsanitized, to
// inject extra cookie attributes / split the response headers.
const maliciousUsername = "</td></tr><script>alert(1)</script>"

func TestServeAuthStage_S4_LoginCookieSanitizesUsername(t *testing.T) {
	sess := armedAdminSession("w2s_probe")
	_, headers, _, handled := serveAuthStage("/wp-login.php", sess)
	if !handled {
		t.Fatalf("S4: handled = false, want true")
	}
	setCookie := headers["Set-Cookie"]
	if !strings.Contains(setCookie, "w2s_probe") {
		t.Errorf("S4: benign username w2s_probe missing verbatim from Set-Cookie: %q", setCookie)
	}

	sess2 := armedAdminSession(maliciousUsername)
	_, headers2, _, handled2 := serveAuthStage("/wp-login.php", sess2)
	if !handled2 {
		t.Fatalf("S4 (malicious): handled = false, want true")
	}
	setCookie2, ok := headers2["Set-Cookie"]
	if !ok {
		t.Fatalf("S4 (malicious): no Set-Cookie header in %v", headers2)
	}
	// The cookie value is itself pipe-delimited (username|expiration|
	// token|hmac, see fabricateAuthCookieValue) and its attribute suffix
	// ("; path=/; HttpOnly") legitimately carries ';' — those are the
	// cookie's OWN structure, not attacker input. Isolate the
	// attacker-controlled username field (the first '|'-delimited segment
	// after "name=") and check only that for the forbidden characters, so
	// this test proves the malicious username can't inject a fake extra
	// field or break out of the field/attribute structure.
	value := setCookie2
	if i := strings.IndexByte(value, '='); i >= 0 {
		value = value[i+1:]
	}
	usernameField := value
	if i := strings.IndexByte(usernameField, '|'); i >= 0 {
		usernameField = usernameField[:i]
	} else {
		t.Fatalf("S4 (malicious): cookie value %q has no '|' field delimiter, want username|expiration|token|hmac", value)
	}
	for _, bad := range []string{"<", ">", ";", "|", "\r", "\n"} {
		if strings.Contains(usernameField, bad) {
			t.Errorf("S4 (malicious): cookie username field %q contains forbidden character %q", usernameField, bad)
		}
	}
	// And the full cookie value must still parse into exactly 4
	// '|'-delimited fields — i.e. the sanitized username couldn't smuggle
	// in an extra field boundary.
	if got := strings.Count(value, "|"); got != 3 {
		t.Errorf("S4 (malicious): cookie value has %d '|' delimiters, want exactly 3 (4 fields): %q", got, value)
	}
}

func TestServeAuthStage_S5_UsersPageEscapesMaliciousUsername(t *testing.T) {
	sess := armedAdminSession(maliciousUsername)
	status, _, body, handled := serveAuthStage("/wp-admin/users.php", sess)
	if !handled {
		t.Fatalf("S5 (malicious): handled = false, want true")
	}
	if status != 200 {
		t.Errorf("S5 (malicious) status = %d, want 200", status)
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("S5 (malicious): body contains an unescaped, executable <script> tag")
	}
	if strings.Contains(body, "</td></tr><script>") {
		t.Errorf("S5 (malicious): body contains an unescaped table-row breakout")
	}
	if !strings.Contains(body, html.EscapeString(maliciousUsername)) {
		t.Errorf("S5 (malicious): body does not contain the HTML-escaped username form")
	}
}

func TestServeAuthStage_Gate_RequiresArmedSession(t *testing.T) {
	paths := []string{
		"/wp-login.php",
		"/wp-admin/users.php",
		"/wp-admin/plugin-install.php?tab=upload",
	}

	t.Run("nil session", func(t *testing.T) {
		for _, p := range paths {
			if _, _, _, handled := serveAuthStage(p, nil); handled {
				t.Errorf("path %q: handled = true with sess=nil, want false", p)
			}
		}
	})

	t.Run("session never reached adminCreated", func(t *testing.T) {
		sess := newChainSession() // adminCreated defaults to false
		for _, p := range paths {
			if _, _, _, handled := serveAuthStage(p, sess); handled {
				t.Errorf("path %q: handled = true with adminCreated=false, want false", p)
			}
		}
	})

	t.Run("unrecognized path even when armed", func(t *testing.T) {
		sess := armedAdminSession("w2s_probe")
		if _, _, _, handled := serveAuthStage("/wp-admin/plugins.php", sess); handled {
			t.Errorf("unrecognized path: handled = true, want false")
		}
	})
}

// forbiddenOpsecTells are strings that must never appear in a served
// template: the oracle-diff capture host/title tells, the real created
// username and password captured in
// tools/oracle-diff/wordpress-6.9.4/chain_capture.jsonl, and the real
// sensor persona hostname — none of which belong in this PUBLIC fork.
var forbiddenOpsecTells = []string{
	"oracle",
	"127.0.0.1:8099",
	"w2s_2f43",
	"marloweanalytics",
}

func TestAdminTemplates_OPSEC_NoOracleOrCaptureTells(t *testing.T) {
	named := map[string]string{
		"dashboard.html":      dashboardTemplate,
		"users.html":          usersTemplate,
		"plugin_install.html": pluginInstallTemplate,
	}
	for name, tpl := range named {
		if tpl == "" {
			t.Fatalf("%s: template embedded empty — go:embed likely broken", name)
		}
		for _, tell := range forbiddenOpsecTells {
			if strings.Contains(strings.ToLower(tpl), strings.ToLower(tell)) {
				t.Errorf("%s: template contains forbidden OPSEC tell %q", name, tell)
			}
		}
	}
}

// emailTellRe flags a hardcoded admin@ or a@example.com style address —
// static filler that would read as a real captured account rather than a
// generic template, distinct from the {{USERNAME}}@example.com pattern
// which only ever renders with the attacker's own forged (w2s_*) username.
var emailTellRe = regexp.MustCompile(`\b(admin|a)@example\.com\b`)

func TestAdminTemplates_OPSEC_NoHardcodedAdminEmail(t *testing.T) {
	named := map[string]string{
		"dashboard.html":      dashboardTemplate,
		"users.html":          usersTemplate,
		"plugin_install.html": pluginInstallTemplate,
	}
	for name, tpl := range named {
		if emailTellRe.MatchString(tpl) {
			t.Errorf("%s: template contains a hardcoded admin@/a@example.com email", name)
		}
	}

	// Also check the rendered S5 body for a realistic (non-"admin") forged
	// username, confirming substitution never produces the forbidden shape.
	sess := armedAdminSession("w2s_probe")
	_, _, body, _ := serveAuthStage("/wp-admin/users.php", sess)
	if emailTellRe.MatchString(body) {
		t.Errorf("rendered users.php body contains a hardcoded admin@/a@example.com email: %s", body)
	}
}
