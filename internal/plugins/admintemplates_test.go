package plugins

import (
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
