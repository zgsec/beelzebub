package tracer

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// --- ClientHello byte builder (oracle fixtures) ------------------------------
//
// A minimal TLS ClientHello encoder used ONLY to author oracle fixtures with
// exact, known wire fields. We deliberately do NOT reuse crypto/tls's marshaller:
// the whole point of the oracle is to control the *wire* bytes (e.g. a
// legacy_version that differs from the supported_versions extension) so we can
// prove what each fingerprint path actually reads off the wire.

type chExtension struct {
	typ  uint16
	data []byte
}

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

// supportedVersionsExt builds a supported_versions (0x002b) ClientHello extension.
func supportedVersionsExt(versions ...uint16) chExtension {
	body := []byte{byte(len(versions) * 2)}
	for _, v := range versions {
		body = append(body, u16(v)...)
	}
	return chExtension{typ: 0x002b, data: body}
}

// buildClientHello assembles a complete TLS handshake record carrying a
// ClientHello with the given wire legacy_version, cipher list, and extensions.
func buildClientHello(legacyVersion uint16, ciphers []uint16, exts []chExtension) []byte {
	var body []byte
	body = append(body, u16(legacyVersion)...) // legacy_version (WIRE field)
	body = append(body, make([]byte, 32)...)   // random (zeroed — irrelevant to JA3/JA4)
	body = append(body, 0x00)                  // legacy_session_id: empty

	var cs []byte
	for _, c := range ciphers {
		cs = append(cs, u16(c)...)
	}
	body = append(body, u16(uint16(len(cs)))...) // cipher_suites length
	body = append(body, cs...)

	body = append(body, 0x01, 0x00) // legacy_compression_methods: [null]

	var ext []byte
	for _, e := range exts {
		ext = append(ext, u16(e.typ)...)
		ext = append(ext, u16(uint16(len(e.data)))...)
		ext = append(ext, e.data...)
	}
	body = append(body, u16(uint16(len(ext)))...) // extensions length
	body = append(body, ext...)

	// handshake header: msg_type(1)=client_hello(0x01) + uint24 length
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// record header: handshake(0x16) + legacy_record_version 0x0301 + uint16 length
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

// stdlibClientHelloInfo replays raw ClientHello bytes into a real tls.Server and
// returns the *tls.ClientHelloInfo the stdlib parser produced — exactly what the
// HTTP strategy's GetConfigForClient receives in production.
func stdlibClientHelloInfo(t *testing.T, raw []byte) *tls.ClientHelloInfo {
	t.Helper()
	cli, srv := net.Pipe()
	t.Cleanup(func() { _ = cli.Close() })
	got := make(chan *tls.ClientHelloInfo, 1)
	go func() {
		s := tls.Server(srv, &tls.Config{
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				got <- h
				return nil, nil
			},
		})
		_ = s.Handshake()
		_ = s.Close()
	}()
	go func() { _, _ = cli.Write(raw) }()
	select {
	case h := <-got:
		return h
	case <-time.After(2 * time.Second):
		t.Fatal("stdlib never invoked GetConfigForClient — ClientHello failed to parse")
		return nil
	}
}

// TestStdlibPath_CannotReadWireLegacyVersion characterizes the BUST (now proven):
// tls.ClientHelloInfo has NO wire legacy_version field, so ComputeJA3FromClientHello
// reconstructs it from supported_versions and emits 771 even though the wire said
// 769. This test PASSES — it pins the structural limitation that motivates the raw
// parser, and should be deleted only when the stdlib JA3 path is retired.
func TestStdlibPath_CannotReadWireLegacyVersion(t *testing.T) {
	raw := buildClientHello(0x0301, []uint16{0x1301}, []chExtension{supportedVersionsExt(0x0303)})
	hello := stdlibClientHelloInfo(t, raw)
	if got := ja3String(hello); !strings.HasPrefix(got, "771,") {
		t.Fatalf("expected stdlib to reconstruct 771 (the documented gap); got %q", got)
	}
}

// TestParseClientHello_ReadsWireLegacyVersion is the GREEN target: the raw parser
// must read the WIRE legacy_version (769) and emit a canonical JA3 string.
func TestParseClientHello_ReadsWireLegacyVersion(t *testing.T) {
	raw := buildClientHello(0x0301, []uint16{0x1301}, []chExtension{supportedVersionsExt(0x0303)})
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	const want = "769,4865,43,," // wire legacy_version 769, cipher 4865, ext 43 (supported_versions)
	if got := ch.JA3(); got != want {
		t.Fatalf("raw JA3:\n  got  %q\n  want %q", got, want)
	}
}

// supportedGroupsExt builds a supported_groups (0x000a) extension.
func supportedGroupsExt(groups ...uint16) chExtension {
	body := u16(uint16(len(groups) * 2))
	for _, g := range groups {
		body = append(body, u16(g)...)
	}
	return chExtension{typ: 0x000a, data: body}
}

// ecPointFormatsExt builds an ec_point_formats (0x000b) extension.
func ecPointFormatsExt(formats ...uint8) chExtension {
	body := []byte{byte(len(formats))}
	return chExtension{typ: 0x000b, data: append(body, formats...)}
}

// serverNameExt builds a minimal server_name (0x0000) extension. JA3 records only
// the extension TYPE, so the host payload is otherwise irrelevant here.
func serverNameExt(host string) chExtension {
	name := []byte(host)
	entry := append([]byte{0x00}, u16(uint16(len(name)))...) // host_name(0) + u16 len
	entry = append(entry, name...)
	body := append(u16(uint16(len(entry))), entry...) // server_name_list u16 length + entry
	return chExtension{typ: 0x0000, data: body}
}

// TestParseClientHello_MatchesSalesforceJA3Oracle cross-validates the raw parser
// against the canonical Salesforce "with extensions" vector (ja3_oracle_test.go):
// cipher order, extension-ID order, supported_groups (curves) and ec_point_formats
// (points) — all against external ground truth.
func TestParseClientHello_MatchesSalesforceJA3Oracle(t *testing.T) {
	raw := buildClientHello(
		0x0301,
		[]uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
		[]chExtension{
			serverNameExt("example.com"),   // ext 0
			supportedGroupsExt(23, 24, 25), // ext 10, curves 23-24-25
			ecPointFormatsExt(0),           // ext 11, point 0
		},
	)
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	const want = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
	if got := ch.JA3(); got != want {
		t.Fatalf("raw JA3 vs Salesforce oracle:\n  got  %q\n  want %q", got, want)
	}
}

// TestParseClientHello_JA3Hash_SalesforceOracle checks the MD5 helper against the
// canonical Salesforce ja3 README hash (the value Shodan/GreyNoise/VT index).
func TestParseClientHello_JA3Hash_SalesforceOracle(t *testing.T) {
	raw := buildClientHello(
		0x0301,
		[]uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
		[]chExtension{serverNameExt("example.com"), supportedGroupsExt(23, 24, 25), ecPointFormatsExt(0)},
	)
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	const want = "ada70206e40642a3e4461f35503241d5" // Salesforce ja3 README
	if got := ch.JA3Hash(); got != want {
		t.Fatalf("JA3 hash vs Salesforce oracle:\n  got  %s\n  want %s", got, want)
	}
}

// TestParseClientHello_StripsGREASE verifies GREASE cipher and extension values
// are removed from the JA3 (spec: ignore GREASE everywhere).
func TestParseClientHello_StripsGREASE(t *testing.T) {
	raw := buildClientHello(
		0x0301,
		[]uint16{0x0A0A, 0x1301, 0x1302}, // 0x0A0A GREASE -> dropped
		[]chExtension{
			{typ: 0x1A1A, data: nil},     // GREASE ext -> dropped
			supportedVersionsExt(0x0303), // ext 43
		},
	)
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	const want = "769,4865-4866,43,,"
	if got := ch.JA3(); got != want {
		t.Fatalf("GREASE not stripped:\n  got  %q\n  want %q", got, want)
	}
}

// TestParseClientHello_RejectsMalformed ensures adversarial/truncated input is
// rejected with an error and NEVER panics (the parser reads attacker bytes).
func TestParseClientHello_RejectsMalformed(t *testing.T) {
	good := buildClientHello(0x0301, []uint16{0x1301}, []chExtension{supportedVersionsExt(0x0303)})
	cases := map[string][]byte{
		"empty":          {},
		"not_handshake":  {0x17, 0x03, 0x01, 0x00, 0x01, 0x00},
		"record_only":    good[:5],
		"wrong_msg_type": {0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}, // server_hello(0x02)
		"truncated_body": good[:len(good)-3],
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on malformed input: %v", r)
				}
			}()
			if _, err := ParseClientHello(in); err == nil {
				t.Fatalf("expected error for malformed input")
			}
		})
	}
}

// sigAlgsExt builds a signature_algorithms (0x000d) extension.
func sigAlgsExt(schemes ...uint16) chExtension {
	body := u16(uint16(len(schemes) * 2))
	for _, s := range schemes {
		body = append(body, u16(s)...)
	}
	return chExtension{typ: 0x000d, data: body}
}

// alpnExt builds an application_layer_protocol_negotiation (0x0010) extension.
func alpnExt(protos ...string) chExtension {
	var list []byte
	for _, pr := range protos {
		list = append(list, byte(len(pr)))
		list = append(list, []byte(pr)...)
	}
	return chExtension{typ: 0x0010, data: append(u16(uint16(len(list))), list...)}
}

// TestParseClientHello_JA4_FoxIOChromiumReference encodes the exact Chromium
// ClientHello from TestComputeJA4FromClientHello_ChromiumReference (tls-sni.pcapng)
// to raw wire bytes, parses it, and requires the JA4 to match FoxIO's published
// Python-reference output. This validates that the parser extracts ciphers,
// extensions, supported_versions, ALPN, signature_algorithms and the SNI flag
// correctly against EXTERNAL ground truth.
func TestParseClientHello_JA4_FoxIOChromiumReference(t *testing.T) {
	raw := buildClientHello(
		0x0303,
		[]uint16{
			0xAAAA, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
			0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
		},
		[]chExtension{
			{typ: 0x9A9A}, {typ: 0xFF01}, {typ: 0x0033}, {typ: 0x002D}, {typ: 0x0005}, {typ: 0x4469},
			sigAlgsExt(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601), // 0x000D
			alpnExt("h2", "http/1.1"), // 0x0010
			{typ: 0x0023}, {typ: 0x001B},
			supportedVersionsExt(0x0A0A, 0x0304, 0x0303),   // 0x002B
			serverNameExt("clientservices.googleapis.com"), // 0x0000
			{typ: 0x0012}, {typ: 0x000A}, {typ: 0x0017}, {typ: 0x000B},
			{typ: 0x6A6A}, {typ: 0x0015},
		},
	)
	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	const want = "t13d1516h2_8daaf6152771_e5627efa2ab1" // FoxIO Python reference
	if got := ch.JA4(); got != want {
		t.Fatalf("JA4 from raw vs FoxIO reference:\n  got  %q\n  want %q", got, want)
	}
}

// fragmentClientHello re-frames a single-record ClientHello into TWO TLS
// handshake records by splitting the handshake payload at `at`. This is a legal,
// real-world (and evasion-relevant) wire shape a naive parser mishandles.
func fragmentClientHello(raw []byte, at int) []byte {
	payload := raw[5:] // strip the single record header
	if at <= 0 || at >= len(payload) {
		at = len(payload) / 2
	}
	rec := func(b []byte) []byte {
		return append([]byte{0x16, 0x03, 0x01, byte(len(b) >> 8), byte(len(b))}, b...)
	}
	return append(rec(payload[:at]), rec(payload[at:])...)
}

// TestParseClientHello_HandlesFragmentation feeds a ClientHello split across two
// TLS records and requires the parser to reassemble it — same JA3 as the whole.
func TestParseClientHello_HandlesFragmentation(t *testing.T) {
	whole := buildClientHello(0x0301, []uint16{0x1301, 0x1302},
		[]chExtension{supportedGroupsExt(23, 24), supportedVersionsExt(0x0303)})
	want, err := ParseClientHello(whole)
	if err != nil {
		t.Fatalf("whole: %v", err)
	}
	frag := fragmentClientHello(whole, 7) // split mid-handshake across 2 records
	got, err := ParseClientHello(frag)
	if err != nil {
		t.Fatalf("fragmented ClientHello rejected (should reassemble): %v", err)
	}
	if got.JA3() != want.JA3() {
		t.Fatalf("fragmentation changed the fingerprint:\n  whole %q\n  frag  %q", want.JA3(), got.JA3())
	}
}

// captureRealClientHello drives a REAL crypto/tls client handshake over an
// in-memory pipe and returns BOTH the raw on-wire ClientHello bytes (captured by
// a TeeConn on the server side) and the stdlib-parsed *tls.ClientHelloInfo from
// the SAME handshake. No hand-built fixtures: the bytes are generated by an actual
// TLS client, and the stdlib's own parse is the independent oracle.
func captureRealClientHello(t *testing.T, clientCfg *tls.Config) ([]byte, *tls.ClientHelloInfo) {
	t.Helper()
	cli, srv := net.Pipe()
	tee := NewTeeConn(srv, 65536, func([]byte) bool { return false })
	gotHello := make(chan *tls.ClientHelloInfo, 1)
	abort := errors.New("captured")
	go func() {
		s := tls.Server(tee, &tls.Config{
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				gotHello <- h
				return nil, abort // we have the hello; stop the server handshake
			},
		})
		_ = s.Handshake()
		_ = s.Close()
	}()
	go func() {
		c := tls.Client(cli, clientCfg)
		_ = c.Handshake()
		_ = c.Close()
	}()
	select {
	case h := <-gotHello:
		return tee.RawBytes(), h // channel receive happens-after the tee's Read-appends
	case <-time.After(2 * time.Second):
		t.Fatal("no ClientHello captured from real client")
		return nil, nil
	}
}

// TestParseClientHello_RealGoClientMatchesStdlib validates the raw parser against
// GENUINE on-wire ClientHello bytes from a real crypto/tls client (TLS 1.2 and
// 1.3), cross-checked against the stdlib's own parse of the same bytes. This is
// the non-circular test: nothing here is hand-encoded. (Real Go clients pin
// legacy_version to 0x0303, where the stdlib reconstruction agrees — so the
// stdlib is a valid oracle here; the legacy_version divergence stays covered by
// the synthetic vector, a protocol-legal case Go's client cannot produce.)
func TestParseClientHello_RealGoClientMatchesStdlib(t *testing.T) {
	cases := []struct {
		name string
		cfg  *tls.Config
	}{
		{"tls13", &tls.Config{InsecureSkipVerify: true, ServerName: "example.com", MinVersion: tls.VersionTLS13}},
		{"tls12", &tls.Config{InsecureSkipVerify: true, ServerName: "example.com", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, hello := captureRealClientHello(t, tc.cfg)
			if len(raw) == 0 {
				t.Fatal("captured zero bytes")
			}
			ch, err := ParseClientHello(raw)
			if err != nil {
				t.Fatalf("ParseClientHello on a REAL %s client hello (%d bytes): %v", tc.name, len(raw), err)
			}
			want := ja3String(hello) // stdlib's independent parse of the same handshake
			if got := ch.JA3(); got != want {
				t.Fatalf("raw parser disagrees with stdlib on a REAL %s client hello:\n  raw    %q\n  stdlib %q", tc.name, got, want)
			}
		})
	}
}
