// Package OLLAMA — GeoIP-backed Cloudflare PoP resolver for cf-ray header.
//
// Real api.openai.com fronts via Cloudflare Anycast. The `cf-ray` response
// header ends in a 3-letter IATA suffix that encodes the edge PoP serving
// the request — always the PoP nearest the CLIENT's IP, NOT the server.
//
// A naive random-per-response PoP pick (which is what this package
// replaces) yields two wrong invariants:
//
//   1. Same client, same service, different requests → different PoPs.
//      Real CF Anycast is sticky within a rebalance window: the same
//      client sees the same PoP for hours at a time.
//   2. Client in Newark hitting two CF-fronted services → different PoPs.
//      Real CF routes the client to its nearest edge regardless of which
//      service; both responses carry the same suffix.
//
// PoPResolver fixes both. Given the client IP:
//
//   - If a GeoLite2-Country.mmdb is loaded, it maps client → ISO country
//     → list of Cloudflare PoPs in that country, then picks deterministically
//     from the list using a hash of the client IP. Same client, same PoP,
//     every time. Different clients in the same country get different PoPs
//     from the available set (reflecting real load-balancing).
//   - Without a GeoIP DB, it falls back to a coarse IANA /8 heuristic:
//     each /8 block maps to the registry (ARIN/RIPE/APNIC/LACNIC/AFRINIC)
//     that administers it, then to that registry's PoP pool. Still
//     deterministic per client, but only plausible to ~continent level.
//
// The DB path default matches the sensor filesystem layout
// (/opt/honeypot-sensor/geoip/ mounted into the container at /geoip).
// Override via OLLAMA_GEOIP_DB env var if needed.

package OLLAMA

import (
	"hash/fnv"
	"net"
	"os"
	"sync"

	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
)

// Cloudflare PoP tables by country. Populated from Cloudflare's public
// network map (cloudflare.com/network). Codes are IATA-style. Order within
// a country doesn't matter — we hash the client IP to pick an index.
var cfPoPsByCountry = map[string][]string{
	// North America
	"US": {"EWR", "IAD", "ORD", "DFW", "ATL", "MIA", "LAX", "SJC", "SEA", "DEN", "BOS", "MSP"},
	"CA": {"YYZ", "YVR", "YUL"},
	"MX": {"MEX", "QRO"},
	// Europe
	"GB": {"LHR", "MAN"},
	"DE": {"FRA", "DUS", "MUC", "TXL"},
	"FR": {"CDG", "MRS"},
	"NL": {"AMS"},
	"IE": {"DUB"},
	"ES": {"MAD", "BCN"},
	"IT": {"MXP", "FCO"},
	"SE": {"ARN"},
	"PL": {"WAW"},
	"CH": {"ZRH"},
	"BE": {"BRU"},
	"AT": {"VIE"},
	"NO": {"OSL"},
	"FI": {"HEL"},
	"DK": {"CPH"},
	"PT": {"LIS"},
	"CZ": {"PRG"},
	"GR": {"ATH"},
	"RO": {"OTP"},
	"BG": {"SOF"},
	"HU": {"BUD"},
	"UA": {"KBP"},
	// Asia-Pacific
	"JP": {"NRT", "HND", "KIX"},
	"KR": {"ICN"},
	"CN": {"HKG"},
	"HK": {"HKG"},
	"TW": {"TPE"},
	"SG": {"SIN"},
	"AU": {"SYD", "MEL", "PER"},
	"NZ": {"AKL"},
	"IN": {"BOM", "DEL", "BLR", "MAA"},
	"ID": {"CGK"},
	"MY": {"KUL"},
	"TH": {"BKK"},
	"VN": {"SGN", "HAN"},
	"PH": {"MNL"},
	// Middle East & Africa
	"AE": {"DXB"},
	"SA": {"JED"},
	"IL": {"TLV"},
	"TR": {"IST"},
	"EG": {"CAI"},
	"ZA": {"JNB", "CPT"},
	"NG": {"LOS"},
	"KE": {"NBO"},
	// Latin America
	"BR": {"GRU", "GIG"},
	"AR": {"EZE"},
	"CL": {"SCL"},
	"CO": {"BOG"},
	"PE": {"LIM"},
}

// Registry-level fallback when no country DB is loaded. Based on IANA /8
// allocations circa 2025. Each entry maps a /8 range to a regional pool.
// The pool names correspond to regional PoP sets defined below.
type ipRange struct {
	firstOctetMin byte
	firstOctetMax byte
	region        string
}

var ianaRegions = []ipRange{
	// Coarse approximation — not every /8 in a range is the named
	// registry, but the majority is close enough for our purposes. See
	// https://www.iana.org/assignments/ipv4-address-space/
	{3, 4, "ARIN"}, {6, 9, "ARIN"}, {11, 13, "ARIN"},
	{15, 24, "ARIN"}, {26, 26, "ARIN"}, {28, 35, "ARIN"},
	{38, 40, "ARIN"}, {44, 45, "ARIN"}, {47, 48, "ARIN"},
	{50, 50, "ARIN"}, {52, 76, "ARIN"}, {96, 100, "ARIN"},
	{104, 108, "ARIN"}, {128, 130, "ARIN"}, {132, 132, "ARIN"},
	{134, 142, "ARIN"}, {144, 149, "ARIN"}, {152, 154, "ARIN"},
	{156, 156, "ARIN"}, {158, 159, "ARIN"}, {161, 170, "ARIN"},
	{172, 174, "ARIN"}, {184, 184, "ARIN"}, {192, 192, "ARIN"},
	{198, 199, "ARIN"}, {204, 209, "ARIN"}, {216, 216, "ARIN"},

	{2, 2, "RIPE"}, {5, 5, "RIPE"}, {25, 25, "RIPE"},
	{37, 37, "RIPE"}, {46, 46, "RIPE"}, {51, 51, "RIPE"},
	{62, 62, "RIPE"}, {77, 95, "RIPE"}, {109, 109, "RIPE"},
	{141, 141, "RIPE"}, {151, 151, "RIPE"}, {176, 178, "RIPE"},
	{185, 185, "RIPE"}, {188, 188, "RIPE"}, {193, 195, "RIPE"},
	{212, 213, "RIPE"}, {217, 217, "RIPE"},

	{1, 1, "APNIC"}, {14, 14, "APNIC"}, {27, 27, "APNIC"},
	{36, 36, "APNIC"}, {39, 39, "APNIC"}, {41, 41, "APNIC"},
	{42, 43, "APNIC"}, {49, 49, "APNIC"}, {58, 61, "APNIC"},
	{101, 103, "APNIC"}, {106, 106, "APNIC"}, {110, 126, "APNIC"},
	{133, 133, "APNIC"}, {150, 150, "APNIC"}, {153, 153, "APNIC"},
	{163, 163, "APNIC"}, {171, 171, "APNIC"}, {175, 175, "APNIC"},
	{180, 183, "APNIC"}, {202, 203, "APNIC"}, {210, 211, "APNIC"},
	{218, 223, "APNIC"},

	{131, 131, "LACNIC"}, {143, 143, "LACNIC"}, {177, 177, "LACNIC"},
	{179, 179, "LACNIC"}, {181, 181, "LACNIC"}, {186, 187, "LACNIC"},
	{189, 191, "LACNIC"}, {200, 201, "LACNIC"},

	{102, 102, "AFRINIC"}, {105, 105, "AFRINIC"}, {154, 155, "AFRINIC"},
	{160, 160, "AFRINIC"}, {196, 197, "AFRINIC"},
}

var registryPoPs = map[string][]string{
	"ARIN":    {"EWR", "IAD", "ORD", "DFW", "ATL", "LAX", "SJC", "SEA", "MIA", "YYZ"},
	"RIPE":    {"FRA", "AMS", "LHR", "CDG", "MXP", "ARN", "DUS", "VIE", "MAD", "WAW"},
	"APNIC":   {"NRT", "HND", "ICN", "SIN", "HKG", "SYD", "BOM", "DEL", "TPE", "KIX"},
	"LACNIC":  {"GRU", "EZE", "SCL", "BOG", "LIM", "MEX"},
	"AFRINIC": {"JNB", "CPT", "LOS", "NBO"},
}

// Default pool used when no DB, no registry match, no country match.
// Picks a plausible global-South/anycast fallback. Still deterministic.
var defaultPoPs = []string{"IAD", "FRA", "NRT", "SIN", "LHR", "GRU", "SYD"}

// PoPResolver maps a client IP to a plausible Cloudflare PoP code.
type PoPResolver struct {
	mu     sync.RWMutex
	geoDB  *geoip2.Reader
	dbPath string
}

// NewPoPResolver constructs a resolver. Load() must be called separately so
// an Init caller can decide whether to tolerate DB-missing errors.
func NewPoPResolver() *PoPResolver { return &PoPResolver{} }

// Load opens the MaxMind GeoLite2-Country DB. dbPath is tried first; if
// empty, the OLLAMA_GEOIP_DB env var is consulted; if that's empty, the
// canonical path /geoip/GeoLite2-Country.mmdb is tried. A missing DB is
// not a fatal error — Resolve falls back to the IANA heuristic.
func (p *PoPResolver) Load(dbPath string) error {
	if dbPath == "" {
		dbPath = os.Getenv("OLLAMA_GEOIP_DB")
	}
	if dbPath == "" {
		dbPath = "/geoip/GeoLite2-Country.mmdb"
	}
	reader, err := geoip2.Open(dbPath)
	if err != nil {
		log.Debugf("cfpop: GeoIP DB not loaded (%s): %v — will use IANA heuristic", dbPath, err)
		return err
	}
	p.mu.Lock()
	p.geoDB = reader
	p.dbPath = dbPath
	p.mu.Unlock()
	log.Infof("cfpop: loaded GeoIP DB from %s", dbPath)
	return nil
}

// Close releases the GeoIP DB handle. Safe to call multiple times.
func (p *PoPResolver) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.geoDB != nil {
		_ = p.geoDB.Close()
		p.geoDB = nil
	}
}

// Resolve returns the PoP code for a client IP. Always returns a plausible
// 3-letter IATA code; never returns an empty string. Deterministic:
// Resolve(ip) is stable across the process lifetime.
//
// Nil-safe: a nil receiver is treated as "no DB loaded, use heuristic".
// This lets tests that don't bother to construct a PoPResolver exercise
// the auth path without panicking.
func (p *PoPResolver) Resolve(clientIP string) string {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return defaultPoPs[0]
	}

	// GeoIP path (only when receiver + DB are both non-nil)
	var db *geoip2.Reader
	if p != nil {
		p.mu.RLock()
		db = p.geoDB
		p.mu.RUnlock()
	}
	if db != nil {
		if rec, err := db.Country(ip); err == nil && rec != nil && rec.Country.IsoCode != "" {
			if pops, ok := cfPoPsByCountry[rec.Country.IsoCode]; ok && len(pops) > 0 {
				return pickFromPool(ip, pops)
			}
		}
	}

	// Heuristic fallback: first octet → registry → pool
	v4 := ip.To4()
	if v4 != nil {
		for _, r := range ianaRegions {
			if v4[0] >= r.firstOctetMin && v4[0] <= r.firstOctetMax {
				if pool, ok := registryPoPs[r.region]; ok && len(pool) > 0 {
					return pickFromPool(ip, pool)
				}
			}
		}
	}
	return pickFromPool(ip, defaultPoPs)
}

// pickFromPool hashes the client IP (full octets) and uses the hash modulo
// len(pool) to pick. Stable per IP across process lifetime — same IP always
// gets the same PoP. The bigger the pool, the more entropy.
func pickFromPool(ip net.IP, pool []string) string {
	h := fnv.New32a()
	if v4 := ip.To4(); v4 != nil {
		_, _ = h.Write(v4)
	} else {
		_, _ = h.Write(ip)
	}
	return pool[int(h.Sum32())%len(pool)]
}
