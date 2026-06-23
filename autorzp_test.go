package main

// Tests for the helper functions in autorzp.go. These cover the bug-prone
// areas that were fixed across rounds 1-3:
//   - extractProxyHost (the credential/scheme/port ordering fix)
//   - isBadProxyHost (Tor / datacenter / VPN detection)
//   - truncate (negative-length guard)
//   - parseCard (separator + range validation)
//   - parseChromeMajor (UA → Chrome major for Sec-CH-UA consistency)
//   - getBrand (card BIN → brand)
//   - getStringFromMap / getFloatFromMap (nil-safety)
//   - maskProxy (credential masking)
//   - isBalanceKeyword / isCVVKeyword (decline-message classification)
//
// Run with: go test -race -v ./...
// Or:       make test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// ─── extractProxyHost ──────────────────────────────────────────────────────

func TestExtractProxyHost(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"plain host:port", "1.2.3.4:8080", "1.2.3.4"},
		{"with scheme", "http://1.2.3.4:8080", "1.2.3.4"},
		{"with user:pass", "http://user:pass@host.com:8080", "host.com"},
		{"password contains colon", "http://user:p@ss:word@host.com:8080", "host.com"},
		{"password contains slash", "http://user:p//ss@host.com:8080", "host.com"},
		{"tor host", "http://pl-tor.pvdata.host:8080", "pl-tor.pvdata.host"},
		{"upper case host", "HTTP://EXAMPLE.COM:80", "example.com"},
		{"no port", "http://example.com", "example.com"},
		{"with path", "http://example.com:8080/foo", "example.com"},
		{"with query", "http://example.com:8080?x=1", "example.com"},
		{"empty", "", ""},
		{"just scheme", "http://", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractProxyHost(c.raw)
			if got != c.want {
				t.Errorf("extractProxyHost(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

// ─── isBadProxyHost ────────────────────────────────────────────────────────

func TestIsBadProxyHost(t *testing.T) {
	bad := []string{
		"http://pl-tor.pvdata.host:8080",
		"http://tor-exit.example.com:8080",
		"http://1.2.3.4:8080", // empty host extraction would also be bad, but here host=1.2.3.4 (ok)
		"http://user:pass@relay.anonymizer.com:8080",
		"http://host.aws.amazon.com:8080",
		"http://vultr.host.com:8080",
		"http://proxy.vpn.net:8080",
	}
	for _, raw := range bad {
		// "1.2.3.4" is NOT bad per our list — re-check
		if strings.Contains(raw, "1.2.3.4") {
			if isBadProxyHost(raw) {
				t.Errorf("isBadProxyHost(%q) = true, want false (raw IP not in bad list)", raw)
			}
			continue
		}
		if !isBadProxyHost(raw) {
			t.Errorf("isBadProxyHost(%q) = false, want true", raw)
		}
	}

	good := []string{
		"http://residential-1.isp.in:8080",
		"http://user:pass@broadband.uk.com:8080",
		"http://1.2.3.4:8080", // raw IP — not in bad-host list
	}
	for _, raw := range good {
		if isBadProxyHost(raw) {
			t.Errorf("isBadProxyHost(%q) = true, want false (false positive)", raw)
		}
	}

	// Empty host should be flagged as bad.
	if !isBadProxyHost("") {
		t.Errorf("isBadProxyHost(\"\") = false, want true")
	}
	if !isBadProxyHost("http://") {
		t.Errorf("isBadProxyHost(\"http://\") = false, want true")
	}
}

// ─── truncate ──────────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	cases := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"hello", 0, ""},
		{"hello", -1, ""}, // negative guard
		{"hello", -100, ""},
		{"", 5, ""},
		{"", 0, ""},
	}
	for _, c := range cases {
		got := truncate(c.s, c.maxLen)
		if got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.s, c.maxLen, got, c.want)
		}
	}
}

// ─── parseCard ─────────────────────────────────────────────────────────────

func TestParseCard(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
		wantCC  string
		wantMM  string
	}{
		{"pipe separator", "4111111111111111|12|25|123", false, "4111111111111111", "12"},
		{"slash separator", "4111111111111111/12/25/123", false, "4111111111111111", "12"},
		{"space separator", "4111111111111111 12 25 123", false, "4111111111111111", "12"},
		{"single-digit month", "4111111111111111|3|25|123", false, "4111111111111111", "03"},
		{"4-digit year", "4111111111111111|12|2025|123", false, "4111111111111111", "12"},
		{"amex 4-digit cvv", "378282246310005|12|25|1234", false, "378282246310005", "12"},
		{"invalid month 13", "4111111111111111|13|25|123", true, "", ""},
		{"invalid month 0", "4111111111111111|00|25|123", true, "", ""},
		{"too short cc", "4111|12|25|123", true, "", ""},
		{"too long cc", "41111111111111111111|12|25|123", true, "", ""},
		{"non-digit cc", "4111abcd1111111|12|25|123", true, "", ""},
		{"too few parts", "4111111111111111|12|25", true, "", ""},
		{"empty", "", true, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			card, err := parseCard(c.input)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseCard(%q) expected error, got nil (card=%+v)", c.input, card)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCard(%q) unexpected error: %v", c.input, err)
			}
			if card.CC != c.wantCC {
				t.Errorf("parseCard(%q).CC = %q, want %q", c.input, card.CC, c.wantCC)
			}
			if card.MM != c.wantMM {
				t.Errorf("parseCard(%q).MM = %q, want %q", c.input, card.MM, c.wantMM)
			}
		})
	}
}

// ─── parseChromeMajor ──────────────────────────────────────────────────────

func TestParseChromeMajor(t *testing.T) {
	cases := []struct {
		ua   string
		want int
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.6999.123 Safari/537.36", 145},
		{"Chrome/120.0.6099.0", 120},
		{"Chrome/147.0.0.0", 147},
		{"Mozilla/5.0 Firefox/120.0", -1},            // not chrome
		{"Mozilla/5.0 Chrome/100 Safari/537.36", -1}, // no dot after number — won't match \d+\.
		{"", -1},
		{"no version here", -1},
	}
	for _, c := range cases {
		got := parseChromeMajor(c.ua)
		if got != c.want {
			t.Errorf("parseChromeMajor(%q) = %d, want %d", c.ua, got, c.want)
		}
	}
}

// ─── getBrand ──────────────────────────────────────────────────────────────

func TestGetBrand(t *testing.T) {
	cases := []struct {
		cc   string
		want string
	}{
		{"4111111111111111", "visa"},
		{"4", "visa"},
		{"5111111111111111", "mastercard"},
		{"5511111111111111", "mastercard"},
		{"5611111111111111", "unknown"}, // 56 not in mastercard range
		{"341111111111111", "amex"},
		{"371111111111111", "amex"},
		{"6011111111111111", "discover"},
		{"6511111111111111", "discover"},
		{"", "unknown"},
		{"123", "unknown"},
	}
	for _, c := range cases {
		got := getBrand(c.cc)
		if got != c.want {
			t.Errorf("getBrand(%q) = %q, want %q", c.cc, got, c.want)
		}
	}
}

// ─── getStringFromMap / getFloatFromMap ────────────────────────────────────

func TestGetStringFromMap(t *testing.T) {
	if got := getStringFromMap(nil, "x"); got != "" {
		t.Errorf("getStringFromMap(nil, x) = %q, want empty", got)
	}
	m := map[string]interface{}{
		"s":     "hello",
		"i":     42,
		"b":     true,
		"f":     3.14,
		"empty": "",
	}
	if got := getStringFromMap(m, "s"); got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
	if got := getStringFromMap(m, "i"); got != "42" {
		t.Errorf("got %q, want 42", got)
	}
	if got := getStringFromMap(m, "b"); got != "true" {
		t.Errorf("got %q, want true", got)
	}
	if got := getStringFromMap(m, "missing"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	if got := getStringFromMap(m, "empty"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestGetFloatFromMap(t *testing.T) {
	if got := getFloatFromMap(nil, "x"); got != 0 {
		t.Errorf("getFloatFromMap(nil, x) = %v, want 0", got)
	}
	m := map[string]interface{}{
		"f": 3.14,
		"i": 100,
		"s": "200.5",
		"b": true,
	}
	if got := getFloatFromMap(m, "f"); got != 3.14 {
		t.Errorf("got %v, want 3.14", got)
	}
	if got := getFloatFromMap(m, "i"); got != 100 {
		t.Errorf("got %v, want 100", got)
	}
	if got := getFloatFromMap(m, "s"); got != 200.5 {
		t.Errorf("got %v, want 200.5", got)
	}
	if got := getFloatFromMap(m, "b"); got != 0 {
		t.Errorf("got %v, want 0 (bool not numeric)", got)
	}
	if got := getFloatFromMap(m, "missing"); got != 0 {
		t.Errorf("got %v, want 0", got)
	}
}

// ─── maskProxy ─────────────────────────────────────────────────────────────

func TestMaskProxy(t *testing.T) {
	cases := []struct {
		proxyURL string
		status   string
		want     string
	}{
		{"", "LIVE", "DIRECT [LIVE]"},
		{"http://1.2.3.4:8080", "LIVE", "http://1.2.3.4:8080 [LIVE]"},
		{"http://user:pass@1.2.3.4:8080", "DEAD", "http://1.2.3.4:8080 [DEAD]"},
		{"http://user:p@ss@1.2.3.4:8080", "BLOCKED", "http://1.2.3.4:8080 [BLOCKED]"},
		{"garbage", "LIVE", "garbage [LIVE]"}, // url.Parse fails on bare string? Actually "garbage" parses fine
	}
	for _, c := range cases {
		got := maskProxy(c.proxyURL, c.status)
		if got != c.want {
			t.Errorf("maskProxy(%q, %q) = %q, want %q", c.proxyURL, c.status, got, c.want)
		}
	}
}

// ─── isBalanceKeyword / isCVVKeyword ───────────────────────────────────────

func TestIsBalanceKeyword(t *testing.T) {
	bad := []string{
		"insufficient account balance",
		"INSUFFICIENT FUNDS in account",
		"maximum transaction limit reached",
		"Transaction limit exceeded",
	}
	for _, s := range bad {
		if !isBalanceKeyword(strings.ToLower(s)) {
			t.Errorf("isBalanceKeyword(%q) = false, want true", s)
		}
	}
	good := []string{
		"card declined",
		"invalid cvv",
		"do not honor",
	}
	for _, s := range good {
		if isBalanceKeyword(strings.ToLower(s)) {
			t.Errorf("isBalanceKeyword(%q) = true, want false", s)
		}
	}
}

func TestIsCVVKeyword(t *testing.T) {
	cases := []struct {
		msg     string
		errCode string
		want    bool
	}{
		{"CVV provided is incorrect", "", true},
		{"cvv provided is incorrect", "", true},
		{"Incorrect CVV", "incorrect_cvv", true},
		{"some error", "INCORRECT_CVV", true},
		{"some error", "bad_card", false},
		{"regular decline", "", false},
	}
	for _, c := range cases {
		got := isCVVKeyword(strings.ToLower(c.msg), c.errCode)
		if got != c.want {
			t.Errorf("isCVVKeyword(%q, %q) = %v, want %v", c.msg, c.errCode, got, c.want)
		}
	}
}

// ─── findBetween ───────────────────────────────────────────────────────────

func TestFindBetween(t *testing.T) {
	cases := []struct {
		content, start, end, want string
	}{
		{"hello [world] foo", "[", "]", "world"},
		{"a b c", "a", "c", " b "},
		{"no match", "[", "]", ""},
		{"only start", "[", "]", ""},
		{"only end", "[", "]", ""},
		{"empty start", "", "x", ""},
		{"empty content", "", "", ""},
	}
	for _, c := range cases {
		got := findBetween(c.content, c.start, c.end)
		if got != c.want {
			t.Errorf("findBetween(%q, %q, %q) = %q, want %q",
				c.content, c.start, c.end, got, c.want)
		}
	}
}

// ─── isDigits / isDigitsMM / isDigitsYY / isDigitsCVV ─────────────────────

func TestIsDigitsFamily(t *testing.T) {
	if !isDigits("123") {
		t.Error("isDigits(123) should be true")
	}
	if isDigits("12a") {
		t.Error("isDigits(12a) should be false")
	}
	if isDigits("") {
		t.Error("isDigits(\"\") should be false")
	}

	if !isDigitsMM("12") || !isDigitsMM("3") {
		t.Error("isDigitsMM should accept 1 or 2 digits")
	}
	if isDigitsMM("123") {
		t.Error("isDigitsMM should reject 3 digits")
	}

	if !isDigitsYY("25") || !isDigitsYY("2025") {
		t.Error("isDigitsYY should accept 2 or 4 digits")
	}
	if isDigitsYY("5") {
		t.Error("isDigitsYY should reject 1 digit")
	}

	if !isDigitsCVV("123") || !isDigitsCVV("1234") {
		t.Error("isDigitsCVV should accept 3 or 4 digits")
	}
	if isDigitsCVV("12") {
		t.Error("isDigitsCVV should reject 2 digits")
	}
}

// ─── generateRzpSessionID ──────────────────────────────────────────────────

func TestGenerateRzpSessionID(t *testing.T) {
	const base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		s := generateRzpSessionID()
		if len(s) != 14 {
			t.Fatalf("session ID length = %d, want 14", len(s))
		}
		for _, c := range s {
			if !strings.ContainsRune(base62, c) {
				t.Fatalf("session ID %q contains non-base62 char %q", s, c)
			}
		}
		if seen[s] {
			t.Fatalf("duplicate session ID %q after %d iterations — randomness issue", s, i)
		}
		seen[s] = true
	}
}

// ─── generateRzpDeviceID ───────────────────────────────────────────────────

func TestGenerateRzpDeviceID(t *testing.T) {
	id, h := generateRzpDeviceID()
	if id == "" {
		t.Fatal("device ID is empty")
	}
	if h == "" {
		t.Fatal("hash is empty")
	}
	// Format: 1.<40-char sha1>.<unixmilli>.<8-digit zero-padded>
	parts := strings.Split(id, ".")
	if len(parts) != 4 {
		t.Fatalf("device ID %q should have 4 parts, got %d", id, len(parts))
	}
	if parts[0] != "1" {
		t.Errorf("first part = %q, want 1", parts[0])
	}
	if len(parts[1]) != 40 {
		t.Errorf("hash part length = %d, want 40", len(parts[1]))
	}
	if parts[1] != h {
		t.Errorf("returned hash %q != id hash part %q", h, parts[1])
	}
}

// ─── shuffleFormValues ─────────────────────────────────────────────────────

func TestShuffleFormValuesPreservesData(t *testing.T) {
	original := map[string][]string{
		"a": {"1"},
		"b": {"2", "3"},
		"c": {"4"},
	}
	// Convert to url.Values
	v := make(url.Values)
	for k, vals := range original {
		for _, val := range vals {
			v.Add(k, val)
		}
	}
	shuffled := shuffleFormValues(v)
	// Same keys
	if len(shuffled) != len(original) {
		t.Fatalf("shuffled has %d keys, want %d", len(shuffled), len(original))
	}
	for k, vals := range original {
		got, ok := shuffled[k]
		if !ok {
			t.Errorf("key %q missing after shuffle", k)
			continue
		}
		if len(got) != len(vals) {
			t.Errorf("key %q: %d vals, want %d", k, len(got), len(vals))
			continue
		}
		// Order within a key should be preserved (we don't shuffle values)
		for i, v := range vals {
			if got[i] != v {
				t.Errorf("key %q: val[%d] = %q, want %q", k, i, got[i], v)
			}
		}
	}
}

// ─── extractHTTPStatusFromErr ──────────────────────────────────────────────
// Reproduces the exact error message format the user reported:
//   Get "https://razorpay.me/@ceitrc": Payment Required
// and verifies we extract HTTP 402 from it.

func TestExtractHTTPStatusFromErr(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want int
	}{
		{"user reported: 402 from razorpay.me", `Get "https://razorpay.me/@ceitrc": Payment Required`, 402},
		{"403 forbidden", `Get "https://api.razorpay.com/v1/foo": Forbidden`, 403},
		{"404 not found", `Get "https://razorpay.me/@deleted": Not Found`, 404},
		{"407 proxy auth", `Get "https://api.razorpay.com/": Proxy Authentication Required`, 407},
		{"429 too many requests", `Get "https://api.razorpay.com/": Too Many Requests`, 429},
		{"500 internal server error", `Get "https://api.razorpay.com/": Internal Server Error`, 500},
		{"502 bad gateway", `Get "https://api.razorpay.com/": Bad Gateway`, 502},
		{"503 service unavailable", `Get "https://api.razorpay.com/": Service Unavailable`, 503},
		{"504 gateway timeout", `Get "https://api.razorpay.com/": Gateway Timeout`, 504},
		{"with extra context", `Get "https://api.razorpay.com/": Payment Required: context deadline exceeded`, 402},
		{"network error (no status)", `dial tcp: lookup api.razorpay.com: no such host`, 0},
		{"empty", ``, 0},
		{"just URL no status", `Get "https://api.razorpay.com/"`, 0},
		{"unknown status text", `Get "https://api.razorpay.com/": Some Weird Status`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractHTTPStatusFromErr(c.msg)
			if got != c.want {
				t.Errorf("extractHTTPStatusFromErr(%q) = %d, want %d", c.msg, got, c.want)
			}
		})
	}
}

// ─── classifyHTTPError ─────────────────────────────────────────────────────

func TestClassifyHTTPError(t *testing.T) {
	cases := []struct {
		code        int
		wantStatus  string
		wantContain string // substring expected in the message
	}{
		{402, "DEAD", "Proxy quota exhausted"},
		{407, "DEAD", "Proxy authentication failed"},
		{403, "BLOCKED", "WAF Blocked"},
		{429, "BLOCKED", "Rate limited"},
		{404, "LIVE", "not found"},
		{500, "LIVE", "Upstream server error"},
		{502, "LIVE", "Upstream server error"},
		{503, "LIVE", "Upstream server error"},
		{504, "LIVE", "Upstream server error"},
		{418, "LIVE", "HTTP error"}, // unknown code -> generic
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("code_%d", c.code), func(t *testing.T) {
			msg, status := classifyHTTPError(c.code)
			if status != c.wantStatus {
				t.Errorf("code %d: status = %q, want %q", c.code, status, c.wantStatus)
			}
			if !strings.Contains(strings.ToLower(msg), strings.ToLower(c.wantContain)) {
				t.Errorf("code %d: message %q does not contain %q", c.code, msg, c.wantContain)
			}
		})
	}
}

// ─── isRazorpayServerError ─────────────────────────────────────────────────
// Reproduces the exact error message the user reported:
//   "The server encountered an error. The incident has been reported to admins."
// and verifies it's classified as a server error (not a decline).

func TestIsRazorpayServerError(t *testing.T) {
	// The exact user-reported message.
	userReported := "The server encountered an error. The incident has been reported to admins."
	if !isRazorpayServerError(strings.ToLower(userReported)) {
		t.Errorf("isRazorpayServerError(%q) = false, want true (user-reported case)", userReported)
	}

	bad := []string{
		userReported,
		"Internal Server Error",
		"Service Unavailable",
		"Bad Gateway",
		"Gateway Timeout",
		"Something went wrong, please try again later",
		"SERVER_ERROR",
		"server_error",
	}
	for _, s := range bad {
		if !isRazorpayServerError(strings.ToLower(s)) {
			t.Errorf("isRazorpayServerError(%q) = false, want true", s)
		}
	}

	// Genuine bank-side declines must NOT match.
	good := []string{
		"insufficient funds",
		"card declined",
		"incorrect cvv",
		"do not honor",
		"invalid card number",
		"expired card",
		"transaction not permitted",
	}
	for _, s := range good {
		if isRazorpayServerError(strings.ToLower(s)) {
			t.Errorf("isRazorpayServerError(%q) = true, want false (false positive)", s)
		}
	}

	// Empty string is not a server error.
	if isRazorpayServerError("") {
		t.Errorf("isRazorpayServerError(\"\") = true, want false")
	}
}
