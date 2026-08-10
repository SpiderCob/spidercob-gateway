package scan

import (
	"regexp"
	"strings"
)

// PIIConfig gates the two lower-confidence PII categories (issue #11
// story 10-11: design doc §7's "email/phone (configurable — often
// legitimate)"). SSN and credit-card detection are unconditional --
// unlike email/phone, a structurally-plausible SSN or a Luhn-valid card
// number is high-confidence enough to redact by default, the same
// posture SecretScanner already takes for confirmed credential shapes.
type PIIConfig struct {
	DetectEmail bool
	DetectPhone bool
}

// ssnPattern matches the NNN-NN-NNNN shape broadly; ssnPlausible then
// filters out the well-known invalid/reserved ranges (all-zero or
// area-900+ area numbers, 666, an all-zero group, an all-zero serial) so
// this doesn't flag every hyphenated 9-digit number a test fixture or
// placeholder happens to contain (story 24).
var ssnPattern = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

func ssnPlausible(match string) bool {
	parts := strings.Split(match, "-")
	if len(parts) != 3 {
		return false
	}
	area, group, serial := parts[0], parts[1], parts[2]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" {
		return false
	}
	if serial == "0000" {
		return false
	}
	return true
}

// creditCardPattern matches a broad digit-group shape (13-19 digits,
// optionally separated by spaces or hyphens, the real-world range across
// card networks) -- luhnValid then does the actual work of separating a
// real card number from an arbitrary same-shaped digit string (story 8:
// "format-plausible-but-invalid numbers... don't get needlessly
// redacted").
var creditCardPattern = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)

func luhnValid(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var emailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
var phonePattern = regexp.MustCompile(`\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b`)

// PIIScanner detects personally identifiable information in outbound
// responses. SSN and Luhn-valid credit cards are redacted (structural
// [REDACTED:<kind>], same convention SecretScanner already uses); email
// and phone are flag-only when enabled, never redacted, since a
// legitimate CRM/support tool's response containing a contact's email or
// phone number is the common case, not the exception (design doc §7).
type PIIScanner struct {
	cfg PIIConfig
}

func NewPIIScanner(cfg PIIConfig) *PIIScanner { return &PIIScanner{cfg: cfg} }

func (s *PIIScanner) Name() string { return "pii" }

// ScanRequest always allows -- outbound-only, same posture as
// SecretScanner/EntropyScanner.
func (s *PIIScanner) ScanRequest(body []byte) Verdict {
	return Verdict{Action: Allow, Scanner: s.Name()}
}

// ssnRedaction and creditCardRedaction are the structural markers
// ScanResponse substitutes in, as []byte -- computed once rather than
// re-allocated per match.
var (
	ssnRedaction        = []byte("[REDACTED:ssn]")
	creditCardRedaction = []byte("[REDACTED:credit-card]")
)

func (s *PIIScanner) ScanResponse(body []byte) ([]byte, Verdict) {
	v := Verdict{Action: Allow, Scanner: s.Name()}

	// ReplaceAllFunc operates directly on []byte, the same approach
	// SecretScanner's ReplaceAll already uses -- flagged by Copilot's
	// review on PR #12 as a byte-safety concern (converting the whole
	// body to a Go string and back on every match, the previous
	// approach here, was claimed to risk corrupting invalid-UTF-8
	// bytes elsewhere in the body). That specific claim doesn't
	// actually hold -- a bare string([]byte)/[]byte(string) conversion
	// in Go is a byte-for-byte reinterpretation with no UTF-8
	// validation or substitution, verified directly before applying
	// this change -- but switching to ReplaceAllFunc is still a real
	// improvement on two fronts the review's summary also named: it's
	// a single pass instead of re-allocating and re-scanning the
	// (potentially large) whole body per match, and it now matches
	// SecretScanner's own pattern instead of diverging from it. Only
	// the matched substring itself -- already known to be a
	// digit/hyphen/space shape per the regex -- is ever converted to a
	// string, for the plausibility/Luhn check.
	var redactedSSN bool
	body = ssnPattern.ReplaceAllFunc(body, func(m []byte) []byte {
		if !ssnPlausible(string(m)) {
			return m
		}
		redactedSSN = true
		return ssnRedaction
	})
	if redactedSSN {
		v = Verdict{Action: Redact, Scanner: s.Name(), Detail: "ssn"}
	}

	var redactedCard bool
	body = creditCardPattern.ReplaceAllFunc(body, func(m []byte) []byte {
		if !luhnValid(digitsOnly(string(m))) {
			return m
		}
		redactedCard = true
		return creditCardRedaction
	})
	if redactedCard {
		v = Verdict{Action: Redact, Scanner: s.Name(), Detail: "credit-card"}
	}

	// Email/phone are lower confidence than a Luhn-valid card or a
	// structurally-plausible SSN -- flag only, and only if a higher-
	// confidence match in this same pass hasn't already set Redact
	// (Redact is the stronger signal; don't downgrade it back to Flag).
	if s.cfg.DetectEmail && v.Action == Allow && emailPattern.Match(body) {
		v = Verdict{Action: Flag, Scanner: s.Name(), Detail: "email"}
	}
	if s.cfg.DetectPhone && v.Action == Allow && phonePattern.Match(body) {
		v = Verdict{Action: Flag, Scanner: s.Name(), Detail: "phone"}
	}

	return body, v
}
