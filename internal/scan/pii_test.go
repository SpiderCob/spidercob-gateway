package scan

import (
	"bytes"
	"strings"
	"testing"
)

func TestPIIScanner_RedactsPlausibleSSN(t *testing.T) {
	body := []byte(`{"result":{"text":"SSN on file: 123-45-6789"}}`)
	out, v := NewPIIScanner(PIIConfig{}).ScanResponse(body)
	if v.Action != Redact {
		t.Fatalf("expected redact, got %s", v.Action)
	}
	if strings.Contains(string(out), "123-45-6789") {
		t.Fatalf("SSN not redacted: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED:ssn]") {
		t.Fatalf("redaction must be structural, got: %s", out)
	}
}

func TestPIIScanner_DoesNotFlagImplausibleSSNShapedNumbers(t *testing.T) {
	// Well-known invalid/reserved SSN ranges -- common in test fixtures
	// and placeholder data -- must not be treated as real PII (story 24).
	cases := []string{
		`{"text":"000-12-3456"}`, // area 000
		`{"text":"666-12-3456"}`, // area 666 (reserved)
		`{"text":"912-12-3456"}`, // area 900+ (reserved)
		`{"text":"123-00-4567"}`, // group 00
		`{"text":"123-45-0000"}`, // serial 0000
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			_, v := NewPIIScanner(PIIConfig{}).ScanResponse([]byte(body))
			if v.Action != Allow {
				t.Fatalf("expected allow for implausible SSN shape, got %s for %s", v.Action, body)
			}
		})
	}
}

func TestPIIScanner_RedactsLuhnValidCreditCard(t *testing.T) {
	// A well-known Luhn-valid test Visa number.
	body := []byte(`{"result":{"text":"card on file: 4111111111111111"}}`)
	out, v := NewPIIScanner(PIIConfig{}).ScanResponse(body)
	if v.Action != Redact {
		t.Fatalf("expected redact, got %s", v.Action)
	}
	if strings.Contains(string(out), "4111111111111111") {
		t.Fatalf("credit card not redacted: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED:credit-card]") {
		t.Fatalf("redaction must be structural, got: %s", out)
	}
}

func TestPIIScanner_DoesNotRedactLuhnInvalidNumber(t *testing.T) {
	// Same shape as a real card number (16 digits) but fails the Luhn
	// checksum -- a format-plausible-but-invalid number, the majority of
	// false positives a naive card-number regex would otherwise redact
	// (story 8).
	body := []byte(`{"result":{"text":"reference number: 4111111111111112"}}`)
	_, v := NewPIIScanner(PIIConfig{}).ScanResponse(body)
	if v.Action != Allow {
		t.Fatalf("expected allow for a Luhn-invalid number, got %s", v.Action)
	}
}

func TestPIIScanner_EmailDetectionOffByDefault(t *testing.T) {
	body := []byte(`{"result":{"text":"contact jane@example.com for help"}}`)
	_, v := NewPIIScanner(PIIConfig{}).ScanResponse(body)
	if v.Action != Allow {
		t.Fatalf("expected allow (email detection off by default), got %s", v.Action)
	}
}

func TestPIIScanner_EmailFlaggedNotRedactedWhenEnabled(t *testing.T) {
	body := []byte(`{"result":{"text":"contact jane@example.com for help"}}`)
	out, v := NewPIIScanner(PIIConfig{DetectEmail: true}).ScanResponse(body)
	if v.Action != Flag {
		t.Fatalf("expected flag when email detection is enabled, got %s", v.Action)
	}
	if !strings.Contains(string(out), "jane@example.com") {
		t.Fatalf("email must NOT be redacted, only flagged: %s", out)
	}
}

func TestPIIScanner_PhoneDetectionOffByDefault(t *testing.T) {
	body := []byte(`{"result":{"text":"call us at 415-555-0132"}}`)
	_, v := NewPIIScanner(PIIConfig{}).ScanResponse(body)
	if v.Action != Allow {
		t.Fatalf("expected allow (phone detection off by default), got %s", v.Action)
	}
}

func TestPIIScanner_PhoneFlaggedNotRedactedWhenEnabled(t *testing.T) {
	body := []byte(`{"result":{"text":"call us at 415-555-0132"}}`)
	out, v := NewPIIScanner(PIIConfig{DetectPhone: true}).ScanResponse(body)
	if v.Action != Flag {
		t.Fatalf("expected flag when phone detection is enabled, got %s", v.Action)
	}
	if !strings.Contains(string(out), "415-555-0132") {
		t.Fatalf("phone number must NOT be redacted, only flagged: %s", out)
	}
}

func TestPIIScanner_RequestsAlwaysAllowed(t *testing.T) {
	body := []byte(`{"params":{"arguments":{"ssn":"123-45-6789"}}}`)
	v := NewPIIScanner(PIIConfig{DetectEmail: true, DetectPhone: true}).ScanRequest(body)
	if v.Action != Allow {
		t.Fatalf("expected ScanRequest to always allow, got %s", v.Action)
	}
}

func TestPIIScanner_RedactionWinsOverFlagWhenBothPresent(t *testing.T) {
	// A response containing both a redactable SSN and a flaggable email
	// must report the stronger Redact verdict, not be silently downgraded
	// to Flag by the lower-confidence email check running after it.
	body := []byte(`{"result":{"text":"SSN 123-45-6789, contact jane@example.com"}}`)
	_, v := NewPIIScanner(PIIConfig{DetectEmail: true}).ScanResponse(body)
	if v.Action != Redact {
		t.Fatalf("expected redact to win over flag, got %s", v.Action)
	}
}

// TestPIIScanner_DoesNotCorruptInvalidUTF8BytesElsewhereInBody documents
// the byte-preservation invariant ReplaceAllFunc-based redaction relies
// on: bytes elsewhere in the body that aren't part of the actual match
// must survive untouched, even if they're not valid UTF-8 on their
// own. (Copilot's review on PR #12 raised this as a risk with the
// previous whole-body string-conversion approach; verified directly
// that a bare string([]byte)/[]byte(string) round-trip in Go doesn't
// actually corrupt invalid UTF-8 -- the real wins from this change are
// avoiding a per-match whole-body reallocation and matching
// SecretScanner's own byte-preserving pattern instead of diverging
// from it. Kept as a real regression guard for the invariant either
// way, not because the old code was proven broken here.)
func TestPIIScanner_DoesNotCorruptInvalidUTF8BytesElsewhereInBody(t *testing.T) {
	invalidUTF8 := []byte{0xff, 0xfe, 0xfd} // never valid UTF-8 on their own
	body := append(append([]byte(`{"text":"SSN 123-45-6789 `), invalidUTF8...), []byte(`"}`)...)

	out, v := NewPIIScanner(PIIConfig{}).ScanResponse(body)
	if v.Action != Redact {
		t.Fatalf("expected redact, got %s", v.Action)
	}
	if !bytes.Contains(out, invalidUTF8) {
		t.Fatalf("invalid-UTF-8 bytes elsewhere in the body were corrupted by redaction: %q", out)
	}
	if bytes.Contains(out, []byte("123-45-6789")) {
		t.Fatalf("SSN not redacted: %q", out)
	}
}

// TestPIIScanner_RedactsAllOccurrencesOfARepeatedSSN guards the same
// fix from a different angle: ReplaceAllFunc naturally handles every
// match in one pass, unlike the old per-match strings.Replace(...,1)
// loop, which happened to work for duplicates only by coincidence of
// iterating once per FindAll match.
func TestPIIScanner_RedactsAllOccurrencesOfARepeatedSSN(t *testing.T) {
	body := []byte(`{"text":"123-45-6789 appears twice: 123-45-6789"}`)
	out, v := NewPIIScanner(PIIConfig{}).ScanResponse(body)
	if v.Action != Redact {
		t.Fatalf("expected redact, got %s", v.Action)
	}
	if strings.Contains(string(out), "123-45-6789") {
		t.Fatalf("a repeated SSN was not fully redacted: %s", out)
	}
	if strings.Count(string(out), "[REDACTED:ssn]") != 2 {
		t.Fatalf("expected both occurrences redacted, got: %s", out)
	}
}

func TestDefaultChain_PIIDetectionOffByDefaultForEmailAndPhone(t *testing.T) {
	body := []byte(`{"result":{"text":"contact jane@example.com or 415-555-0132"}}`)
	_, verdicts := Default().ScanResponse(body)
	for _, v := range verdicts {
		if v.Scanner == "pii" {
			t.Fatalf("expected no pii verdicts from Default() (email/phone off by default), got %v", v)
		}
	}
}
