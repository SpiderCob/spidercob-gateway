package scan

import (
	"math"
	"testing"
)

func TestShannonEntropyBitsPerChar(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want float64
	}{
		{"all one character has zero entropy", "aaaaaaaaaa", 0.0},
		{"two equally likely symbols has 1 bit/char", "abababab", 1.0},
		{"four equally likely symbols has 2 bits/char", "abcdabcdabcd", 2.0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shannonEntropyBitsPerChar(c.in)
			if math.Abs(got-c.want) > 0.01 {
				t.Fatalf("shannonEntropyBitsPerChar(%q) = %.4f, want %.4f", c.in, got, c.want)
			}
		})
	}
}

func TestEntropyScanner_FlagsHighEntropyUnnamedToken(t *testing.T) {
	// A long, random-looking token that doesn't match any named secret
	// pattern -- exactly the "unknown-shaped secret" case this scanner
	// exists for (story 6).
	body := []byte(`{"result":{"internal_token":"qX7z2mKpL9wR4vT8nY1sB6cJ0hF3dG5a"}}`)
	out, v := NewEntropyScanner().ScanResponse(body)
	if v.Action != Flag {
		t.Fatalf("expected flag for a high-entropy unnamed token, got %s", v.Action)
	}
	if string(out) != string(body) {
		t.Fatalf("entropy scanner must never redact (only flag): body changed")
	}
}

func TestEntropyScanner_AllowsLowEntropyLongString(t *testing.T) {
	// A long but low-entropy (highly repetitive) string must not flag --
	// length alone isn't suspicious.
	body := []byte(`{"result":{"note":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
	_, v := NewEntropyScanner().ScanResponse(body)
	if v.Action != Allow {
		t.Fatalf("expected allow for a low-entropy long string, got %s", v.Action)
	}
}

func TestEntropyScanner_AllowsShortHighEntropyToken(t *testing.T) {
	// Below the minimum-length cutoff, even a maximally-random token must
	// not flag -- short random-looking strings (hashes of short input,
	// small IDs) are too common to be a useful signal.
	body := []byte(`{"result":{"id":"aB3xQ9"}}`)
	_, v := NewEntropyScanner().ScanResponse(body)
	if v.Action != Allow {
		t.Fatalf("expected allow for a short token below the length cutoff, got %s", v.Action)
	}
}

func TestEntropyScanner_RequestsAlwaysAllowed(t *testing.T) {
	// Outbound-only, same posture as SecretScanner's ScanRequest --
	// secrets/high-entropy content flowing *into* an MCP server is
	// usually legitimate credential-in-transit config.
	body := []byte(`{"params":{"arguments":{"token":"qX7z2mKpL9wR4vT8nY1sB6cJ0hF3dG5a"}}}`)
	v := NewEntropyScanner().ScanRequest(body)
	if v.Action != Allow {
		t.Fatalf("expected ScanRequest to always allow, got %s", v.Action)
	}
}

func TestDefaultChain_EntropyScannerDoesNotDoubleFlagAlreadyRedactedSecret(t *testing.T) {
	// Chain ordering (story 26/27): SecretScanner runs before
	// EntropyScanner in Default(), so by the time the entropy scanner
	// sees the body, a matched secret has already been replaced with its
	// [REDACTED:...] marker -- nothing high-entropy is left for it to
	// independently (and redundantly) flag.
	body := []byte(`{"result":{"text":"key AKIAABCDEFGHIJKLMNOP leaked in ticket"}}`)
	out, verdicts := Default().ScanResponse(body)
	if string(out) == string(body) {
		t.Fatalf("expected the secret to be redacted")
	}
	var entropyFlags int
	for _, v := range verdicts {
		if v.Scanner == "entropy" {
			entropyFlags++
		}
	}
	if entropyFlags != 0 {
		t.Fatalf("expected 0 entropy-scanner verdicts on an already-redacted secret, got %d: %v", entropyFlags, verdicts)
	}
}
