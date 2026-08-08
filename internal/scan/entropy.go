package scan

import (
	"fmt"
	"math"
	"regexp"
)

// entropyMinTokenLen and entropyThresholdBitsPerChar are named constants
// (issue #11 story 17), not magic numbers, so tuning them later is a
// one-line change. 20 chars filters out short IDs/hashes that are too
// common to be a useful signal on their own; 4.0 bits/char is close to
// the theoretical max for a purely-hex alphabet (log2(16) = 4.0) and
// comfortably below a base64 alphabet's max (log2(64) = 6.0) -- catches
// random-looking hex/base64/alnum tokens without flagging ordinary
// structured identifiers.
const (
	entropyMinTokenLen          = 20
	entropyThresholdBitsPerChar = 4.0
)

// entropyTokenPattern extracts credential-shaped candidate substrings --
// contiguous runs of characters actually used by real token/key alphabets
// (base64, hex, typical API-key charsets). JSON's own structural
// characters (quotes, colons, commas, braces) and ordinary prose's
// spaces are natural token boundaries this pattern never crosses, so it
// works directly against raw JSON bytes without needing to parse them.
var entropyTokenPattern = regexp.MustCompile(`[A-Za-z0-9+/=_-]{` + fmt.Sprint(entropyMinTokenLen) + `,}`)

// shannonEntropyBitsPerChar returns s's Shannon entropy in bits per
// character -- a pure, directly-testable function independent of any
// scanning machinery.
func shannonEntropyBitsPerChar(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, n := range counts {
		p := float64(n) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// EntropyScanner flags (never redacts -- story 7) outbound content
// containing a long, high-entropy substring that no named secret pattern
// already caught: an unknown-shaped secret (a new vendor's key format, a
// randomly generated internal token) that SecretScanner's fixed pattern
// list has no way to recognize (story 6). Deliberately its own Scanner
// rather than folded into SecretScanner -- design doc §7's "an ML
// classifier slots in as another Scanner" framing is exactly the "small,
// hot-swappable units" posture this mirrors.
type EntropyScanner struct{}

func NewEntropyScanner() *EntropyScanner { return &EntropyScanner{} }

func (s *EntropyScanner) Name() string { return "entropy" }

// ScanRequest always allows -- outbound-only, the same posture
// SecretScanner's ScanRequest already takes: content flowing *into* an
// MCP server is usually legitimate credential-in-transit config.
func (s *EntropyScanner) ScanRequest(body []byte) Verdict {
	return Verdict{Action: Allow, Scanner: s.Name()}
}

func (s *EntropyScanner) ScanResponse(body []byte) ([]byte, Verdict) {
	for _, tok := range entropyTokenPattern.FindAll(body, -1) {
		e := shannonEntropyBitsPerChar(string(tok))
		if e >= entropyThresholdBitsPerChar {
			return body, Verdict{
				Action:  Flag,
				Scanner: s.Name(),
				Detail:  fmt.Sprintf("high-entropy token (%.2f bits/char, %d chars)", e, len(tok)),
			}
		}
	}
	return body, Verdict{Action: Allow, Scanner: s.Name()}
}
