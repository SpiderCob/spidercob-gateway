package scan

import (
	"fmt"
	"regexp"
	"sort"
)

// Seed rules. Secret patterns derived from the Gitleaks ruleset (MIT);
// injection heuristics are commodity patterns — the modular Scanner interface
// exists precisely so these can be replaced by better detectors over time.

var secretPatterns = map[string]*regexp.Regexp{
	"aws-access-key":    regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	"gcp-api-key":       regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	"private-key-block": regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	"jwt":               regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
	"slack-token":       regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),

	// Phase 3c (issue #11 story 5) -- expanded beyond the original five,
	// still deliberately Gitleaks-derived rather than invented from
	// scratch (design doc §7).
	"azure-storage-key": regexp.MustCompile(`\bAccountKey=[A-Za-z0-9+/]{86}==`),
	// sk_/rk_ live or test secret keys only -- pk_ (publishable) keys are
	// meant to be public and must not be flagged.
	"stripe-key": regexp.MustCompile(`\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b`),
	// Classic PATs (ghp_) are a fixed 36-char suffix; fine-grained PATs
	// (github_pat_) are longer and underscore-delimited.
	"github-token": regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b`),
	// Only a connection string with embedded user:password credentials is
	// a secret -- a bare host/port/db URI with no credentials is not.
	"db-connection-string": regexp.MustCompile(`\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/]+:[^@\s]+@[^\s]+`),
}

type SecretScanner struct{}

func NewSecretScanner() *SecretScanner { return &SecretScanner{} }

func (s *SecretScanner) Name() string { return "secrets" }

// ScanRequest: secrets flowing *into* an MCP server are usually legitimate
// credentials in transit config; we only redact on the way out.
func (s *SecretScanner) ScanRequest(body []byte) Verdict {
	return Verdict{Action: Allow, Scanner: s.Name()}
}

func (s *SecretScanner) ScanResponse(body []byte) ([]byte, Verdict) {
	v := Verdict{Action: Allow, Scanner: s.Name()}
	for name, re := range secretPatterns {
		if re.Match(body) {
			body = re.ReplaceAll(body, []byte(fmt.Sprintf("[REDACTED:%s]", name)))
			v = Verdict{Action: Redact, Scanner: s.Name(), Detail: name}
		}
	}
	return body, v
}

// NewResponseWindow implements StreamScanner (issue #55): windowed,
// boundary-safe secret redaction for streamed (SSE) responses, using the
// exact same pattern set as ScanResponse above.
func (s *SecretScanner) NewResponseWindow() ResponseWindow {
	rules := make([]patternRule, 0, len(secretPatterns))
	for name, re := range secretPatterns {
		rules = append(rules, patternRule{name: name, re: re})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].name < rules[j].name })
	return &windowedRedactor{scanner: s.Name(), margin: defaultWindowMargin, rules: rules}
}

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (all )?(previous|prior) instructions`),
	regexp.MustCompile(`(?i)disregard (the )?(system|previous) prompt`),
	regexp.MustCompile(`(?i)you are now (in )?(developer|dan) mode`),
	regexp.MustCompile(`(?i)when you (summarize|read) this[,]? (also|you must)`),
}

type InjectionScanner struct{}

func NewInjectionScanner() *InjectionScanner { return &InjectionScanner{} }

func (s *InjectionScanner) Name() string { return "injection-heuristics" }

// ScanRequest matches against a normalized copy of body (issue #11
// stories 12-14: homoglyph/zero-width evasion resistance) — the returned
// Verdict is the only thing derived from it; the caller's own copy of
// body is untouched.
func (s *InjectionScanner) ScanRequest(body []byte) Verdict {
	normalized := normalizeForDetection(body)
	for _, re := range injectionPatterns {
		if re.Match(normalized) {
			return Verdict{Action: Flag, Scanner: s.Name(), Detail: re.String()}
		}
	}
	return Verdict{Action: Allow, Scanner: s.Name()}
}

// ScanResponse also checks tool RESULTS for instruction-like content aimed at
// the LLM — response-embedded injection is the #1 vector into agents.
// Matches against a normalized copy (same evasion resistance as
// ScanRequest); the body returned to the caller is always the original,
// unmodified bytes — normalization is detection-only.
func (s *InjectionScanner) ScanResponse(body []byte) ([]byte, Verdict) {
	if matched, detail := injectionResponseMatch(body); matched {
		return body, Verdict{Action: Flag, Scanner: s.Name(), Detail: detail}
	}
	return body, Verdict{Action: Allow, Scanner: s.Name()}
}

// injectionResponseMatch is the detection logic ScanResponse and
// NewResponseWindow both drive: does buf, once normalized the same way
// ScanRequest already normalizes (homoglyph/zero-width evasion
// resistance), contain any response-embedded injection pattern. Factored
// out (issue #61) so the windowed path can't drift from the buffered
// one.
func injectionResponseMatch(buf []byte) (matched bool, detail string) {
	normalized := normalizeForDetection(buf)
	for _, re := range injectionPatterns {
		if re.Match(normalized) {
			return true, "response-embedded: " + re.String()
		}
	}
	return false, ""
}

// NewResponseWindow implements StreamScanner (issue #61): windowed,
// boundary-safe injection-phrase flagging for streamed (SSE) responses,
// matching against a normalized copy of the buffer exactly as
// ScanResponse above already does -- the same evasion resistance
// (homoglyph/zero-width normalization) applies to a streamed response
// too. Flag-only, same as the buffered path -- never redacts, and the
// raw (unnormalized) bytes are always what gets relayed; normalization
// here is detection-only, same contract as the buffered path's own.
func (s *InjectionScanner) NewResponseWindow() ResponseWindow {
	return &windowedFlagger{scanner: s.Name(), margin: defaultWindowMargin, match: injectionResponseMatch}
}
