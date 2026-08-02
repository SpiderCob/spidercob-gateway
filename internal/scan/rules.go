package scan

import (
	"fmt"
	"regexp"
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

var injectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore (all )?(previous|prior) instructions`),
	regexp.MustCompile(`(?i)disregard (the )?(system|previous) prompt`),
	regexp.MustCompile(`(?i)you are now (in )?(developer|dan) mode`),
	regexp.MustCompile(`(?i)when you (summarize|read) this[,]? (also|you must)`),
}

type InjectionScanner struct{}

func NewInjectionScanner() *InjectionScanner { return &InjectionScanner{} }

func (s *InjectionScanner) Name() string { return "injection-heuristics" }

func (s *InjectionScanner) ScanRequest(body []byte) Verdict {
	for _, re := range injectionPatterns {
		if re.Match(body) {
			return Verdict{Action: Flag, Scanner: s.Name(), Detail: re.String()}
		}
	}
	return Verdict{Action: Allow, Scanner: s.Name()}
}

// ScanResponse also checks tool RESULTS for instruction-like content aimed at
// the LLM — response-embedded injection is the #1 vector into agents.
func (s *InjectionScanner) ScanResponse(body []byte) ([]byte, Verdict) {
	for _, re := range injectionPatterns {
		if re.Match(body) {
			return body, Verdict{Action: Flag, Scanner: s.Name(), Detail: "response-embedded: " + re.String()}
		}
	}
	return body, Verdict{Action: Allow, Scanner: s.Name()}
}
