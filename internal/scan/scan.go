// Package scan implements the Spidercob sanitization pipeline (design doc §7).
// Every scanner is a small, hot-swappable unit; the Chain runs them in order.
package scan

type Action int

const (
	Allow Action = iota
	Flag
	Redact
	Block
)

func (a Action) String() string {
	switch a {
	case Allow:
		return "allow"
	case Flag:
		return "flag"
	case Redact:
		return "redact"
	case Block:
		return "block"
	}
	return "unknown"
}

type Verdict struct {
	Action  Action
	Scanner string
	Detail  string
}

// Scanner inspects JSON-RPC payloads on the MCP data path.
type Scanner interface {
	Name() string
	// ScanRequest inspects an inbound (agent -> MCP) body.
	ScanRequest(body []byte) Verdict
	// ScanResponse inspects an outbound (MCP -> agent) body and may return a
	// redacted copy. Redaction must be structural, never silent dropping.
	ScanResponse(body []byte) ([]byte, Verdict)
}

type Chain struct{ Scanners []Scanner }

func (c *Chain) ScanRequest(body []byte) []Verdict {
	var out []Verdict
	for _, s := range c.Scanners {
		v := s.ScanRequest(body)
		if v.Action != Allow {
			out = append(out, v)
		}
		if v.Action == Block {
			break
		}
	}
	return out
}

func (c *Chain) ScanResponse(body []byte) ([]byte, []Verdict) {
	var out []Verdict
	for _, s := range c.Scanners {
		nb, v := s.ScanResponse(body)
		body = nb
		if v.Action != Allow {
			out = append(out, v)
		}
	}
	return body, out
}

// Default returns the seed chain with PII email/phone detection off
// (design doc §7: "often legitimate" — off unless a caller explicitly
// opts in via DefaultWithPII). See DefaultWithPII for the full chain and
// scanner-ordering rationale.
func Default() *Chain {
	return DefaultWithPII(PIIConfig{})
}

// DefaultWithPII returns the seed chain: secret redaction, PII
// redaction/flagging (SSN/credit-card unconditional, email/phone gated
// by piiCfg), entropy-based unknown-secret flagging (outbound), and
// injection heuristics (both directions, flag-only by default — honest
// defaults, see design doc §7). Order is deliberate (issue #11 stories
// 26-27): structural, high-confidence scanners (SecretScanner,
// PIIScanner) run before EntropyScanner, since Chain.ScanResponse
// threads each scanner's output into the next — a value an earlier
// scanner already redacted is gone from the body EntropyScanner sees, so
// it can't also flag the same value as "unknown high-entropy content."
func DefaultWithPII(piiCfg PIIConfig) *Chain {
	return &Chain{Scanners: []Scanner{NewSecretScanner(), NewPIIScanner(piiCfg), NewEntropyScanner(), NewInjectionScanner()}}
}
