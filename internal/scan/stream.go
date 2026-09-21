package scan

// StreamScanner is implemented by scanners that support windowed,
// incremental scanning of streamed (SSE) responses, in addition to the
// buffered ScanResponse every Scanner already provides. A scanner that
// doesn't implement this is skipped on streaming responses -- Phase 1's
// original behavior when this interface was only groundwork, still the
// per-scanner fallback today (design doc §6: "streaming responses
// scanned in windowed chunks with redaction applied before flush").
//
// SecretScanner and PIIScanner implement this via windowedRedactor
// (issue #55, window.go) -- the two scanners that already redact
// unconditionally in the buffered chain. EntropyScanner and
// InjectionScanner (flag-only, never redact) implement it too, via the
// separate windowedFlagger (issue #61, window.go) -- a streamed response
// now gets the same four-scanner coverage a buffered one does.
// internal/proxy's forwardStreaming is the real consumer: it composes a
// Chain's implementing scanners into one window (Chain.NewResponseWindow)
// and relays an SSE response through it incrementally, falling back to
// the buffered path entirely if no scanner in the chain implements this.
type StreamScanner interface {
	Scanner
	// NewResponseWindow returns a fresh, stateful window for one streaming
	// response. A window must not be reused across responses.
	NewResponseWindow() ResponseWindow
}

// ResponseWindow incrementally scans a streamed response. Implementations
// must hold back enough trailing context between Feed calls that a match
// spanning a chunk boundary is still caught, rather than flushing every
// byte immediately.
type ResponseWindow interface {
	// Feed consumes one chunk and returns the prefix of it (plus any
	// earlier held-back bytes) that's now safe to flush downstream, along
	// with any verdicts raised by what was flushed.
	Feed(chunk []byte) (flushed []byte, verdicts []Verdict)
	// Flush is called once at stream end and returns any bytes still held
	// back, plus final verdicts.
	Flush() (flushed []byte, verdicts []Verdict)
}
