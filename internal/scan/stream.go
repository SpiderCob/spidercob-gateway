package scan

// StreamScanner is implemented by scanners that support windowed,
// incremental scanning of streamed (SSE) responses, in addition to the
// buffered ScanResponse every Scanner already provides. A scanner that
// doesn't implement this is skipped on streaming responses -- Phase 1's
// existing behavior -- until a real implementation lands in Phase 3
// (design doc §6: "streaming responses scanned in windowed chunks with
// redaction applied before flush").
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
