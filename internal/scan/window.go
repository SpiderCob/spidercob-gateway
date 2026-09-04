package scan

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
)

// defaultWindowMargin is the trailing byte count a windowedRedactor never
// treats as safe to release -- generous enough to comfortably hold any of
// this chain's real secret/PII shapes (an AWS key is 20 bytes, a Stripe
// key or GitHub PAT a few dozen, a realistic JWT or a credentialed DB
// connection string a few hundred at most) even though a couple of the
// underlying regexes (jwt, db-connection-string) are technically
// unbounded-length. A single match longer than this margin could still
// be split across a chunk boundary -- a deliberate, documented limit
// (issue #55 spec), not a claim of gapless coverage for arbitrary-length
// input.
//
// Deliberately kept in the low hundreds of bytes, not a larger "extra
// safe" number: Chain.NewResponseWindow composes one windowedRedactor per
// scanner in sequence, and each stage independently withholds its own
// margin from what the *previous* stage already released -- a chain of N
// windowed scanners compounds to roughly N*margin bytes of real-world
// hold-back before anything reaches the client, on top of whatever
// margin any single stage needs on its own. A larger constant here
// directly trades away how small a genuinely-streamed response has to be
// before this chain's own buffering defeats the point of streaming it at
// all.
const defaultWindowMargin = 512

// patternRule is one candidate pattern a windowedRedactor checks: a
// regex plus, for patterns where a structural match isn't enough on its
// own (an SSN needs plausibility-filtering, a card number needs a Luhn
// check), an optional accept function deciding whether a given match is
// actually redacted. redaction is the literal bytes substituted in;
// nil means build "[REDACTED:<name>]" per match, the shape
// SecretScanner's own (buffered) ScanResponse already uses.
type patternRule struct {
	name      string
	re        *regexp.Regexp
	accept    func(match []byte) bool
	redaction []byte
}

type matchSpan struct {
	start, end int
	name       string
	redaction  []byte
}

// findMatches runs every rule against buf and returns the accepted,
// non-overlapping matches in left-to-right order. Overlapping candidates
// (two different patterns matching the same bytes) are resolved by
// keeping whichever starts first and discarding anything that starts
// before it ends -- a deterministic tie-break, unlike the buffered
// scanners' own map-iteration order, which doesn't matter for their
// single-pass whole-body replace but would make windowed flush
// boundaries non-deterministic if left to chance.
func findMatches(rules []patternRule, buf []byte) []matchSpan {
	var spans []matchSpan
	for _, r := range rules {
		for _, loc := range r.re.FindAllIndex(buf, -1) {
			start, end := loc[0], loc[1]
			if r.accept != nil && !r.accept(buf[start:end]) {
				continue
			}
			redaction := r.redaction
			if redaction == nil {
				redaction = []byte(fmt.Sprintf("[REDACTED:%s]", r.name))
			}
			spans = append(spans, matchSpan{start: start, end: end, name: r.name, redaction: redaction})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })

	var out []matchSpan
	lastEnd := -1
	for _, s := range spans {
		if s.start < lastEnd {
			continue
		}
		out = append(out, s)
		lastEnd = s.end
	}
	return out
}

// windowedRedactor is the shared ResponseWindow implementation for both
// SecretScanner and PIIScanner: hold back a trailing margin of bytes
// across Feed calls so a match spanning a chunk boundary is never
// released before the rest of it has arrived, redacting whatever's safe
// to flush using the same structural "[REDACTED:<kind>]" substitution
// their buffered ScanResponse implementations already use.
type windowedRedactor struct {
	scanner string
	margin  int
	rules   []patternRule
	held    []byte
}

func (w *windowedRedactor) Feed(chunk []byte) ([]byte, []Verdict) {
	buf := append(w.held, chunk...)
	if len(buf) <= w.margin {
		w.held = buf
		return nil, nil
	}

	safeLen := len(buf) - w.margin
	matches := findMatches(w.rules, buf)

	var out bytes.Buffer
	var verdicts []Verdict
	pos := 0
	holdFrom := len(buf)
	for _, m := range matches {
		if m.end > safeLen {
			// This match starts inside (or crosses into) the margin
			// zone -- hold everything from its start onward for the
			// next Feed call rather than flushing any of it now.
			holdFrom = m.start
			break
		}
		out.Write(buf[pos:m.start])
		out.Write(m.redaction)
		verdicts = append(verdicts, Verdict{Action: Redact, Scanner: w.scanner, Detail: m.name})
		pos = m.end
	}
	if holdFrom == len(buf) {
		out.Write(buf[pos:safeLen])
		w.held = append([]byte(nil), buf[safeLen:]...)
	} else {
		out.Write(buf[pos:holdFrom])
		w.held = append([]byte(nil), buf[holdFrom:]...)
	}
	return out.Bytes(), verdicts
}

func (w *windowedRedactor) Flush() ([]byte, []Verdict) {
	if len(w.held) == 0 {
		return nil, nil
	}
	matches := findMatches(w.rules, w.held)
	var out bytes.Buffer
	var verdicts []Verdict
	pos := 0
	for _, m := range matches {
		out.Write(w.held[pos:m.start])
		out.Write(m.redaction)
		verdicts = append(verdicts, Verdict{Action: Redact, Scanner: w.scanner, Detail: m.name})
		pos = m.end
	}
	out.Write(w.held[pos:])
	w.held = nil
	return out.Bytes(), verdicts
}

// windowedFlagger is the shared ResponseWindow implementation for
// flag-only (non-redacting) scanners -- EntropyScanner and
// InjectionScanner (issue #61). Unlike windowedRedactor, it never
// rewrites the bytes it relays: match reports whether buf currently
// contains a qualifying match (using the exact same detection logic the
// scanner's own buffered ScanResponse already runs) and, if so, the
// verdict detail text to report.
//
// "Flag once, then stop" (issue #61 spec): once a windowedFlagger has
// raised its one verdict for a response, it stops scanning entirely and
// becomes pure passthrough for whatever's left -- mirroring
// EntropyScanner/InjectionScanner's own buffered ScanResponse, which
// already returns on the first match found. This is what lets it avoid
// any positional bookkeeping for a match that happens to still be
// visible inside the held-back margin across multiple Feed calls: once
// flagged, the question of "have I already reported this exact match"
// never comes up.
//
// margin is the same fixed hold-back defaultWindowMargin already uses
// for windowedRedactor, and carries the identical documented limit: a
// qualifying match longer than margin, still arriving across a chunk
// boundary, could in principle be missed. Simpler than windowedRedactor
// by construction -- with nothing ever rewritten, match is checked
// against the whole held-plus-new-chunk buffer on every Feed rather than
// needing matchSpan's per-match redaction-boundary bookkeeping. The
// tradeoff: match re-scans that whole buffer (bounded by margin plus one
// chunk, never the whole stream) on every Feed call until it fires,
// rather than only the boundary-adjacent new bytes -- a real, deliberate
// CPU cost for the simplicity, not a correctness concern (self-review,
// issue #61).
type windowedFlagger struct {
	scanner string
	margin  int
	match   func(buf []byte) (matched bool, detail string)
	flagged bool
	held    []byte
}

func (w *windowedFlagger) Feed(chunk []byte) ([]byte, []Verdict) {
	if w.flagged {
		// Caller (internal/proxy's forwardStreaming) writes and reuses
		// its read buffer synchronously before the next Feed, so
		// returning chunk verbatim is safe today -- copied anyway for
		// consistency with every other return path in this file, and to
		// not depend on that caller detail holding forever (self-review,
		// issue #61).
		return append([]byte(nil), chunk...), nil
	}
	buf := append(w.held, chunk...)
	if matched, detail := w.match(buf); matched {
		w.flagged = true
		w.held = nil
		return buf, []Verdict{{Action: Flag, Scanner: w.scanner, Detail: detail}}
	}
	if len(buf) <= w.margin {
		w.held = buf
		return nil, nil
	}
	safeLen := len(buf) - w.margin
	out := append([]byte(nil), buf[:safeLen]...)
	w.held = append([]byte(nil), buf[safeLen:]...)
	return out, nil
}

func (w *windowedFlagger) Flush() ([]byte, []Verdict) {
	held := w.held
	w.held = nil
	if w.flagged || len(held) == 0 {
		return held, nil
	}
	if matched, detail := w.match(held); matched {
		// Mirrors Feed's own match branch (self-review, issue #61): a
		// ResponseWindow's contract is one call to Flush per response,
		// but setting flagged here too means a stray Feed/Flush call
		// after this one still can't double-flag, rather than relying
		// solely on every current caller's own discipline.
		w.flagged = true
		return held, []Verdict{{Action: Flag, Scanner: w.scanner, Detail: detail}}
	}
	return held, nil
}

// chainWindow composes one ResponseWindow per StreamScanner-implementing
// scanner in a Chain, in the chain's own order -- mirroring how
// Chain.ScanResponse threads a buffered body through each scanner in
// sequence. Each window only ever sees, as "new" input, whatever the
// previous window has already decided is safe to release; a scanner's
// own held-back margin is never visible to the scanner after it.
type chainWindow struct{ windows []ResponseWindow }

// NewResponseWindow returns a composed window covering every scanner in
// c that implements StreamScanner, in chain order, or ok=false if none
// do -- the caller's signal to fall back to the existing buffered path
// rather than ever forwarding streamed bytes with no scanning applied at
// all (the same safe default stream.go's own doc comment already
// promised before any scanner implemented the interface).
func (c *Chain) NewResponseWindow() (window ResponseWindow, ok bool) {
	var windows []ResponseWindow
	for _, s := range c.Scanners {
		if ss, ok := s.(StreamScanner); ok {
			windows = append(windows, ss.NewResponseWindow())
		}
	}
	if len(windows) == 0 {
		return nil, false
	}
	return &chainWindow{windows: windows}, true
}

func (c *chainWindow) Feed(chunk []byte) ([]byte, []Verdict) {
	data := chunk
	var all []Verdict
	for _, w := range c.windows {
		flushed, verdicts := w.Feed(data)
		data = flushed
		all = append(all, verdicts...)
	}
	return data, all
}

// Flush drains every window in order. A window's own Flush releases only
// what it personally held back; that output is new, unseen data to every
// later window in the chain, so it's fed forward (via Feed, not Flush)
// before that window's own Flush runs -- otherwise a scanner's
// leftover tail could reach the client having skipped a later scanner
// entirely.
func (c *chainWindow) Flush() ([]byte, []Verdict) {
	var all []Verdict
	var pending []byte
	for i, w := range c.windows {
		if i > 0 {
			fed, v := w.Feed(pending)
			all = append(all, v...)
			pending = fed
		}
		tail, v := w.Flush()
		all = append(all, v...)
		pending = append(pending, tail...)
	}
	return pending, all
}
