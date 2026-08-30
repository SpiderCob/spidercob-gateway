package scan

import (
	"bytes"
	"testing"
)

// fakeWindow is a minimal test double proving the streaming interface can
// express the real technique it exists for: holding back a trailing margin
// of bytes across Feed calls so a pattern split across a chunk boundary
// isn't missed, then redacting once the full pattern is visible.
type fakeWindow struct {
	held []byte
}

const fakeNeedle = "SECRET"

func (w *fakeWindow) Feed(chunk []byte) ([]byte, []Verdict) {
	buf := append(w.held, chunk...)

	// Hold back the last len(needle)-1 bytes as a safety margin: a match
	// straddling this Feed call and the next one must not be flushed (and
	// therefore missed) before the rest of it arrives.
	margin := len(fakeNeedle) - 1
	if margin >= len(buf) {
		w.held = buf
		return nil, nil
	}
	flush, held := buf[:len(buf)-margin], buf[len(buf)-margin:]
	w.held = append([]byte(nil), held...)

	var verdicts []Verdict
	if bytes.Contains(flush, []byte(fakeNeedle)) {
		flush = bytes.ReplaceAll(flush, []byte(fakeNeedle), []byte("[REDACTED]"))
		verdicts = append(verdicts, Verdict{Action: Redact, Scanner: "fake", Detail: fakeNeedle})
	}
	return flush, verdicts
}

func (w *fakeWindow) Flush() ([]byte, []Verdict) {
	rest := w.held
	w.held = nil
	var verdicts []Verdict
	if bytes.Contains(rest, []byte(fakeNeedle)) {
		rest = bytes.ReplaceAll(rest, []byte(fakeNeedle), []byte("[REDACTED]"))
		verdicts = append(verdicts, Verdict{Action: Redact, Scanner: "fake", Detail: fakeNeedle})
	}
	return rest, verdicts
}

type fakeStreamScanner struct{ *SecretScanner }

func (fakeStreamScanner) NewResponseWindow() ResponseWindow { return &fakeWindow{} }

func TestResponseWindow_HoldsBackSplitMatchAcrossChunks(t *testing.T) {
	var s StreamScanner = fakeStreamScanner{NewSecretScanner()}
	w := s.NewResponseWindow()

	var out bytes.Buffer
	var verdicts []Verdict

	// "SECRET" arrives split across two Feed calls: "...SEC" then "RET...".
	chunks := [][]byte{[]byte("token=SEC"), []byte("RET;done")}
	for _, c := range chunks {
		flushed, v := w.Feed(c)
		out.Write(flushed)
		verdicts = append(verdicts, v...)
	}
	flushed, v := w.Flush()
	out.Write(flushed)
	verdicts = append(verdicts, v...)

	if bytes.Contains(out.Bytes(), []byte("SECRET")) {
		t.Fatalf("split match not caught, raw secret leaked: %q", out.String())
	}
	if got, want := out.String(), "token=[REDACTED];done"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if len(verdicts) == 0 {
		t.Fatal("expected at least one redact verdict")
	}
}

func TestOnlyRedactingScannersImplementStreamScanner(t *testing.T) {
	// Issue #55: SecretScanner and PIIScanner (the two scanners that
	// already redact unconditionally in the buffered chain) implement
	// windowed streaming. EntropyScanner/InjectionScanner (flag-only)
	// deliberately don't yet -- proxy.go's streaming path must keep
	// falling back to buffered-only scanning for those two until a
	// follow-up closes that gap (issue #55 spec's Out of Scope).
	want := map[string]bool{
		"secrets": true,
		"pii":     true,
	}
	for _, s := range Default().Scanners {
		_, implements := s.(StreamScanner)
		if implements != want[s.Name()] {
			t.Errorf("%s: StreamScanner implemented=%v, want %v", s.Name(), implements, want[s.Name()])
		}
	}
}
