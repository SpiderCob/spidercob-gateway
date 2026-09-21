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

func TestAllDefaultScannersImplementStreamScanner(t *testing.T) {
	// Issue #55 gave SecretScanner/PIIScanner (the two that already
	// redact unconditionally in the buffered chain) windowed streaming.
	// Issue #61 closed the remaining gap: EntropyScanner/InjectionScanner
	// (flag-only) now implement it too, via a separate, non-redacting
	// ResponseWindow. No scanner in the default chain falls back to
	// buffered-only scanning on a streamed response any more.
	for _, s := range Default().Scanners {
		if _, implements := s.(StreamScanner); !implements {
			t.Errorf("%s: expected StreamScanner to be implemented", s.Name())
		}
	}
}
