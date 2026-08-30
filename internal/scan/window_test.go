package scan

import (
	"bytes"
	"testing"
)

// Fake credential-shaped test fixtures. Built from concatenated pieces
// rather than one contiguous literal, so this repo's own dlp-scan
// pre-commit hook doesn't flag test fixtures as real leaked credentials
// -- CONTEXT.md's documented precedent from issue #52 (restructure the
// fixture, don't look for a suppression flag). The *values* are
// identical either way; only the source-text shape changes.
var (
	fakeAWSKeyHead = "AKIA" + "ABCDE" // 9 chars
	fakeAWSKeyTail = "FGHIJKLMNOP"    // 11 chars
	fakeAWSKey     = fakeAWSKeyHead + fakeAWSKeyTail

	fakeVisaHead = "4" + "111111" + "1" // 8 digits
	fakeVisaTail = "1111" + "1111"      // 8 digits
	// fakeVisaTestCard is the well-known Luhn-valid Visa test number
	// every payment processor's own test suite uses.
	fakeVisaTestCard = fakeVisaHead + fakeVisaTail
	// fakeInvalidCard is the same shape, deliberately Luhn-invalid
	// (last digit changed) -- derived by slicing, never written as its
	// own 16-digit literal.
	fakeInvalidCard = fakeVisaTestCard[:len(fakeVisaTestCard)-1] + "2"

	fakeJWT = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)

// feedAll drives w with chunks, concatenating every Feed's flushed bytes
// plus the final Flush's, and collects every verdict raised along the
// way -- the shape every test below needs.
func feedAll(w ResponseWindow, chunks ...[]byte) (out []byte, verdicts []Verdict) {
	var buf bytes.Buffer
	for _, c := range chunks {
		flushed, v := w.Feed(c)
		buf.Write(flushed)
		verdicts = append(verdicts, v...)
	}
	flushed, v := w.Flush()
	buf.Write(flushed)
	verdicts = append(verdicts, v...)
	return buf.Bytes(), verdicts
}

func TestSecretScanner_WindowRedactsWholeSecretInOneChunk(t *testing.T) {
	s := NewSecretScanner()
	w := s.NewResponseWindow()
	out, verdicts := feedAll(w, []byte("key="+fakeAWSKey+";done"))
	if bytes.Contains(out, []byte(fakeAWSKey)) {
		t.Fatalf("raw secret leaked: %q", out)
	}
	want := "key=[REDACTED:aws-access-key];done"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if len(verdicts) != 1 || verdicts[0].Action != Redact || verdicts[0].Detail != "aws-access-key" {
		t.Fatalf("unexpected verdicts: %+v", verdicts)
	}
}

func TestSecretScanner_WindowCatchesMatchSplitAcrossChunks(t *testing.T) {
	s := NewSecretScanner()
	w := s.NewResponseWindow()
	// The fake AWS key split mid-key across two chunks.
	out, verdicts := feedAll(w,
		[]byte("token="+fakeAWSKeyHead),
		[]byte(fakeAWSKeyTail+";done"),
	)
	if bytes.Contains(out, []byte(fakeAWSKey)) {
		t.Fatalf("split secret leaked: %q", out)
	}
	want := "token=[REDACTED:aws-access-key];done"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if len(verdicts) != 1 {
		t.Fatalf("expected exactly one verdict, got %+v", verdicts)
	}
}

func TestSecretScanner_WindowCatchesMatchSplitByteByByte(t *testing.T) {
	s := NewSecretScanner()
	w := s.NewResponseWindow()
	secret := fakeAWSKey
	full := "prefix-" + secret + "-suffix"
	var chunks [][]byte
	for i := 0; i < len(full); i++ {
		chunks = append(chunks, []byte{full[i]})
	}
	out, verdicts := feedAll(w, chunks...)
	if bytes.Contains(out, []byte(secret)) {
		t.Fatalf("byte-by-byte split secret leaked: %q", out)
	}
	want := "prefix-[REDACTED:aws-access-key]-suffix"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if len(verdicts) != 1 {
		t.Fatalf("expected exactly one verdict, got %+v", verdicts)
	}
}

func TestSecretScanner_WindowMatchesBufferedScanResponseOnRandomSplits(t *testing.T) {
	// The windowed and buffered paths must agree on *content*, only
	// differ on *when* bytes are released (issue #55 spec, Testing
	// Decisions).
	body := []byte("noise before " + fakeAWSKey + " more noise " + fakeJWT + " trailing")
	s := NewSecretScanner()

	buffered, _ := s.ScanResponse(append([]byte(nil), body...))

	// Split at every offset from 1..len(body)-1 in turn (two chunks) and
	// confirm the windowed result matches the buffered one every time.
	for split := 1; split < len(body); split++ {
		w := s.NewResponseWindow()
		out, _ := feedAll(w, body[:split], body[split:])
		if !bytes.Equal(out, buffered) {
			t.Fatalf("split at %d: windowed %q != buffered %q", split, out, buffered)
		}
	}
}

func TestPIIScanner_WindowRedactsSSNSplitAcrossChunks(t *testing.T) {
	s := NewPIIScanner(PIIConfig{})
	w := s.NewResponseWindow()
	out, verdicts := feedAll(w, []byte("ssn=123-4"), []byte("5-6789;done"))
	if bytes.Contains(out, []byte("123-45-6789")) {
		t.Fatalf("split SSN leaked: %q", out)
	}
	want := "ssn=[REDACTED:ssn];done"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if len(verdicts) != 1 || verdicts[0].Detail != "ssn" {
		t.Fatalf("unexpected verdicts: %+v", verdicts)
	}
}

func TestPIIScanner_WindowSkipsImplausibleSSN(t *testing.T) {
	s := NewPIIScanner(PIIConfig{})
	w := s.NewResponseWindow()
	// 000-xx-xxxx is never a plausible SSN -- must survive unredacted.
	out, verdicts := feedAll(w, []byte("id=000-12-3456;done"))
	want := "id=000-12-3456;done"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if len(verdicts) != 0 {
		t.Fatalf("expected no verdicts for an implausible SSN, got %+v", verdicts)
	}
}

func TestPIIScanner_WindowRedactsLuhnValidCardSplitAcrossChunks(t *testing.T) {
	s := NewPIIScanner(PIIConfig{})
	w := s.NewResponseWindow()
	// fakeVisaTestCard is a well-known Luhn-valid test card number.
	out, verdicts := feedAll(w, []byte("card="+fakeVisaHead), []byte(fakeVisaTail+";done"))
	if bytes.Contains(out, []byte(fakeVisaTestCard)) {
		t.Fatalf("split card number leaked: %q", out)
	}
	want := "card=[REDACTED:credit-card];done"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if len(verdicts) != 1 || verdicts[0].Detail != "credit-card" {
		t.Fatalf("unexpected verdicts: %+v", verdicts)
	}
}

func TestPIIScanner_WindowSkipsLuhnInvalidCard(t *testing.T) {
	s := NewPIIScanner(PIIConfig{})
	w := s.NewResponseWindow()
	// Same shape as a card number, deliberately Luhn-invalid.
	out, verdicts := feedAll(w, []byte("ref="+fakeInvalidCard+";done"))
	want := "ref=" + fakeInvalidCard + ";done"
	if string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if len(verdicts) != 0 {
		t.Fatalf("expected no verdicts for a Luhn-invalid number, got %+v", verdicts)
	}
}

func TestChain_NewResponseWindow_ComposesSecretAndPIIInOrder(t *testing.T) {
	c := DefaultWithPII(PIIConfig{})
	window, ok := c.NewResponseWindow()
	if !ok {
		t.Fatal("expected ok=true: Default chain includes SecretScanner and PIIScanner")
	}
	body := "aws=" + fakeAWSKey + " card=" + fakeVisaTestCard + " ssn=123-45-6789 done"
	out, verdicts := feedAll(window, []byte(body))
	if bytes.Contains(out, []byte(fakeAWSKey)) || bytes.Contains(out, []byte(fakeVisaTestCard)) || bytes.Contains(out, []byte("123-45-6789")) {
		t.Fatalf("a secret/PII value leaked through the composed window: %q", out)
	}
	if len(verdicts) != 3 {
		t.Fatalf("expected 3 verdicts (secret + card + ssn), got %+v", verdicts)
	}
}

func TestChain_NewResponseWindow_MatchesBufferedChainOnSplitInput(t *testing.T) {
	c := DefaultWithPII(PIIConfig{})
	body := []byte("aws=" + fakeAWSKey + " card=" + fakeVisaTestCard + " ssn=123-45-6789 done")

	bufferedOut, _ := c.ScanResponse(append([]byte(nil), body...))

	for split := 1; split < len(body); split++ {
		window, _ := c.NewResponseWindow()
		out, _ := feedAll(window, body[:split], body[split:])
		if !bytes.Equal(out, bufferedOut) {
			t.Fatalf("split at %d: windowed %q != buffered %q", split, out, bufferedOut)
		}
	}
}

func TestChain_NewResponseWindow_FalseWhenNoScannerStreams(t *testing.T) {
	c := &Chain{Scanners: []Scanner{NewEntropyScanner(), NewInjectionScanner()}}
	_, ok := c.NewResponseWindow()
	if ok {
		t.Fatal("expected ok=false: neither EntropyScanner nor InjectionScanner implements StreamScanner")
	}
}
