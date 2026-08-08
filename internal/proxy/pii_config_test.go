package proxy

import (
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
)

// TestNew_ScanDetectEmailPhoneConfigReachesTheScanChain proves
// config.ScanDetectEmail/ScanDetectPhone actually reach the Gateway's
// wired scan chain, not just internal/scan's own PIIConfig-parameterized
// constructor (already covered directly in internal/scan's tests).
//
// This is deliberately a construction-wiring check on the Gateway's
// scanners field, not an HTTP-level test: a response-side Flag verdict
// has no externally observable HTTP effect today -- block_on_scan_flag
// only escalates REQUEST-side verdicts (proxy.go's tools/call gate), not
// response-side ones (forward()'s response scanning only logs). That's
// pre-existing scope from issue #7, not something this issue changes, so
// there is no black-box HTTP behavior to assert on here -- the correct
// seam for "did config reach the chain" is the chain itself.
func TestNew_ScanDetectEmailPhoneConfigReachesTheScanChain(t *testing.T) {
	cases := []struct {
		name        string
		detectEmail bool
		detectPhone bool
		body        string
		wantVerdict bool
	}{
		{"email detection enabled flags an email", true, false, `{"text":"contact jane@example.com"}`, true},
		{"email detection disabled (default) does not flag", false, false, `{"text":"contact jane@example.com"}`, false},
		{"phone detection enabled flags a phone number", false, true, `{"text":"call 415-555-0132"}`, true},
		{"phone detection disabled (default) does not flag", false, false, `{"text":"call 415-555-0132"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{
				Listen:          ":0",
				ScanDetectEmail: c.detectEmail,
				ScanDetectPhone: c.detectPhone,
			}
			gw, err := New(cfg, fakeValidator{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() {
				if err := gw.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})

			_, verdicts := gw.scanners.ScanResponse([]byte(c.body))
			var flagged bool
			for _, v := range verdicts {
				if v.Scanner == "pii" {
					flagged = true
				}
			}
			if flagged != c.wantVerdict {
				t.Fatalf("pii verdict present = %v, want %v (verdicts: %v)", flagged, c.wantVerdict, verdicts)
			}
		})
	}
}
