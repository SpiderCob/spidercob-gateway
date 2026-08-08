package scan

import (
	"strings"
	"testing"
)

// TestSecretRedaction_ExpandedPatterns covers the Phase 3c pattern
// expansion (issue #11 story 5) -- real-world credential shapes beyond
// the original five (AWS, GCP, private key, JWT, Slack). Table-driven,
// same assertion shape as TestSecretRedaction: the secret's literal text
// must be gone, and the structural [REDACTED:<kind>] marker must be
// present in its place.
func TestSecretRedaction_ExpandedPatterns(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantKind   string
		wantAbsent string
	}{
		{
			name:       "azure storage account key",
			body:       `AccountKey=abcdEFGH1234567890abcdEFGH1234567890abcdEFGH1234567890abcdEFGH1234567890abcdEFGH123456==`,
			wantKind:   "azure-storage-key",
			wantAbsent: "abcdEFGH1234567890",
		},
		{
			name:       "stripe live secret key",
			body:       `stripe_key: sk_live_4eC39HqLyjWDarjtT1zdp7dc`,
			wantKind:   "stripe-key",
			wantAbsent: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		},
		{
			name:       "stripe restricted key",
			body:       `rk_live_51H8anQ2eZvKYlo2C0d6ffZ`,
			wantKind:   "stripe-key",
			wantAbsent: "rk_live_51H8anQ2eZvKYlo2C0d6ffZ",
		},
		{
			name:       "github classic personal access token",
			body:       `Authorization header used ghp_1234567890abcdefghijklmnopqrstuvwxyz for the request`,
			wantKind:   "github-token",
			wantAbsent: "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		},
		{
			name:       "github fine-grained personal access token",
			body:       `github_pat_11ABCDEFG0abcdefghijklmnop_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ`,
			wantKind:   "github-token",
			wantAbsent: "github_pat_11ABCDEFG0",
		},
		{
			name:       "postgres connection string with embedded credentials",
			body:       `DATABASE_URL=postgres://appuser:s3cr3tPass@db.internal.example.com:5432/prod`,
			wantKind:   "db-connection-string",
			wantAbsent: "s3cr3tPass",
		},
		{
			name:       "mongodb+srv connection string with embedded credentials",
			body:       `mongodb+srv://svc_account:hunter2@cluster0.example.mongodb.net/mydb`,
			wantKind:   "db-connection-string",
			wantAbsent: "hunter2",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, v := NewSecretScanner().ScanResponse([]byte(c.body))
			if v.Action != Redact {
				t.Fatalf("expected redact, got %s (detail=%s)", v.Action, v.Detail)
			}
			if strings.Contains(string(out), c.wantAbsent) {
				t.Fatalf("secret not redacted, still present in output: %s", out)
			}
			if !strings.Contains(string(out), "[REDACTED:"+c.wantKind+"]") {
				t.Fatalf("redaction must be structural and name %q, got: %s", c.wantKind, out)
			}
		})
	}
}

// TestSecretRedaction_ExpandedPatternsDoNotFalsePositive guards against
// the expanded pattern set being so loose it flags ordinary text --
// generic-looking DB URLs without embedded credentials, and short
// alphanumeric strings that merely start with a recognized prefix, must
// stay clean.
func TestSecretRedaction_ExpandedPatternsDoNotFalsePositive(t *testing.T) {
	cases := []string{
		`DATABASE_URL=postgres://db.internal.example.com:5432/prod`, // no embedded credentials
		`the ghost story ghp_ was about a haunted pull request`,     // too short to be a real token
		`stripe_publishable_key: pk_live_4eC39HqLyjWDarjtT1zdp7dc`,  // publishable keys aren't secret
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			out, v := NewSecretScanner().ScanResponse([]byte(body))
			if v.Action != Allow {
				t.Fatalf("expected allow for non-secret text, got %s (detail=%s, out=%s)", v.Action, v.Detail, out)
			}
		})
	}
}
