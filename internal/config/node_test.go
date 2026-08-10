package config

import "testing"

// TestValidateNode exercises the pure per-transport/name validation
// directly (issue #15 story 17) -- the exact logic config.Load's node
// loop already applied, now a standalone function internal/adminapi's
// node-creation endpoint reuses without duplicating the rules.
func TestValidateNode(t *testing.T) {
	cases := []struct {
		name    string
		in      Node
		wantErr bool
	}{
		{
			name: "valid streamable_http",
			in:   Node{Name: "jira", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
		},
		{
			name: "valid stdio",
			in:   Node{Name: "local", Transport: TransportStdio, Command: "go", Args: []string{"run", "./x"}},
		},
		{
			name: "empty transport defaults to streamable_http and is valid with upstream_url",
			in:   Node{Name: "jira", UpstreamURL: "http://localhost:3001"},
		},
		{
			name:    "missing name",
			in:      Node{Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			name:    "streamable_http missing upstream_url",
			in:      Node{Name: "jira", Transport: TransportStreamableHTTP},
			wantErr: true,
		},
		{
			name:    "stdio missing command",
			in:      Node{Name: "local", Transport: TransportStdio},
			wantErr: true,
		},
		{
			name:    "unknown transport",
			in:      Node{Name: "jira", Transport: "carrier-pigeon", UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			name:    "name contains a slash",
			in:      Node{Name: "jira/prod", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			name:    "name has leading whitespace",
			in:      Node{Name: " jira", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			name:    "name has trailing whitespace",
			in:      Node{Name: "jira ", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			// Flagged by Copilot's review on PR #16: the doc comment
			// claims the name is safe as a URL path segment and RFC
			// 8707 resource-URI suffix, but a space isn't -- it would
			// need escaping and wouldn't round-trip through the
			// proxy's /mcp/<name>/ routing, which never unescapes.
			name:    "name contains a space",
			in:      Node{Name: "jira prod", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			name:    "name contains a percent sign",
			in:      Node{Name: "jira%20prod", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			name:    "name contains a question mark",
			in:      Node{Name: "jira?", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			name:    "name contains a hash",
			in:      Node{Name: "jira#1", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
			wantErr: true,
		},
		{
			name: "name with dots, underscores, and hyphens is valid",
			in:   Node{Name: "jira-prod_v2.internal", Transport: TransportStreamableHTTP, UpstreamURL: "http://localhost:3001"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ValidateNode(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ValidateNode(%+v): got nil error, want non-nil", c.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateNode(%+v): %v", c.in, err)
			}
			if got.Transport == "" {
				t.Fatalf("ValidateNode(%+v) returned an empty Transport, want it defaulted", c.in)
			}
		})
	}
}

func TestValidateNode_DefaultsEmptyTransportToStreamableHTTP(t *testing.T) {
	got, err := ValidateNode(Node{Name: "jira", UpstreamURL: "http://localhost:3001"})
	if err != nil {
		t.Fatalf("ValidateNode: %v", err)
	}
	if got.Transport != TransportStreamableHTTP {
		t.Fatalf("Transport = %q, want %q", got.Transport, TransportStreamableHTTP)
	}
}
