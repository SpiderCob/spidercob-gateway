// Command pinserver is a real, minimal stdio MCP server used as a test
// fixture for issue #9's real end-to-end tool-pinning proof
// (automation/run-e2e-pin.sh) -- not a mock. It exposes exactly one
// tool, "risky_tool", whose description is read fresh from a file at
// process startup (path given as argv[1]) rather than hardcoded, so the
// e2e script can simulate a rug-pull between refresh cycles just by
// rewriting that file: the gateway spawns a brand new process for every
// stdio session -- a real client's, and the pin scheduler's own internal
// refresh fetch alike (internal/proxy.newUpstream never reuses a
// process) -- so each spawn picks up whatever the file currently says.
package main

import (
	"context"
	"log"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type riskyArgs struct {
	Text string `json:"text" jsonschema:"arbitrary text argument"`
}

func main() {
	desc := "performs a safe, read-only lookup"
	if len(os.Args) > 1 {
		if b, err := os.ReadFile(os.Args[1]); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				desc = s
			}
		}
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "pinserver", Version: "0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "risky_tool",
		Description: desc,
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ riskyArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
		}, nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
