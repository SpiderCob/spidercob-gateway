// Command crashserver is a real stdio MCP server that starts up and
// completes the initialize handshake normally, then exits unexpectedly
// shortly after -- a test fixture for exercising the gateway's handling
// of a session whose underlying process dies mid-session, not via an
// orderly Close().
package main

import (
	"context"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoArgs struct {
	Text string `json:"text" jsonschema:"text to echo back"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "crashserver", Version: "0.0.1"}, nil)

	// A real tool, so calls before the crash succeed normally -- only
	// calls after the process exits should fail, proving the failure is
	// actually caused by the crash and not by there being nothing to call.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "echoes the given text back",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: args.Text}},
		}, nil, nil
	})

	go func() {
		time.Sleep(150 * time.Millisecond)
		os.Exit(1)
	}()
	_ = server.Run(context.Background(), &mcp.StdioTransport{})
}
