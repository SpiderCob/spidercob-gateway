// Command echoserver is a real, minimal stdio MCP server used as a test
// fixture for internal/proxy/stdioadapter -- not a mock. It's spawned as a
// real child process over real stdin/stdout, per the repo's workflow rule
// of validating against a real MCP server rather than faking the protocol.
package main

import (
	"context"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoArgs struct {
	Text string `json:"text" jsonschema:"text to echo back"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "echoserver", Version: "0.0.1"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "echoes the given text back",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: args.Text}},
		}, nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
