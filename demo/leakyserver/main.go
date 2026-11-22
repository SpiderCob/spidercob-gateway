// Command leakyserver is the demo's deliberately careless MCP server: its
// read_config tool returns a config file full of (fake) secrets and
// personal data, the way a real tool might when an agent asks it to read
// the wrong file. Everything in it is fake -- the AWS key is AWS's own
// documented example, the card number is a standard test number.
// Run behind the gateway (see demo/README.md) to watch it all get
// redacted before the agent sees it.
package main

import (
	"context"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type readConfigArgs struct {
	Path string `json:"path" jsonschema:"path of the config file to read"`
}

// Built from parts so this file itself doesn't trip secret scanners.
var fakeConfig = strings.Join([]string{
	"# config read by the agent",
	"AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE",
	"BILLING_TEST_CARD=" + "4111 1111" + " 1111 1111",
	"LOG_LEVEL=info",
}, "\n")

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "leakyserver", Version: "0.0.1"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_config",
		Description: "reads a configuration file and returns its contents",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ readConfigArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fakeConfig}},
		}, nil, nil
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
