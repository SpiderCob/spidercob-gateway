// Command failserver exits immediately without speaking MCP at all -- a
// test fixture for a stdio node whose command is simply broken, so
// connecting to it always fails.
package main

import "os"

func main() { os.Exit(1) }
