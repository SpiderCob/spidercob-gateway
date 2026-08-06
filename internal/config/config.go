// Package config loads the gateway configuration.
// JSON for now to stay stdlib-only; YAML lands with the admin UI (design doc §9).
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Transport identifies how the gateway reaches a node's upstream.
const (
	TransportStreamableHTTP = "streamable_http"
	TransportStdio          = "stdio"
)

// Node is one upstream MCP server registered behind the gateway.
type Node struct {
	Name        string   `json:"name"`
	Transport   string   `json:"transport,omitempty"` // TransportStreamableHTTP (default) or TransportStdio
	UpstreamURL string   `json:"upstream_url,omitempty"`
	Command     string   `json:"command,omitempty"`
	Args        []string `json:"args,omitempty"`
}

type Config struct {
	Listen string `json:"listen"`
	Nodes  []Node `json:"nodes"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	for i, n := range c.Nodes {
		if n.Name == "" {
			return nil, fmt.Errorf("every node needs a name")
		}
		if n.Transport == "" {
			n.Transport = TransportStreamableHTTP
		}
		switch n.Transport {
		case TransportStreamableHTTP:
			if n.UpstreamURL == "" {
				return nil, fmt.Errorf("node %s: streamable_http nodes need upstream_url", n.Name)
			}
		case TransportStdio:
			if n.Command == "" {
				return nil, fmt.Errorf("node %s: stdio nodes need command", n.Name)
			}
		default:
			return nil, fmt.Errorf("node %s: unknown transport %q", n.Name, n.Transport)
		}
		c.Nodes[i] = n
	}
	return &c, nil
}
