// Package config loads the gateway configuration.
// JSON for now to stay stdlib-only; YAML lands with the admin UI (design doc §9).
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Node is one upstream MCP server registered behind the gateway.
type Node struct {
	Name        string `json:"name"`
	UpstreamURL string `json:"upstream_url"`
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
	for _, n := range c.Nodes {
		if n.Name == "" || n.UpstreamURL == "" {
			return nil, fmt.Errorf("every node needs a name and upstream_url")
		}
	}
	return &c, nil
}
