package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// Config mirrors the JSON configuration file.
type Config struct {
	// ListenAddr is the local high-port address the resolver binds, e.g. "127.0.0.1:8053".
	ListenAddr string `json:"listen_addr"`
	// RootHints are IPv4 addresses of root servers (no hostnames).
	RootHints []string `json:"root_hints"`
	// UpstreamPort is the single port used for every upstream authority.
	UpstreamPort int `json:"upstream_port"`
	// UpstreamTimeoutMs bounds one upstream exchange.
	UpstreamTimeoutMs int `json:"upstream_timeout_ms"`
	// ResolveTimeoutMs bounds a whole resolution (total deadline).
	ResolveTimeoutMs int `json:"resolve_timeout_ms"`
	// MaxUpstreamQueries caps upstream requests per client query (budget).
	MaxUpstreamQueries int `json:"max_upstream_queries"`
	// CacheMaxEntries caps the number of cached results.
	CacheMaxEntries int `json:"cache_max_entries"`

	upstreamTimeout time.Duration
	resolveTimeout  time.Duration
}

func (c *Config) setDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:8053"
	}
	if c.UpstreamPort == 0 {
		c.UpstreamPort = 15353
	}
	if c.UpstreamTimeoutMs <= 0 {
		c.UpstreamTimeoutMs = 2000
	}
	if c.ResolveTimeoutMs <= 0 {
		c.ResolveTimeoutMs = 8000
	}
	if c.MaxUpstreamQueries <= 0 {
		c.MaxUpstreamQueries = 64
	}
	if c.CacheMaxEntries <= 0 {
		c.CacheMaxEntries = 1024
	}
	c.upstreamTimeout = time.Duration(c.UpstreamTimeoutMs) * time.Millisecond
	c.resolveTimeout = time.Duration(c.ResolveTimeoutMs) * time.Millisecond
}

func (c *Config) validate() error {
	if len(c.RootHints) == 0 {
		return fmt.Errorf("config: root_hints must not be empty")
	}
	for _, ip := range c.RootHints {
		if net.ParseIP(ip).To4() == nil {
			return fmt.Errorf("config: root hint %q is not an IPv4 address", ip)
		}
	}
	return nil
}

// LoadConfig reads and validates the JSON configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
