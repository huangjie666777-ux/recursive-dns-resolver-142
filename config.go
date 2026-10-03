package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
)

// RootHint is one IPv4 root server entry from the JSON config.
type RootHint struct {
	Name string `json:"name"`
	IPv4 string `json:"ipv4"`
}

// Config mirrors the JSON configuration file.
type Config struct {
	ListenAddr        string     `json:"listen_addr"`
	ListenPort        int        `json:"listen_port"`
	RootHints         []RootHint `json:"root_hints"`
	UpstreamPort      int        `json:"upstream_port"`
	UpstreamTimeoutMs int        `json:"upstream_timeout_ms"`
	QueryDeadlineSec  int        `json:"query_deadline_sec"`
	MaxUpstream       int        `json:"max_upstream_queries"`
	MaxDepth          int        `json:"max_delegation_depth"`
	CacheMaxEntries   int        `json:"cache_max_entries"`
	CacheMaxNegTTL    uint32     `json:"cache_max_negative_ttl"`
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		ListenAddr:        "127.0.0.1",
		ListenPort:        15353,
		UpstreamPort:      15354,
		UpstreamTimeoutMs: 3000,
		QueryDeadlineSec:  30,
		MaxUpstream:       64,
		MaxDepth:          24,
		CacheMaxEntries:   1024,
		CacheMaxNegTTL:    3600,
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ListenPort <= 1024 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("listen_port must be a high port, got %d", cfg.ListenPort)
	}
	if len(cfg.RootHints) == 0 {
		return nil, fmt.Errorf("root_hints must not be empty")
	}
	for _, h := range cfg.RootHints {
		if net.ParseIP(h.IPv4).To4() == nil {
			return nil, fmt.Errorf("root hint %q has invalid IPv4 %q", h.Name, h.IPv4)
		}
	}
	if cfg.UpstreamPort <= 0 || cfg.UpstreamPort > 65535 {
		return nil, fmt.Errorf("invalid upstream_port %d", cfg.UpstreamPort)
	}
	return cfg, nil
}
