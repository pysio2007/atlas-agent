package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	CenterURL         string        `yaml:"center_url"`
	Token             string        `yaml:"token"`
	StorePath         string        `yaml:"store_path"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	ReconnectMaxSecs  int           `yaml:"reconnect_max_secs"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		StorePath:         "/var/lib/atlas-agent/state.db",
		HeartbeatInterval: 30 * time.Second,
		ReconnectMaxSecs:  60,
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.CenterURL) == "" {
		return fmt.Errorf("center_url is required")
	}
	u, err := url.Parse(c.CenterURL)
	if err != nil {
		return fmt.Errorf("center_url is invalid: %w", err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("center_url scheme must be ws or wss")
	}
	if u.Host == "" {
		return fmt.Errorf("center_url host is required")
	}
	if strings.TrimSpace(c.Token) == "" {
		return fmt.Errorf("token is required")
	}
	if strings.TrimSpace(c.StorePath) == "" {
		return fmt.Errorf("store_path is required")
	}
	if c.HeartbeatInterval <= 0 {
		return fmt.Errorf("heartbeat_interval must be positive")
	}
	if c.ReconnectMaxSecs <= 0 {
		return fmt.Errorf("reconnect_max_secs must be positive")
	}
	return nil
}
