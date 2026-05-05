package config

import (
	"os"
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

	return cfg, nil
}
