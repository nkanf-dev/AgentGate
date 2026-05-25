package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Server   ServerConfig   `koanf:"server"`
	Database DatabaseConfig `koanf:"database"`
	Auth     AuthConfig     `koanf:"auth"`
	Policy   PolicyConfig   `koanf:"policy"`
}

type ServerConfig struct {
	Addr        string   `koanf:"addr"`
	CORSOrigins []string `koanf:"cors_origins"`
}

type DatabaseConfig struct {
	DSN string `koanf:"dsn"`
}

type AuthConfig struct {
	AdapterTokens  []string `koanf:"adapter_tokens"`
	OperatorTokens []string `koanf:"operator_tokens"`
	AdminTokens    []string `koanf:"admin_tokens"`
}

type PolicyConfig struct {
	Path string `koanf:"path"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Addr: ":8080",
		},
		Database: DatabaseConfig{
			DSN: "file:agentgate.db?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)",
		},
		Auth: AuthConfig{
			AdapterTokens:  []string{"adapter-local-token"},
			OperatorTokens: []string{"operator-local-token"},
			AdminTokens:    []string{"admin-local-token"},
		},
		Policy: PolicyConfig{
			Path: "config/default_policy.json",
		},
	}
}

func Load(configPath string) (*Config, error) {
	k := koanf.New(".")
	cfg := DefaultConfig()

	// Load config file if provided.
	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("load config file: %w", err)
		}
	}

	// Load environment variables with AGENTGATE_ prefix.
	// Converts AGENTGATE_SERVER_ADDR -> server.addr
	// Handles comma-separated values for slice fields.
	if err := k.Load(env.Provider("AGENTGATE_", ".", func(s string) string {
		return strings.Replace(
			strings.ToLower(strings.TrimPrefix(s, "AGENTGATE_")),
			"_", ".", -1,
		)
	}), nil); err != nil {
		return nil, fmt.Errorf("load env vars: %w", err)
	}

	// Process slice env vars that koanf couldn't parse automatically.
	// This handles AGENTGATE_AUTH_ADAPTER_TOKENS=token1,token2 -> auth.adapter_tokens: ["token1", "token2"]
	if err := loadSliceEnvVars(k); err != nil {
		return nil, fmt.Errorf("load slice env vars: %w", err)
	}

	// Unmarshal into config struct.
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// Validate required fields.
	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// loadSliceEnvVars processes environment variables that should be treated as slices.
func loadSliceEnvVars(k *koanf.Koanf) error {
	sliceEnvVars := map[string]string{
		"AGENTGATE_SERVER_CORS_ORIGINS":  "server.cors_origins",
		"AGENTGATE_AUTH_ADAPTER_TOKENS":  "auth.adapter_tokens",
		"AGENTGATE_AUTH_OPERATOR_TOKENS": "auth.operator_tokens",
		"AGENTGATE_AUTH_ADMIN_TOKENS":    "auth.admin_tokens",
	}

	for envKey, configKey := range sliceEnvVars {
		if val := os.Getenv(envKey); val != "" {
			parts := strings.Split(val, ",")
			result := make([]string, 0, len(parts))
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					result = append(result, part)
				}
			}
			if err := k.Set(configKey, result); err != nil {
				return fmt.Errorf("set %s: %w", configKey, err)
			}
		}
	}
	return nil
}

func validate(cfg *Config) error {
	if cfg.Server.Addr == "" {
		return fmt.Errorf("server.addr is required")
	}
	if cfg.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}
	if len(cfg.Auth.AdapterTokens) == 0 {
		return fmt.Errorf("auth.adapter_tokens is required")
	}
	if len(cfg.Auth.OperatorTokens) == 0 {
		return fmt.Errorf("auth.operator_tokens is required")
	}
	if len(cfg.Auth.AdminTokens) == 0 {
		return fmt.Errorf("auth.admin_tokens is required")
	}
	if cfg.Policy.Path == "" {
		return fmt.Errorf("policy.path is required")
	}
	return nil
}

// GetConfigPath returns the config file path from environment or default.
func GetConfigPath() string {
	if path := os.Getenv("AGENTGATE_CONFIG"); path != "" {
		return path
	}

	// Search in default locations.
	defaults := []string{"agentgate.yaml", "config/agentgate.yaml"}
	for _, p := range defaults {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}
