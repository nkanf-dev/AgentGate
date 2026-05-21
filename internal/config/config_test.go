package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.Addr != ":8080" {
		t.Fatalf("default addr = %q, want :8080", cfg.Server.Addr)
	}
	if cfg.Database.DSN == "" {
		t.Fatal("default dsn should not be empty")
	}
	if len(cfg.Auth.AdapterTokens) == 0 {
		t.Fatal("default adapter tokens should not be empty")
	}
}

func TestLoadFromYAML(t *testing.T) {
	// Create temp config file.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agentgate.yaml")
	content := `
server:
  addr: ":9090"
  cors_origins:
    - "https://example.com"
database:
  dsn: "file:test.db"
auth:
  adapter_tokens:
    - "test-adapter"
  operator_tokens:
    - "test-operator"
  admin_tokens:
    - "test-admin"
policy:
  path: "test-policy.json"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Server.Addr != ":9090" {
		t.Fatalf("addr = %q, want :9090", cfg.Server.Addr)
	}
	if len(cfg.Server.CORSOrigins) != 1 || cfg.Server.CORSOrigins[0] != "https://example.com" {
		t.Fatalf("cors_origins = %v, want [https://example.com]", cfg.Server.CORSOrigins)
	}
	if cfg.Database.DSN != "file:test.db" {
		t.Fatalf("dsn = %q, want file:test.db", cfg.Database.DSN)
	}
	if len(cfg.Auth.AdapterTokens) != 1 || cfg.Auth.AdapterTokens[0] != "test-adapter" {
		t.Fatalf("adapter_tokens = %v, want [test-adapter]", cfg.Auth.AdapterTokens)
	}
	if cfg.Policy.Path != "test-policy.json" {
		t.Fatalf("policy path = %q, want test-policy.json", cfg.Policy.Path)
	}
}

func TestLoadFromEnvVars(t *testing.T) {
	// Save and restore env vars.
	envVars := map[string]string{
		"AGENTGATE_SERVER_ADDR":        "",
		"AGENTGATE_DATABASE_DSN":       "",
		"AGENTGATE_AUTH_ADAPTER_TOKENS": "",
	}
	origEnv := make(map[string]string)
	for key := range envVars {
		origEnv[key] = os.Getenv(key)
	}
	defer func() {
		for key, val := range origEnv {
			if val == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, val)
			}
		}
	}()

	// Set env vars.
	os.Setenv("AGENTGATE_SERVER_ADDR", ":7070")
	os.Setenv("AGENTGATE_DATABASE_DSN", "file:env.db")
	os.Setenv("AGENTGATE_AUTH_ADAPTER_TOKENS", "env-adapter")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Server.Addr != ":7070" {
		t.Fatalf("addr = %q, want :7070", cfg.Server.Addr)
	}
	if cfg.Database.DSN != "file:env.db" {
		t.Fatalf("dsn = %q, want file:env.db", cfg.Database.DSN)
	}
	// Note: koanf env provider doesn't handle slices well by default.
	// This test verifies the basic string override works.
}

func TestValidateRequiredFields(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Addr: "",
		},
	}
	if err := validate(cfg); err == nil {
		t.Fatal("expected validation error for empty addr")
	}

	cfg = &Config{
		Server:   ServerConfig{Addr: ":8080"},
		Database: DatabaseConfig{DSN: ""},
	}
	if err := validate(cfg); err == nil {
		t.Fatal("expected validation error for empty dsn")
	}

	cfg = &Config{
		Server:   ServerConfig{Addr: ":8080"},
		Database: DatabaseConfig{DSN: "file:test.db"},
		Auth: AuthConfig{
			AdapterTokens:  []string{"token"},
			OperatorTokens: []string{"token"},
			AdminTokens:    []string{"token"},
		},
		Policy: PolicyConfig{Path: ""},
	}
	if err := validate(cfg); err == nil {
		t.Fatal("expected validation error for empty policy.path")
	}
}

func TestGetConfigPath(t *testing.T) {
	// Save and restore env var.
	orig, hadOrig := os.LookupEnv("AGENTGATE_CONFIG")
	defer func() {
		if hadOrig {
			os.Setenv("AGENTGATE_CONFIG", orig)
		} else {
			os.Unsetenv("AGENTGATE_CONFIG")
		}
	}()

	// Test default path.
	os.Unsetenv("AGENTGATE_CONFIG")
	if path := GetConfigPath(); path != "agentgate.yaml" {
		t.Fatalf("default config path = %q, want agentgate.yaml", path)
	}

	// Test custom path.
	os.Setenv("AGENTGATE_CONFIG", "/custom/path.yaml")
	if path := GetConfigPath(); path != "/custom/path.yaml" {
		t.Fatalf("custom config path = %q, want /custom/path.yaml", path)
	}
}

func TestEnvVarOverridesSlice(t *testing.T) {
	// Create temp config file with all tokens configured.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agentgate.yaml")
	content := `
server:
  addr: ":8080"
auth:
  adapter_tokens:
    - "yaml-adapter"
  operator_tokens:
    - "yaml-operator"
  admin_tokens:
    - "yaml-admin"
policy:
  path: "config/default_policy.json"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Set only one env var.
	os.Setenv("AGENTGATE_AUTH_ADAPTER_TOKENS", "env-adapter")
	defer os.Unsetenv("AGENTGATE_AUTH_ADAPTER_TOKENS")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// Check adapter_tokens was overridden.
	if len(cfg.Auth.AdapterTokens) != 1 || cfg.Auth.AdapterTokens[0] != "env-adapter" {
		t.Fatalf("adapter_tokens = %v, want [env-adapter]", cfg.Auth.AdapterTokens)
	}

	// Check other tokens preserved from YAML.
	if len(cfg.Auth.OperatorTokens) != 1 || cfg.Auth.OperatorTokens[0] != "yaml-operator" {
		t.Fatalf("operator_tokens = %v, want [yaml-operator]", cfg.Auth.OperatorTokens)
	}
	if len(cfg.Auth.AdminTokens) != 1 || cfg.Auth.AdminTokens[0] != "yaml-admin" {
		t.Fatalf("admin_tokens = %v, want [yaml-admin]", cfg.Auth.AdminTokens)
	}
}

func TestEnvVarOverridesMultipleSlices(t *testing.T) {
	// Create temp config file.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agentgate.yaml")
	content := `
server:
  addr: ":8080"
auth:
  adapter_tokens:
    - "yaml-adapter"
  operator_tokens:
    - "yaml-operator"
  admin_tokens:
    - "yaml-admin"
policy:
  path: "config/default_policy.json"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Set multiple env vars.
	os.Setenv("AGENTGATE_AUTH_ADAPTER_TOKENS", "env-adapter")
	os.Setenv("AGENTGATE_AUTH_OPERATOR_TOKENS", "env-operator")
	defer os.Unsetenv("AGENTGATE_AUTH_ADAPTER_TOKENS")
	defer os.Unsetenv("AGENTGATE_AUTH_OPERATOR_TOKENS")

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	// Check overridden tokens.
	if len(cfg.Auth.AdapterTokens) != 1 || cfg.Auth.AdapterTokens[0] != "env-adapter" {
		t.Fatalf("adapter_tokens = %v, want [env-adapter]", cfg.Auth.AdapterTokens)
	}
	if len(cfg.Auth.OperatorTokens) != 1 || cfg.Auth.OperatorTokens[0] != "env-operator" {
		t.Fatalf("operator_tokens = %v, want [env-operator]", cfg.Auth.OperatorTokens)
	}

	// Check admin_tokens preserved from YAML.
	if len(cfg.Auth.AdminTokens) != 1 || cfg.Auth.AdminTokens[0] != "yaml-admin" {
		t.Fatalf("admin_tokens = %v, want [yaml-admin]", cfg.Auth.AdminTokens)
	}
}
