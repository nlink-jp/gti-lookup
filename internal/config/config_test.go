package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate points every discovery path at a temp dir and clears the tool's
// environment, so a test never reads the developer's real config or key.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	for _, k := range []string{
		"GTI_LOOKUP_API_KEY", "VT_APIKEY", "GTI_LOOKUP_BASE_URL",
		"GTI_LOOKUP_DEFAULT_LIMIT", "GTI_LOOKUP_CACHE_DIR",
		"GTI_LOOKUP_THREAT_TTL_HOURS", "GTI_LOOKUP_IOC_TTL_HOURS",
		"GTI_LOOKUP_TIMEOUT_SECONDS",
	} {
		t.Setenv(k, "")
	}
	return dir
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestDefaults(t *testing.T) {
	isolate(t)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, DefaultBaseURL)
	}
	if cfg.DefaultLimit != DefaultLimit {
		t.Errorf("DefaultLimit = %d, want %d", cfg.DefaultLimit, DefaultLimit)
	}
	if cfg.ThreatTTL != DefaultThreatTTL {
		t.Errorf("ThreatTTL = %v, want %v", cfg.ThreatTTL, DefaultThreatTTL)
	}
	if cfg.IOCTTL != DefaultIOCTTL {
		t.Errorf("IOCTTL = %v, want %v", cfg.IOCTTL, DefaultIOCTTL)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}
	if cfg.HasKey() {
		t.Error("a key appeared from nowhere")
	}
}

// A missing key is not a Load error: cache inspection and the MCP handshake
// must work without one. The commands that query GTI are what refuse to run.
func TestMissingKeyIsNotALoadError(t *testing.T) {
	isolate(t)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("Load without a key: %v", err)
	}
	if cfg.HasKey() {
		t.Error("HasKey() = true with no key configured")
	}
}

func TestFileValuesApplied(t *testing.T) {
	dir := isolate(t)
	path := writeConfig(t, dir, `
# comment
[api]
key = "file-key"
base_url = "https://example.test/api/v3"

[query]
default_limit = 3

[cache]
threat_ttl_hours = 48
ioc_ttl_hours = 2

[network]
timeout_seconds = 5
`)
	cfg, err := Load(path, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "file-key" {
		t.Errorf("APIKey = %q, want file-key", cfg.APIKey)
	}
	if cfg.BaseURL != "https://example.test/api/v3" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.DefaultLimit != 3 {
		t.Errorf("DefaultLimit = %d, want 3", cfg.DefaultLimit)
	}
	if cfg.ThreatTTL != 48*time.Hour {
		t.Errorf("ThreatTTL = %v, want 48h", cfg.ThreatTTL)
	}
	if cfg.IOCTTL != 2*time.Hour {
		t.Errorf("IOCTTL = %v, want 2h", cfg.IOCTTL)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", cfg.Timeout)
	}
}

// Precedence: flag > environment variable > config file > built-in default.
func TestPrecedence(t *testing.T) {
	dir := isolate(t)
	path := writeConfig(t, dir, "[api]\nkey = \"file-key\"\n\n[network]\ntimeout_seconds = 5\n")

	t.Setenv("GTI_LOOKUP_API_KEY", "env-key")
	t.Setenv("GTI_LOOKUP_TIMEOUT_SECONDS", "9")

	cfg, err := Load(path, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "env-key" {
		t.Errorf("env did not override file: APIKey = %q", cfg.APIKey)
	}
	if cfg.Timeout != 9*time.Second {
		t.Errorf("env did not override file: Timeout = %v", cfg.Timeout)
	}

	// The flag (timeoutOverride) beats both.
	cfg, err = Load(path, 11*time.Second)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Timeout != 11*time.Second {
		t.Errorf("flag did not override env: Timeout = %v", cfg.Timeout)
	}
}

// VT_APIKEY is honoured because Google's own GTI tooling uses it, but this
// tool's own variable wins when both are set.
func TestKeyEnvAliasAndPriority(t *testing.T) {
	isolate(t)
	t.Setenv("VT_APIKEY", "vt-key")
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "vt-key" {
		t.Errorf("VT_APIKEY ignored: APIKey = %q", cfg.APIKey)
	}

	t.Setenv("GTI_LOOKUP_API_KEY", "own-key")
	cfg, err = Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "own-key" {
		t.Errorf("GTI_LOOKUP_API_KEY should win over VT_APIKEY: APIKey = %q", cfg.APIKey)
	}
}

func TestMissingConfigFileIsNotAnError(t *testing.T) {
	dir := isolate(t)
	if _, err := Load(filepath.Join(dir, "absent.toml"), 0); err != nil {
		t.Errorf("a missing config file should fall back to defaults, got: %v", err)
	}
}

func TestInvalidValuesAreRejectedByName(t *testing.T) {
	tests := []struct {
		body string
		want string
	}{
		{"[query]\ndefault_limit = zero\n", "default_limit"},
		{"[query]\ndefault_limit = 0\n", "default_limit"},
		{"[cache]\nthreat_ttl_hours = -1\n", "threat_ttl_hours"},
		{"[cache]\nioc_ttl_hours = 0\n", "ioc_ttl_hours"},
		{"[network]\ntimeout_seconds = 0\n", "timeout_seconds"},
		{"[api]\nbase_url", "expected key = value"},
	}
	for _, tc := range tests {
		dir := isolate(t)
		path := writeConfig(t, dir, tc.body)
		_, err := Load(path, 0)
		if err == nil {
			t.Errorf("%q: want an error naming %s", tc.body, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %q does not name %s", tc.body, err, tc.want)
		}
	}
}

// The key carries the licence's authority, so nothing that renders settings
// may reveal it.
func TestRedactedHidesKey(t *testing.T) {
	cfg := &Config{APIKey: "super-secret-value"}
	if got := cfg.Redacted(); strings.Contains(got.APIKey, "super-secret") {
		t.Errorf("Redacted() leaked the key: %q", got.APIKey)
	}
	if cfg.APIKey != "super-secret-value" {
		t.Error("Redacted() mutated the original config")
	}
	none := &Config{}
	if none.Redacted().APIKey != "" {
		t.Error("Redacted() invented a key where there was none")
	}
}

// ParseFloat reads "NaN" and "Inf", and NaN passes any range check written as
// "reject what is below the floor". A number is accepted from inside its range.
func TestNumbersThatAreNotNumbersAreRefused(t *testing.T) {
	for _, in := range []string{"NaN", "nan", "Inf", "+Inf", "-Inf", "1e300", "-1"} {
		if d, err := parseSeconds(in); err == nil {
			t.Errorf("parseSeconds(%q) = %v, want a refusal", in, d)
		}
		if d, err := parseHours(in); err == nil {
			t.Errorf("parseHours(%q) = %v, want a refusal", in, d)
		}
	}
	if d, err := parseSeconds("1.5"); err != nil || d <= 0 {
		t.Errorf("parseSeconds(\"1.5\") = %v, %v", d, err)
	}
	if d, err := parseHours("1.5"); err != nil || d <= 0 {
		t.Errorf("parseHours(\"1.5\") = %v, %v", d, err)
	}
	if _, err := parseSeconds("0"); err == nil {
		t.Errorf("parseSeconds(\"0\") was accepted")
	}
	if _, err := parseHours("0"); err == nil {
		t.Errorf("parseHours(\"0\") was accepted")
	}
}
