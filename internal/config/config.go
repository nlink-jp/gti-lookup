package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the GTI API root. GTI is served over the VirusTotal v3
	// API surface; a licensed key is what turns it into Google Threat
	// Intelligence.
	DefaultBaseURL = "https://www.virustotal.com/api/v3"
	// DefaultLimit is how many results a search or relationship expansion
	// lists before summarising the rest.
	DefaultLimit = 10
	// DefaultTimeout bounds each HTTPS exchange.
	DefaultTimeout = 30 * time.Second
	// DefaultThreatTTL is how long a cached collection (threat actor,
	// campaign, malware family, report) answer stays fresh. Curated
	// collections change slowly, so a day keeps repeated pivots down to one
	// request.
	DefaultThreatTTL = 24 * time.Hour
	// DefaultIOCTTL is how long a cached IOC (file, domain, IP, URL) answer
	// stays fresh. IOC assessments move with new analyses, so this is
	// deliberately short.
	DefaultIOCTTL = 1 * time.Hour
)

// Config holds resolved runtime settings.
type Config struct {
	APIKey       string        // GTI API key; required for every query
	BaseURL      string        // API root
	DefaultLimit int           // results listed before the rest are summarised
	CacheDir     string        // result-cache directory
	ThreatTTL    time.Duration // freshness window for collection answers
	IOCTTL       time.Duration // freshness window for IOC answers
	Timeout      time.Duration // network timeout per exchange
}

// Load resolves configuration. If configPath is empty the default location
// (~/.config/gti-lookup/config.toml) is used when present. Environment
// variables override file values; a non-zero timeoutOverride wins over both.
//
// A missing API key is not a Load error: cache inspection and the MCP
// handshake must work without one. Commands that query GTI check HasKey and
// fail with a pointed message instead.
func Load(configPath string, timeoutOverride time.Duration) (*Config, error) {
	cfg := &Config{
		BaseURL:      DefaultBaseURL,
		DefaultLimit: DefaultLimit,
		CacheDir:     DefaultCacheDir(),
		ThreatTTL:    DefaultThreatTTL,
		IOCTTL:       DefaultIOCTTL,
		Timeout:      DefaultTimeout,
	}

	if configPath == "" {
		configPath = DefaultConfigPath()
	}
	if configPath != "" {
		if f, err := os.Open(configPath); err == nil {
			defer func() { _ = f.Close() }()
			sections, perr := parseTOML(f)
			if perr != nil {
				return nil, fmt.Errorf("parse config %s: %w", configPath, perr)
			}
			if aerr := applySections(cfg, sections); aerr != nil {
				return nil, fmt.Errorf("config %s: %w", configPath, aerr)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("open config %s: %w", configPath, err)
		}
	}

	if err := applyEnv(cfg); err != nil {
		return nil, err
	}
	if timeoutOverride > 0 {
		cfg.Timeout = timeoutOverride
	}
	return cfg, validate(cfg)
}

// HasKey reports whether an API key is configured.
func (c *Config) HasKey() bool { return c.APIKey != "" }

// Redacted returns the config with the key replaced by a fixed marker, for
// anything that prints or serialises settings. The key is never rendered: it
// carries the licence's authority, and GTI has no narrower scope to fall back
// on.
func (c *Config) Redacted() Config {
	clone := *c
	if clone.APIKey != "" {
		clone.APIKey = "[set]"
	}
	return clone
}

func validate(cfg *Config) error {
	if cfg.DefaultLimit < 1 {
		return fmt.Errorf("[query] default_limit must be at least 1")
	}
	if cfg.BaseURL == "" {
		return fmt.Errorf("[api] base_url must not be empty")
	}
	return nil
}

func applySections(cfg *Config, sections map[string]map[string]string) error {
	if a := sections["api"]; a != nil {
		if v := a["key"]; v != "" {
			cfg.APIKey = v
		}
		if v := a["base_url"]; v != "" {
			cfg.BaseURL = v
		}
	}
	if q := sections["query"]; q != nil {
		if v := q["default_limit"]; v != "" {
			n, err := parseInt(v)
			if err != nil {
				return fmt.Errorf("[query] default_limit: %w", err)
			}
			cfg.DefaultLimit = n
		}
	}
	if c := sections["cache"]; c != nil {
		if v := c["threat_ttl_hours"]; v != "" {
			d, err := parseHours(v)
			if err != nil {
				return fmt.Errorf("[cache] threat_ttl_hours: %w", err)
			}
			cfg.ThreatTTL = d
		}
		if v := c["ioc_ttl_hours"]; v != "" {
			d, err := parseHours(v)
			if err != nil {
				return fmt.Errorf("[cache] ioc_ttl_hours: %w", err)
			}
			cfg.IOCTTL = d
		}
		if v := c["dir"]; v != "" {
			cfg.CacheDir = expandHome(v)
		}
	}
	if n := sections["network"]; n != nil {
		if v := n["timeout_seconds"]; v != "" {
			d, err := parseSeconds(v)
			if err != nil {
				return fmt.Errorf("[network] timeout_seconds: %w", err)
			}
			cfg.Timeout = d
		}
	}
	return nil
}

func applyEnv(cfg *Config) error {
	// GTI_LOOKUP_API_KEY is this tool's own name and wins. VT_APIKEY is the
	// variable Google's own GTI tooling conventionally uses, accepted so an
	// environment already set up for it works here unchanged.
	if v := os.Getenv("GTI_LOOKUP_API_KEY"); v != "" {
		cfg.APIKey = v
	} else if v := os.Getenv("VT_APIKEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("GTI_LOOKUP_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("GTI_LOOKUP_DEFAULT_LIMIT"); v != "" {
		n, err := parseInt(v)
		if err != nil {
			return fmt.Errorf("GTI_LOOKUP_DEFAULT_LIMIT: %w", err)
		}
		cfg.DefaultLimit = n
	}
	if v := os.Getenv("GTI_LOOKUP_CACHE_DIR"); v != "" {
		cfg.CacheDir = expandHome(v)
	}
	if v := os.Getenv("GTI_LOOKUP_THREAT_TTL_HOURS"); v != "" {
		d, err := parseHours(v)
		if err != nil {
			return fmt.Errorf("GTI_LOOKUP_THREAT_TTL_HOURS: %w", err)
		}
		cfg.ThreatTTL = d
	}
	if v := os.Getenv("GTI_LOOKUP_IOC_TTL_HOURS"); v != "" {
		d, err := parseHours(v)
		if err != nil {
			return fmt.Errorf("GTI_LOOKUP_IOC_TTL_HOURS: %w", err)
		}
		cfg.IOCTTL = d
	}
	if v := os.Getenv("GTI_LOOKUP_TIMEOUT_SECONDS"); v != "" {
		d, err := parseSeconds(v)
		if err != nil {
			return fmt.Errorf("GTI_LOOKUP_TIMEOUT_SECONDS: %w", err)
		}
		cfg.Timeout = d
	}
	return nil
}

func parseInt(v string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%q is not an integer", v)
	}
	return n, nil
}

func parseSeconds(v string) (time.Duration, error) {
	s, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || s <= 0 {
		return 0, fmt.Errorf("%q is not a positive number", v)
	}
	return time.Duration(s * float64(time.Second)), nil
}

func parseHours(v string) (time.Duration, error) {
	h, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || h <= 0 {
		return 0, fmt.Errorf("%q is not a positive number", v)
	}
	return time.Duration(h * float64(time.Hour)), nil
}

// DefaultConfigPath returns the default config file location, honoring
// XDG_CONFIG_HOME.
func DefaultConfigPath() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "gti-lookup", "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "gti-lookup", "config.toml")
}

// DefaultCacheDir returns the default cache directory, honoring
// XDG_CACHE_HOME. Cached answers are re-fetchable transient state, so they
// belong under the cache home, not data.
func DefaultCacheDir() string {
	if x := os.Getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "gti-lookup")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "gti-lookup-cache"
	}
	return filepath.Join(home, ".cache", "gti-lookup")
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// parseTOML parses the minimal subset this tool needs: [section] headers and
// key = value lines, where value is an optionally quoted string. Comments start
// with '#'. It intentionally does not support arrays, nested tables, or typed
// values. Vendored from the sibling lookup tools rather than imported, matching
// the series.
func parseTOML(r io.Reader) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	current := ""
	sections[current] = map[string]string{}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if strings.HasPrefix(raw, "[") {
			end := strings.IndexByte(raw, ']')
			if end < 0 {
				return nil, fmt.Errorf("line %d: unterminated section header", line)
			}
			current = strings.TrimSpace(raw[1:end])
			if _, ok := sections[current]; !ok {
				sections[current] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", line)
		}
		key := strings.TrimSpace(raw[:eq])
		val := parseValue(strings.TrimSpace(raw[eq+1:]))
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key", line)
		}
		sections[current][key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return sections, nil
}

// parseValue strips surrounding quotes, or trims a trailing inline comment from
// a bare value.
func parseValue(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		q := v[0]
		if end := strings.IndexByte(v[1:], q); end >= 0 {
			return v[1 : 1+end]
		}
	}
	if hash := strings.IndexByte(v, '#'); hash >= 0 {
		v = strings.TrimSpace(v[:hash])
	}
	return v
}
