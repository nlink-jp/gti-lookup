package app

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/nlink-jp/gti-lookup/internal/cache"
	"github.com/nlink-jp/gti-lookup/internal/config"
	"github.com/nlink-jp/gti-lookup/internal/engine"
	"github.com/nlink-jp/gti-lookup/internal/gti"
	"github.com/nlink-jp/gti-lookup/internal/mcp"
)

// runMCP serves the stdio MCP server until stdin closes. MCP has no
// protocol-level cancel, so a closing stdin is the shutdown signal.
func runMCP(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	var configPath string
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	fs.StringVar(&configPath, "config", "", "config file path")
	fs.StringVar(&configPath, "c", "", "config file path (shorthand)")
	if _, err := parseInterleaved(fs, args); err != nil {
		return exitError
	}

	cfg, err := config.Load(configPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "gti-lookup: %v\n", err)
		return exitError
	}
	store := &cache.Store{Dir: cfg.CacheDir}
	client := gti.New(cfg.BaseURL, cfg.APIKey, cfg.Timeout, "gti-lookup/"+version)

	srv := &mcp.Server{
		Cfg:     cfg,
		Cache:   store,
		Version: version,
		Eng:     engine.New(cfg, store, client),
	}

	if err := srv.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "gti-lookup: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}
