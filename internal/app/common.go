package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nlink-jp/gti-lookup/internal/cache"
	"github.com/nlink-jp/gti-lookup/internal/config"
	"github.com/nlink-jp/gti-lookup/internal/engine"
	"github.com/nlink-jp/gti-lookup/internal/gti"
)

// commonFlags are the flags every query command shares, so `--refresh` and
// `--config` mean the same thing everywhere rather than being re-declared
// (and eventually diverging) per command.
type commonFlags struct {
	jsonOut bool
	refresh bool
	timeout time.Duration
	config  string
	limit   int
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.jsonOut, "json", false, "JSON output")
	fs.BoolVar(&c.jsonOut, "j", false, "JSON output (shorthand)")
	fs.BoolVar(&c.refresh, "refresh", false, "bypass the result cache and re-query")
	fs.DurationVar(&c.timeout, "timeout", 0, "network timeout (e.g. 10s)")
	fs.StringVar(&c.config, "config", "", "config file path")
	fs.StringVar(&c.config, "c", "", "config file path (shorthand)")
	fs.IntVar(&c.limit, "limit", 0, "results to list (default from config)")
}

// buildEngine resolves configuration and wires the shared engine.
func (c *commonFlags) buildEngine(version string) (*engine.Engine, error) {
	cfg, err := config.Load(c.config, c.timeout)
	if err != nil {
		return nil, err
	}
	client := gti.New(cfg.BaseURL, cfg.APIKey, cfg.Timeout, "gti-lookup/"+version)
	return engine.New(cfg, &cache.Store{Dir: cfg.CacheDir}, client), nil
}

// exitFor maps an error onto the exit contract: caller mistakes are usage
// errors, everything upstream is a partial failure — the analyst must be able
// to tell "I typed it wrong" from "GTI did not answer".
func exitFor(err error) int {
	switch engine.Code(err) {
	case engine.CodeInvalidArgument, engine.CodeMissingKey, "":
		return exitError
	default:
		return exitPartial
	}
}

// fail prints one structured error line to stderr and picks the exit code.
func fail(stderr io.Writer, err error) int {
	if code := engine.Code(err); code != "" {
		fmt.Fprintf(stderr, "gti-lookup: [%s] %v\n", code, err)
	} else {
		fmt.Fprintf(stderr, "gti-lookup: %v\n", err)
	}
	return exitFor(err)
}

// renderJSON writes one indented JSON document.
func renderJSON(stdout io.Writer, v any) error {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// summaryLine renders one collection summary as a single scannable line.
func summaryLine(s engine.ThreatSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %-14s %s", s.CollectionType, s.Name)
	if s.Name == "" {
		fmt.Fprintf(&b, "%s", s.ID)
	}
	if len(s.AltNames) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(s.AltNames, ", "))
	}
	if s.LastModified != "" {
		fmt.Fprintf(&b, "  modified %s", s.LastModified)
	}
	fmt.Fprintf(&b, "\n      id: %s", s.ID)
	return b.String()
}

// moreLine renders the retrieval accounting: what was fetched next to what
// upstream holds, so a page is never mistaken for the whole answer.
func moreLine(retrieved int, more bool, upstream int) string {
	switch {
	case upstream > 0 && (more || upstream > retrieved):
		return fmt.Sprintf("retrieved %d of %d upstream — raise --limit or narrow the query for the rest", retrieved, upstream)
	case more:
		return fmt.Sprintf("retrieved %d; upstream holds more — raise --limit or narrow the query", retrieved)
	default:
		return fmt.Sprintf("retrieved %d", retrieved)
	}
}

// parseInterleaved parses flags that appear anywhere among the positional
// arguments, and returns the positionals.
//
// Go's flag package stops at the first non-flag argument, so a plain Parse
// would read `ioc example.com --full` as two targets and silently ignore the
// flag. Writing the target first is the natural way to type this, and a flag
// that is quietly dropped is worse than one that is rejected — so parse in
// rounds, taking one positional at a time.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
}
