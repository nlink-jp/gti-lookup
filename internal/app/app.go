// Package app implements the gti-lookup command-line interface: subcommand
// dispatch plus the search / threat / ioc / cache / mcp commands. Core logic
// lives in the indicator, gti, cache, config, and engine packages; this
// package is the thin I/O shell around them.
package app

import (
	"fmt"
	"io"
	"os"
)

// Exit codes. An indicator with no associations is a successful answer — most
// indicators an analyst types are not in any curated collection — so it is
// distinct from an operational failure. Exit 1 (an upstream failure prevented
// some queries) joins this block with the first command that can return it.
const (
	exitOK    = 0 // every query was answered (empty answers included)
	exitError = 2 // usage / validation / configuration error
)

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string, version string) int {
	return run(args, version, os.Stdin, os.Stdout, os.Stderr)
}

// run is Run with injected streams, so dispatch, the version banner and the
// command output can be tested without touching the process's own stdio.
func run(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "search":
		return notImplemented(cmd, stderr)
	case "threat":
		return notImplemented(cmd, stderr)
	case "ioc":
		return notImplemented(cmd, stderr)
	case "cache":
		return runCache(rest, stdout, stderr)
	case "mcp":
		return runMCP(rest, version, stdin, stdout, stderr)
	case "version", "--version", "-v":
		printVersion(stdout, version)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return exitError
	}
}

// notImplemented is the scaffold's stand-in for the lookup commands. They are
// dispatched (so the usage text stays honest) but refuse to pretend.
func notImplemented(cmd string, stderr io.Writer) int {
	fmt.Fprintf(stderr, "gti-lookup: %s is not implemented yet — the design is fixed in docs/ja/gti-lookup-rfp.ja.md\n", cmd)
	return exitError
}

// printVersion is the single source of the version banner. `--version` and the
// `version` subcommand must print byte-identical output: a Homebrew formula's
// `brew test` calls `--version`, while humans type `version`, and a formula
// that tests one while the docs teach the other is how a release ships broken.
func printVersion(w io.Writer, version string) {
	fmt.Fprintln(w, "gti-lookup "+version)
	fmt.Fprintln(w, "Data source: Google Threat Intelligence (www.virustotal.com/api/v3).")
	fmt.Fprintln(w, "A GTI licence API key is required; queries are recorded against it.")
}

func usage(w io.Writer) {
	fmt.Fprint(w, `gti-lookup — curated threat-actor context, from Google Threat Intelligence

Usage:
  gti-lookup <command> [flags] [target...]

Commands:
  search <query>           Search threats (actors, campaigns, malware families, ...)
  threat <collection-id>   Curated report for one collection; --related pivots
  ioc <value>              Actor context for a hash, domain, IP or URL
  cache status             Show the result-cache state
  cache clear              Clear the result cache
  mcp                      Run as a local MCP server (stdio)
  version                  Print the version

search, threat and ioc are not implemented yet; their design is fixed in
docs/ja/gti-lookup-rfp.ja.md.

Exit codes:
  0  every query was answered (an empty answer is a valid answer)
  1  an upstream failure prevented some queries
  2  error (invalid input, bad configuration, ...)

A valid Google Threat Intelligence licence is required: the API key is
mandatory, and every query is recorded against the licence holder's account.
Only Google's index is read, so no packet reaches the target under
investigation. The tool is read-only by design — no collection writes and no
sample uploads, permanently.
`)
}
