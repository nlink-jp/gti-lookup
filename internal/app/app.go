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
// distinct from an operational failure.
const (
	exitOK      = 0 // every query was answered (empty answers included)
	exitPartial = 1 // an upstream failure prevented or degraded some queries
	exitError   = 2 // usage / validation / configuration error
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
		return runSearch(rest, version, stdout, stderr)
	case "search-iocs":
		return runSearchIOCs(rest, version, stdout, stderr)
	case "threat":
		return runThreat(rest, version, stdout, stderr)
	case "ioc":
		return runIOC(rest, version, stdout, stderr)
	case "behaviour":
		return runBehaviour(rest, version, stdout, stderr)
	case "hunting":
		return runHunting(rest, version, stdout, stderr)
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
  search <query>           Search the collections catalogue (vulnerabilities)
  search-iocs <query>      Search the IOC corpus with GTI intelligence syntax
  threat <collection-id>   Report for one collection; --related pivots, --mitre ATT&CK
  ioc <value ...>          Threat context for hashes, domains, IPs or URLs
  behaviour <hash>         Sandbox behaviour summary; --section expands one part
  hunting [ruleset-id]     Your LiveHunt rulesets (list, or one with rules text)
  cache status             Show the result-cache state
  cache clear              Clear the result cache
  mcp                      Run as a local MCP server (stdio)
  version                  Print the version

Shared flags:
  -j, --json               JSON output (JSONL for multiple ioc targets)
  --refresh                Bypass the result cache and re-query
  --limit <n>              Results to list (default 10, max 40)
  --timeout <dur>          Network timeout (e.g. 10s; default 30s)
  -c, --config <path>      Config file (default ~/.config/gti-lookup/config.toml)

search flags:
  --type <t>               vulnerability
  --order <key>            relevance-, creation_date+, ... (default relevance-)

search-iocs flags:
  --order <key>            e.g. last_submission_date- (default: upstream ranking)

threat / ioc flags:
  --related <name>         Expand one relationship (curated list; see get_usage)
  --related-other <name>   Send an uncurated relationship name upstream as-is

threat flags:
  --mitre                  ATT&CK tactics/techniques tree of the collection

ioc flags:
  --full                   Full report instead of the trimmed threat context

behaviour flags:
  --section <name>         One section from the index (e.g. dns_lookups)
  --offset <n>             Items to skip inside the section

The indicator type is detected from its shape: MD5/SHA1/SHA256 hash, IPv4,
IPv6, URL (scheme://...), or domain.

Exit codes:
  0  every query was answered (an empty answer is a valid answer)
  1  an upstream failure prevented or degraded some queries
  2  error (invalid input, bad configuration, ...)

A valid Google Threat Intelligence licence is required: the API key is
mandatory, and every query is recorded against the licence holder's account.
Only Google's index is read, so no packet reaches the target under
investigation. The tool is read-only by design — no collection writes and no
sample uploads, permanently.

This tool ships the GTI Standard feature set. The Enterprise-only catalogue
(curated threat actors, campaigns, reports, threat profiles, DTM) is out of
scope; threat context arrives through the community collections an indicator
is associated with.

The default ioc answer is deliberately trimmed to GTI's assessment and the
associated threats: per-engine verdicts, passive DNS, reputation feeds and
URL behaviour are owned by malware-lookup, rdns-lookup, abuse-lookup and
urlscan-lookup. --full opts into the whole report when GTI's view is wanted
as a second opinion.
`)
}
