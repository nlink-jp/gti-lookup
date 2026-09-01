# gti-lookup

Threat context from Google Threat Intelligence (GTI) — as a CLI and a local
MCP server, shipping the **GTI Standard feature set**.

> **Status: under development, pre-release.** The core is implemented,
> offline-tested, and live-verified against the real GTI API (2026-09-01).
> The design is fixed in
> [docs/ja/gti-lookup-rfp.ja.md](docs/ja/gti-lookup-rfp.ja.md)
> ([English](docs/en/gti-lookup-rfp.md)); scope decisions since then are
> recorded in AGENTS.md.

Where the sibling lookup tools each answer one question from free sources,
this one reads Google's index with a licensed key: which community-reported
threats an indicator is **associated** with, how a sample **behaves** in
Google's sandboxes, corpus-wide **IOC search** in GTI query syntax, the
**vulnerability catalogue** with relationship pivots and ATT&CK trees, and
your own **LiveHunt rulesets**.

Only Google's index is read, so **no packet reaches the target under
investigation**. The tool is **read-only by design**: no collection writes,
no ruleset writes, and no sample uploads, permanently.

## Requirements

**A commercial Google Threat Intelligence account is required.** This tool is
the exception in the lookup series: its siblings answer with no account at
all (rdns-lookup, doh-lookup, tor-exit-lookup, whois-lookup, ...) or with a
free API key (abuse-lookup, otx-lookup, malware-lookup), but gti-lookup does
nothing without a **paid GTI licence** and its API key. The free VirusTotal
tier is not sufficient, and there is no anonymous or degraded free mode.
Every query is recorded against the licence holder's account.

**This tool ships the GTI Standard feature set.** The Enterprise-only
catalogue — curated threat actors, campaigns, reports, threat profiles,
DTM — is deliberately out of scope: those features cannot be exercised (and
therefore cannot be tested) on a Standard licence, and an untestable feature
does not ship. Threat context arrives through the community collections an
indicator is associated with.

## Installation

Pre-release: build from source.

```bash
make build        # → dist/gti-lookup
```

## Configuration

Copy [config.example.toml](config.example.toml) to
`~/.config/gti-lookup/config.toml` and set the API key. Environment variables
override the file: `GTI_LOOKUP_API_KEY` (or `VT_APIKEY`, the variable Google's
own GTI tooling uses), `GTI_LOOKUP_BASE_URL`, `GTI_LOOKUP_THREAT_TTL_HOURS`,
`GTI_LOOKUP_IOC_TTL_HOURS`, `GTI_LOOKUP_TIMEOUT_SECONDS`, and more — the
example file documents every setting.

## Commands

```
gti-lookup search <query> [--type vulnerability] [--order relevance-]
gti-lookup search-iocs <query> [--order last_submission_date-]
gti-lookup threat <collection-id> [--related <name> | --related-other <name> | --mitre]
gti-lookup ioc <value ...> [--full] [--related <name> | --related-other <name>]
gti-lookup behaviour <hash> [--section <name>] [--offset N]
gti-lookup hunting [ruleset-id]
gti-lookup cache status|clear
gti-lookup mcp
gti-lookup version
```

- `search` queries the collections catalogue (on Standard: vulnerabilities).
- `search-iocs` searches the IOC corpus with GTI intelligence syntax
  (`entity:file`, `p:60+`, `fs:2024-01-01+`, `tag:`, ...).
- `threat` prints one collection's report; `--related` expands a pivot,
  `--mitre` the ATT&CK tactic/technique tree.
- `ioc` detects the indicator type from its shape (MD5/SHA1/SHA256, IP,
  domain, URL) and answers with the associated threats (plus
  `gti_assessment` where the licence provides it). Several values run in
  sequence (`--json` emits JSONL). `--full` opts into the whole report.
- `behaviour` reads the sandbox behaviour summary: an index of sections
  first (a full summary can exceed 2 MB), then one section paged with
  `--section` / `--offset` / `--limit`.
- `hunting` lists your LiveHunt rulesets (or shows one, YARA text included)
  — always live, never cached, so it answers "did my rule take?".
- Shared flags: `--json`, `--refresh` (bypass the cache), `--limit`,
  `--timeout`, `--config`.
- Exit codes: 0 answered (an empty answer is a valid answer), 1 an upstream
  failure prevented or degraded some queries (`INCONCLUSIVE` in the output),
  2 usage/configuration error.

## MCP server

`gti-lookup mcp` speaks MCP over stdio and exposes `search_threats`,
`search_iocs`, `get_threat`, `get_threat_related`, `get_threat_mitre_tree`,
`lookup_ioc`, `get_ioc_related`, `get_file_behaviour`,
`list_hunting_rulesets`, `get_hunting_ruleset`, `cache_status` and
`get_usage`. `get_usage` returns the embedded manual and is the canonical
tool reference, including the error-recovery table. Tool errors are
structured JSON (`{code, message}`), and large answers are budgeted at the
tool boundary: `get_threat` caps descriptions (escapable via
`description_max`), `get_threat_mitre_tree` is compact by default
(`full: true` escapes), and `get_file_behaviour` serves an index before
sections.

## Documentation

- [Design (RFP), Japanese](docs/ja/gti-lookup-rfp.ja.md) /
  [English](docs/en/gti-lookup-rfp.md)

## Acknowledgements

Google's [mcp-security](https://github.com/google/mcp-security) GTI server
(Apache-2.0) served as the design reference for the tool surface; this project
is an independent Go implementation and shares no code with it.

## License

MIT — see [LICENSE](LICENSE).
