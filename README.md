# gti-lookup

Curated threat-actor context for an indicator, from Google Threat Intelligence
(GTI) — as a CLI and a local MCP server.

> **Status: under development, pre-release.** The core is implemented and
> tested offline (`search` / `threat` / `ioc`, the MCP server, caching);
> live verification against the real GTI API is still pending. The design is
> fixed in [docs/ja/gti-lookup-rfp.ja.md](docs/ja/gti-lookup-rfp.ja.md)
> ([English](docs/en/gti-lookup-rfp.md)).

Where the sibling lookup tools answer from public or community sources —
`otx-lookup` reads community campaign reports — this one reads the
Mandiant/Google curated catalogue: which **threat actor**, **campaign** or
**malware family** an indicator is associated with, who that actor targets,
and which reports describe it. It works in both directions: actor → IOCs and
IOC → actor.

Only Google's index is read, so **no packet reaches the target under
investigation**. The tool is **read-only by design**: no collection writes and
no sample uploads, permanently.

## Requirements

- A **Google Threat Intelligence licence** and its API key. The free
  VirusTotal tier is not sufficient, and every query is recorded against the
  licence holder's account.

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
gti-lookup search <query> [--type threat-actor] [--order relevance-] [--limit N]
gti-lookup threat <collection-id> [--related <name> | --related-other <name>]
gti-lookup ioc <value ...> [--full] [--related <name> | --related-other <name>]
gti-lookup cache status|clear
gti-lookup mcp
gti-lookup version
```

- `search` queries the curated catalogue; `--type` narrows to one kind
  (threat-actor, malware-family, campaign, report, software-toolkit,
  vulnerability, collection).
- `threat` prints one collection's report; `--related` expands a pivot
  (associations, domains, files, hunting_rulesets, ...).
- `ioc` detects the indicator type from its shape (MD5/SHA1/SHA256, IP,
  domain, URL) and answers with GTI's `gti_assessment` plus the associated
  threats. Several values run in sequence (`--json` emits JSONL). By default
  the answer is trimmed to the actor context; `--full` opts into the whole
  report.
- Shared flags: `--json`, `--refresh` (bypass the cache), `--limit`,
  `--timeout`, `--config`.
- Exit codes: 0 answered (an empty answer is a valid answer), 1 an upstream
  failure prevented or degraded some queries (`INCONCLUSIVE` in the output),
  2 usage/configuration error.

## MCP server

`gti-lookup mcp` speaks MCP over stdio and exposes `search_threats`,
`get_threat`, `get_threat_related`, `lookup_ioc`, `get_ioc_related`,
`cache_status` and `get_usage`. `get_usage` returns the embedded manual and
is the canonical tool reference, including the error-recovery table. Tool
errors are structured JSON (`{code, message}`); `get_threat` caps the
description field inside tool responses (accounted, escapable via
`description_max`).

## Documentation

- [Design (RFP), Japanese](docs/ja/gti-lookup-rfp.ja.md) /
  [English](docs/en/gti-lookup-rfp.md)

## Acknowledgements

Google's [mcp-security](https://github.com/google/mcp-security) GTI server
(Apache-2.0) served as the design reference for the tool surface; this project
is an independent Go implementation and shares no code with it.

## License

MIT — see [LICENSE](LICENSE).
