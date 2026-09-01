# gti-lookup

Curated threat-actor context for an indicator, from Google Threat Intelligence
(GTI) — as a CLI and a local MCP server.

> **Status: under development, pre-release.** The scaffold (configuration,
> result cache, MCP handshake, `cache` command) works; the lookup commands
> (`search`, `threat`, `ioc`) are not implemented yet. The design is fixed in
> [docs/ja/gti-lookup-rfp.ja.md](docs/ja/gti-lookup-rfp.ja.md)
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
gti-lookup search <query>           Search threats (actors, campaigns, malware families, ...)
gti-lookup threat <collection-id>   Curated report for one collection; --related pivots
gti-lookup ioc <value>              Actor context for a hash, domain, IP or URL
gti-lookup cache status|clear       Inspect or clear the result cache
gti-lookup mcp                      Run as a local MCP server (stdio)
gti-lookup version                  Print the version
```

`search`, `threat` and `ioc` are placeholders in this build and exit with an
error saying so.

## MCP server

`gti-lookup mcp` speaks MCP over stdio. This build exposes `cache_status` and
`get_usage`; the lookup tools arrive with the engine. `get_usage` returns the
embedded manual and is the canonical tool reference.

## Documentation

- [Design (RFP), Japanese](docs/ja/gti-lookup-rfp.ja.md) /
  [English](docs/en/gti-lookup-rfp.md)

## Acknowledgements

Google's [mcp-security](https://github.com/google/mcp-security) GTI server
(Apache-2.0) served as the design reference for the tool surface; this project
is an independent Go implementation and shares no code with it.

## License

MIT — see [LICENSE](LICENSE).
