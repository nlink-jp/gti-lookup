# AGENTS.md — gti-lookup

## Project summary

Go CLI + local MCP server attaching curated threat-actor context (threat
actors, campaigns, malware families, their targets and reports) to an
indicator or a search term, from Google Threat Intelligence. Read-only by
design; a GTI licence API key is mandatory. Part of
`nlink-jp/cybersecurity-series`.

- Module path: `github.com/nlink-jp/gti-lookup`
- Language: Go 1.25+, standard library only
- Design authority: `docs/ja/gti-lookup-rfp.ja.md` (RFP; English mirror in
  `docs/en/`)

## Build / test commands

```bash
make build       # → dist/gti-lookup (never `go build` directly)
make test        # go test -race -cover ./... — fully offline
make e2e         # live GTI tests (network + key required; `e2e` build tag)
make check       # lint + test + build-all
make package     # release archives + darwin notarization
```

## Structure

```
main.go                 entry; -ldflags -X main.version
internal/app/           CLI dispatch (search/threat/ioc/cache/mcp/version/help)
internal/config/        sectioned-TOML subset; GTI_LOOKUP_* / VT_APIKEY env; two TTLs
internal/cache/         fixed-TTL JSON-file cache, atomic writes, read-time TTL
internal/mcp/           stdio JSON-RPC 2.0 MCP server; usage.md embedded via go:embed
internal/gti/           (planned) REST client, x-apikey header
internal/engine/        (planned) shared core: classify → cache → gti → shape
internal/indicator/     (planned) input classifier (hash/IP/domain/URL)
e2e/                    (planned) live tests behind the `e2e` tag
scripts/                codesign/notarize + brew generation (org templates)
```

## Current state

Phase 2 scaffold. `search` / `threat` / `ioc` are dispatched but exit 2 with
"not implemented yet". The MCP server exposes `cache_status` and `get_usage`
only. Exit codes: 0 = answered, 2 = usage/config error (1 = partial upstream
failure joins with the first lookup command).

## Gotchas

- `config.Load` succeeds **without** an API key on purpose: cache inspection
  and the MCP handshake must work key-less. Query paths must check
  `cfg.HasKey()` themselves and refuse with a pointed message.
- `VT_APIKEY` is accepted as the key's env alias (Google's own GTI tooling
  uses it); `GTI_LOOKUP_API_KEY` wins when both are set.
- Two cache TTLs (`ThreatTTL` 24 h / `IOCTTL` 1 h defaults) share one store;
  the caller picks which TTL applies at `Get` time. Never `Put` a degraded
  result.
- The MCP layer answers `get_usage` **before** dispatch (it returns raw
  Markdown, not JSON). Tool failures are `isError: true` results with
  structured `{code, message}` text — never JSON-RPC protocol errors.
- Server-side argument validation must be tested through the dummy JSON-RPC
  harness in `internal/mcp/server_test.go`: schema-checking clients reject
  enum violations before they ever reach the server.
- Live measurements that contradict gtidocs.virustotal.com go here, dated.
