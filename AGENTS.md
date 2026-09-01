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
internal/app/           CLI dispatch (search/threat/ioc/cache/mcp/version/help), rendering
internal/config/        sectioned-TOML subset; GTI_LOOKUP_* / VT_APIKEY env; two TTLs
internal/cache/         fixed-TTL JSON-file cache, atomic writes, read-time TTL
internal/mcp/           stdio JSON-RPC 2.0 MCP server; usage.md embedded via go:embed
internal/gti/           REST client: GetObject/ListObjects, x-apikey, stable error slugs
internal/engine/        shared core: classify → cache → gti → shape; honesty rules
internal/indicator/     input classifier (hash/IP/domain/URL, from shape)
e2e/                    live tests behind the `e2e` tag (not written yet)
scripts/                codesign/notarize + brew generation (org templates)
```

## Current state

Core implemented and offline-green (`make test`, `-race`, httptest +
fake-client + dummy JSON-RPC harness). CLI: `search` / `threat` / `ioc`
(multi-target, JSONL) / `cache` / `mcp`. MCP: `search_threats`, `get_threat`,
`get_threat_related`, `lookup_ioc`, `get_ioc_related`, `cache_status`,
`get_usage`. Exit codes: 0 = answered, 1 = upstream failure/degraded
(`INCONCLUSIVE`), 2 = usage/config error. Pending: e2e live tests, RFP
Phase-2 tools (`search_iocs` / `get_threat_rules` / `get_hunting_ruleset`),
release.

## Gotchas

- `config.Load` succeeds **without** an API key on purpose: cache inspection
  and the MCP handshake must work key-less. The refusal lives in
  `engine.requireKey` (code `missing_api_key`).
- `VT_APIKEY` is accepted as the key's env alias (Google's own GTI tooling
  uses it); `GTI_LOOKUP_API_KEY` wins when both are set.
- **URL identifiers are unpadded base64url** (`gti.URLID`), matching vt-py.
  Google's own MCP server uses the *standard* alphabet, which corrupts the
  path when the encoding yields `+` or `/`. Verify against the live API in
  e2e (as of 2026-09-01, unverified).
- **Relationship descriptors use the plural path** `/{obj}/{id}/relationships/{rel}`
  (per gtidocs); full related objects use `/{obj}/{id}/{rel}` with an
  `attributes=` narrowing. Google's MCP server requests the singular
  `/relationship/` — unverified which the API canonically accepts; e2e must
  confirm, and whether `attributes=` narrowing works on relationship
  endpoints (as of 2026-09-01, both unverified).
- Two cache TTLs (`ThreatTTL` 24 h / `IOCTTL` 1 h defaults) share one store;
  the caller picks which TTL applies at `Get` time. Degraded results
  (`IOC.Incomplete`) are never `Put`.
- Brief and full IOC views must not share a cache slot (the view is part of
  the key) — a trimmed answer served under `--full` would silently hide the
  report.
- The MCP layer answers `get_usage` **before** dispatch (it returns raw
  Markdown, not JSON). Tool failures are `isError: true` results with
  structured `{code, message}` text — never JSON-RPC protocol errors. Tool
  arguments are decoded with `DisallowUnknownFields`, so a mistyped
  parameter surfaces instead of being swallowed.
- The response budget lives at the MCP boundary (`capDescription`), not in
  the engine: the CLI's `--json` stays complete by design.
- Server-side argument validation must be tested through the dummy JSON-RPC
  harness in `internal/mcp/server_test.go`: schema-checking clients reject
  enum violations before they ever reach the server.
- Live measurements that contradict gtidocs.virustotal.com go here, dated.
