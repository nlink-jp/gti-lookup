# CLAUDE.md — gti-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server that attaches **curated threat-actor context** to an
indicator or a search term by reading **Google Threat Intelligence**
(`https://www.virustotal.com/api/v3`, licensed key). Where `otx-lookup`
answers from community reports, this one answers from the Mandiant/Google
curated catalogue: which threat actor, campaign or malware family an indicator
is associated with, who that actor targets, and which reports describe it —
in both directions, actor → IOCs and IOC → actor.

Only Google's index is read, so **no packet reaches the target under
investigation**.

## Build & test

```bash
make build       # → dist/gti-lookup  (never `go build` directly — it drops the binary in the repo root)
make test        # go test -race -cover ./...   (fully offline)
make e2e         # live tests against the real GTI API (network + licence key required)
make check       # lint + test + build-all
```

Go 1.25+. **No external dependencies — standard library only.**

## Architecture

```
main.go                 CLI entry: main.version → app.Run
internal/indicator/     Pre-network gate: classify hash/IP/domain/URL from shape
internal/gti/           GTI REST client (x-apikey header, read-only, stable error slugs)
internal/cache/         Fixed-TTL JSON-file cache, atomic writes, TTL applied at read time
internal/config/        Sectioned-TOML subset + GTI_LOOKUP_* / VT_APIKEY resolution
internal/engine/        classify → cache → gti → actor-context shaping; shared by CLI + MCP
internal/app/           Dispatch + search/threat/ioc/cache/mcp; text and JSON rendering
internal/mcp/           Zero-dep stdio JSON-RPC 2.0 server; embedded get_usage manual
e2e/                    Live tests behind the `e2e` build tag (not written yet)
```

Design authority: [docs/ja/gti-lookup-rfp.ja.md](docs/ja/gti-lookup-rfp.ja.md).
Core logic takes injected dependencies (the HTTP client behind an interface,
clocks injected) so tests are deterministic and offline.

## Key conventions

- **Read-only, permanently.** No `create_collection` / `update_collection` /
  IOC writes, and specifically **no sample or URL uploads** (`analyse_file`
  has no equivalent here) — uploading a sample tells a third party what the
  organization is looking at. Do not add write or upload paths.
- **The API key is mandatory, and every query is billed to it.** GTI answers
  nothing anonymously. Load succeeds without a key (cache inspection and the
  MCP handshake must work), but query commands check `HasKey` and refuse with
  a pointed message. The key is sent only in the `x-apikey` header — never in
  a URL, never logged. `config.toml` is gitignored.
- **The default IOC answer is trimmed to actor context** (`gti_assessment` +
  `associations`); the full report is opt-in via `full`. The trimmed default
  is the coexistence line with the sibling lookup tools (malware-lookup,
  abuse-lookup, urlscan-lookup, rdns-lookup own the overlapping questions) —
  do not widen the default set.
- **One search tool, typed by enum.** The upstream's seven search wrappers are
  one endpoint with a type filter; here that is one `search_threats` with a
  `collection_type` enum. Relationship parameters take a curated enum plus a
  free-form passthrough for names the enum does not carry.
- **A tool result must fit in a client's response budget.** GTI report objects
  are enormous; request narrowed attributes/relationships upstream, cap ranked
  lists, and account for everything dropped. This is the otx-lookup 162 KB
  lesson — do not let a new field grow unbounded into a tool response.
- **Two cache TTLs.** Collection answers age on `ThreatTTL` (slow-moving,
  default 24 h), IOC answers on `IOCTTL` (default 1 h). TTLs are applied at
  read time. Degraded results are never cached.
- **A partial answer is never presented as a complete one.** Report what
  upstream holds next to what was retrieved; an answer built on a failed
  lookup is never reported as "no associations".
- **Engine is shared** by CLI and MCP so their behaviour cannot diverge.
- **No SDK dependency.** The GTI client is direct net/http against the v3
  API. Google's mcp-security GTI server (Apache-2.0) is a design reference
  only; attribution lives in README.md.

## Status

Core implemented (RFP dev-plan Phase 1): `search` / `threat` / `ioc` commands,
the five MCP lookup tools, caching, offline test suite green (`-race`, all
layers). **Not yet done**: live verification against the real GTI API
(`make e2e` — the e2e tests themselves are unwritten), the RFP's Phase-2
features (`search_iocs`, `get_threat_rules`, `get_hunting_ruleset`), and
release. Endpoint shapes that still need live confirmation are flagged in
AGENTS.md Gotchas; record measurements there as they land.

## Communication Language

All communication between contributors and Claude Code is conducted in
**Japanese**.
