# CLAUDE.md — gti-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server reading **Google Threat Intelligence**
(`https://www.virustotal.com/api/v3`, licensed key) with the **GTI Standard
feature set**: association context and sandbox behaviour for an indicator,
IOC corpus search in GTI query syntax, the vulnerability catalogue with
pivots and ATT&CK trees, and the account's own LiveHunt rulesets.

**Standard-tier scope is a release rule, not an accident**: the
Enterprise-only catalogue (curated threat actors, campaigns, reports, threat
profiles, DTM) cannot be exercised on a Standard licence, an untestable
feature does not ship, and Enterprise will not be purchased. Do not add
Enterprise-gated features speculatively.

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
e2e/                    Live tests behind the `e2e` build tag (`make e2e`; network + licence key)
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
- **Account state is never cached.** LiveHunt ruleset answers are always
  live: someone toggles a rule in the console and asks whether it took — a
  cached "disabled" would gaslight them.
- **Huge documents are served index-first.** A behaviour summary measured
  2.2 MB and a MITRE tree 258 KB. `behaviour` answers with a section index
  and pages one section on demand (maps page in key order); the MCP MITRE
  tool is compact by default with `full: true` as the escape. Never inline
  either document whole into a tool response.
- **A partial answer is never presented as a complete one.** Report what
  upstream holds next to what was retrieved; an answer built on a failed
  lookup is never reported as "no associations".
- **Engine is shared** by CLI and MCP so their behaviour cannot diverge.
- **No SDK dependency.** The GTI client is direct net/http against the v3
  API. Google's mcp-security GTI server (Apache-2.0) is a design reference
  only; attribution lives in README.md.

## Status

Released and integrated (`git tag` lists the versions).

Standard-tier feature set implemented and **live-verified 2026-09-01** with a
gti-standard key: `search` / `search-iocs` / `threat` (`--related`,
`--mitre`) / `ioc` / `behaviour` / `hunting` commands and the twelve MCP
tools, offline test suite green (`-race`, all layers). See AGENTS.md Gotchas
for the dated measurements (filter vocabulary, tier gate, behaviour summary
size). The live pass is codified in `e2e/live_test.go` behind the `e2e`
build tag (`make e2e`; network + licence key; skips itself without a key);
it drives the engine directly, not the CLI or the MCP layer — AGENTS.md
lists what it covers. Dropped by the standard-tier rule:
`get_collection_rules`-style pivots (empty at Standard), collection
timeline (Forbidden), threat profiles (Forbidden), DTM (Forbidden).

## Communication Language

All communication between contributors and Claude Code is conducted in
**Japanese**.
