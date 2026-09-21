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

`make lint` is `golangci-lint run ./...` with the default linter set.
`.golangci.yml` excludes exactly one thing from errcheck — `fmt.Fprint*`, which
in this repository only ever writes to the stdout/stderr that `app.Run` is
handed — and nothing else. errcheck stays on everywhere else because
`internal/cache` writes result files: `writeAtomic` is atomic only because the
`Close` error is checked before the rename. The exclusion matches by function
name, not by destination, so do not write a file with `fmt.Fprint*`. Do not add
a second exclusion to get a finding out of the way; fix the code.

## Structure

```
main.go                 entry; -ldflags -X main.version
internal/app/           CLI dispatch + rendering (search/search-iocs/threat/ioc/
                        behaviour/hunting/cache/mcp/version/help)
internal/config/        sectioned-TOML subset; GTI_LOOKUP_* / VT_APIKEY env; two TTLs
internal/cache/         fixed-TTL JSON-file cache, atomic writes, read-time TTL
internal/mcp/           stdio JSON-RPC 2.0 MCP server; usage.md embedded via go:embed
internal/gti/           REST client: GetObject/ListObjects/GetData, x-apikey, stable slugs
internal/engine/        shared core: classify → cache → gti → shape; honesty rules
internal/indicator/     input classifier (hash/IP/domain/URL, from shape)
e2e/                    live tests behind the `e2e` tag (`make e2e`; network + licence key)
scripts/                codesign/notarize + brew generation (org templates)
```

## Current state

Standard-tier feature set implemented, offline-green (`make test`, `-race`,
httptest + fake-client + dummy JSON-RPC harness) and **live-verified
2026-09-01** against the real API with a gti-standard key. CLI: `search`
(vulnerability catalogue) / `search-iocs` (intelligence syntax) / `threat`
(`--related`, `--mitre`) / `ioc` (multi-target, JSONL) / `behaviour`
(index → section paging) / `hunting` (LiveHunt list/detail, never cached) /
`cache` / `mcp`. MCP (12 tools): `search_threats`, `search_iocs`,
`get_threat`, `get_threat_related`, `get_threat_mitre_tree`, `lookup_ioc`,
`get_ioc_related`, `get_file_behaviour`, `list_hunting_rulesets`,
`get_hunting_ruleset`, `cache_status`, `get_usage`. Exit codes: 0 =
answered, 1 = upstream failure/degraded (`INCONCLUSIVE`), 2 = usage/config
error. **Scope rule**: Standard tier only — Enterprise-gated features
(curated actors/campaigns/reports, threat profiles, timeline, DTM,
collection-linked rulesets) are deliberately not shipped; untestable is
unshippable. Released and integrated (`git tag` lists the versions).

**Live suite** (`make e2e`; network + a licence key; kept out of
`go test ./...` by the `e2e` build tag; skips itself when no key is
configured): `e2e/live_test.go` drives the engine directly against the real
API with the cache isolated in a tempdir — the CLI and MCP layers are not
exercised live. Assertions are behavioural, never exact counts. Covered:
vulnerability search (underscore filter vocabulary), hash lookup with
associations (attributes narrowing), URL lookup (unpadded base64url id),
collection report + `domains` descriptor pivot (plural `/relationships/`
path), MITRE tree, behaviour index + one section page, intelligence search
(`total_hits` accounting), LiveHunt ruleset list. Not covered live:
`IOCRelated`, the single-ruleset `HuntingRuleset`, IP and domain lookups.

## Gotchas

- `config.Load` succeeds **without** an API key on purpose: cache inspection
  and the MCP handshake must work key-less. The refusal lives in
  `engine.requireKey` (code `missing_api_key`).
- `VT_APIKEY` is accepted as the key's env alias (Google's own GTI tooling
  uses it); `GTI_LOOKUP_API_KEY` wins when both are set.
- **URL identifiers are unpadded base64url** (`gti.URLID`), matching vt-py.
  Google's own MCP server uses the *standard* alphabet, which corrupts the
  path when the encoding yields `+` or `/`. **Verified live 2026-09-01**:
  `urls/{RawURLEncoding}` answers correctly.
- **Relationship descriptors use the plural path** `/{obj}/{id}/relationships/{rel}`;
  full related objects use `/{obj}/{id}/{rel}` with `attributes=` narrowing.
  **Both verified live 2026-09-01** (descriptors return ids + `meta.count`;
  `attributes=name,collection_type` narrowing works on relationship
  endpoints). Google's MCP server requests the singular `/relationship/` —
  not what we use.
- **The `collection_type` filter rejects the documented vocabulary.**
  Measured 2026-09-01 (gti-standard key): the hyphenated values from gtidocs
  (`threat-actor`, `malware-family`, `campaign`, `report`, `collection`) are
  rejected with `Invalid value for collection_type`, parentheses or not; the
  parser accepts underscore tokens (`threat_actor`, `malware_family`,
  `software_toolkit`, `vulnerability`, `campaigns`, `threat_report`,
  `intelligence_report`, `ioc_collection`, `sigma_ruleset`, `yara_ruleset`).
  `engine.filterTypeToken` maps the documented vocabulary to those tokens.
  The `campaign→campaigns`, `report→threat_report`, `collection→ioc_collection`
  mappings are accepted upstream but **semantically unverified** — on this
  tier the gated content answers empty, so re-verify with an Enterprise key.
- **Licence tier gates the catalogue.** This machine's key carries
  `gti-standard`: curated threat-actor / campaign / report content is
  invisible (type-filtered and free-text searches return them as empty, not
  403), and `gti_assessment` is absent from IOC objects (WannaCry included).
  What works at this tier: `vulnerability` collections (searchable, rich),
  community collections (alienvault_* etc., reachable via associations),
  every IOC relationship pivot, descriptors, counts. Per gtidocs, threat
  actors / campaigns / country & industry profiles need **GTI Enterprise or
  Enterprise+**. Expect richer answers — and re-run verification — under
  such a key.
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
- Every tool schema is closed (`additionalProperties: false`, organization
  ADR-021 §10). It is applied by `closeSchemas` as one pass over the finished
  tool list, not by each literal, so a tool added later cannot forget it;
  `TestEveryToolSchemaIsClosed` reads the schemas back off `tools/list`. The
  closed schema and the strict decoder are two halves of one contract — the
  schema stops the typo at the client, the decoder stops it here — so do not
  drop either. Only the top level is closed; a nested free-form object keeps
  what it declares.
- The response budget lives at the MCP boundary (`capDescription`), not in
  the engine: the CLI's `--json` stays complete by design.
- Server-side argument validation must be tested through the dummy JSON-RPC
  harness in `internal/mcp/server_test.go`: schema-checking clients reject
  enum violations before they ever reach the server.
- Behaviour summaries are huge: WannaCry's measured **2.2 MB** with
  2,000-item sections, and `attack_techniques` is a 63-key **map**, not a
  list. `engine.FileBehaviour` therefore serves an index (lists AND maps
  become named sections; only scalars ride inline) and pages one section by
  offset/limit — maps in key order as `{key, value}`. The raw summary is
  cached once under its own key; section paging is local.
- The MITRE tree measured **258 KB** for one community collection. The MCP
  tool is compact by default (tactic/technique ids+names+counts) with
  `full: true` as the escape; the CLI `--json` returns the raw tree.
- LiveHunt endpoints (`/intelligence/hunting_rulesets`) work at Standard
  (verified live 2026-09-01 against a real ruleset) and are **never
  cached** — account configuration must answer live. `enabled: false`
  rulesets exist and must be surfaced as "will not fire".
- `/intelligence/search` works at Standard, honours `attributes=` narrowing,
  and reports its total as `meta.total_hits` (a float) instead of
  `meta.count` — the client folds both into `ObjectList.Count`.
- Measured Forbidden at Standard (2026-09-01): `/threat_profiles`,
  `/collections/{id}/timeline/events`, `/dtm/docs/search` (despite a `dtm`
  privilege flag). Collection-linked `hunting_rulesets` answer `count: 0`.
- **golangci-lint shows at most 3 findings with the same text**, so its
  "N issues" undercounts a repeated finding. Measured 2026-09-20: the default
  output reported 8 errcheck findings where
  `golangci-lint run --max-same-issues 0 --max-issues-per-linter 0 ./...`
  listed 93. Size a finding with the untruncated run before deciding how to
  handle it.
- Live measurements that contradict gtidocs.virustotal.com go here, dated.
