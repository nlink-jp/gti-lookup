# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-01

First release: threat context from Google Threat Intelligence as a CLI and a
local MCP server, live-verified against the real API.

**Scope is pinned to the GTI Standard feature set**: a feature that cannot
be exercised on a Standard licence cannot be tested, and an untestable
feature does not ship. Enterprise-gated content (curated threat actors,
campaigns, reports, threat profiles, timeline, DTM, collection-linked
rulesets) is out of scope; `search --type` offers `vulnerability`, the one
catalogue type Standard can search.

### Added

- `search-iocs` command / `search_iocs` tool: IOC corpus search in GTI
  intelligence query syntax, rows narrowed to identity, corpus-wide hit
  accounting.
- `behaviour` command / `get_file_behaviour` tool: sandbox behaviour
  summary served as a section index (a live summary measured 2.2 MB) with
  per-section offset/limit paging; keyed sections page in key order.
- `threat --mitre` / `get_threat_mitre_tree`: the collection's ATT&CK tree —
  compact identity view by default (the raw tree measured 258 KB),
  `full: true` / `--json` for everything.
- `hunting` command / `list_hunting_rulesets` + `get_hunting_ruleset`
  tools: the account's own LiveHunt rulesets with YARA text, never cached
  and flagging disabled rulesets ("will not fire").

- Core lookup functionality (read-only, licensed GTI API): `search` /
  `threat` / `ioc` CLI commands and the `search_threats`, `get_threat`,
  `get_threat_related`, `lookup_ioc`, `get_ioc_related` MCP tools, all over
  one shared engine.
  - Indicator type detected from shape (MD5/SHA1/SHA256, IP, domain, URL).
  - The default `ioc` answer is trimmed to `gti_assessment` + associations;
    `--full` / `full: true` opts into the whole report (minus the per-engine
    scan matrix).
  - Relationship pivots take a curated enum plus a free-form
    `relationship_other` passthrough.
  - Page accounting on every list (`retrieved` / `more` / `total_upstream`);
    a failed association expansion is reported as `incomplete` /
    `INCONCLUSIVE` (exit 1) and never cached.
  - MCP tool responses budget the `description` field (capped with
    accounting, escapable via `description_max`).
- Live verification against the real GTI API (2026-09-01, gti-standard
  key): search, reports, both pivot shapes, hash/URL lookups, caching and
  the MCP face all confirmed. The `collection_type` filter is sent in the
  underscore vocabulary the live parser accepts (the documented hyphenated
  values are rejected upstream); text output renders `*_date` attributes as
  dates instead of scientific notation.
- Project scaffold: CLI dispatch with the byte-identical `version` /
  `--version` contract, sectioned-TOML configuration with `GTI_LOOKUP_*` /
  `VT_APIKEY` resolution and two cache TTLs (threat 24 h / IOC 1 h),
  fixed-TTL JSON-file result cache, stdio JSON-RPC 2.0 MCP server with an
  embedded `get_usage` manual and structured `{code, message}` tool errors.
