# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- Project scaffold: CLI dispatch with the byte-identical `version` /
  `--version` contract, sectioned-TOML configuration with `GTI_LOOKUP_*` /
  `VT_APIKEY` resolution and two cache TTLs (threat 24 h / IOC 1 h),
  fixed-TTL JSON-file result cache, stdio JSON-RPC 2.0 MCP server with an
  embedded `get_usage` manual and structured `{code, message}` tool errors.
