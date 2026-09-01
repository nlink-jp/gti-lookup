# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffold: CLI dispatch (`version` / `help` / `cache` / `mcp` plus
  placeholders for `search`, `threat`, `ioc`), sectioned-TOML configuration
  with `GTI_LOOKUP_*` / `VT_APIKEY` resolution, fixed-TTL JSON-file result
  cache, and a stdio JSON-RPC 2.0 MCP server exposing `cache_status` and
  `get_usage`.
