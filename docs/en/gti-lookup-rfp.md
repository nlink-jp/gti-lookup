# RFP: gti-lookup

> Generated: 2026-09-01
> Status: Draft

## 1. Problem Statement

The existing lookup family covers IOC reputation and community-sourced campaign
context (otx-lookup), but lacks curated **threat actor intelligence** from
Mandiant/Google. In an environment holding a valid Google Threat Intelligence
(GTI) license, this tool queries threat actor, campaign, and malware family
information from IOCs or keywords, adding context to IR and threat
investigations.

The original (server/gti in google/mcp-security) runs via uvx as third-party
Python code — a configuration that does not meet organizational standards and
hinders environment deployability. It is therefore reimplemented as a read-only
subset in the cybersecurity-series lookup style (single Go binary, CLI + MCP,
read-only, structured errors, TTL cache).

Target users are the organization's IR/threat-investigation workflows,
including Claude Code via mcp-tactics.

## 2. Functional Specification

### Commands / API Surface

**MCP tools** (roughly 36 original tools consolidated into about 10):

| Tool | Description | Original | Phase |
|---|---|---|---|
| `search_threats(query, collection_type?, limit?, order_by?)` | Cross-collection search. `collection_type` enum: `threat-actor` / `campaign` / `malware-family` / `software-toolkit` / `report` / `vulnerability` / `all` | 7 search_* tools merged into one | 1 |
| `get_threat(id)` | Collection ID → curated report (aliases, targeted industries/countries, ATT&CK, sources, timestamps) | get_collection_report | 1 |
| `get_threat_related(id, relationship, limit?)` | Related entities of a collection (member IOCs, related actors, etc.) | get_entities_related_to_a_collection | 1 |
| `lookup_ioc(value, full?)` | Auto-detects hash/domain/IP/URL. Default response focuses on `gti_assessment` + `associations`; `full: true` returns the full report | get_{file,domain,ip,url}_report merged | 1 |
| `get_ioc_related(value, relationship, limit?)` | Relationship pivot for an IOC (contacted_*, etc.) | get_entities_related_to_a_* merged | 1 |
| `search_iocs(query, limit?, order_by?)` | Intelligence search using GTI query syntax | search_iocs | 2 |
| `get_threat_rules(collection_id, top_n?)` | YARA/Sigma rules tied to a collection | get_collection_rules | 2 |
| `get_hunting_ruleset(ruleset_id)` | Direct hunting ruleset fetch | get_hunting_ruleset | 2 |
| `cache_status()` | Cache state (series standard) | — | 1 |
| `get_usage()` | Tool reference + error-recovery table (series standard) | — | 1 |

- IOC type auto-detection: 32/40/64 hex digits → MD5/SHA1/SHA256; IP/domain/URL
  by format (same single-entry-point style as malware-lookup)
- The `relationship` parameter accepts a **curated enum plus a free-form
  string**: 10–15 relationships useful for actor investigation (associations,
  contacted_*, member IOCs, etc.) are offered as an enum, while arbitrary GTI
  relationship names remain accepted
- The default `lookup_ioc` response is trimmed for the MCP response budget and
  to coexist with the existing lookup family. The full report is opt-in
  (otx-lookup's "capability present but off by default" approach)

**CLI** (subcommands mirroring the MCP tools):

```
gti-lookup search <query> [--type threat-actor|campaign|...] [--limit N]
gti-lookup threat <collection-id> [--related <relationship>]
gti-lookup ioc <value> [--full] [--related <relationship>]
gti-lookup rules <collection-id>          # Phase 2
gti-lookup hunting <ruleset-id>           # Phase 2
gti-lookup search-iocs <query>            # Phase 2
gti-lookup cache-status
```

### Input / Output

- Single-item queries via arguments (a handful to a few dozen lookups;
  bulk optimization is out of scope)
- JSON to stdout (jq-friendly); diagnostics to stderr
- Exit contract: 0 = lookup completed / 1 = upstream failure (results still
  printed) / 2 = usage error (same contract as malware-lookup)
- MCP tool errors are structured JSON `{code, message, details?}`

### Configuration

- `~/.config/gti-lookup/config.toml` (api_key, cache TTLs, timeout) with
  environment-variable overrides. `~/.config` is searched on macOS too, per
  organizational convention
- Per-object cache TTLs: long for collection reports, short for IOC
  assessments. Degraded results are never cached
- Sample configuration uses placeholder values only (no real keys or
  environment-specific values committed)

### External Dependencies

- GTI API v3 (`https://www.virustotal.com/api/v3`) only; authentication via
  the `x-apikey` header
- No vt-py-equivalent SDK; direct REST calls with Go's standard net/http
  (precedent: splunk-mcp)

## 3. Design Decisions

- **Language = Go**: the very motivation for the rewrite — removing the
  third-party Python + uvx setup, single-binary deployment, and joining the
  existing sign/notarize/tap release pipeline
- **Skeleton**: port `internal/{transport,jsonrpc,mcpserver,toolerr}` from
  data-toolbox-mcp (canonical guide: mcp-server-design.md in
  nlink-jp/knowledge). Tool handler layer and the GTI client are new code
- **Search consolidation**: the 7 search tools are the same endpoint with
  different type filters; one tool also reduces tool-listing token cost
- **Complementary positioning**:
  - Counterpart to otx-lookup (community campaign context) for Google/Mandiant
    curated context
  - Coexists with malware-lookup (free 3-source verdicts for unlicensed
    environments); gti-lookup is exclusively for licensed environments
  - `lookup_ioc --full` may overlap with other lookup tools, but the trimmed
    default keeps them coexisting
- **Explicitly out of scope**: write operations (create/update collections,
  update_iocs_in_collection), analyse_file (uploading samples to a third
  party — a significant OpSec action), DTM search, threat profiles,
  collection timeline / MITRE tree (decide in Phase 2), bulk optimization,
  sample download

## 4. Development Plan

### Phase 1: Core

- Config loader / TTL cache / GTI REST client
- `search_threats` / `get_threat` / `get_threat_related` / `lookup_ioc` /
  `get_ioc_related` / `cache_status` / `get_usage`
- CLI subcommands (search / threat / ioc / cache-status)
- Tests: unit tests with httptest mocks + response shaping (tests are
  mandatory; design with pure functions and injected dependencies)

### Phase 2: Features

- `search_iocs` / `get_threat_rules` / `get_hunting_ruleset`
- Decide on collection timeline / MITRE tree
- Live verification → record actual API behavior vs. documentation in
  AGENTS.md Gotchas

### Phase 3: Release

- README.md / README.ja.md, CHANGELOG.md
- make build-all → sign & notarize → homebrew-tap
- Add submodule to umbrella (cybersecurity-series), update org profile
- **Update mcp-tactics** (mandatory follow-up when servers change)
- check-org.sh green

Each phase is independently reviewable.

## 5. Required API Scopes / Permissions

- A single GTI-licensed API key (`x-apikey` header). No OAuth / IAM roles
- Assumes execution in an environment holding a valid license (free VT API
  terms-of-service issues are out of scope — malware-lookup already serves
  that environment)

## 6. Series Placement

Series: **cybersecurity-series**
Reason: sibling of the lookup family (asn/whois/abuse/otx/malware-lookup,
etc.). A read-only threat-intelligence query tool that adopts the series
conventions as-is (CLI + MCP, structured errors, TTL cache, get_usage,
explicit OpSec posture).

## 7. External Platform Constraints

- Quotas and rate limits depend on the license tier. 429 is returned as a
  structured error; degraded results are never cached
- Report objects are very large → strict attribute/relationship selection is
  required (budget the entire MCP response)
- Collection IDs are typed identifiers such as `threat-actor--<hash>`;
  search uses GTI's own query syntax
- DTM / threat profiles are license-tier-dependent features (out of scope
  here)
- The canonical API reference is gtidocs.virustotal.com. Divergence between
  observed and documented behavior is recorded in AGENTS.md Gotchas

---

## Discussion Log

- **Purpose settled**: the request is "add threat actor intelligence."
  Motivation is curated actor context missing from the existing lookup
  family. SCC / SecOps / SOAR servers are out of scope
- **Rewrite motivation**: uvx execution + third-party Python code does not
  meet organizational standards; switch to a single Go binary for
  deployability
- **License**: runs in an environment holding a valid GTI license — no issue
- **Naming**: `gti-intel` rejected as redundant (the "I" in GTI already means
  intelligence) → settled on `gti-lookup`, matching the lookup family naming
  pattern
- **Scope**: adopt both directions — collections plus IOC reports (IOC →
  associations → actor). Include search_iocs / hunting rulesets; exclude DTM.
  Write operations + analyse_file confirmed excluded
- **Search consolidation**: 7 search_* tools → one `search_threats` +
  `collection_type` enum
- **lookup_ioc response policy**: the initial proposal trimmed responses to
  assessment + associations (otx-lookup's coexistence principle), but full
  reports were requested to leverage the license. Compromise: trimmed
  default, opt-in via the `full` parameter
- **relationship parameter**: curated enum + free-form string (the original
  lists 50+ relationships for files alone → curated presentation chosen for
  model-guessing risk and response budget)
- **Delivery form**: CLI + MCP per series convention
