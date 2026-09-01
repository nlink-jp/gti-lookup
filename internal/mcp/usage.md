# gti-lookup MCP server — usage

gti-lookup reads Google Threat Intelligence with the **GTI Standard feature
set**: threat context and sandbox behaviour for an indicator, IOC corpus
search, the vulnerability catalogue with its pivots and ATT&CK trees, and
your own LiveHunt rulesets.

- **IOC → context**: `lookup_ioc` → `get_ioc_related` / `get_file_behaviour`
- **corpus search**: `search_iocs` (GTI intelligence query syntax)
- **catalogue**: `search_threats` → `get_threat` → `get_threat_related` /
  `get_threat_mitre_tree`
- **own account**: `list_hunting_rulesets` → `get_hunting_ruleset`

Only Google's index is read, so no packet reaches the target under
investigation. A valid GTI licence key is required, and **every query is
recorded against the licence holder's account**. This server reports what
Google claims and never invents a verdict of its own.

**The Enterprise-only catalogue is out of scope.** Curated threat actors,
campaigns, reports, threat profiles and DTM answer only to GTI Enterprise /
Enterprise+ licences, so this server does not offer them; threat context
arrives through the community collections an indicator is associated with.
Do not read "no associations" as an actor verdict.

Results are cached locally (collections ~24 h, IOC answers ~1 h by default);
pass `refresh: true` to bypass. LiveHunt ruleset answers are never cached.
An empty answer is a valid answer; a result with `incomplete: true` is NOT —
treat it as unanswered.

## Tools

### search_threats

Search the collections catalogue. Arguments: `query` (search terms),
`collection_type` (`vulnerability` — the one type the Standard tier can
search), `order_by` (`relevance-` default, `creation_date-`, ... with `+`
ascending variants), `limit` (1–40), `refresh`. At least one of `query` /
`collection_type` is required. The result carries `retrieved`, `more` and
`total_upstream`; each row's `id` feeds `get_threat`, `get_threat_related`
and `get_threat_mitre_tree`.

### search_iocs

Search the IOC corpus (files, URLs, domains, IPs) with GTI intelligence
query syntax — free text plus modifiers such as `entity:file`, `p:60+`
(detections), `fs:2024-01-01+` (first seen), `tag:`, `type:`. Arguments:
`query` (required), `order_by` (e.g. `last_submission_date-`; empty lets
upstream rank), `limit`, `refresh`. Rows are narrowed to identity
(names, hashes, dates); expand one with `lookup_ioc`. `total_upstream` is
the corpus-wide hit count.

### get_threat

Report for one collection `id` (`vulnerability--cve-...`, community ids like
`alienvault_...`). The `description` is capped at 6000 characters; when the
cap bites, `description_truncated: true` and `description_total_chars`
appear, and `description_max` raises the cap (`-1` = unlimited).

### get_threat_related

Expand one relationship of a collection. `relationship` (enum):
`associations`, `attack_techniques`, `campaigns`, `domains`, `files`,
`ip_addresses`, `malware_families`, `reports`, `software_toolkits`,
`suspected_threat_actors`, `threat_actors`, `urls`, `vulnerabilities`.
Any other upstream name goes through `relationship_other` verbatim — never
both parameters at once. For IOC pivots the item `id` is the value itself
and feeds `lookup_ioc`.

### get_threat_mitre_tree

ATT&CK tree of a collection: tactics and the techniques observed in its
IOCs. Compact by default — tactic and technique ids/names with counts (the
raw tree for one collection measured 258 KB); `full: true` returns
everything, descriptions and signatures included.

### lookup_ioc

Threat context for one indicator. `value` is the indicator itself — an
MD5/SHA1/SHA256 hash, an IP, a domain, or a URL, detected from its shape
(NOT a collection id, NOT free text). Result: `gti_assessment` when the
licence provides it, trimmed identity `attributes`, the `associations`
(community collections naming this indicator) with page accounting, and
`incomplete` + `note` when the association expansion failed — degraded, not
clean. The default answer is deliberately trimmed: per-engine verdicts,
passive DNS, reputation and URL behaviour are owned by malware-lookup,
rdns-lookup, abuse-lookup and urlscan-lookup; `full: true` opts into GTI's
whole report (minus the per-engine scan matrix) as a second opinion.

### get_ioc_related

Expand one relationship of an indicator. `relationship` (enum):
`associations`, `attack_techniques`, `campaigns`, `collections`,
`communicating_files`, `contacted_domains`, `contacted_ips`,
`contacted_urls`, `downloaded_files`, `dropped_files`, `embedded_domains`,
`embedded_ips`, `embedded_urls`, `malware_families`,
`related_threat_actors`, `reports`. `relationship_other` passes any other
upstream name (e.g. `resolutions` — rdns-lookup owns that question; ask GTI
deliberately, as a second opinion).

### get_file_behaviour

Sandbox behaviour summary of a file hash. Without `section`: an **index** —
section names with item counts plus the scalar summary fields (a full
summary can exceed 2 MB, so sections are named, not returned). With
`section` (a name from the index — e.g. `dns_lookups`, `processes_created`,
`files_dropped`, `attack_techniques`): that section's items, paged by
`offset`/`limit` so every entry stays reachable. Keyed sections
(`attack_techniques`) page in key order as `{key, value}` entries.

### list_hunting_rulesets / get_hunting_ruleset

Your own LiveHunt rulesets: the list (id, name, `enabled`, rule count) and
one ruleset with its YARA text. **Never cached** — this is live account
configuration, the answer to "did my rule take?". Read-only: creating,
editing and enabling rulesets happens in the GTI console. A ruleset with
`enabled: false` will not fire.

### cache_status

State of the local result cache: directory, entry count, total size, both
TTLs. No arguments. TTLs apply at read time; degraded results are never
cached.

### get_usage

This document. No arguments.

## Errors

Tool failures are returned as results (`isError: true`) whose text content is
structured JSON: `{"code": "<stable-slug>", "message": "<human-readable>"}`.

| code | meaning | recovery |
|---|---|---|
| `missing_api_key` | no GTI licence key is configured | set `[api] key` in `~/.config/gti-lookup/config.toml` or `GTI_LOOKUP_API_KEY`; there is no anonymous mode |
| `invalid_argument` | an argument failed validation (bad type, unknown field, path-shaped id, uncurated relationship, unknown behaviour section) | fix the argument the message names — a wrong behaviour section is answered with the real section list |
| `auth_error` | GTI rejected the key (401) | the key is wrong or revoked — verify it |
| `forbidden` | the licence does not cover this endpoint (403) | Enterprise-gated content — out of this tool's scope |
| `not_found` | the object does not exist upstream (404) | for IOCs this can simply mean GTI has never seen it — a finding, not a failure |
| `quota_exceeded` | the licence's request budget is spent (429) | wait for the quota window; degraded results were not cached, so retry cleanly |
| `bad_request` | upstream rejected the query (400) | usually a malformed search query — simplify it |
| `upstream_error` | GTI answered 5xx | transient; retry later |
| `network_error` | the exchange failed | check connectivity/proxy |
| `decode_error` | 2xx with an undocumented body | upstream drift — report it |
| `unknown_tool` | the tool name does not exist | use a tool listed above |
