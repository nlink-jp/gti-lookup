# gti-lookup MCP server — usage

gti-lookup attaches curated threat-actor context to an indicator or a search
term by reading Google Threat Intelligence (GTI): which threat actor, campaign
or malware family an indicator is associated with, who that actor targets, and
which reports describe it — in both directions:

- **actor → IOCs**: `search_threats` → `get_threat` → `get_threat_related`
- **IOC → actor**: `lookup_ioc` → `get_ioc_related`

Only Google's index is read, so no packet reaches the target under
investigation. A valid GTI licence key is required, and **every query is
recorded against the licence holder's account**. This server reports what
Google claims (`gti_assessment`, associations) and never invents a verdict of
its own.

Results are cached locally (collections ~24 h, IOC answers ~1 h by default);
pass `refresh: true` to bypass. An empty answer is a valid answer; a result
with `incomplete: true` is NOT — treat it as unanswered.

## Tools

### search_threats

Search the curated threat catalogue. Arguments:

| argument | meaning |
|---|---|
| `query` | search terms (actor name, alias, family, CVE, free text) |
| `collection_type` | `threat-actor`, `malware-family`, `campaign`, `report`, `software-toolkit`, `vulnerability`, `collection` — set it whenever the request names a kind |
| `order_by` | `relevance-` (default), `creation_date-`, `last_modification_date-`, or `+` ascending variants |
| `limit` | rows per page, 1–40 |
| `refresh` | bypass the cache |

At least one of `query` / `collection_type` is required. The result carries
`retrieved`, `more` and `total_upstream` — a page is never the whole
catalogue; raise `limit` or narrow the query to reach the rest. Each row's
`id` feeds `get_threat` and `get_threat_related`.

### get_threat

Curated report for one collection `id` (`threat-actor--<uuid>`,
`report--<hash>`, `malpedia_...`, ...). The `description` is capped at 6000
characters; when the cap bites, `description_truncated: true` and
`description_total_chars` appear, and `description_max` raises the cap
(`-1` = unlimited) in the same call shape.

### get_threat_related

Expand one relationship of a collection. `relationship` (enum):
`associations`, `attack_techniques`, `campaigns`, `domains`, `files`,
`hunting_rulesets`, `ip_addresses`, `malware_families`, `reports`,
`software_toolkits`, `suspected_threat_actors`, `threat_actors`, `urls`,
`vulnerabilities`. Any other upstream name goes through
`relationship_other` verbatim — never both parameters at once.

Items carry `name`/`collection_type` where upstream has them; for IOC pivots
the `id` is the value itself and feeds `lookup_ioc`.

### lookup_ioc

Actor context for one indicator. `value` is the indicator itself — an
MD5/SHA1/SHA256 hash, an IP, a domain, or a URL, detected from its shape
(NOT a collection id, NOT free text). Result:

| field | meaning |
|---|---|
| `gti_assessment` | Google's own verdict block, passed through verbatim |
| `attributes` | identity attributes (trimmed by default) |
| `associations` | the curated threats naming this indicator |
| `associations_retrieved` / `associations_more` / `associations_upstream` | page accounting |
| `incomplete` + `note` | the association expansion failed — the answer is degraded, not clean |

The default answer is deliberately trimmed: per-engine verdicts, passive DNS,
reputation and URL behaviour are owned by malware-lookup, rdns-lookup,
abuse-lookup and urlscan-lookup. `full: true` opts into GTI's whole report
(minus the per-engine scan matrix) as a second opinion.

### get_ioc_related

Expand one relationship of an indicator. `relationship` (enum):
`associations`, `attack_techniques`, `campaigns`, `collections`,
`communicating_files`, `contacted_domains`, `contacted_ips`,
`contacted_urls`, `downloaded_files`, `dropped_files`, `embedded_domains`,
`embedded_ips`, `embedded_urls`, `malware_families`,
`related_threat_actors`, `reports`. `relationship_other` passes any other
upstream name (e.g. `resolutions` — rdns-lookup owns that question; ask GTI
deliberately, as a second opinion).

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
| `invalid_argument` | an argument failed validation (bad type, unknown field, path-shaped id, uncurated relationship) | fix the argument the message names |
| `auth_error` | GTI rejected the key (401) | the key is wrong or revoked — verify it |
| `forbidden` | the licence does not cover this endpoint (403) | not recoverable here; note which feature needs a higher tier |
| `not_found` | the object does not exist upstream (404) | for IOCs this can simply mean GTI has never seen it — a finding, not a failure |
| `quota_exceeded` | the licence's request budget is spent (429) | wait for the quota window; degraded results were not cached, so retry cleanly |
| `bad_request` | upstream rejected the query (400) | usually a malformed search query — simplify it |
| `upstream_error` | GTI answered 5xx | transient; retry later |
| `network_error` | the exchange failed | check connectivity/proxy |
| `decode_error` | 2xx with an undocumented body | upstream drift — report it |
| `unknown_tool` | the tool name does not exist | use a tool listed above |
