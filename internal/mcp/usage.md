# gti-lookup MCP server — usage

gti-lookup attaches curated threat-actor context to an indicator or a search
term by reading Google Threat Intelligence (GTI): which threat actor, campaign
or malware family an indicator is associated with, who that actor targets, and
which reports describe it — in both directions, actor → IOCs and IOC → actor.

Only Google's index is read, so no packet reaches the target under
investigation. A valid GTI licence key is required, and every query is
recorded against the licence holder's account.

**The lookup tools are not implemented yet.** This build answers `cache_status`
and `get_usage` only; `search_threats`, `get_threat`, `get_threat_related`,
`lookup_ioc` and `get_ioc_related` arrive with the engine. Their design is
fixed in `docs/ja/gti-lookup-rfp.ja.md` in the repository.

## Tools

### cache_status

State of the local result cache. No arguments.

Result fields:

| field | meaning |
|---|---|
| `dir` | cache directory |
| `entries` | number of cached answers |
| `bytes` | total size on disk |
| `threat_ttl_hours` | freshness window for collection (actor/campaign/family/report) answers |
| `ioc_ttl_hours` | freshness window for IOC (file/domain/IP/URL) answers |

TTLs are applied at read time: lowering one in the config expires matching
entries already on disk. Degraded results are never cached.

### get_usage

This document. No arguments.

## Errors

Tool failures are returned as results (`isError: true`) whose text content is
structured JSON:

```json
{"code": "<stable-slug>", "message": "<human-readable>"}
```

| code | meaning | recovery |
|---|---|---|
| `unknown_tool` | the tool name does not exist in this build | call `get_usage` and use a listed tool |
| `invalid_argument` | an argument failed validation | fix the argument named in `message` |
