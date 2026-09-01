// Package cache is a fixed-TTL JSON-file cache with atomic writes, shared by
// the CLI and the MCP server.
//
// The TTL is applied at read time rather than at write time, so changing
// threat_ttl_hours or ioc_ttl_hours in the config takes effect on entries
// already on disk. Which TTL applies is the caller's decision: collection
// answers age on ThreatTTL, IOC answers on IOCTTL.
//
// Degraded results are never cached. A lookup that fell back because an
// upstream call failed would otherwise freeze an incomplete answer in place
// for the whole TTL, and the analyst would have no way to tell.
package cache
