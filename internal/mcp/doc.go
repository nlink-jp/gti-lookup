// Package mcp is a dependency-free stdio JSON-RPC 2.0 MCP server exposing
// search_threats, get_threat, get_threat_related, lookup_ioc,
// get_ioc_related, cache_status and get_usage over the shared engine.
//
// get_usage is canonical: the mcp-tactics skill deliberately documents no
// parameters, so the embedded manual is what an agent reads before its first
// call. Tool errors are structured JSON ({code, message}); tool arguments are
// decoded strictly so a mistyped parameter is surfaced, not swallowed.
//
// The response budget lives at this boundary: get_threat caps the description
// field (accounted, escapable via description_max) because this is where a
// result enters a model's context — the engine and the CLI stay complete.
//
// MCP has no protocol-level cancel; a closing stdin is the shutdown signal.
package mcp
