// Package mcp is a dependency-free stdio JSON-RPC 2.0 MCP server. The lookup
// tools (search_threats, get_threat, lookup_ioc, ...) land with the engine;
// today it exposes cache_status and get_usage.
//
// get_usage is canonical: the mcp-tactics skill deliberately documents no
// parameters, so the embedded manual is what an agent reads before its first
// call. Tool errors are structured JSON ({code, message}).
//
// MCP has no protocol-level cancel; a closing stdin is the shutdown signal.
package mcp
