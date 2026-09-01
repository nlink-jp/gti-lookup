// Package engine will be the shared core behind both the CLI and the MCP
// server: classify the input, consult the cache, call gti, and shape the
// response into the actor context that is this tool's reason to exist —
// threat actors, campaigns, malware families, their targets, and the reports
// that describe them.
//
// Sharing the engine is what keeps the two faces from drifting: an agent
// calling the MCP server and a human typing the CLI must get the same answer
// for the same input.
//
// Two rules will live here rather than in the presentation layer:
//
//   - The default IOC answer is trimmed to the actor context
//     (gti_assessment + associations); the full report is opt-in via `full`.
//     The trimmed default is what keeps this tool from answering questions
//     the sibling lookup tools already own.
//
//   - A partial answer is never presented as a complete one: what upstream
//     holds is always reported next to what was retrieved, and a degraded
//     result is never cached.
//
// Not implemented yet; the design is fixed in docs/ja/gti-lookup-rfp.ja.md.
package engine
