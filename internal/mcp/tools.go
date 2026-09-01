package mcp

import (
	"context"
	"encoding/json"
	"errors"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
const (
	ToolCacheStatus = "cache_status"
	ToolGetUsage    = "get_usage"
)

// Error codes this layer emits. The GTI client's own codes join this
// vocabulary when the lookup tools land, so an agent sees one set end to end.
const (
	CodeInvalidArgument = "invalid_argument"
	CodeUnknownTool     = "unknown_tool"
)

const instructions = `gti-lookup attaches curated threat-actor context to an indicator or a search ` +
	`term by reading Google Threat Intelligence: which threat actor, campaign or malware family ` +
	`an indicator is associated with, who that actor targets, and which reports describe it. ` +
	`Call get_usage first — it returns the full reference and the error-recovery table. ` +
	`Only Google's index is read, so no packet reaches the target under investigation. ` +
	`A valid GTI licence key is required, and every query is recorded against the licence ` +
	`holder's account. The lookup tools are not implemented yet: today this server answers ` +
	`cache_status and get_usage only.`

func toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name": ToolCacheStatus,
			"description": "State of the local result cache: directory, entry count, total size, " +
				"and the write-time range. Collection answers age on the threat TTL, IOC answers " +
				"on the shorter IOC TTL; both are applied at read time.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        ToolGetUsage,
			"description": "The full reference for this server: tools, arguments, result schema, and the error-recovery table. Call this first.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
	}
}

func (s *Server) dispatch(ctx context.Context, name string, args json.RawMessage) (any, error) {
	_ = ctx
	_ = args
	switch name {
	case ToolCacheStatus:
		return s.cacheStatus()
	default:
		// get_usage never reaches here: it returns Markdown and is answered
		// before dispatch.
		return nil, &argError{code: CodeUnknownTool, msg: "unknown tool: " + name + " (call get_usage for the tool list)"}
	}
}

func (s *Server) cacheStatus() (any, error) {
	st := s.Cache.Stat()
	return map[string]any{
		"dir":              st.Dir,
		"entries":          st.Entries,
		"bytes":            st.Bytes,
		"threat_ttl_hours": s.Cfg.ThreatTTL.Hours(),
		"ioc_ttl_hours":    s.Cfg.IOCTTL.Hours(),
	}, nil
}

// argError is a structured tool-layer error: a stable code an agent can branch
// on plus a human-readable message.
type argError struct {
	code string
	msg  string
}

func (e *argError) Error() string { return e.msg }

// structuredError maps an error onto the {code, message} pair an agent sees.
func structuredError(err error) map[string]string {
	var ae *argError
	if errors.As(err, &ae) {
		return map[string]string{"code": ae.code, "message": ae.msg}
	}
	return map[string]string{"code": CodeInvalidArgument, "message": err.Error()}
}
