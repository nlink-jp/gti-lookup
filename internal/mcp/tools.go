package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nlink-jp/gti-lookup/internal/engine"
)

// Tool names. Adding a tool is a compatible change; renaming one is breaking.
const (
	ToolSearchThreats    = "search_threats"
	ToolGetThreat        = "get_threat"
	ToolGetThreatRelated = "get_threat_related"
	ToolLookupIOC        = "lookup_ioc"
	ToolGetIOCRelated    = "get_ioc_related"
	ToolCacheStatus      = "cache_status"
	ToolGetUsage         = "get_usage"
)

// Error codes this layer adds; the engine and gti codes join the same
// vocabulary, so an agent sees one set end to end.
const (
	CodeInvalidArgument = "invalid_argument"
	CodeUnknownTool     = "unknown_tool"
)

// Engine is the subset of the shared core the tools need. Both faces go
// through the same engine, so an agent and a human cannot get different
// answers.
type Engine interface {
	SearchThreats(ctx context.Context, query string, opts engine.SearchOptions) (*engine.ThreatSearch, error)
	Threat(ctx context.Context, id string, opts engine.ThreatOptions) (*engine.Threat, error)
	ThreatRelated(ctx context.Context, id string, opts engine.RelatedOptions) (*engine.Related, error)
	LookupIOC(ctx context.Context, value string, opts engine.IOCOptions) (*engine.IOC, error)
	IOCRelated(ctx context.Context, value string, opts engine.RelatedOptions) (*engine.Related, error)
}

const instructions = `gti-lookup attaches curated threat-actor context to an indicator or a search ` +
	`term by reading Google Threat Intelligence: which threat actor, campaign or malware family ` +
	`an indicator is associated with, who that actor targets, and which reports describe it — ` +
	`in both directions, actor → IOCs (search_threats, get_threat, get_threat_related) and ` +
	`IOC → actor (lookup_ioc, get_ioc_related). Call get_usage first — it returns the full ` +
	`reference, the result schema, and the error-recovery table. Only Google's index is read, ` +
	`so no packet reaches the target under investigation; note that every query is recorded ` +
	`against the licence holder's GTI account. An indicator with no associations is a normal ` +
	`result, not an error. This server reports what Google claims (gti_assessment, associations) ` +
	`and never invents a verdict of its own.`

// descriptionDefaultMax caps get_threat's description field inside a tool
// response. Reports carry essays; the cap is escapable per call via
// description_max (-1 = unlimited), so the tail stays reachable in the same
// result rather than in a file.
const descriptionDefaultMax = 6000

func toolDefinitions() []map[string]any {
	limitProp := map[string]any{
		"type":        "integer",
		"description": fmt.Sprintf("Results to list (1-%d; default from the server config, normally 10).", engine.MaxLimit),
		"minimum":     1,
		"maximum":     engine.MaxLimit,
	}
	refreshProp := map[string]any{
		"type":        "boolean",
		"description": "Bypass the result cache and re-query upstream.",
	}
	relationshipOtherProp := map[string]any{
		"type": "string",
		"description": "Escape hatch: send an upstream relationship name the enum does not carry " +
			"(e.g. resolutions, historical_whois — those overlap sibling lookup servers, ask deliberately). " +
			"Give either relationship or relationship_other, never both.",
	}

	return []map[string]any{
		{
			"name": ToolSearchThreats,
			"description": "Search the curated threat catalogue (collections): threat actors, malware " +
				"families, campaigns, reports, software toolkits, vulnerabilities. Returns compact " +
				"summaries with ids for get_threat / get_threat_related. Give a query, a " +
				"collection_type, or both. retrieved/more/total_upstream account for what this page " +
				"holds versus what upstream has.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Search terms (actor name, alias, family, CVE, free text). Empty is allowed when collection_type is set.",
					},
					"collection_type": map[string]any{
						"type":        "string",
						"enum":        engine.CollectionTypes,
						"description": "Restrict to one threat kind. Strongly recommended when the request names one (an actor, a family, a campaign...).",
					},
					"order_by": map[string]any{
						"type":        "string",
						"description": `Order key with direction suffix: "relevance-" (default), "creation_date-", "last_modification_date-", or the "+" ascending variants.`,
					},
					"limit":   limitProp,
					"refresh": refreshProp,
				},
			},
		},
		{
			"name": ToolGetThreat,
			"description": "Curated report for one collection id (threat-actor--<uuid>, report--<hash>, " +
				"malpedia_..., ...): description, aliases, targets, sources, dates. The description is " +
				"capped at 6000 chars with the drop accounted; raise or lift the cap with " +
				"description_max when the tail matters.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Collection id, from search_threats or an association.",
					},
					"description_max": map[string]any{
						"type":        "integer",
						"description": "Description cap in characters (default 6000; -1 = unlimited).",
					},
					"refresh": refreshProp,
				},
				"required": []string{"id"},
			},
		},
		{
			"name": ToolGetThreatRelated,
			"description": "Pivot from a collection to what it relates to: its IOCs (domains, files, " +
				"ip_addresses, urls), its actors and families, its ATT&CK techniques, its detection " +
				"rules (hunting_rulesets). Items carry names where upstream has them; ids double as " +
				"input to get_threat / lookup_ioc.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Collection id.",
					},
					"relationship": map[string]any{
						"type":        "string",
						"enum":        engine.CollectionRelationships,
						"description": "Curated pivot to expand.",
					},
					"relationship_other": relationshipOtherProp,
					"limit":              limitProp,
					"refresh":            refreshProp,
				},
				"required": []string{"id"},
			},
		},
		{
			"name": ToolLookupIOC,
			"description": "Actor context for one indicator — MD5/SHA1/SHA256 hash, IP, domain, or URL, " +
				"detected from its shape: Google's own gti_assessment plus the curated threats " +
				"(actors, campaigns, families, reports) associated with it. No associations is a " +
				"valid answer. incomplete:true means the association expansion failed — treat that " +
				"as unanswered, never as clean. The default answer is deliberately trimmed: " +
				"per-engine verdicts, passive DNS, reputation and URL behaviour belong to " +
				"malware-lookup, rdns-lookup, abuse-lookup and urlscan-lookup; full:true opts into " +
				"GTI's whole report as a second opinion.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"value": map[string]any{
						"type":        "string",
						"description": "The indicator itself (hash, IP, domain, or URL). NOT a collection id and NOT free text — search_threats handles those.",
					},
					"full": map[string]any{
						"type":        "boolean",
						"description": "Return the full report (minus the per-engine scan matrix) instead of the trimmed actor context.",
					},
					"limit":   limitProp,
					"refresh": refreshProp,
				},
				"required": []string{"value"},
			},
		},
		{
			"name": ToolGetIOCRelated,
			"description": "Pivot from an indicator along one relationship: infrastructure it touches " +
				"(contacted_domains, contacted_ips, contacted_urls), files around it " +
				"(communicating_files, downloaded_files, dropped_files), embedded IOCs, or the " +
				"curated threats naming it (associations, campaigns, malware_families, " +
				"related_threat_actors, reports).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"value": map[string]any{
						"type":        "string",
						"description": "The indicator (hash, IP, domain, or URL).",
					},
					"relationship": map[string]any{
						"type":        "string",
						"enum":        engine.IOCRelationships,
						"description": "Curated pivot to expand.",
					},
					"relationship_other": relationshipOtherProp,
					"limit":              limitProp,
					"refresh":            refreshProp,
				},
				"required": []string{"value"},
			},
		},
		{
			"name": ToolCacheStatus,
			"description": "State of the local result cache: directory, entry count, total size. " +
				"Collection answers age on the threat TTL, IOC answers on the shorter IOC TTL; " +
				"both are applied at read time.",
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
	switch name {
	case ToolSearchThreats:
		return s.searchThreats(ctx, args)
	case ToolGetThreat:
		return s.getThreat(ctx, args)
	case ToolGetThreatRelated:
		return s.getThreatRelated(ctx, args)
	case ToolLookupIOC:
		return s.lookupIOC(ctx, args)
	case ToolGetIOCRelated:
		return s.getIOCRelated(ctx, args)
	case ToolCacheStatus:
		return s.cacheStatus()
	default:
		// get_usage never reaches here: it returns Markdown and is answered
		// before dispatch.
		return nil, &argError{code: CodeUnknownTool, msg: "unknown tool: " + name + " (call get_usage for the tool list)"}
	}
}

// decodeArgs parses tool arguments strictly: an unknown field is a mistyped
// parameter the agent should learn about, not something to swallow.
func decodeArgs(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return &argError{code: CodeInvalidArgument, msg: "arguments: " + err.Error()}
	}
	return nil
}

func (s *Server) searchThreats(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Query          string `json:"query"`
		CollectionType string `json:"collection_type"`
		OrderBy        string `json:"order_by"`
		Limit          int    `json:"limit"`
		Refresh        bool   `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	return s.Eng.SearchThreats(ctx, a.Query, engine.SearchOptions{
		CollectionType: a.CollectionType,
		OrderBy:        a.OrderBy,
		Limit:          a.Limit,
		Refresh:        a.Refresh,
	})
}

func (s *Server) getThreat(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		ID             string `json:"id"`
		DescriptionMax *int   `json:"description_max"`
		Refresh        bool   `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	res, err := s.Eng.Threat(ctx, a.ID, engine.ThreatOptions{Refresh: a.Refresh})
	if err != nil {
		return nil, err
	}
	max := descriptionDefaultMax
	if a.DescriptionMax != nil {
		max = *a.DescriptionMax
	}
	return capDescription(res, max), nil
}

// capDescription applies the tool-response budget to a report's description.
// The engine's answer (and the CLI's --json) stays complete; the cap lives at
// the boundary where the result enters a model's context. The drop is always
// accounted and always escapable via description_max.
func capDescription(res *engine.Threat, max int) *engine.Threat {
	if max < 0 || res.Attributes == nil {
		return res
	}
	desc, ok := res.Attributes["description"].(string)
	if !ok {
		return res
	}
	runes := []rune(desc)
	if len(runes) <= max {
		return res
	}
	clone := *res
	clone.Attributes = make(map[string]any, len(res.Attributes)+2)
	for k, v := range res.Attributes {
		clone.Attributes[k] = v
	}
	clone.Attributes["description"] = string(runes[:max])
	clone.Attributes["description_truncated"] = true
	clone.Attributes["description_total_chars"] = len(runes)
	return &clone
}

func (s *Server) getThreatRelated(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		ID                string `json:"id"`
		Relationship      string `json:"relationship"`
		RelationshipOther string `json:"relationship_other"`
		Limit             int    `json:"limit"`
		Refresh           bool   `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	return s.Eng.ThreatRelated(ctx, a.ID, engine.RelatedOptions{
		Relationship:      a.Relationship,
		RelationshipOther: a.RelationshipOther,
		Limit:             a.Limit,
		Refresh:           a.Refresh,
	})
}

func (s *Server) lookupIOC(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Value   string `json:"value"`
		Full    bool   `json:"full"`
		Limit   int    `json:"limit"`
		Refresh bool   `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	return s.Eng.LookupIOC(ctx, a.Value, engine.IOCOptions{
		Full:    a.Full,
		Limit:   a.Limit,
		Refresh: a.Refresh,
	})
}

func (s *Server) getIOCRelated(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Value             string `json:"value"`
		Relationship      string `json:"relationship"`
		RelationshipOther string `json:"relationship_other"`
		Limit             int    `json:"limit"`
		Refresh           bool   `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	return s.Eng.IOCRelated(ctx, a.Value, engine.RelatedOptions{
		Relationship:      a.Relationship,
		RelationshipOther: a.RelationshipOther,
		Limit:             a.Limit,
		Refresh:           a.Refresh,
	})
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

// structuredError maps an error onto the {code, message} pair an agent sees:
// this layer's own codes first, then the engine and gti vocabulary.
func structuredError(err error) map[string]string {
	var ae *argError
	if errors.As(err, &ae) {
		return map[string]string{"code": ae.code, "message": ae.msg}
	}
	if code := engine.Code(err); code != "" {
		return map[string]string{"code": code, "message": err.Error()}
	}
	return map[string]string{"code": CodeInvalidArgument, "message": err.Error()}
}
