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
	ToolSearchThreats      = "search_threats"
	ToolSearchIOCs         = "search_iocs"
	ToolGetThreat          = "get_threat"
	ToolGetThreatRelated   = "get_threat_related"
	ToolGetThreatMitreTree = "get_threat_mitre_tree"
	ToolLookupIOC          = "lookup_ioc"
	ToolGetIOCRelated      = "get_ioc_related"
	ToolGetFileBehaviour   = "get_file_behaviour"
	ToolListHuntingRules   = "list_hunting_rulesets"
	ToolGetHuntingRuleset  = "get_hunting_ruleset"
	ToolCacheStatus        = "cache_status"
	ToolGetUsage           = "get_usage"
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
	SearchIOCs(ctx context.Context, query string, opts engine.IOCSearchOptions) (*engine.IOCSearch, error)
	Threat(ctx context.Context, id string, opts engine.ThreatOptions) (*engine.Threat, error)
	ThreatRelated(ctx context.Context, id string, opts engine.RelatedOptions) (*engine.Related, error)
	ThreatMitreTree(ctx context.Context, id string, opts engine.ThreatOptions) (*engine.MitreTree, error)
	LookupIOC(ctx context.Context, value string, opts engine.IOCOptions) (*engine.IOC, error)
	IOCRelated(ctx context.Context, value string, opts engine.RelatedOptions) (*engine.Related, error)
	FileBehaviour(ctx context.Context, value string, opts engine.BehaviourOptions) (*engine.Behaviour, error)
	HuntingRulesets(ctx context.Context, limit int) (*engine.HuntingRulesetList, error)
	HuntingRuleset(ctx context.Context, id string) (*engine.HuntingRuleset, error)
}

const instructions = `gti-lookup reads Google Threat Intelligence with the GTI Standard feature ` +
	`set: threat context for an indicator (lookup_ioc, get_ioc_related), sandbox behaviour of a ` +
	`file (get_file_behaviour), IOC corpus search in GTI query syntax (search_iocs), and the ` +
	`collections catalogue — vulnerability search (search_threats), reports, pivots and ATT&CK ` +
	`trees (get_threat, get_threat_related, get_threat_mitre_tree). Call get_usage first — it ` +
	`returns the full reference, the result schema, and the error-recovery table. Only Google's ` +
	`index is read, so no packet reaches the target under investigation; note that every query ` +
	`is recorded against the licence holder's GTI account. An indicator with no associations is ` +
	`a normal result, not an error. This server reports what Google claims and never invents a ` +
	`verdict of its own. The Enterprise-only catalogue (curated threat actors, campaigns, ` +
	`reports) is out of scope: actor context arrives through community collections in ` +
	`associations.`

// descriptionDefaultMax caps get_threat's description field inside a tool
// response. Reports carry essays; the cap is escapable per call via
// description_max (-1 = unlimited), so the tail stays reachable in the same
// result rather than in a file.
const descriptionDefaultMax = 6000

// closeSchemas sets additionalProperties:false on every tool's top-level input
// schema, as organization ADR-021 §10 requires: an agent's mistyped argument
// then comes back as an error instead of being silently dropped.
//
// It is a pass over the finished list rather than a helper each schema has to
// call, so a tool added later as a plain literal cannot forget it — the rule is
// enforced by the one place every schema goes through, not by authors
// remembering. Only the top level is touched; a nested object that deliberately
// accepts free-form keys keeps whatever it declares.
func closeSchemas(defs []map[string]any) []map[string]any {
	for _, def := range defs {
		if schema, ok := def["inputSchema"].(map[string]any); ok {
			schema["additionalProperties"] = false
		}
	}
	return defs
}

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

	return closeSchemas([]map[string]any{
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
			"name": ToolSearchIOCs,
			"description": "Search the IOC corpus (files, URLs, domains, IPs) with GTI intelligence " +
				"query syntax — modifiers like entity:file, p:60+ (positives), fs:2024-01-01+ " +
				"(first seen), tag:, type:. Rows are narrowed to identity; expand one with " +
				"lookup_ioc. total_upstream reports the corpus-wide hit count.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "GTI intelligence query (free text plus modifiers).",
					},
					"order_by": map[string]any{
						"type":        "string",
						"description": `Order key, e.g. "last_submission_date-". Empty lets upstream rank.`,
					},
					"limit":   limitProp,
					"refresh": refreshProp,
				},
				"required": []string{"query"},
			},
		},
		{
			"name": ToolGetThreatMitreTree,
			"description": "ATT&CK tree of a collection: tactics and the techniques observed in its " +
				"IOCs. Compact by default (tactic and technique ids/names with counts — the raw " +
				"tree for one collection measured 258 KB); full:true returns everything, " +
				"descriptions and signatures included.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Collection id.",
					},
					"full": map[string]any{
						"type":        "boolean",
						"description": "Return the raw tree instead of the compact view. Large.",
					},
					"refresh": refreshProp,
				},
				"required": []string{"id"},
			},
		},
		{
			"name": ToolGetFileBehaviour,
			"description": "Sandbox behaviour summary of a file hash. Without section: an index — " +
				"section names with item counts, plus the scalar summary fields (a full summary " +
				"can exceed 2 MB, so sections are named, not returned). With section (a name from " +
				"the index, e.g. dns_lookups, processes_created, files_dropped, attack_techniques): " +
				"that section's items, paged by offset/limit so every entry stays reachable.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"value": map[string]any{
						"type":        "string",
						"description": "The file hash (MD5/SHA1/SHA256).",
					},
					"section": map[string]any{
						"type":        "string",
						"description": "One section name from the index. Omit for the index.",
					},
					"offset": map[string]any{
						"type":        "integer",
						"description": "Items to skip inside the section (default 0).",
						"minimum":     0,
					},
					"limit":   limitProp,
					"refresh": refreshProp,
				},
				"required": []string{"value"},
			},
		},
		{
			"name": ToolListHuntingRules,
			"description": "The account's own LiveHunt rulesets: id, name, enabled flag, rule count. " +
				"Never cached — this is live account configuration, the answer to \"did my rule " +
				"take?\". Expand one with get_hunting_ruleset.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"limit": limitProp},
			},
		},
		{
			"name": ToolGetHuntingRuleset,
			"description": "One LiveHunt ruleset by id, YARA rules text included. Read-only: " +
				"creating, editing and enabling rulesets happens in the GTI console.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{
						"type":        "string",
						"description": "Ruleset id, from list_hunting_rulesets.",
					},
				},
				"required": []string{"id"},
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
	})
}

func (s *Server) dispatch(ctx context.Context, name string, args json.RawMessage) (any, error) {
	switch name {
	case ToolSearchThreats:
		return s.searchThreats(ctx, args)
	case ToolSearchIOCs:
		return s.searchIOCs(ctx, args)
	case ToolGetThreat:
		return s.getThreat(ctx, args)
	case ToolGetThreatRelated:
		return s.getThreatRelated(ctx, args)
	case ToolGetThreatMitreTree:
		return s.getThreatMitreTree(ctx, args)
	case ToolLookupIOC:
		return s.lookupIOC(ctx, args)
	case ToolGetIOCRelated:
		return s.getIOCRelated(ctx, args)
	case ToolGetFileBehaviour:
		return s.getFileBehaviour(ctx, args)
	case ToolListHuntingRules:
		return s.listHuntingRulesets(ctx, args)
	case ToolGetHuntingRuleset:
		return s.getHuntingRuleset(ctx, args)
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

func (s *Server) searchIOCs(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Query   string `json:"query"`
		OrderBy string `json:"order_by"`
		Limit   int    `json:"limit"`
		Refresh bool   `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	return s.Eng.SearchIOCs(ctx, a.Query, engine.IOCSearchOptions{
		OrderBy: a.OrderBy,
		Limit:   a.Limit,
		Refresh: a.Refresh,
	})
}

func (s *Server) getThreatMitreTree(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		ID      string `json:"id"`
		Full    bool   `json:"full"`
		Refresh bool   `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	res, err := s.Eng.ThreatMitreTree(ctx, a.ID, engine.ThreatOptions{Refresh: a.Refresh})
	if err != nil {
		return nil, err
	}
	if a.Full {
		return res, nil
	}
	return compactMitre(res), nil
}

// compactMitre reduces the tree to tactic and technique identities with
// counts — the tool-response budget again: the raw tree for one community
// collection measured 258 KB, and descriptions of standard ATT&CK techniques
// add nothing an agent cannot look up by id. full:true escapes the cap.
func compactMitre(res *engine.MitreTree) any {
	type technique struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Count int    `json:"count,omitempty"`
	}
	type tactic struct {
		ID         string      `json:"id"`
		Name       string      `json:"name"`
		Techniques []technique `json:"techniques"`
	}
	var tactics []tactic
	rawTactics, _ := res.Tree["tactics"].([]any)
	for _, rt := range rawTactics {
		m, _ := rt.(map[string]any)
		if m == nil {
			continue
		}
		ta := tactic{ID: str(m["id"]), Name: str(m["name"])}
		rawTechs, _ := m["techniques"].([]any)
		for _, rtc := range rawTechs {
			tm, _ := rtc.(map[string]any)
			if tm == nil {
				continue
			}
			count, _ := tm["count"].(float64)
			ta.Techniques = append(ta.Techniques, technique{ID: str(tm["id"]), Name: str(tm["name"]), Count: int(count)})
		}
		tactics = append(tactics, ta)
	}
	return map[string]any{
		"id":      res.ID,
		"tactics": tactics,
		"note":    "compact view: descriptions and signatures omitted — pass full:true for the raw tree",
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func (s *Server) getFileBehaviour(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Value   string `json:"value"`
		Section string `json:"section"`
		Offset  int    `json:"offset"`
		Limit   int    `json:"limit"`
		Refresh bool   `json:"refresh"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	return s.Eng.FileBehaviour(ctx, a.Value, engine.BehaviourOptions{
		Section: a.Section,
		Offset:  a.Offset,
		Limit:   a.Limit,
		Refresh: a.Refresh,
	})
}

func (s *Server) listHuntingRulesets(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		Limit int `json:"limit"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	return s.Eng.HuntingRulesets(ctx, a.Limit)
}

func (s *Server) getHuntingRuleset(ctx context.Context, raw json.RawMessage) (any, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := decodeArgs(raw, &a); err != nil {
		return nil, err
	}
	return s.Eng.HuntingRuleset(ctx, a.ID)
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
