// Package engine is the shared core behind both the CLI and the MCP server:
// classify the input, consult the cache, call gti, and shape the response
// into the actor context that is this tool's reason to exist — threat actors,
// campaigns, malware families, their targets, and the reports that describe
// them.
//
// Sharing the engine is what keeps the two faces from drifting: an agent
// calling the MCP server and a human typing the CLI must get the same answer
// for the same input.
//
// Two rules live here rather than in the presentation layer:
//
//   - The default IOC answer is trimmed to the actor context
//     (gti_assessment + associations); the full report is opt-in. The trimmed
//     default is what keeps this tool from answering questions the sibling
//     lookup tools already own.
//
//   - A partial answer is never presented as a complete one: a result built
//     on a failed expansion carries Incomplete plus the reason, and a
//     degraded result is never cached.
package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/nlink-jp/gti-lookup/internal/cache"
	"github.com/nlink-jp/gti-lookup/internal/config"
	"github.com/nlink-jp/gti-lookup/internal/gti"
	"github.com/nlink-jp/gti-lookup/internal/indicator"
)

// Client is the subset of the GTI client the engine needs, injected so tests
// run offline.
type Client interface {
	GetObject(ctx context.Context, path string, query url.Values) (*gti.Object, error)
	ListObjects(ctx context.Context, path string, query url.Values) (*gti.ObjectList, error)
}

// Error codes this layer adds to the gti vocabulary.
const (
	CodeMissingKey      = "missing_api_key"
	CodeInvalidArgument = "invalid_argument"
)

// Error is a structured engine error.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Code maps any error this package returns onto the stable slug an agent
// sees: the engine's own codes first, then the gti client's.
func Code(err error) string {
	var ee *Error
	if errors.As(err, &ee) {
		return ee.Code
	}
	return gti.Code(err)
}

// MaxLimit caps every list request. The GTI API itself caps pages at 40.
const MaxLimit = 40

// Engine is the shared core.
type Engine struct {
	cfg    *config.Config
	store  *cache.Store
	client Client
	now    func() time.Time
}

// New wires an engine. The clock is time.Now; tests replace it via WithClock.
func New(cfg *config.Config, store *cache.Store, client Client) *Engine {
	return &Engine{cfg: cfg, store: store, client: client, now: time.Now}
}

// WithClock returns a copy using the given clock, for deterministic tests.
func (e *Engine) WithClock(now func() time.Time) *Engine {
	clone := *e
	clone.now = now
	return &clone
}

// requireKey refuses to build a query without a licence key. Load succeeds
// without one so cache inspection and the MCP handshake work; the refusal
// lives here, at the entry to every query path, with a pointed message.
func (e *Engine) requireKey() error {
	if e.cfg.HasKey() {
		return nil
	}
	return &Error{Code: CodeMissingKey, Message: "no GTI API key is configured — set [api] key in " +
		"~/.config/gti-lookup/config.toml or the GTI_LOOKUP_API_KEY environment variable (a GTI licence is required)"}
}

// resolveLimit applies the configured default and the API page cap.
func (e *Engine) resolveLimit(limit int) (int, error) {
	if limit == 0 {
		limit = e.cfg.DefaultLimit
	}
	if limit < 1 || limit > MaxLimit {
		return 0, &Error{Code: CodeInvalidArgument,
			Message: fmt.Sprintf("limit must be between 1 and %d (got %d)", MaxLimit, limit)}
	}
	return limit, nil
}

// lookupCached runs the cache-aside pattern: a fresh entry answers, otherwise
// fetch runs and its result is cached — unless fetch marks it degraded.
func lookupCached[T any](e *Engine, key string, ttl time.Duration, refresh bool,
	fetch func() (*T, bool, error)) (*T, error) {
	if !refresh {
		if raw, ok := e.store.Get(key, e.now(), ttl); ok {
			out := new(T)
			if err := json.Unmarshal(raw, out); err == nil {
				return out, nil
			}
			// A corrupt entry reads as a miss; the fetch below overwrites it.
		}
	}
	result, cacheable, err := fetch()
	if err != nil {
		return nil, err
	}
	if cacheable {
		if raw, err := json.Marshal(result); err == nil {
			_ = e.store.Put(key, raw, e.now()) // an unwritable cache degrades, never fails a lookup
		}
	}
	return result, nil
}

var (
	collectionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$`)
	relationshipPattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	orderPattern        = regexp.MustCompile(`^[a-z_]{1,40}[+-]?$`)
)

// SearchOptions parameterise SearchThreats. Zero values mean the defaults.
type SearchOptions struct {
	CollectionType string // one of CollectionTypes, or "" for every type
	OrderBy        string // e.g. "relevance-" (the default), "creation_date+"
	Limit          int
	Refresh        bool
}

// SearchThreats searches the curated collections catalogue.
func (e *Engine) SearchThreats(ctx context.Context, query string, opts SearchOptions) (*ThreatSearch, error) {
	if err := e.requireKey(); err != nil {
		return nil, err
	}
	if opts.CollectionType != "" && !CollectionTypeSet[opts.CollectionType] {
		return nil, &Error{Code: CodeInvalidArgument,
			Message: fmt.Sprintf("unknown collection_type %q; one of: %s", opts.CollectionType, collectionTypesJoined)}
	}
	if query == "" && opts.CollectionType == "" {
		return nil, &Error{Code: CodeInvalidArgument,
			Message: "give a query, a collection_type, or both — an unfiltered search of the whole catalogue answers nothing useful"}
	}
	if opts.OrderBy == "" {
		opts.OrderBy = "relevance-"
	}
	if !orderPattern.MatchString(opts.OrderBy) {
		return nil, &Error{Code: CodeInvalidArgument,
			Message: fmt.Sprintf("order_by %q is not an order key (e.g. relevance-, creation_date+)", opts.OrderBy)}
	}
	limit, err := e.resolveLimit(opts.Limit)
	if err != nil {
		return nil, err
	}

	filter := query
	if opts.CollectionType != "" {
		filter = "collection_type:" + opts.CollectionType
		if query != "" {
			filter += " " + query
		}
	}

	key := cache.Key("search", orDefault(opts.CollectionType, "any"), opts.OrderBy, strconv.Itoa(limit), query)
	return lookupCached(e, key, e.cfg.ThreatTTL, opts.Refresh, func() (*ThreatSearch, bool, error) {
		list, err := e.client.ListObjects(ctx, "collections", url.Values{
			"filter":     {filter},
			"order":      {opts.OrderBy},
			"limit":      {strconv.Itoa(limit)},
			"attributes": {searchAttributes},
		})
		if err != nil {
			return nil, false, err
		}
		res := &ThreatSearch{
			Query:          query,
			CollectionType: opts.CollectionType,
			OrderBy:        opts.OrderBy,
			Retrieved:      len(list.Objects),
			More:           list.Cursor != "",
			TotalUpstream:  list.Count,
			Threats:        summaries(list.Objects),
		}
		return res, true, nil
	})
}

// ThreatOptions parameterise Threat.
type ThreatOptions struct {
	Refresh bool
}

// Threat fetches one collection's curated report.
func (e *Engine) Threat(ctx context.Context, id string, opts ThreatOptions) (*Threat, error) {
	if err := e.requireKey(); err != nil {
		return nil, err
	}
	if !collectionIDPattern.MatchString(id) {
		return nil, &Error{Code: CodeInvalidArgument,
			Message: fmt.Sprintf("%q is not a collection id (e.g. threat-actor--<uuid>, report--<hash>)", id)}
	}

	key := cache.Key("threat", id)
	return lookupCached(e, key, e.cfg.ThreatTTL, opts.Refresh, func() (*Threat, bool, error) {
		obj, err := e.client.GetObject(ctx, "collections/"+id, url.Values{
			// aggregations is a huge IOC-commonality blob with its own future
			// tool; it has no place inside a report.
			"exclude_attributes": {"aggregations"},
		})
		if err != nil {
			return nil, false, err
		}
		res := &Threat{
			ID:             obj.ID,
			CollectionType: stringAttr(obj.Attributes, "collection_type"),
			Name:           stringAttr(obj.Attributes, "name"),
			Attributes:     obj.Attributes,
		}
		return res, true, nil
	})
}

// RelatedOptions parameterise the two relationship pivots.
type RelatedOptions struct {
	// Relationship is a curated name (CollectionRelationships /
	// IOCRelationships). RelationshipOther passes any other upstream name
	// through — the escape hatch the enum does not carry.
	Relationship      string
	RelationshipOther string
	Limit             int
	Refresh           bool
}

// ThreatRelated expands one relationship of a collection.
func (e *Engine) ThreatRelated(ctx context.Context, id string, opts RelatedOptions) (*Related, error) {
	if err := e.requireKey(); err != nil {
		return nil, err
	}
	if !collectionIDPattern.MatchString(id) {
		return nil, &Error{Code: CodeInvalidArgument,
			Message: fmt.Sprintf("%q is not a collection id (e.g. threat-actor--<uuid>, report--<hash>)", id)}
	}
	rel, err := resolveRelationship(opts, CollectionRelationshipSet)
	if err != nil {
		return nil, err
	}
	limit, err := e.resolveLimit(opts.Limit)
	if err != nil {
		return nil, err
	}
	key := cache.Key("threatrel", id, rel, strconv.Itoa(limit))
	return lookupCached(e, key, e.cfg.ThreatTTL, opts.Refresh, func() (*Related, bool, error) {
		return e.fetchRelated(ctx, "collections/"+id, id, rel, limit)
	})
}

// IOCOptions parameterise LookupIOC.
type IOCOptions struct {
	// Full switches from the trimmed actor-context answer to the full report
	// (minus per-engine last_analysis_results). The trimmed default is the
	// coexistence line with the sibling lookup tools — full is the opt-in.
	Full    bool
	Limit   int // associations listed
	Refresh bool
}

// LookupIOC answers "which curated threats is this indicator associated
// with": the object's assessment plus its associations, by default nothing
// more.
func (e *Engine) LookupIOC(ctx context.Context, value string, opts IOCOptions) (*IOC, error) {
	if err := e.requireKey(); err != nil {
		return nil, err
	}
	ind, err := indicator.Classify(value)
	if err != nil {
		return nil, &Error{Code: CodeInvalidArgument, Message: err.Error()}
	}
	limit, err := e.resolveLimit(opts.Limit)
	if err != nil {
		return nil, err
	}

	view := "brief"
	if opts.Full {
		view = "full"
	}
	key := cache.Key("ioc", string(ind.Kind), ind.Value, view, strconv.Itoa(limit))
	return lookupCached(e, key, e.cfg.IOCTTL, opts.Refresh, func() (*IOC, bool, error) {
		query := url.Values{}
		if opts.Full {
			// Even "full" excludes the per-engine scan matrix: it dwarfs
			// everything else and malware-lookup's verdict already covers it.
			query.Set("exclude_attributes", "last_analysis_results")
		} else {
			query.Set("attributes", iocAttributes[ind.Kind])
		}
		obj, err := e.client.GetObject(ctx, iocPath(ind), query)
		if err != nil {
			return nil, false, err
		}

		res := &IOC{
			Value:      ind.Value,
			Kind:       string(ind.Kind),
			ID:         obj.ID,
			Assessment: popAssessment(obj.Attributes),
			Attributes: obj.Attributes,
		}

		assoc, err := e.client.ListObjects(ctx, iocPath(ind)+"/associations", url.Values{
			"attributes": {summaryAttributes},
			"limit":      {strconv.Itoa(limit)},
		})
		if err != nil {
			// The report stands, but the actor context — the point of this
			// tool — is missing. Say so, and never cache the degraded answer.
			res.Incomplete = true
			res.Note = "associations could not be retrieved: " + err.Error()
			return res, false, nil
		}
		res.Associations = summaries(assoc.Objects)
		res.AssociationsRetrieved = len(assoc.Objects)
		res.AssociationsMore = assoc.Cursor != ""
		res.AssociationsUpstream = assoc.Count
		return res, true, nil
	})
}

// IOCRelated expands one relationship of an indicator.
func (e *Engine) IOCRelated(ctx context.Context, value string, opts RelatedOptions) (*Related, error) {
	if err := e.requireKey(); err != nil {
		return nil, err
	}
	ind, err := indicator.Classify(value)
	if err != nil {
		return nil, &Error{Code: CodeInvalidArgument, Message: err.Error()}
	}
	rel, err := resolveRelationship(opts, IOCRelationshipSet)
	if err != nil {
		return nil, err
	}
	limit, err := e.resolveLimit(opts.Limit)
	if err != nil {
		return nil, err
	}
	key := cache.Key("iocrel", string(ind.Kind), ind.Value, rel, strconv.Itoa(limit))
	return lookupCached(e, key, e.cfg.IOCTTL, opts.Refresh, func() (*Related, bool, error) {
		return e.fetchRelated(ctx, iocPath(ind), ind.Value, rel, limit)
	})
}

// fetchRelated picks the request shape by what the relationship returns:
// collections and other name-bearing objects are fetched as full objects
// narrowed to their naming attributes (their descriptors are opaque ids);
// everything else — including free-form names — uses descriptors, where the
// id is the value itself.
func (e *Engine) fetchRelated(ctx context.Context, basePath, subject, rel string, limit int) (*Related, bool, error) {
	var list *gti.ObjectList
	var err error
	if attrs, ok := relObjectAttributes[rel]; ok {
		list, err = e.client.ListObjects(ctx, basePath+"/"+rel, url.Values{
			"attributes": {attrs},
			"limit":      {strconv.Itoa(limit)},
		})
	} else {
		list, err = e.client.ListObjects(ctx, basePath+"/relationships/"+rel, url.Values{
			"limit": {strconv.Itoa(limit)},
		})
	}
	if err != nil {
		return nil, false, err
	}
	res := &Related{
		Subject:       subject,
		Relationship:  rel,
		Retrieved:     len(list.Objects),
		More:          list.Cursor != "",
		TotalUpstream: list.Count,
		Items:         relatedItems(list.Objects),
	}
	return res, true, nil
}

// resolveRelationship applies the enum-plus-passthrough contract.
func resolveRelationship(opts RelatedOptions, curated map[string]bool) (string, error) {
	if opts.RelationshipOther != "" {
		if opts.Relationship != "" {
			return "", &Error{Code: CodeInvalidArgument,
				Message: "give either relationship or relationship_other, not both"}
		}
		if !relationshipPattern.MatchString(opts.RelationshipOther) {
			return "", &Error{Code: CodeInvalidArgument,
				Message: fmt.Sprintf("%q is not a relationship name (lowercase letters, digits, underscores)", opts.RelationshipOther)}
		}
		return opts.RelationshipOther, nil
	}
	if opts.Relationship == "" {
		return "", &Error{Code: CodeInvalidArgument, Message: "relationship is required"}
	}
	if !curated[opts.Relationship] {
		return "", &Error{Code: CodeInvalidArgument,
			Message: fmt.Sprintf("%q is not a curated relationship here; pass it as relationship_other to send it upstream anyway", opts.Relationship)}
	}
	return opts.Relationship, nil
}

func iocPath(ind indicator.Indicator) string {
	switch ind.Kind {
	case indicator.File:
		return "files/" + ind.Value
	case indicator.IP:
		return "ip_addresses/" + ind.Value
	case indicator.Domain:
		return "domains/" + ind.Value
	default: // indicator.URL
		return "urls/" + gti.URLID(ind.Value)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
