package engine

import (
	"sort"
	"strings"
	"time"

	"github.com/nlink-jp/gti-lookup/internal/gti"
	"github.com/nlink-jp/gti-lookup/internal/indicator"
)

// CollectionTypes is the searchable catalogue vocabulary this tool ships:
// the GTI Standard feature set. The catalogue also holds threat-actor /
// campaign / report / malware-family collections, but those answer only to
// Enterprise licences (measured 2026-09-01: typed searches return empty even
// with query terms) — a type we cannot test is a type we do not ship.
// get_threat/lookup_ioc remain type-agnostic: whatever id or association the
// licence can see, they can fetch.
var CollectionTypes = []string{"vulnerability"}

// CollectionTypeSet is CollectionTypes as a membership set.
var CollectionTypeSet = toSet(CollectionTypes)

// filterTypeToken translates the documented vocabulary into what the live
// filter parser actually accepts (measured 2026-09-01): the hyphenated forms
// from gtidocs are rejected as "Invalid value for collection_type"; the
// parser wants underscore tokens. See AGENTS.md Gotchas for the full
// measured vocabulary, kept there for when an Enterprise key ever widens
// CollectionTypes again.
var filterTypeToken = map[string]string{
	"vulnerability": "vulnerability",
}

var collectionTypesJoined = strings.Join(CollectionTypes, ", ")

// CollectionRelationships are the curated pivots from a collection. The
// upstream list is longer; these are the ones that serve actor investigation.
// Anything else goes through relationship_other (hunting_rulesets moved
// there: at Standard tier it never carries data to test against).
var CollectionRelationships = []string{
	"associations", "attack_techniques", "campaigns", "domains", "files",
	"ip_addresses", "malware_families", "reports",
	"software_toolkits", "suspected_threat_actors", "threat_actors",
	"urls", "vulnerabilities",
}

// CollectionRelationshipSet is CollectionRelationships as a membership set.
var CollectionRelationshipSet = toSet(CollectionRelationships)

// IOCRelationships are the curated pivots from an indicator. Passive-DNS
// style pivots (resolutions) are deliberately absent: rdns-lookup owns that
// question — reach them via relationship_other when GTI's view is wanted as a
// second opinion.
var IOCRelationships = []string{
	"associations", "attack_techniques", "campaigns", "collections",
	"communicating_files", "contacted_domains", "contacted_ips",
	"contacted_urls", "downloaded_files", "dropped_files",
	"embedded_domains", "embedded_ips", "embedded_urls",
	"malware_families", "related_threat_actors", "reports",
}

// IOCRelationshipSet is IOCRelationships as a membership set.
var IOCRelationshipSet = toSet(IOCRelationships)

// relObjectAttributes lists the relationships whose descriptors are opaque
// ids, and the naming attributes to fetch full objects with instead. Every
// relationship absent here — the network pivots, and every free-form name —
// uses descriptors, where the id is the value.
var relObjectAttributes = map[string]string{
	"associations":            summaryAttributes,
	"campaigns":               summaryAttributes,
	"collections":             summaryAttributes,
	"malware_families":        summaryAttributes,
	"related_threat_actors":   summaryAttributes,
	"reports":                 summaryAttributes,
	"software_toolkits":       summaryAttributes,
	"suspected_threat_actors": summaryAttributes,
	"threat_actors":           summaryAttributes,
	"vulnerabilities":         summaryAttributes,
	"attack_techniques":       "name",
}

// summaryAttributes is the narrowed attribute set for collection summaries.
const summaryAttributes = "name,collection_type,alt_names,last_modification_date"

// searchAttributes is what a search result row carries.
const searchAttributes = "name,collection_type,alt_names,creation_date,last_modification_date"

// iocSearchAttributes narrows an intelligence-search row to identity: the
// union of the per-type identity fields (absent ones are simply omitted).
// Verified 2026-09-01: the attributes parameter works on /intelligence/search.
const iocSearchAttributes = "meaningful_name,type_description,size,md5,sha1,sha256," +
	"url,last_final_url,title,creation_date,first_submission_date,last_submission_date"

// iocAttributes is the trimmed default per indicator kind: identity plus
// gti_assessment. Everything a sibling lookup tool owns (per-engine verdicts,
// passive DNS, reputation feeds) stays out of the default on purpose.
var iocAttributes = map[indicator.Kind]string{
	indicator.File:   "md5,sha1,sha256,meaningful_name,type_description,size,first_submission_date,last_submission_date,tags,gti_assessment",
	indicator.Domain: "creation_date,registrar,tags,gti_assessment",
	indicator.IP:     "country,as_owner,tags,gti_assessment",
	indicator.URL:    "url,last_final_url,title,first_submission_date,tags,gti_assessment",
}

// ThreatSummary is one collection, reduced to what identifies it.
type ThreatSummary struct {
	ID             string   `json:"id"`
	CollectionType string   `json:"collection_type,omitempty"`
	Name           string   `json:"name,omitempty"`
	AltNames       []string `json:"alt_names,omitempty"`
	LastModified   string   `json:"last_modified,omitempty"`
}

// ThreatSearch is the result of SearchThreats.
type ThreatSearch struct {
	Query          string          `json:"query"`
	CollectionType string          `json:"collection_type,omitempty"`
	OrderBy        string          `json:"order_by"`
	Retrieved      int             `json:"retrieved"`
	More           bool            `json:"more,omitempty"`
	TotalUpstream  int             `json:"total_upstream,omitempty"` // -1/0 omitted: upstream did not say
	Threats        []ThreatSummary `json:"threats"`
}

// Threat is one collection's curated report.
type Threat struct {
	ID             string         `json:"id"`
	CollectionType string         `json:"collection_type,omitempty"`
	Name           string         `json:"name,omitempty"`
	Attributes     map[string]any `json:"attributes"`
}

// RelatedItem is one related entity. For descriptor pivots the id is the
// value itself (a contacted domain, an embedded IP); for collection pivots
// the naming fields are filled in.
type RelatedItem struct {
	ID             string `json:"id"`
	Type           string `json:"type,omitempty"`
	Name           string `json:"name,omitempty"`
	CollectionType string `json:"collection_type,omitempty"`
}

// Related is the result of a relationship expansion.
type Related struct {
	Subject       string        `json:"subject"`
	Relationship  string        `json:"relationship"`
	Retrieved     int           `json:"retrieved"`
	More          bool          `json:"more,omitempty"`
	TotalUpstream int           `json:"total_upstream,omitempty"`
	Items         []RelatedItem `json:"items"`
}

// IOCItem is one intelligence-search hit, narrowed to identity.
type IOCItem struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// IOCSearch is the result of SearchIOCs.
type IOCSearch struct {
	Query         string    `json:"query"`
	OrderBy       string    `json:"order_by,omitempty"`
	Retrieved     int       `json:"retrieved"`
	More          bool      `json:"more,omitempty"`
	TotalUpstream int       `json:"total_upstream,omitempty"`
	Items         []IOCItem `json:"items"`
}

// BehaviourSection is one section of a sandbox behaviour summary, as listed
// by the index view.
type BehaviourSection struct {
	Name  string `json:"name"`
	Items int    `json:"items"`
}

// Behaviour is the result of FileBehaviour. Without a section it is an
// index — the summary for WannaCry alone is over 2 MB, so the sections are
// named and counted rather than returned; with a section it is one section's
// items, paged by offset/limit so every entry stays reachable.
type Behaviour struct {
	Value     string             `json:"value"`
	Sections  []BehaviourSection `json:"sections,omitempty"`
	Summary   map[string]any     `json:"summary_fields,omitempty"`
	Section   string             `json:"section,omitempty"`
	Total     int                `json:"total,omitempty"`
	Offset    int                `json:"offset,omitempty"`
	Retrieved int                `json:"retrieved,omitempty"`
	More      bool               `json:"more,omitempty"`
	Items     []any              `json:"items,omitempty"`
}

// MitreTree is the result of ThreatMitreTree: the collection's ATT&CK tree
// as upstream sends it. The MCP layer compacts it — the raw tree for one
// community collection measured 258 KB.
type MitreTree struct {
	ID   string         `json:"id"`
	Tree map[string]any `json:"tree"`
}

// HuntingRulesetSummary is one row of the account's LiveHunt ruleset list.
type HuntingRulesetSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	Enabled       bool   `json:"enabled"`
	NumberOfRules int    `json:"number_of_rules,omitempty"`
}

// HuntingRulesetList is the result of HuntingRulesets. This is the account's
// own live configuration, so it is never cached.
type HuntingRulesetList struct {
	Retrieved int                     `json:"retrieved"`
	More      bool                    `json:"more,omitempty"`
	Items     []HuntingRulesetSummary `json:"items"`
}

// HuntingRuleset is one LiveHunt ruleset, rules text included.
type HuntingRuleset struct {
	ID              string   `json:"id"`
	Name            string   `json:"name,omitempty"`
	Enabled         bool     `json:"enabled"`
	MatchObjectType string   `json:"match_object_type,omitempty"`
	NumberOfRules   int      `json:"number_of_rules,omitempty"`
	RuleNames       []string `json:"rule_names,omitempty"`
	Rules           string   `json:"rules,omitempty"`
	CreationDate    string   `json:"creation_date,omitempty"`
	Modified        string   `json:"modification_date,omitempty"`
}

// IOC is the result of LookupIOC.
type IOC struct {
	Value string `json:"value"`
	Kind  string `json:"kind"`
	ID    string `json:"id,omitempty"`
	// Assessment is GTI's own verdict block (gti_assessment), passed through
	// verbatim: this tool reports what Google claims and invents no verdict of
	// its own.
	Assessment            map[string]any  `json:"gti_assessment,omitempty"`
	Attributes            map[string]any  `json:"attributes,omitempty"`
	Associations          []ThreatSummary `json:"associations"`
	AssociationsRetrieved int             `json:"associations_retrieved"`
	AssociationsMore      bool            `json:"associations_more,omitempty"`
	AssociationsUpstream  int             `json:"associations_upstream,omitempty"`
	// Incomplete marks an answer built on a failed expansion. It is never
	// cached, and a renderer must never present it as "no associations".
	Incomplete bool   `json:"incomplete,omitempty"`
	Note       string `json:"note,omitempty"`
}

// summaries reduces collection objects to their identifying fields.
func summaries(objs []gti.Object) []ThreatSummary {
	out := make([]ThreatSummary, 0, len(objs))
	for _, o := range objs {
		out = append(out, ThreatSummary{
			ID:             o.ID,
			CollectionType: stringAttr(o.Attributes, "collection_type"),
			Name:           stringAttr(o.Attributes, "name"),
			AltNames:       stringsAttr(o.Attributes, "alt_names"),
			LastModified:   dateAttr(o.Attributes, "last_modification_date"),
		})
	}
	return out
}

func relatedItems(objs []gti.Object) []RelatedItem {
	out := make([]RelatedItem, 0, len(objs))
	for _, o := range objs {
		out = append(out, RelatedItem{
			ID:             o.ID,
			Type:           o.Type,
			Name:           stringAttr(o.Attributes, "name"),
			CollectionType: stringAttr(o.Attributes, "collection_type"),
		})
	}
	return out
}

// popAssessment lifts gti_assessment out of the attribute map so the verdict
// block sits at the top of the result instead of being buried, without
// duplicating it.
func popAssessment(attrs map[string]any) map[string]any {
	if attrs == nil {
		return nil
	}
	a, _ := attrs["gti_assessment"].(map[string]any)
	delete(attrs, "gti_assessment")
	return a
}

func stringAttr(attrs map[string]any, key string) string {
	s, _ := attrs[key].(string)
	return s
}

func stringsAttr(attrs map[string]any, key string) []string {
	raw, _ := attrs[key].([]any)
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// dateAttr renders a unix-seconds attribute as a date. The hour adds nothing
// for catalogue entries and costs width in every listing.
func dateAttr(attrs map[string]any, key string) string {
	f, ok := attrs[key].(float64)
	if !ok || f <= 0 {
		return ""
	}
	return time.Unix(int64(f), 0).UTC().Format("2006-01-02")
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, s := range items {
		set[s] = true
	}
	return set
}
