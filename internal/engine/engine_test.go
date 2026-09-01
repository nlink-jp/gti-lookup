package engine

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/gti-lookup/internal/cache"
	"github.com/nlink-jp/gti-lookup/internal/config"
	"github.com/nlink-jp/gti-lookup/internal/gti"
)

type call struct {
	path  string
	query url.Values
}

// fakeClient records every request and answers from injected functions, so
// engine tests run offline and assert the exact upstream contract.
type fakeClient struct {
	gets   []call
	lists  []call
	datas  []call
	getFn  func(path string, q url.Values) (*gti.Object, error)
	listFn func(path string, q url.Values) (*gti.ObjectList, error)
	dataFn func(path string, q url.Values) (json.RawMessage, error)
}

func (f *fakeClient) GetData(_ context.Context, path string, q url.Values) (json.RawMessage, error) {
	f.datas = append(f.datas, call{path, q})
	if f.dataFn == nil {
		return json.RawMessage(`{}`), nil
	}
	return f.dataFn(path, q)
}

func (f *fakeClient) GetObject(_ context.Context, path string, q url.Values) (*gti.Object, error) {
	f.gets = append(f.gets, call{path, q})
	if f.getFn == nil {
		return &gti.Object{ID: "stub", Type: "stub"}, nil
	}
	return f.getFn(path, q)
}

func (f *fakeClient) ListObjects(_ context.Context, path string, q url.Values) (*gti.ObjectList, error) {
	f.lists = append(f.lists, call{path, q})
	if f.listFn == nil {
		return &gti.ObjectList{Count: -1}, nil
	}
	return f.listFn(path, q)
}

func testEngine(t *testing.T, client Client) *Engine {
	t.Helper()
	cfg := &config.Config{
		APIKey:       "test-key",
		BaseURL:      config.DefaultBaseURL,
		DefaultLimit: 10,
		CacheDir:     t.TempDir(),
		ThreatTTL:    config.DefaultThreatTTL,
		IOCTTL:       config.DefaultIOCTTL,
		Timeout:      time.Second,
	}
	e := New(cfg, &cache.Store{Dir: cfg.CacheDir}, client)
	return e.WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
}

func TestEveryQueryPathRequiresAKey(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	e.cfg = &config.Config{DefaultLimit: 10, ThreatTTL: time.Hour, IOCTTL: time.Hour, CacheDir: t.TempDir()}

	ctx := context.Background()
	checks := map[string]error{}
	_, err := e.SearchThreats(ctx, "apt", SearchOptions{})
	checks["SearchThreats"] = err
	_, err = e.Threat(ctx, "threat-actor--x", ThreatOptions{})
	checks["Threat"] = err
	_, err = e.ThreatRelated(ctx, "threat-actor--x", RelatedOptions{Relationship: "associations"})
	checks["ThreatRelated"] = err
	_, err = e.LookupIOC(ctx, "example.com", IOCOptions{})
	checks["LookupIOC"] = err
	_, err = e.IOCRelated(ctx, "example.com", RelatedOptions{Relationship: "associations"})
	checks["IOCRelated"] = err

	for name, err := range checks {
		if Code(err) != CodeMissingKey {
			t.Errorf("%s without a key: code = %q, want %q (err: %v)", name, Code(err), CodeMissingKey, err)
		}
	}
	if len(fake.gets)+len(fake.lists) != 0 {
		t.Error("a keyless query still reached upstream")
	}
}

func TestSearchThreatsBuildsFilterAndShapesResult(t *testing.T) {
	fake := &fakeClient{listFn: func(path string, q url.Values) (*gti.ObjectList, error) {
		return &gti.ObjectList{
			Objects: []gti.Object{{
				ID:   "threat-actor--x",
				Type: "collection",
				Attributes: map[string]any{
					"name":                   "Example Actor",
					"collection_type":        "threat-actor",
					"alt_names":              []any{"EXAMPLE-GROUP", "AXE"},
					"last_modification_date": float64(1_700_000_000),
				},
			}},
			Cursor: "next",
			Count:  17,
		}, nil
	}}
	e := testEngine(t, fake)

	res, err := e.SearchThreats(context.Background(), "example", SearchOptions{CollectionType: "vulnerability", Limit: 5})
	if err != nil {
		t.Fatalf("SearchThreats: %v", err)
	}

	q := fake.lists[0].query
	if fake.lists[0].path != "collections" {
		t.Errorf("path = %s", fake.lists[0].path)
	}
	if got := q.Get("filter"); got != "collection_type:vulnerability example" {
		t.Errorf("filter = %q", got)
	}
	if q.Get("order") != "relevance-" || q.Get("limit") != "5" {
		t.Errorf("order/limit = %q/%q", q.Get("order"), q.Get("limit"))
	}
	if !strings.Contains(q.Get("attributes"), "name") {
		t.Errorf("attributes not narrowed: %q", q.Get("attributes"))
	}

	if res.Retrieved != 1 || !res.More || res.TotalUpstream != 17 {
		t.Errorf("accounting = %+v", res)
	}
	got := res.Threats[0]
	if got.Name != "Example Actor" || got.CollectionType != "threat-actor" ||
		got.LastModified != "2023-11-14" || len(got.AltNames) != 2 {
		t.Errorf("summary = %+v", got)
	}
}

func TestSearchThreatsValidation(t *testing.T) {
	e := testEngine(t, &fakeClient{})
	ctx := context.Background()
	cases := []struct {
		name string
		call func() error
	}{
		{"unknown type", func() error {
			_, err := e.SearchThreats(ctx, "x", SearchOptions{CollectionType: "apt-group"})
			return err
		}},
		{"enterprise-gated type is not shipped", func() error {
			// Measured 2026-09-01: typed actor searches answer empty on a
			// Standard licence, so the type is not in the shipped vocabulary.
			_, err := e.SearchThreats(ctx, "x", SearchOptions{CollectionType: "threat-actor"})
			return err
		}},
		{"empty query and type", func() error {
			_, err := e.SearchThreats(ctx, "", SearchOptions{})
			return err
		}},
		{"order injection", func() error {
			_, err := e.SearchThreats(ctx, "x", SearchOptions{OrderBy: "relevance-&attributes=secret"})
			return err
		}},
		{"limit over the page cap", func() error {
			_, err := e.SearchThreats(ctx, "x", SearchOptions{Limit: 41})
			return err
		}},
	}
	for _, tc := range cases {
		if Code(tc.call()) != CodeInvalidArgument {
			t.Errorf("%s: want %s", tc.name, CodeInvalidArgument)
		}
	}
}

func TestThreatExcludesAggregationsAndExtractsIdentity(t *testing.T) {
	fake := &fakeClient{getFn: func(path string, q url.Values) (*gti.Object, error) {
		return &gti.Object{ID: "threat-actor--x", Type: "collection", Attributes: map[string]any{
			"name": "Example Actor", "collection_type": "threat-actor", "description": "…",
		}}, nil
	}}
	e := testEngine(t, fake)
	res, err := e.Threat(context.Background(), "threat-actor--x", ThreatOptions{})
	if err != nil {
		t.Fatalf("Threat: %v", err)
	}
	if fake.gets[0].path != "collections/threat-actor--x" {
		t.Errorf("path = %s", fake.gets[0].path)
	}
	if fake.gets[0].query.Get("exclude_attributes") != "aggregations" {
		t.Errorf("aggregations not excluded: %v", fake.gets[0].query)
	}
	if res.Name != "Example Actor" || res.CollectionType != "threat-actor" {
		t.Errorf("identity not extracted: %+v", res)
	}
}

// A collection id goes into the request path, so anything path-shaped must be
// rejected before it can rewrite the URL.
func TestThreatRejectsPathShapedIDs(t *testing.T) {
	e := testEngine(t, &fakeClient{})
	for _, id := range []string{"", "a/b", "../etc", "a b", "a?x=1"} {
		if _, err := e.Threat(context.Background(), id, ThreatOptions{}); Code(err) != CodeInvalidArgument {
			t.Errorf("id %q was not rejected", id)
		}
	}
}

func TestThreatRelatedPicksRequestShapeByRelationship(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	ctx := context.Background()

	// A collection-returning pivot fetches full objects narrowed to names —
	// its descriptors are opaque ids.
	if _, err := e.ThreatRelated(ctx, "threat-actor--x", RelatedOptions{Relationship: "malware_families"}); err != nil {
		t.Fatalf("ThreatRelated: %v", err)
	}
	if got := fake.lists[0]; got.path != "collections/threat-actor--x/malware_families" ||
		!strings.Contains(got.query.Get("attributes"), "collection_type") {
		t.Errorf("collection pivot request = %+v", got)
	}

	// An IOC-returning pivot uses descriptors — the id is the value itself.
	if _, err := e.ThreatRelated(ctx, "threat-actor--x", RelatedOptions{Relationship: "domains"}); err != nil {
		t.Fatalf("ThreatRelated: %v", err)
	}
	if got := fake.lists[1]; got.path != "collections/threat-actor--x/relationships/domains" ||
		got.query.Get("attributes") != "" {
		t.Errorf("descriptor pivot request = %+v", got)
	}
}

func TestRelationshipEnumPlusPassthroughContract(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	ctx := context.Background()

	// Uncurated names are refused with a pointer at the escape hatch...
	_, err := e.ThreatRelated(ctx, "x", RelatedOptions{Relationship: "resolutions"})
	if Code(err) != CodeInvalidArgument || !strings.Contains(err.Error(), "relationship_other") {
		t.Errorf("uncurated enum value: %v", err)
	}
	// ...which sends them upstream verbatim, as descriptors.
	if _, err := e.ThreatRelated(ctx, "x", RelatedOptions{RelationshipOther: "resolutions"}); err != nil {
		t.Fatalf("passthrough: %v", err)
	}
	if got := fake.lists[0].path; got != "collections/x/relationships/resolutions" {
		t.Errorf("passthrough path = %s", got)
	}
	// Both at once is a contradiction, not a preference.
	_, err = e.ThreatRelated(ctx, "x", RelatedOptions{Relationship: "domains", RelationshipOther: "resolutions"})
	if Code(err) != CodeInvalidArgument {
		t.Errorf("both parameters accepted: %v", err)
	}
	// And path-shaped names never reach the URL.
	_, err = e.ThreatRelated(ctx, "x", RelatedOptions{RelationshipOther: "a/b"})
	if Code(err) != CodeInvalidArgument {
		t.Errorf("path-shaped relationship accepted: %v", err)
	}
}

func TestLookupIOCBriefTrimsAndLiftsAssessment(t *testing.T) {
	fake := &fakeClient{
		getFn: func(path string, q url.Values) (*gti.Object, error) {
			return &gti.Object{ID: "example.com", Type: "domain", Attributes: map[string]any{
				"registrar":      "Example Registrar",
				"gti_assessment": map[string]any{"verdict": map[string]any{"value": "VERDICT_MALICIOUS"}},
			}}, nil
		},
		listFn: func(path string, q url.Values) (*gti.ObjectList, error) {
			return &gti.ObjectList{Objects: []gti.Object{{
				ID: "threat-actor--x", Type: "collection",
				Attributes: map[string]any{"name": "Example Actor", "collection_type": "threat-actor"},
			}}, Count: 3}, nil
		},
	}
	e := testEngine(t, fake)

	res, err := e.LookupIOC(context.Background(), "Example.COM", IOCOptions{})
	if err != nil {
		t.Fatalf("LookupIOC: %v", err)
	}
	if fake.gets[0].path != "domains/example.com" {
		t.Errorf("object path = %s", fake.gets[0].path)
	}
	if got := fake.gets[0].query.Get("attributes"); !strings.Contains(got, "gti_assessment") {
		t.Errorf("brief view did not narrow attributes: %q", got)
	}
	if fake.lists[0].path != "domains/example.com/associations" {
		t.Errorf("associations path = %s", fake.lists[0].path)
	}
	if res.Assessment == nil {
		t.Error("gti_assessment was not lifted to the top level")
	}
	if _, still := res.Attributes["gti_assessment"]; still {
		t.Error("gti_assessment is duplicated inside attributes")
	}
	if len(res.Associations) != 1 || res.Associations[0].Name != "Example Actor" {
		t.Errorf("associations = %+v", res.Associations)
	}
	if res.AssociationsUpstream != 3 {
		t.Errorf("upstream total dropped: %+v", res)
	}
}

func TestLookupIOCFullStillExcludesScanMatrix(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	if _, err := e.LookupIOC(context.Background(), "192.0.2.1", IOCOptions{Full: true}); err != nil {
		t.Fatalf("LookupIOC: %v", err)
	}
	q := fake.gets[0].query
	if q.Get("exclude_attributes") != "last_analysis_results" || q.Get("attributes") != "" {
		t.Errorf("full view query = %v", q)
	}
	if fake.gets[0].path != "ip_addresses/192.0.2.1" {
		t.Errorf("path = %s", fake.gets[0].path)
	}
}

func TestLookupIOCURLUsesUnpaddedBase64Path(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	if _, err := e.LookupIOC(context.Background(), "https://example.com/x", IOCOptions{}); err != nil {
		t.Fatalf("LookupIOC: %v", err)
	}
	path := fake.gets[0].path
	if !strings.HasPrefix(path, "urls/") || strings.ContainsAny(strings.TrimPrefix(path, "urls/"), "+/=") {
		t.Errorf("url path = %s", path)
	}
}

// The point of the tool is the actor context; when that half fails the result
// says so, and the degraded answer is never frozen into the cache.
func TestLookupIOCDegradedIsMarkedAndNotCached(t *testing.T) {
	failing := true
	fake := &fakeClient{
		listFn: func(path string, q url.Values) (*gti.ObjectList, error) {
			if failing {
				return nil, &gti.Error{Code: gti.CodeQuota, Message: "quota"}
			}
			return &gti.ObjectList{Count: -1}, nil
		},
	}
	e := testEngine(t, fake)
	ctx := context.Background()

	res, err := e.LookupIOC(ctx, "example.com", IOCOptions{})
	if err != nil {
		t.Fatalf("LookupIOC: %v", err)
	}
	if !res.Incomplete || !strings.Contains(res.Note, "associations") {
		t.Errorf("degraded result not marked: %+v", res)
	}

	// Upstream recovers; the next call must re-fetch rather than replay the
	// degraded answer from the cache.
	failing = false
	res, err = e.LookupIOC(ctx, "example.com", IOCOptions{})
	if err != nil {
		t.Fatalf("LookupIOC after recovery: %v", err)
	}
	if res.Incomplete {
		t.Error("the degraded answer was served from the cache")
	}
}

func TestCompleteAnswersAreCachedAndRefreshBypasses(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	ctx := context.Background()

	if _, err := e.LookupIOC(ctx, "example.com", IOCOptions{}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := e.LookupIOC(ctx, "example.com", IOCOptions{}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(fake.gets) != 1 {
		t.Errorf("a fresh cache entry did not answer: %d upstream fetches", len(fake.gets))
	}
	if _, err := e.LookupIOC(ctx, "example.com", IOCOptions{Refresh: true}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if len(fake.gets) != 2 {
		t.Errorf("refresh did not bypass the cache: %d upstream fetches", len(fake.gets))
	}
}

// Brief and full views must not share a cache slot: a trimmed answer served
// under a --full request would silently hide the report.
func TestBriefAndFullDoNotShareACacheSlot(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	ctx := context.Background()
	if _, err := e.LookupIOC(ctx, "example.com", IOCOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.LookupIOC(ctx, "example.com", IOCOptions{Full: true}); err != nil {
		t.Fatal(err)
	}
	if len(fake.gets) != 2 {
		t.Errorf("brief and full shared a cache slot: %d upstream fetches", len(fake.gets))
	}
}

func TestIOCRelatedClassifiesAndBuildsPath(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	if _, err := e.IOCRelated(context.Background(),
		"ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA",
		RelatedOptions{Relationship: "contacted_domains"}); err != nil {
		t.Fatalf("IOCRelated: %v", err)
	}
	want := "files/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/relationships/contacted_domains"
	if fake.lists[0].path != want {
		t.Errorf("path = %s, want %s", fake.lists[0].path, want)
	}
}

func TestSearchIOCsBuildsQueryAndShapesRows(t *testing.T) {
	fake := &fakeClient{listFn: func(path string, q url.Values) (*gti.ObjectList, error) {
		return &gti.ObjectList{
			Objects: []gti.Object{{ID: "8433eac2", Type: "file",
				Attributes: map[string]any{"meaningful_name": "sample.exe", "sha256": "8433eac2..."}}},
			Cursor: "next",
			Count:  1234,
		}, nil
	}}
	e := testEngine(t, fake)
	res, err := e.SearchIOCs(context.Background(), "wannacry entity:file p:60+", IOCSearchOptions{OrderBy: "last_submission_date-", Limit: 5})
	if err != nil {
		t.Fatalf("SearchIOCs: %v", err)
	}
	got := fake.lists[0]
	if got.path != "intelligence/search" {
		t.Errorf("path = %s", got.path)
	}
	if got.query.Get("query") != "wannacry entity:file p:60+" || got.query.Get("order") != "last_submission_date-" {
		t.Errorf("query params = %v", got.query)
	}
	if !strings.Contains(got.query.Get("attributes"), "sha256") {
		t.Errorf("rows not narrowed: %q", got.query.Get("attributes"))
	}
	if res.Retrieved != 1 || !res.More || res.TotalUpstream != 1234 {
		t.Errorf("accounting = %+v", res)
	}
	if res.Items[0].Type != "file" || res.Items[0].Attributes["meaningful_name"] != "sample.exe" {
		t.Errorf("item = %+v", res.Items[0])
	}
}

func TestSearchIOCsValidation(t *testing.T) {
	e := testEngine(t, &fakeClient{})
	if _, err := e.SearchIOCs(context.Background(), "", IOCSearchOptions{}); Code(err) != CodeInvalidArgument {
		t.Errorf("empty query accepted: %v", err)
	}
	if _, err := e.SearchIOCs(context.Background(), "x", IOCSearchOptions{OrderBy: "a&b=c"}); Code(err) != CodeInvalidArgument {
		t.Errorf("order injection accepted: %v", err)
	}
}

const behaviourFixture = `{
	"dns_lookups": [{"hostname": "a.example"}, {"hostname": "b.example"}, {"hostname": "c.example"}],
	"processes_created": ["p1"],
	"verdicts": ["MALWARE"],
	"attack_techniques": {"T1055": [{"severity": "HIGH"}], "T1070": [{"severity": "INFO"}]},
	"has_html_report": true
}`

func behaviourFake() *fakeClient {
	return &fakeClient{dataFn: func(path string, q url.Values) (json.RawMessage, error) {
		return json.RawMessage(behaviourFixture), nil
	}}
}

const hash40 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

func TestFileBehaviourIndexNamesSectionsWithCounts(t *testing.T) {
	e := testEngine(t, behaviourFake())
	res, err := e.FileBehaviour(context.Background(), hash40, BehaviourOptions{})
	if err != nil {
		t.Fatalf("FileBehaviour: %v", err)
	}
	found := map[string]int{}
	for _, s := range res.Sections {
		found[s.Name] = s.Items
	}
	if found["dns_lookups"] != 3 || found["processes_created"] != 1 {
		t.Errorf("sections = %+v", res.Sections)
	}
	// Maps are sections too — a live summary carried 63 keyed entries under
	// attack_techniques, which would defeat the index if inlined.
	if found["attack_techniques"] != 2 {
		t.Errorf("map section missing: %+v", res.Sections)
	}
	if _, leaked := res.Summary["attack_techniques"]; leaked {
		t.Error("map content leaked into the index summary")
	}
	// Scalar fields ride along inline instead of hiding behind a section.
	if res.Summary["has_html_report"] != true {
		t.Errorf("summary fields = %+v", res.Summary)
	}
	if len(res.Items) != 0 {
		t.Error("the index view leaked section items")
	}
}

// A keyed section pages in key order as {key, value} entries.
func TestFileBehaviourMapSectionPagesByKey(t *testing.T) {
	e := testEngine(t, behaviourFake())
	res, err := e.FileBehaviour(context.Background(), hash40,
		BehaviourOptions{Section: "attack_techniques", Offset: 1, Limit: 1})
	if err != nil {
		t.Fatalf("FileBehaviour: %v", err)
	}
	if res.Total != 2 || res.Retrieved != 1 || res.More {
		t.Errorf("accounting = %+v", res)
	}
	item, _ := res.Items[0].(map[string]any)
	if item["key"] != "T1070" {
		t.Errorf("key order not applied: %+v", res.Items)
	}
}

func TestFileBehaviourSectionPagesWithAccounting(t *testing.T) {
	e := testEngine(t, behaviourFake())
	res, err := e.FileBehaviour(context.Background(), hash40,
		BehaviourOptions{Section: "dns_lookups", Offset: 1, Limit: 1})
	if err != nil {
		t.Fatalf("FileBehaviour: %v", err)
	}
	if res.Total != 3 || res.Retrieved != 1 || !res.More || res.Offset != 1 {
		t.Errorf("accounting = %+v", res)
	}
	item, _ := res.Items[0].(map[string]any)
	if item["hostname"] != "b.example" {
		t.Errorf("offset not applied: %+v", res.Items)
	}
}

// A wrong section name teaches the caller the real ones instead of guessing.
func TestFileBehaviourUnknownSectionListsSections(t *testing.T) {
	e := testEngine(t, behaviourFake())
	_, err := e.FileBehaviour(context.Background(), hash40, BehaviourOptions{Section: "network"})
	if Code(err) != CodeInvalidArgument || !strings.Contains(err.Error(), "dns_lookups") {
		t.Errorf("error does not list the sections: %v", err)
	}
}

func TestFileBehaviourRejectsNonFileIndicators(t *testing.T) {
	e := testEngine(t, behaviourFake())
	_, err := e.FileBehaviour(context.Background(), "example.com", BehaviourOptions{})
	if Code(err) != CodeInvalidArgument || !strings.Contains(err.Error(), "files only") {
		t.Errorf("domain accepted for behaviour: %v", err)
	}
}

// The 2 MB summary is fetched once; paging through sections is local.
func TestFileBehaviourSummaryIsFetchedOnce(t *testing.T) {
	fake := behaviourFake()
	e := testEngine(t, fake)
	ctx := context.Background()
	if _, err := e.FileBehaviour(ctx, hash40, BehaviourOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.FileBehaviour(ctx, hash40, BehaviourOptions{Section: "dns_lookups"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.FileBehaviour(ctx, hash40, BehaviourOptions{Section: "dns_lookups", Offset: 2}); err != nil {
		t.Fatal(err)
	}
	if len(fake.datas) != 1 {
		t.Errorf("summary fetched %d times, want 1", len(fake.datas))
	}
}

// Account state answers live: someone toggles a rule in the console and asks
// whether it took — a cached "disabled" would gaslight them.
func TestHuntingRulesetsAreNeverCached(t *testing.T) {
	fake := &fakeClient{listFn: func(path string, q url.Values) (*gti.ObjectList, error) {
		return &gti.ObjectList{Objects: []gti.Object{{ID: "25811887535",
			Attributes: map[string]any{"name": "r", "enabled": false, "number_of_rules": float64(2)}}}, Count: -1}, nil
	}}
	e := testEngine(t, fake)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		res, err := e.HuntingRulesets(ctx, 0)
		if err != nil {
			t.Fatalf("HuntingRulesets: %v", err)
		}
		if res.Items[0].Enabled || res.Items[0].NumberOfRules != 2 {
			t.Errorf("summary = %+v", res.Items[0])
		}
	}
	if len(fake.lists) != 2 {
		t.Errorf("list served from cache (%d upstream calls, want 2)", len(fake.lists))
	}
	if fake.lists[0].path != "intelligence/hunting_rulesets" {
		t.Errorf("path = %s", fake.lists[0].path)
	}

	for i := 0; i < 2; i++ {
		if _, err := e.HuntingRuleset(ctx, "25811887535"); err != nil {
			t.Fatalf("HuntingRuleset: %v", err)
		}
	}
	if len(fake.gets) != 2 {
		t.Errorf("detail served from cache (%d upstream calls, want 2)", len(fake.gets))
	}
}

func TestHuntingRulesetExtractsRulesText(t *testing.T) {
	fake := &fakeClient{getFn: func(path string, q url.Values) (*gti.Object, error) {
		return &gti.Object{ID: "25811887535", Type: "hunting_ruleset", Attributes: map[string]any{
			"name": "Untitled YARA ruleset", "enabled": false,
			"rules": "rule x { condition: true }", "rule_names": []any{"x"},
			"number_of_rules": float64(1), "match_object_type": "file",
		}}, nil
	}}
	e := testEngine(t, fake)
	res, err := e.HuntingRuleset(context.Background(), "25811887535")
	if err != nil {
		t.Fatalf("HuntingRuleset: %v", err)
	}
	if res.Rules == "" || res.Enabled || res.MatchObjectType != "file" || len(res.RuleNames) != 1 {
		t.Errorf("ruleset = %+v", res)
	}
}

func TestThreatMitreTreeFetchesAndShapes(t *testing.T) {
	fake := &fakeClient{dataFn: func(path string, q url.Values) (json.RawMessage, error) {
		return json.RawMessage(`{"tactics":[{"id":"TA0003","name":"Persistence"}]}`), nil
	}}
	e := testEngine(t, fake)
	res, err := e.ThreatMitreTree(context.Background(), "alienvault_x", ThreatOptions{})
	if err != nil {
		t.Fatalf("ThreatMitreTree: %v", err)
	}
	if fake.datas[0].path != "collections/alienvault_x/mitre_tree" {
		t.Errorf("path = %s", fake.datas[0].path)
	}
	tactics, _ := res.Tree["tactics"].([]any)
	if len(tactics) != 1 {
		t.Errorf("tree = %+v", res.Tree)
	}
}

func TestDefaultLimitComesFromConfig(t *testing.T) {
	fake := &fakeClient{}
	e := testEngine(t, fake)
	if _, err := e.SearchThreats(context.Background(), "x", SearchOptions{}); err != nil {
		t.Fatalf("SearchThreats: %v", err)
	}
	if got := fake.lists[0].query.Get("limit"); got != "10" {
		t.Errorf("limit = %q, want the configured default 10", got)
	}
}
