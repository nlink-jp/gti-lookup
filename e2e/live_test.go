//go:build e2e

package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/gti-lookup/internal/cache"
	"github.com/nlink-jp/gti-lookup/internal/config"
	"github.com/nlink-jp/gti-lookup/internal/engine"
	"github.com/nlink-jp/gti-lookup/internal/gti"
)

// Fixtures. Chosen for stability, not for interest.
//
// Never assert an exact count: the corpus and the community catalogue move
// daily, and a test pinned to a number becomes a false alarm within weeks.
// What is asserted is behaviour — that a permanently-indexed object answers,
// that accounting fields are qualified rather than invented, and that the
// Standard-tier request shapes (underscore filter vocabulary, unpadded
// base64url URL ids, plural relationships path, attributes narrowing) are
// still what the live API accepts.
const (
	// WannaCry. Permanently indexed, with associations and a sandbox summary.
	knownHash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
	// The WannaCry kill-switch URL. Permanently indexed; exercises the URL id.
	knownURL = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com/"
	// An AlienVault community collection mirrored since 2017.
	communityCollection = "alienvault_59254c2c4459994fc0600111"
)

// newEngine wires the real stack against the real API, with the cache
// isolated in a tempdir so a stale entry cannot mask a regression. The API
// key is read from the operator's config as usual — these tests are about
// what upstream actually does.
func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	cfg, err := config.Load("", 20*time.Second)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if !cfg.HasKey() {
		t.Skip("no GTI API key configured; e2e needs a licensed key")
	}
	cfg.CacheDir = filepath.Join(t.TempDir(), "cache")
	client := gti.New(cfg.BaseURL, cfg.APIKey, cfg.Timeout, "gti-lookup/e2e")
	return engine.New(cfg, &cache.Store{Dir: cfg.CacheDir}, client)
}

// The one catalogue type Standard can search must keep answering, in the
// underscore filter vocabulary this tool sends.
func TestLiveVulnerabilitySearch(t *testing.T) {
	e := newEngine(t)
	res, err := e.SearchThreats(context.Background(), "log4j",
		engine.SearchOptions{CollectionType: "vulnerability", Limit: 3})
	if err != nil {
		t.Fatalf("SearchThreats: %v", err)
	}
	if res.Retrieved == 0 {
		t.Fatal("log4j vulnerability search answered empty — the filter vocabulary may have moved")
	}
	if res.Threats[0].CollectionType != "vulnerability" {
		t.Errorf("row type = %q", res.Threats[0].CollectionType)
	}
}

func TestLiveIOCLookupCarriesAssociations(t *testing.T) {
	e := newEngine(t)
	res, err := e.LookupIOC(context.Background(), knownHash, engine.IOCOptions{Limit: 5})
	if err != nil {
		t.Fatalf("LookupIOC: %v", err)
	}
	if res.Incomplete {
		t.Fatalf("degraded answer: %s", res.Note)
	}
	if res.AssociationsRetrieved == 0 {
		t.Fatal("WannaCry reports no associations — narrowing on the associations endpoint may have broken")
	}
	if res.Associations[0].Name == "" {
		t.Error("association rows lost their names — attributes narrowing may have broken")
	}
}

// The URL identifier is unpadded base64url; if the API stops accepting it,
// this is the test that says so.
func TestLiveURLLookup(t *testing.T) {
	e := newEngine(t)
	res, err := e.LookupIOC(context.Background(), knownURL, engine.IOCOptions{Limit: 3})
	if err != nil {
		t.Fatalf("LookupIOC(url): %v", err)
	}
	if got, _ := res.Attributes["url"].(string); !strings.Contains(got, "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea") {
		t.Errorf("url attribute = %q", got)
	}
}

func TestLiveThreatReportAndDescriptorPivot(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	threat, err := e.Threat(ctx, communityCollection, engine.ThreatOptions{})
	if err != nil {
		t.Fatalf("Threat: %v", err)
	}
	if threat.Name == "" {
		t.Error("collection report carries no name")
	}
	if _, leaked := threat.Attributes["aggregations"]; leaked {
		t.Error("aggregations were not excluded")
	}

	// The plural /relationships/ descriptor path.
	rel, err := e.ThreatRelated(ctx, communityCollection,
		engine.RelatedOptions{Relationship: "domains", Limit: 5})
	if err != nil {
		t.Fatalf("ThreatRelated: %v", err)
	}
	if rel.Retrieved == 0 {
		t.Error("the collection reports no domains — the descriptors path may have moved")
	}
}

func TestLiveMitreTree(t *testing.T) {
	e := newEngine(t)
	res, err := e.ThreatMitreTree(context.Background(), communityCollection, engine.ThreatOptions{})
	if err != nil {
		t.Fatalf("ThreatMitreTree: %v", err)
	}
	if tactics, _ := res.Tree["tactics"].([]any); len(tactics) == 0 {
		t.Error("mitre tree carries no tactics")
	}
}

func TestLiveBehaviourIndexAndSection(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	index, err := e.FileBehaviour(ctx, knownHash, engine.BehaviourOptions{})
	if err != nil {
		t.Fatalf("FileBehaviour(index): %v", err)
	}
	if len(index.Sections) == 0 {
		t.Fatal("behaviour index reports no sections")
	}

	section, err := e.FileBehaviour(ctx, knownHash,
		engine.BehaviourOptions{Section: index.Sections[0].Name, Limit: 2})
	if err != nil {
		t.Fatalf("FileBehaviour(section): %v", err)
	}
	if section.Total == 0 || section.Retrieved == 0 {
		t.Errorf("section accounting = %+v", section)
	}
}

func TestLiveIntelligenceSearch(t *testing.T) {
	e := newEngine(t)
	res, err := e.SearchIOCs(context.Background(), "wannacry entity:file p:60+",
		engine.IOCSearchOptions{Limit: 3})
	if err != nil {
		t.Fatalf("SearchIOCs: %v", err)
	}
	if res.Retrieved == 0 {
		t.Fatal("the corpus reports no wannacry files — intelligence search may have moved")
	}
	if res.TotalUpstream <= 0 {
		t.Error("total_hits accounting missing")
	}
}

// Account state must answer, whatever it holds — an account with no rulesets
// is a valid answer, an error is not.
func TestLiveHuntingRulesets(t *testing.T) {
	e := newEngine(t)
	if _, err := e.HuntingRulesets(context.Background(), 5); err != nil {
		t.Fatalf("HuntingRulesets: %v", err)
	}
}
