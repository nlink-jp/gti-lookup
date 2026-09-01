package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nlink-jp/gti-lookup/internal/cache"
	"github.com/nlink-jp/gti-lookup/internal/config"
	"github.com/nlink-jp/gti-lookup/internal/engine"
	"github.com/nlink-jp/gti-lookup/internal/gti"
)

// fakeEngine answers with canned results and records the options it was
// called with, so the tool layer's argument plumbing is what gets tested.
type fakeEngine struct {
	searchOpts engine.SearchOptions
	iocOpts    engine.IOCOptions
	relOpts    engine.RelatedOptions
	threat     *engine.Threat
	err        error
}

func (f *fakeEngine) SearchThreats(_ context.Context, query string, opts engine.SearchOptions) (*engine.ThreatSearch, error) {
	f.searchOpts = opts
	if f.err != nil {
		return nil, f.err
	}
	return &engine.ThreatSearch{Query: query, OrderBy: "relevance-", Retrieved: 1,
		Threats: []engine.ThreatSummary{{ID: "threat-actor--x", Name: "Example Actor", CollectionType: "threat-actor"}}}, nil
}

func (f *fakeEngine) Threat(_ context.Context, id string, _ engine.ThreatOptions) (*engine.Threat, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.threat != nil {
		return f.threat, nil
	}
	return &engine.Threat{ID: id, Attributes: map[string]any{}}, nil
}

func (f *fakeEngine) ThreatRelated(_ context.Context, id string, opts engine.RelatedOptions) (*engine.Related, error) {
	f.relOpts = opts
	if f.err != nil {
		return nil, f.err
	}
	return &engine.Related{Subject: id, Relationship: opts.Relationship + opts.RelationshipOther}, nil
}

func (f *fakeEngine) LookupIOC(_ context.Context, value string, opts engine.IOCOptions) (*engine.IOC, error) {
	f.iocOpts = opts
	if f.err != nil {
		return nil, f.err
	}
	return &engine.IOC{Value: value, Kind: "domain"}, nil
}

func (f *fakeEngine) IOCRelated(_ context.Context, value string, opts engine.RelatedOptions) (*engine.Related, error) {
	f.relOpts = opts
	if f.err != nil {
		return nil, f.err
	}
	return &engine.Related{Subject: value, Relationship: opts.Relationship + opts.RelationshipOther}, nil
}

func testServer(t *testing.T) *Server {
	t.Helper()
	return testServerWith(t, &fakeEngine{})
}

func testServerWith(t *testing.T, eng Engine) *Server {
	t.Helper()
	return &Server{
		Cfg:     &config.Config{ThreatTTL: config.DefaultThreatTTL, IOCTTL: config.DefaultIOCTTL},
		Cache:   &cache.Store{Dir: t.TempDir()},
		Version: "test",
		Eng:     eng,
	}
}

// serve feeds newline-delimited frames through the server and returns the
// decoded responses. This dummy JSON-RPC harness is what reaches the server-
// side validation paths a schema-checking client would never exercise.
func serve(t *testing.T, s *Server, frames ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(frames, "\n") + "\n")
	var out strings.Builder
	if err := s.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	dec := json.NewDecoder(strings.NewReader(out.String()))
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode response: %v (raw: %s)", err, out.String())
		}
		resps = append(resps, m)
	}
	return resps
}

func TestInitializeIdentifiesTheServer(t *testing.T) {
	resps := serve(t, testServer(t), `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	result, _ := resps[0]["result"].(map[string]any)
	if result == nil {
		t.Fatalf("initialize returned no result: %v", resps[0])
	}
	if result["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v, want %s", result["protocolVersion"], protocolVersion)
	}
	info, _ := result["serverInfo"].(map[string]any)
	if info == nil || info["name"] != "gti-lookup" {
		t.Errorf("serverInfo does not name the server: %v", result["serverInfo"])
	}
	if s, _ := result["instructions"].(string); !strings.Contains(s, "get_usage") {
		t.Error("instructions do not point the agent at get_usage")
	}
}

func TestMalformedFrameGetsParseError(t *testing.T) {
	resps := serve(t, testServer(t), `{not json`)
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	errObj, _ := resps[0]["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("no error object: %v", resps[0])
	}
	if code, _ := errObj["code"].(float64); int(code) != -32700 {
		t.Errorf("code = %v, want -32700", errObj["code"])
	}
}

func TestUnknownMethodIsMethodNotFound(t *testing.T) {
	resps := serve(t, testServer(t), `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	errObj, _ := resps[0]["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("no error object: %v", resps[0])
	}
	if code, _ := errObj["code"].(float64); int(code) != -32601 {
		t.Errorf("code = %v, want -32601", errObj["code"])
	}
}

// Notifications (no id) must not be answered — not even unknown ones.
func TestNotificationsAreNotAnswered(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled"}`,
		`{"jsonrpc":"2.0","method":"something/unknown"}`,
	)
	if len(resps) != 0 {
		t.Errorf("notifications were answered: %v", resps)
	}
}

func TestToolsListNamesEveryTool(t *testing.T) {
	resps := serve(t, testServer(t), `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	result, _ := resps[0]["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	names := map[string]bool{}
	for _, tl := range tools {
		m, _ := tl.(map[string]any)
		if m == nil {
			t.Fatalf("tool entry is not an object: %v", tl)
		}
		name, _ := m["name"].(string)
		names[name] = true
		if _, ok := m["inputSchema"]; !ok {
			t.Errorf("tool %s has no inputSchema", name)
		}
	}
	for _, want := range []string{
		ToolSearchThreats, ToolGetThreat, ToolGetThreatRelated,
		ToolLookupIOC, ToolGetIOCRelated, ToolCacheStatus, ToolGetUsage,
	} {
		if !names[want] {
			t.Errorf("tools/list is missing %s (got %v)", want, names)
		}
	}
}

// toolResultText extracts the single text block of a tool result.
func toolResultText(t *testing.T, resp map[string]any) (string, bool) {
	t.Helper()
	result, _ := resp["result"].(map[string]any)
	if result == nil {
		t.Fatalf("no result: %v", resp)
	}
	content, _ := result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content blocks = %d, want 1", len(content))
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	return text, result["isError"] == true
}

func TestSearchThreatsToolPlumbsArguments(t *testing.T) {
	eng := &fakeEngine{}
	resps := serve(t, testServerWith(t, eng),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_threats",`+
			`"arguments":{"query":"lazarus","collection_type":"threat-actor","limit":5,"refresh":true}}}`)
	text, isErr := toolResultText(t, resps[0])
	if isErr {
		t.Fatalf("tool errored: %s", text)
	}
	if eng.searchOpts.CollectionType != "threat-actor" || eng.searchOpts.Limit != 5 || !eng.searchOpts.Refresh {
		t.Errorf("options not plumbed: %+v", eng.searchOpts)
	}
	if !strings.Contains(text, "Example Actor") {
		t.Errorf("result does not carry the summary: %s", text)
	}
}

// Arguments are decoded strictly: a mistyped parameter name is an error the
// agent should see, not something to swallow.
func TestMistypedArgumentIsRejected(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_ioc",`+
			`"arguments":{"value":"example.com","fulll":true}}}`)
	text, isErr := toolResultText(t, resps[0])
	if !isErr {
		t.Fatalf("mistyped argument was accepted: %s", text)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("tool error is not structured JSON: %s", text)
	}
	if payload["code"] != CodeInvalidArgument || !strings.Contains(payload["message"], "fulll") {
		t.Errorf("error does not name the bad field: %v", payload)
	}
}

// The description cap is a tool-response budget: applied by default, always
// accounted, and escapable per call — the tail stays reachable in the same
// result.
func TestGetThreatCapsDescriptionWithAccounting(t *testing.T) {
	long := strings.Repeat("あ", descriptionDefaultMax+100)
	eng := &fakeEngine{threat: &engine.Threat{ID: "report--x",
		Attributes: map[string]any{"description": long}}}
	srv := testServerWith(t, eng)

	resps := serve(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_threat","arguments":{"id":"report--x"}}}`)
	text, isErr := toolResultText(t, resps[0])
	if isErr {
		t.Fatalf("tool errored: %s", text)
	}
	var capped struct {
		Attributes struct {
			Description string `json:"description"`
			Truncated   bool   `json:"description_truncated"`
			Total       int    `json:"description_total_chars"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal([]byte(text), &capped); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !capped.Attributes.Truncated || capped.Attributes.Total != descriptionDefaultMax+100 {
		t.Errorf("drop not accounted: %+v", capped.Attributes)
	}
	if got := len([]rune(capped.Attributes.Description)); got != descriptionDefaultMax {
		t.Errorf("description length = %d, want %d", got, descriptionDefaultMax)
	}

	// -1 lifts the cap in the same call shape. (A fresh struct: Unmarshal
	// leaves absent fields untouched, so reuse would keep the stale flag.)
	resps = serve(t, srv,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_threat",`+
			`"arguments":{"id":"report--x","description_max":-1}}}`)
	text, _ = toolResultText(t, resps[0])
	var lifted struct {
		Attributes struct {
			Description string `json:"description"`
			Truncated   bool   `json:"description_truncated"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal([]byte(text), &lifted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lifted.Attributes.Truncated || len([]rune(lifted.Attributes.Description)) != descriptionDefaultMax+100 {
		t.Error("description_max=-1 did not lift the cap")
	}
}

// Engine and client failures keep their stable codes through the tool layer.
func TestEngineErrorCodesSurviveTheToolLayer(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{&engine.Error{Code: engine.CodeMissingKey, Message: "no key"}, engine.CodeMissingKey},
		{&gti.Error{Code: gti.CodeQuota, Message: "spent"}, gti.CodeQuota},
	} {
		resps := serve(t, testServerWith(t, &fakeEngine{err: tc.err}),
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_ioc","arguments":{"value":"example.com"}}}`)
		text, isErr := toolResultText(t, resps[0])
		if !isErr {
			t.Fatalf("engine failure did not set isError: %s", text)
		}
		var payload map[string]string
		if err := json.Unmarshal([]byte(text), &payload); err != nil {
			t.Fatalf("unstructured error: %s", text)
		}
		if payload["code"] != tc.code {
			t.Errorf("code = %q, want %q", payload["code"], tc.code)
		}
	}
}

func TestRelationshipPassthroughReachesTheEngine(t *testing.T) {
	eng := &fakeEngine{}
	serve(t, testServerWith(t, eng),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_ioc_related",`+
			`"arguments":{"value":"example.com","relationship_other":"resolutions"}}}`)
	if eng.relOpts.RelationshipOther != "resolutions" {
		t.Errorf("relationship_other not plumbed: %+v", eng.relOpts)
	}
}

func TestGetUsageReturnsTheManual(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_usage"}}`)
	result, _ := resps[0]["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("content blocks = %d, want 1", len(content))
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	if !strings.Contains(text, "cache_status") {
		t.Error("the manual does not document cache_status")
	}
	if result["isError"] == true {
		t.Error("get_usage reported an error")
	}
}

func TestCacheStatusReportsBothTTLs(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cache_status"}}`)
	result, _ := resps[0]["result"].(map[string]any)
	content, _ := result["content"].([]any)
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)

	var payload map[string]any
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("cache_status did not return JSON: %v (raw: %s)", err, text)
	}
	if payload["threat_ttl_hours"] != config.DefaultThreatTTL.Hours() {
		t.Errorf("threat_ttl_hours = %v", payload["threat_ttl_hours"])
	}
	if payload["ioc_ttl_hours"] != config.DefaultIOCTTL.Hours() {
		t.Errorf("ioc_ttl_hours = %v", payload["ioc_ttl_hours"])
	}
}

// An unknown tool is a tool result, not a protocol error: the model has to see
// it. The body is the structured {code, message} vocabulary.
func TestUnknownToolIsAStructuredToolError(t *testing.T) {
	resps := serve(t, testServer(t),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"analyse_file"}}`)
	result, _ := resps[0]["result"].(map[string]any)
	if result == nil {
		t.Fatalf("unknown tool produced a protocol error: %v", resps[0])
	}
	if result["isError"] != true {
		t.Error("unknown tool did not set isError")
	}
	content, _ := result["content"].([]any)
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	var payload map[string]string
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("tool error is not structured JSON: %s", text)
	}
	if payload["code"] != CodeUnknownTool {
		t.Errorf("code = %q, want %q", payload["code"], CodeUnknownTool)
	}
}

func TestBlankLinesAreIgnored(t *testing.T) {
	resps := serve(t, testServer(t), "", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "")
	if len(resps) != 1 {
		t.Fatalf("got %d responses, want 1", len(resps))
	}
	if resps[0]["error"] != nil {
		t.Errorf("ping failed: %v", resps[0])
	}
}
