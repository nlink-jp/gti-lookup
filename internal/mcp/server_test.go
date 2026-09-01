package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nlink-jp/gti-lookup/internal/cache"
	"github.com/nlink-jp/gti-lookup/internal/config"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		Cfg:     &config.Config{ThreatTTL: config.DefaultThreatTTL, IOCTTL: config.DefaultIOCTTL},
		Cache:   &cache.Store{Dir: t.TempDir()},
		Version: "test",
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
	for _, want := range []string{ToolCacheStatus, ToolGetUsage} {
		if !names[want] {
			t.Errorf("tools/list is missing %s (got %v)", want, names)
		}
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
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_ioc"}}`)
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
