package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// setupIntegration isolates config and cache in a temp dir, points the tool
// at a stub GTI server, and returns the mux to hang endpoints on plus a
// counter of requests that actually reached it.
func setupIntegration(t *testing.T) (*http.ServeMux, *atomic.Int64) {
	t.Helper()
	mux := http.NewServeMux()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("x-apikey") != "integration-key" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":{"code":"AuthenticationRequiredError","message":"no key"}}`))
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("GTI_LOOKUP_API_KEY", "")
	t.Setenv("VT_APIKEY", "")

	confDir := filepath.Join(dir, "config", "gti-lookup")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "[api]\nkey = \"integration-key\"\nbase_url = \"" + srv.URL + "\"\n"
	if err := os.WriteFile(filepath.Join(confDir, "config.toml"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return mux, &hits
}

func TestSearchEndToEnd(t *testing.T) {
	mux, _ := setupIntegration(t)
	mux.HandleFunc("/collections", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("filter"); got != "collection_type:threat_actor lazarus" {
			t.Errorf("filter = %q", got)
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"threat-actor--x","type":"collection","attributes":` +
			`{"name":"Example Actor","collection_type":"threat-actor"}}],"meta":{"count":1}}`))
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"search", "lazarus", "--type", "threat-actor", "--json"}, "test", nil, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
	}
	var res map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	threats, _ := res["threats"].([]any)
	if len(threats) != 1 {
		t.Errorf("threats = %v", res["threats"])
	}
}

func TestThreatTextRendering(t *testing.T) {
	mux, _ := setupIntegration(t)
	mux.HandleFunc("/collections/threat-actor--x", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"threat-actor--x","type":"collection","attributes":` +
			`{"name":"Example Actor","collection_type":"threat-actor","description":"An example.",` +
			`"targeted_industries":["a","b"]}}}`))
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"threat", "threat-actor--x"}, "test", nil, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"threat-actor: Example Actor", "An example.", "targeted_industries: [2 items]"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

func TestIOCTextLeadsWithAssessmentAndActors(t *testing.T) {
	mux, _ := setupIntegration(t)
	mux.HandleFunc("/domains/example.com", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"example.com","type":"domain","attributes":` +
			`{"registrar":"Example Registrar","gti_assessment":{"verdict":{"value":"VERDICT_MALICIOUS"},` +
			`"threat_score":{"value":80}}}}}`))
	})
	mux.HandleFunc("/domains/example.com/associations", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"threat-actor--x","type":"collection","attributes":` +
			`{"name":"Example Actor","collection_type":"threat-actor"}}],"meta":{"count":1}}`))
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"ioc", "example.com"}, "test", nil, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"gti_assessment:", "verdict: VERDICT_MALICIOUS", "Example Actor"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

// A failed associations expansion must surface as INCONCLUSIVE and exit 1 —
// an empty list here would read as "clean", the worst way to be wrong.
func TestIOCDegradedPrintsInconclusiveAndExitsPartial(t *testing.T) {
	mux, _ := setupIntegration(t)
	mux.HandleFunc("/domains/example.com", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"example.com","type":"domain","attributes":{}}}`))
	})
	mux.HandleFunc("/domains/example.com/associations", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":{"code":"QuotaExceededError","message":"spent"}}`))
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"ioc", "example.com"}, "test", nil, &stdout, &stderr)
	if code != exitPartial {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitPartial, stderr.String())
	}
	if !strings.Contains(stdout.String(), "INCONCLUSIVE") {
		t.Errorf("output does not lead with INCONCLUSIVE:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "no curated threat") {
		t.Errorf("a degraded answer was rendered as clean:\n%s", stdout.String())
	}
}

// Multiple targets: JSONL output, a failing target is reported on stderr and
// turns the exit partial, and the healthy targets still answer.
func TestIOCMultipleTargetsJSONL(t *testing.T) {
	mux, _ := setupIntegration(t)
	mux.HandleFunc("/domains/good.example", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"good.example","type":"domain","attributes":{}}}`))
	})
	mux.HandleFunc("/domains/good.example/associations", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[],"meta":{}}`))
	})
	mux.HandleFunc("/domains/bad.example", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"code":"NotFoundError","message":"unknown"}}`))
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"ioc", "good.example", "bad.example", "--json"}, "test", nil, &stdout, &stderr)
	if code != exitPartial {
		t.Fatalf("exit = %d, want %d", code, exitPartial)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 1 {
		t.Errorf("JSONL lines = %d, want 1 (only the healthy target)", len(lines))
	}
	if !strings.Contains(stderr.String(), "bad.example") {
		t.Errorf("stderr does not name the failed target: %s", stderr.String())
	}
}

// The second identical query answers from the cache: same output, no second
// request upstream.
func TestSecondLookupAnswersFromCache(t *testing.T) {
	mux, hits := setupIntegration(t)
	mux.HandleFunc("/domains/example.com", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":"example.com","type":"domain","attributes":{}}}`))
	})
	mux.HandleFunc("/domains/example.com/associations", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[],"meta":{}}`))
	})

	var first, second, stderr bytes.Buffer
	if code := run([]string{"ioc", "example.com", "--json"}, "test", nil, &first, &stderr); code != exitOK {
		t.Fatalf("first: exit %d, stderr %s", code, stderr.String())
	}
	after := hits.Load()
	if code := run([]string{"ioc", "example.com", "--json"}, "test", nil, &second, &stderr); code != exitOK {
		t.Fatalf("second: exit %d, stderr %s", code, stderr.String())
	}
	if hits.Load() != after {
		t.Errorf("the second lookup went upstream (%d → %d requests)", after, hits.Load())
	}
	if first.String() != second.String() {
		t.Errorf("cached answer differs:\n%s\n---\n%s", first.String(), second.String())
	}
}

func TestRelatedPassthroughEndToEnd(t *testing.T) {
	mux, _ := setupIntegration(t)
	mux.HandleFunc("/domains/example.com/relationships/resolutions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"192.0.2.1","type":"resolution"}],"meta":{"count":1}}`))
	})

	var stdout, stderr bytes.Buffer
	code := run([]string{"ioc", "example.com", "--related-other", "resolutions"}, "test", nil, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "192.0.2.1") {
		t.Errorf("output is missing the related id:\n%s", stdout.String())
	}
}
