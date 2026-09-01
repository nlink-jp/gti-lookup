package gti

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(srv.URL, "test-key", 5*time.Second, "gti-lookup/test")
}

// The key travels in the x-apikey header and nowhere else — never in the URL,
// where it would end up in proxy logs.
func TestAuthTravelsInHeaderOnly(t *testing.T) {
	var gotHeader, gotURL string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("x-apikey")
		gotURL = r.URL.String()
		_, _ = w.Write([]byte(`{"data":{"id":"x","type":"domain"}}`))
	})
	if _, err := c.GetObject(context.Background(), "domains/example.com", nil); err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if gotHeader != "test-key" {
		t.Errorf("x-apikey = %q, want test-key", gotHeader)
	}
	if strings.Contains(gotURL, "test-key") {
		t.Errorf("the key leaked into the URL: %s", gotURL)
	}
}

func TestGetObjectParsesEnvelope(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/collections/threat-actor--x" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("exclude_attributes") != "aggregations" {
			t.Errorf("query not passed through: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"data":{"id":"threat-actor--x","type":"collection","attributes":{"name":"Example Actor"}}}`))
	})
	q := url.Values{"exclude_attributes": {"aggregations"}}
	obj, err := c.GetObject(context.Background(), "collections/threat-actor--x", q)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if obj.ID != "threat-actor--x" || obj.Type != "collection" {
		t.Errorf("object = %+v", obj)
	}
	if obj.Attributes["name"] != "Example Actor" {
		t.Errorf("attributes = %v", obj.Attributes)
	}
}

func TestListObjectsParsesPageAndCursor(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"a","type":"collection"},{"id":"b","type":"collection"}],` +
			`"meta":{"cursor":"next-page","count":42}}`))
	})
	list, err := c.ListObjects(context.Background(), "collections", nil)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(list.Objects) != 2 || list.Cursor != "next-page" || list.Count != 42 {
		t.Errorf("list = %+v", list)
	}
}

func TestListReadsIntelligenceTotalHits(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"a","type":"file"}],"meta":{"cursor":"x","total_hits":1234.0}}`))
	})
	list, err := c.ListObjects(context.Background(), "intelligence/search", nil)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if list.Count != 1234 {
		t.Errorf("Count = %d, want 1234 (from total_hits)", list.Count)
	}
}

func TestGetDataReturnsRawDocument(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"tactics":[{"id":"TA0003"}]}}`))
	})
	raw, err := c.GetData(context.Background(), "collections/x/mitre_tree", nil)
	if err != nil {
		t.Fatalf("GetData: %v", err)
	}
	if !strings.Contains(string(raw), "TA0003") {
		t.Errorf("raw = %s", raw)
	}
	// And a missing data member is upstream drift, not an empty answer.
	c2 := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
	})
	if _, err := c2.GetData(context.Background(), "x", nil); Code(err) != CodeDecode {
		t.Errorf("missing data member: code = %q, want %q", Code(err), CodeDecode)
	}
}

func TestListWithoutCountReportsMinusOne(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[],"meta":{}}`))
	})
	list, err := c.ListObjects(context.Background(), "collections", nil)
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if list.Count != -1 {
		t.Errorf("Count = %d, want -1 (upstream did not report one)", list.Count)
	}
}

func TestStatusCodesMapToStableSlugs(t *testing.T) {
	tests := []struct {
		status int
		code   string
	}{
		{401, CodeAuth},
		{403, CodeForbid},
		{404, CodeNotFound},
		{400, CodeBadReq},
		{429, CodeQuota},
		{500, CodeUpstream},
		{503, CodeUpstream},
	}
	for _, tc := range tests {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"error":{"code":"UpstreamCode","message":"upstream detail"}}`))
		})
		_, err := c.GetObject(context.Background(), "files/x", nil)
		if err == nil {
			t.Errorf("HTTP %d: no error", tc.status)
			continue
		}
		if Code(err) != tc.code {
			t.Errorf("HTTP %d: code = %q, want %q", tc.status, Code(err), tc.code)
		}
		if !strings.Contains(err.Error(), "UpstreamCode") {
			t.Errorf("HTTP %d: upstream evidence dropped: %v", tc.status, err)
		}
	}
}

// A structured upstream body is evidence; a garbage body must not hide the
// status.
func TestErrorWithGarbageBodyStillNamesStatus(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte("<html>not json</html>"))
	})
	_, err := c.GetObject(context.Background(), "files/x", nil)
	if Code(err) != CodeNotFound {
		t.Fatalf("code = %q, want %q", Code(err), CodeNotFound)
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error does not name the status: %v", err)
	}
}

func TestOKWithGarbageBodyIsDecodeError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>not json</html>"))
	})
	_, err := c.GetObject(context.Background(), "files/x", nil)
	if Code(err) != CodeDecode {
		t.Errorf("code = %q, want %q", Code(err), CodeDecode)
	}
}

func TestNetworkFailureIsNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // the address now refuses connections
	c := New(srv.URL, "k", time.Second, "gti-lookup/test")
	_, err := c.GetObject(context.Background(), "files/x", nil)
	if Code(err) != CodeNetwork {
		t.Errorf("code = %q, want %q (err: %v)", Code(err), CodeNetwork, err)
	}
}

func TestCodeOnForeignErrorIsEmpty(t *testing.T) {
	if got := Code(errors.New("plain")); got != "" {
		t.Errorf("Code(plain error) = %q, want empty", got)
	}
}

// The URL identifier is unpadded base64url — the canonical vt-py encoding.
// The standard alphabet would corrupt the path whenever it yields '+' or '/'.
func TestURLIDIsUnpaddedBase64URL(t *testing.T) {
	id := URLID("https://example.com/a?b=c&d=~~~")
	if strings.ContainsAny(id, "+/=") {
		t.Errorf("URLID contains characters unsafe in a path segment: %q", id)
	}
	if URLID("http://a") == URLID("http://b") {
		t.Error("distinct URLs collided")
	}
}
