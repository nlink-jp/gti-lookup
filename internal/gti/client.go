// Package gti is the Google Threat Intelligence REST client: direct net/http
// calls against the v3 API (no SDK), authenticating with the licence key in
// the x-apikey header — never in a URL, never logged.
//
// The client is deliberately read-only: object GETs and listing GETs only.
// Collection writes and file uploads have no place here, permanently —
// uploading a sample tells a third party what the organization is looking at.
package gti

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Stable error codes an agent can branch on. New codes are a compatible
// change; renaming one is breaking.
const (
	CodeAuth     = "auth_error"     // 401: the key is missing, wrong, or revoked
	CodeForbid   = "forbidden"      // 403: the licence does not cover this endpoint
	CodeNotFound = "not_found"      // 404: the object does not exist upstream
	CodeBadReq   = "bad_request"    // 400: the query or path was rejected
	CodeQuota    = "quota_exceeded" // 429: the licence's request budget is spent
	CodeUpstream = "upstream_error" // 5xx and everything else upstream
	CodeNetwork  = "network_error"  // the exchange itself failed
	CodeDecode   = "decode_error"   // 2xx with a body that is not the documented shape
)

// Error is a structured client error.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Code returns the stable error code, or "" when err did not come from this
// client.
func Code(err error) string {
	var ge *Error
	if errors.As(err, &ge) {
		return ge.Code
	}
	return ""
}

// maxBody bounds one response read. GTI report objects are large but not
// unbounded; past this size something upstream is broken and streaming it
// into memory helps nobody.
const maxBody = 32 << 20

// Client is a read-only GTI v3 API client.
type Client struct {
	baseURL string
	apiKey  string
	ua      string
	hc      *http.Client
}

// New builds a client. baseURL is the API root without a trailing slash;
// userAgent identifies this tool in upstream logs.
func New(baseURL, apiKey string, timeout time.Duration, userAgent string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		ua:      userAgent,
		hc:      &http.Client{Timeout: timeout},
	}
}

// Object is one API object: {id, type, attributes}.
type Object struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// ObjectList is one page of objects plus the paging state upstream reported.
type ObjectList struct {
	Objects []Object
	Cursor  string // non-empty when upstream holds more
	Count   int    // upstream's total when reported, else -1
}

// URLID converts a URL into the identifier the API addresses it by:
// unpadded base64url, matching the canonical vt-py client. (Google's own MCP
// server uses the standard alphabet instead, which corrupts the path whenever
// the encoding contains '+' or '/'.)
func URLID(u string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(u))
}

// GetObject fetches one object: GET {base}/{path}?{query}.
func (c *Client) GetObject(ctx context.Context, path string, query url.Values) (*Object, error) {
	body, err := c.get(ctx, path, query)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Data Object `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, &Error{Code: CodeDecode, Message: "decode object: " + err.Error()}
	}
	if envelope.Data.ID == "" && envelope.Data.Type == "" {
		return nil, &Error{Code: CodeDecode, Message: "decode object: response carries no data object"}
	}
	return &envelope.Data, nil
}

// GetData fetches an endpoint whose data member is not an object list — the
// behaviour summary and the MITRE tree return plain documents there — and
// hands the raw data back for the caller to shape.
func (c *Client) GetData(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	body, err := c.get(ctx, path, query)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, &Error{Code: CodeDecode, Message: "decode data: " + err.Error()}
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, &Error{Code: CodeDecode, Message: "decode data: response carries no data member"}
	}
	return envelope.Data, nil
}

// ListObjects fetches one page of objects: GET {base}/{path}?{query}.
func (c *Client) ListObjects(ctx context.Context, path string, query url.Values) (*ObjectList, error) {
	body, err := c.get(ctx, path, query)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Data []Object `json:"data"`
		Meta struct {
			Cursor string `json:"cursor"`
			Count  *int   `json:"count"`
			// The intelligence search reports its total under a different
			// name — and as a float.
			TotalHits *float64 `json:"total_hits"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, &Error{Code: CodeDecode, Message: "decode list: " + err.Error()}
	}
	list := &ObjectList{Objects: envelope.Data, Cursor: envelope.Meta.Cursor, Count: -1}
	if envelope.Meta.Count != nil {
		list.Count = *envelope.Meta.Count
	} else if envelope.Meta.TotalHits != nil {
		list.Count = int(*envelope.Meta.TotalHits)
	}
	return list, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	u := c.baseURL + "/" + strings.TrimLeft(path, "/")
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, &Error{Code: CodeBadReq, Message: "build request: " + err.Error()}
	}
	// The key travels only in this header. It must never appear in the URL —
	// URLs end up in proxy logs — and never in an error message.
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, &Error{Code: CodeNetwork, Message: "exchange failed: " + sanitizeNetErr(err)}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, &Error{Code: CodeNetwork, Message: "read response: " + sanitizeNetErr(err)}
	}
	if resp.StatusCode == http.StatusOK {
		return body, nil
	}
	return nil, statusError(resp.StatusCode, body)
}

// sanitizeNetErr keeps a transport error useful without ever echoing a header.
// net/http errors carry the URL, which is fine — the key is not in it.
func sanitizeNetErr(err error) string { return err.Error() }

// statusError maps an upstream failure onto the stable code vocabulary,
// keeping upstream's own code and message as evidence.
func statusError(status int, body []byte) *Error {
	code := CodeUpstream
	switch {
	case status == http.StatusUnauthorized:
		code = CodeAuth
	case status == http.StatusForbidden:
		code = CodeForbid
	case status == http.StatusNotFound:
		code = CodeNotFound
	case status == http.StatusBadRequest:
		code = CodeBadReq
	case status == http.StatusTooManyRequests:
		code = CodeQuota
	}

	msg := fmt.Sprintf("GTI answered HTTP %d", status)
	var upstream struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &upstream); err == nil && upstream.Error.Code != "" {
		msg = fmt.Sprintf("%s (%s: %s)", msg, upstream.Error.Code, upstream.Error.Message)
	}
	switch code {
	case CodeAuth:
		msg += " — the API key is missing, wrong, or revoked; check [api] key in the config"
	case CodeForbid:
		msg += " — the GTI licence does not cover this endpoint"
	case CodeQuota:
		msg += " — the licence's request budget is spent; retry after the quota window resets"
	}
	return &Error{Code: code, Message: msg}
}
