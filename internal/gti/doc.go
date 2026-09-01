// Package gti will hold the Google Threat Intelligence REST client: direct
// net/http calls against the v3 API (no SDK), authenticating with the licence
// key in the x-apikey header — never in a URL, never logged.
//
// The client is deliberately read-only: object GETs, relationship GETs and
// searches. Collection writes and file uploads have no place here,
// permanently — uploading a sample tells a third party what the organization
// is looking at.
//
// Not implemented yet; the surface is fixed in docs/ja/gti-lookup-rfp.ja.md.
package gti
