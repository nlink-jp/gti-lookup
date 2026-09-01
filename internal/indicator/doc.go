// Package indicator will be the pre-network gate: classify an input as an
// MD5 / SHA1 / SHA256 hash (by hex length 32/40/64), an IPv4/IPv6 address, a
// domain, or a URL before anything is sent upstream — the same
// single-entry-point style as malware-lookup. Collection IDs
// (threat-actor--<hash>, ...) are typed identifiers and are handled by their
// own commands, not classified here.
//
// Not implemented yet; the design is fixed in docs/ja/gti-lookup-rfp.ja.md.
package indicator
