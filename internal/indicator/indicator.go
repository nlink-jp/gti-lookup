// Package indicator is the pre-network gate: classify an input as a file
// hash, an IP address, a URL or a domain before anything is sent upstream —
// the same single-entry-point style as malware-lookup. Collection IDs
// (threat-actor--<uuid>, malpedia_win_..., ...) are typed identifiers and are
// handled by their own commands, not classified here.
package indicator

import (
	"fmt"
	"net/netip"
	"strings"
)

// Kind is the classified indicator type. The values double as the GTI API
// object collection names, so they appear verbatim in results.
type Kind string

const (
	File   Kind = "file"
	IP     Kind = "ip_address"
	Domain Kind = "domain"
	URL    Kind = "url"
)

// Indicator is a classified input: its kind plus the canonical form that is
// sent upstream and used as the cache key.
type Indicator struct {
	Kind  Kind
	Value string
}

// Classify detects what an input is from its shape, in a fixed order: file
// hash (32/40/64 hex digits — MD5/SHA1/SHA256, the malware-lookup rule), IP
// address (IPv4 or IPv6), URL (has a scheme), then domain. Hashes, domains
// and schemes are canonicalised to lower case; URL paths keep their case.
func Classify(input string) (Indicator, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return Indicator{}, fmt.Errorf("empty indicator")
	}

	if isHex(s) {
		switch len(s) {
		case 32, 40, 64:
			return Indicator{Kind: File, Value: strings.ToLower(s)}, nil
		default:
			return Indicator{}, fmt.Errorf("%q looks like hex but is %d digits; a hash is 32 (MD5), 40 (SHA1) or 64 (SHA256)", s, len(s))
		}
	}

	if addr, err := netip.ParseAddr(s); err == nil {
		return Indicator{Kind: IP, Value: addr.String()}, nil
	}

	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		if scheme == "" || rest == "" {
			return Indicator{}, fmt.Errorf("%q is not a usable URL", s)
		}
		return Indicator{Kind: URL, Value: strings.ToLower(scheme) + "://" + rest}, nil
	}

	if isDomain(s) {
		return Indicator{Kind: Domain, Value: strings.ToLower(s)}, nil
	}

	return Indicator{}, fmt.Errorf("cannot classify %q: not a hash (32/40/64 hex), IP address, URL (scheme://...) or domain", s)
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// isDomain accepts dotted names of LDH labels (letters, digits, hyphens —
// including punycode xn-- labels). A single label ("localhost") is rejected:
// GTI indexes public names, and a bare word is far more likely to be a typo
// or a search term that belongs to the search command instead.
func isDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	// The rightmost label must not be all digits — that shape is a malformed
	// IP, not a name.
	last := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}
