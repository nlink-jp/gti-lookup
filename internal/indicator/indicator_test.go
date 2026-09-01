package indicator

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		in    string
		kind  Kind
		value string
	}{
		// Hashes canonicalise to lower case.
		{"D41D8CD98F00B204E9800998ECF8427E", File, "d41d8cd98f00b204e9800998ecf8427e"},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", File, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
		{"ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA", File,
			"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"},
		// IPs, both families.
		{"192.0.2.1", IP, "192.0.2.1"},
		{"2001:db8::1", IP, "2001:db8::1"},
		// URLs keep path case; the scheme is lowered.
		{"HTTPS://example.com/A/B?q=1", URL, "https://example.com/A/B?q=1"},
		{"http://192.0.2.1/x", URL, "http://192.0.2.1/x"},
		// Domains lower-case, punycode passes.
		{"Example.COM", Domain, "example.com"},
		{"xn--r8jz45g.example", Domain, "xn--r8jz45g.example"},
		{"sub.domain-name.co.jp", Domain, "sub.domain-name.co.jp"},
		// Surrounding whitespace is an accident, not a signal.
		{"  example.com  ", Domain, "example.com"},
	}
	for _, tc := range tests {
		got, err := Classify(tc.in)
		if err != nil {
			t.Errorf("Classify(%q): %v", tc.in, err)
			continue
		}
		if got.Kind != tc.kind || got.Value != tc.value {
			t.Errorf("Classify(%q) = %v %q, want %v %q", tc.in, got.Kind, got.Value, tc.kind, tc.value)
		}
	}
}

func TestClassifyRejects(t *testing.T) {
	tests := []struct {
		in   string
		want string // substring the error must carry so the user learns why
	}{
		{"", "empty"},
		{"deadbeef", "8 digits"},                  // hex but not a hash length
		{"localhost", "cannot classify"},          // single label is not a domain
		{"threat actor name", "cannot classify"},  // search terms belong to search
		{"example..com", "cannot classify"},       // empty label
		{"-bad.example.com", "cannot classify"},   // label starts with hyphen
		{"1.2.3.4.5", "cannot classify"},          // malformed IP is not a domain
		{"://missing-scheme", "not a usable URL"}, // empty scheme
		{"https://", "not a usable URL"},          // scheme with nothing behind it
	}
	for _, tc := range tests {
		_, err := Classify(tc.in)
		if err == nil {
			t.Errorf("Classify(%q) accepted, want error", tc.in)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Classify(%q) error %q does not contain %q", tc.in, err, tc.want)
		}
	}
}

// A 64-hex string that also parses as nothing else must stay a hash even if
// it could theoretically be a hostname label.
func TestHashWinsOverDomainShapes(t *testing.T) {
	in := strings.Repeat("ab", 16) // 32 hex chars
	got, err := Classify(in)
	if err != nil || got.Kind != File {
		t.Errorf("Classify(%q) = %v, %v; want File", in, got.Kind, err)
	}
}
