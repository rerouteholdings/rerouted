package api

import "testing"

// Per-origin limits count registrable domains, so one domain's subdomains share them, while
// separate sites on a shared host (a public suffix) don't (SPEC §9.5).
func TestOriginKey(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"chat.evil.example", "spam1.evil.example", true},
		{"evil.example", "x.y.evil.example", true},
		{"kat.github.io", "ravi.github.io", false},
		{"a.test", "b.test", false},
		{"chat.example.co.uk", "other.example.co.uk", true},
		{"chat.example.co.uk", "chat.another.co.uk", false},
	} {
		if got := originKey(c.a) == originKey(c.b); got != c.same {
			t.Errorf("%s and %s: same origin %v, want %v (%s, %s)", c.a, c.b, got, c.same, originKey(c.a), originKey(c.b))
		}
	}
}
