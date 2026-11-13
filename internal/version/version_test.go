package version

import "testing"

func TestUserAgent(t *testing.T) {
	old := Number
	defer func() { Number = old }()
	Number = "0.1.0"
	if got, want := UserAgent(), "rerouted/0.1.0 (Tieroute homeserver; https://rerouteholdings.llc)"; got != want {
		t.Fatalf("UserAgent() = %q, want %q", got, want)
	}
}
