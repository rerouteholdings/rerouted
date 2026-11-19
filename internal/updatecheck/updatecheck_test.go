package updatecheck

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.2.1", "0.2.0", true},
		{"0.2.0", "0.2.0", false},
		{"0.2.0", "0.2.1", false},
		{"0.10.0", "0.9.9", true},
		{"1.0.0", "0.99.99", true},
		{"0.2.0", "0.2.0-rc.6", true},  // a release is newer than its prereleases
		{"0.2.0-rc.6", "0.2.0", false}, // and a prerelease older than its release
		{"0.2.0-rc.10", "0.2.0-rc.6", true},
		{"0.2.0-rc.6", "0.1.9", true},
		{"0.2.0-beta", "0.2.0-alpha", true},
		{"0.2.0-rc.1.1", "0.2.0-rc.1", true},
		{"v0.3.0", "0.2.0", true},
		{"0.2.0+build.5", "0.2.0", false},
		{"garbage", "0.2.0", false},
		{"0.2", "0.1.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCheck(t *testing.T) {
	var ua []string
	body := `{"version":"0.2.1","published":"2026-11-20","notes":"https://chat.example/notes"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = append(ua, r.Header.Get("User-Agent"))
		if len(r.URL.RawQuery) > 0 || r.Header.Get("Cookie") != "" {
			t.Error("the request carries more than the User-Agent")
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()
	var logs bytes.Buffer
	var heard []string
	c := &Checker{URL: srv.URL, Current: "0.2.0", UserAgent: "rerouted/0.2.0 (Tieroute homeserver; https://rerouteholdings.llc)",
		Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), OnNewer: func(r Release) { heard = append(heard, r.Version) }}
	if r, ok := c.Check(t.Context()); !ok || r.Version != "0.2.1" {
		t.Fatal(r, ok)
	}
	if _, ok := c.Check(t.Context()); ok {
		t.Fatal("the same version was reported twice")
	}
	body = `{"version":"0.2.2","published":"2026-11-21","notes":""}`
	if _, ok := c.Check(t.Context()); !ok {
		t.Fatal("a second new version wasn't reported")
	}
	if len(heard) != 2 || strings.Count(logs.String(), "a newer rerouted is available") != 2 {
		t.Fatalf("heard %v, logs %s", heard, logs.String())
	}
	if ua[0] != c.UserAgent {
		t.Fatalf("User-Agent %q", ua[0])
	}

	// Failures log at debug only.
	body = `not json`
	logs.Reset()
	if _, ok := c.Check(t.Context()); ok {
		t.Fatal("garbage reported")
	}
	if !strings.Contains(logs.String(), "level=DEBUG") || strings.Contains(logs.String(), "level=INFO") {
		t.Fatalf("logs: %s", logs.String())
	}
	c.Current = "0.3.0"
	c.told = ""
	body = `{"version":"0.2.2"}`
	if _, ok := c.Check(t.Context()); ok {
		t.Fatal("an older version reported")
	}
}
