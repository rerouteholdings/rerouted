package api

import (
	"context"
	"testing"
	"time"
)

// SPEC §16.3: reports are kept, can be forwarded to the reported identity's server, and
// can't be sent in someone else's name.
func TestReports(t *testing.T) {
	a, b, _, sb := twoServers(t)
	kat, bob := newUserOn(t, a, "kat", "a.test"), newUserOn(t, b, "bob", "b.test")
	call(t, a, "GET", "resolve/bob.b.test", kat.token, nil, nil)
	report := map[string]any{"reporter": kat.id, "reported": bob.id, "reason": "spam"}
	if c := call(t, a, "POST", "report", kat.token, map[string]any{"report": report, "forward": true}, nil); c != 202 {
		t.Fatalf("report: %d", c)
	}
	for range 100 {
		if rs, _ := sb.st.Reports().List(context.Background(), 10); len(rs) == 1 {
			if rs[0].Origin != "a.test" || rs[0].Reporter != kat.id {
				t.Fatalf("forwarded report: %+v", rs[0])
			}
			goto forwarded
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the report never reached bob's server")
forwarded:
	report["reporter"] = bob.id
	if c := call(t, a, "POST", "report", kat.token, map[string]any{"report": report}, nil); c != 403 {
		t.Fatalf("a report in someone else's name: %d, want 403", c)
	}
}
