package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// SPEC §17.3: reports are kept, can be forwarded to the reported identity's server, and
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

// evidence2 is one item of a version 2 report's evidence (SPEC §17.3): an app-message signed
// by the sender's message key, and the msg-key that certifies it.
func evidence2(t *testing.T, u *v2User) map[string]any {
	t.Helper()
	mkPub, mkPriv, _ := ed25519.GenerateKey(rand.Reader)
	mk := signed2(t, wire.TypeMsgKey, map[string]any{"id": u.id, "dev": u.dev.Public().Hash(), "key": []byte(mkPub), "n": 1}, u.dev)
	body, _ := wire.Marshal(map[string]any{"group": randBytes(32), "ts": time.Now().Unix(), "content": map[string]any{"type": "text", "body": "buy my thing"}})
	in, _ := wire.SigInputV2("app-message", string(body))
	msg, _ := wire.Signed{T: "app-message", B: string(body), K: wire.Bytes(mkPub), S: ed25519.Sign(mkPriv, in)}.Encode()
	return map[string]any{"msg": wire.Raw(msg), "mk": mk, "delivery": randBytes(16), "blob": randBytes(32)}
}

// SPEC §17.3: a version 2 report, with its evidence, kept and forwarded through version 2
// S2S report.
func TestV2Reports(t *testing.T) {
	a, b, sa, sb := twoServers(t)
	kat := newV2User(t, a, "kat", "a.test")
	ravi := newV2User(t, b, "ravi", "b.test")
	call2(t, a, "GET", "resolve/ravi.b.test", kat.token, nil, nil)
	report := map[string]any{"reporter": kat.id, "reported": ravi.id, "reason": "spam", "evidence": []any{evidence2(t, ravi)}}
	if c := call2(t, a, "POST", "report", kat.token, map[string]any{"report": report, "forward": true}, nil); c != 202 {
		t.Fatalf("report: %d", c)
	}
	if rs, _ := sa.st.Reports().List(context.Background(), 10); len(rs) != 1 || rs[0].Reported != ravi.id {
		t.Fatalf("kept at a.test: %+v", rs)
	}
	for range 100 {
		if rs, _ := sb.st.Reports().List(context.Background(), 10); len(rs) == 1 {
			if rs[0].Origin != "a.test" || rs[0].Reporter != kat.id || !strings.Contains(string(rs[0].Body), `"mk"`) {
				t.Fatalf("forwarded report: %+v", rs[0])
			}
			goto forwarded
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the report never reached ravi's server")
forwarded:
	report["reporter"] = ravi.id
	if c := call2(t, a, "POST", "report", kat.token, map[string]any{"report": report}, nil); c != 403 {
		t.Fatalf("a report in someone else's name: %d", c)
	}
	// Evidence has version 2's shape: a signed app-message and its msg-key.
	report["reporter"] = kat.id
	for name, ev := range map[string]any{
		"no mk":         map[string]any{"msg": evidence2(t, ravi)["msg"]},
		"not signed":    map[string]any{"msg": "hello", "mk": evidence2(t, ravi)["mk"]},
		"swapped":       map[string]any{"msg": evidence2(t, ravi)["mk"], "mk": evidence2(t, ravi)["msg"]},
		"short blob":    map[string]any{"msg": evidence2(t, ravi)["msg"], "mk": evidence2(t, ravi)["mk"], "blob": randBytes(8)},
		"not an object": "a screenshot",
	} {
		report["evidence"] = []any{ev}
		var e wire.Error
		if c := call2(t, a, "POST", "report", kat.token, map[string]any{"report": report}, &e); c != 400 || e.Code != wire.ErrCodeBadRequest {
			t.Errorf("%s: %d %+v", name, c, e)
		}
	}
	report["evidence"] = []any{}
	if c := call2(t, a, "POST", "report", kat.token, map[string]any{"report": report}, nil); c != 202 {
		t.Fatalf("a report without evidence: %d", c)
	}
	// The receiving homeserver checks a forwarded report's reason too: 2,000 code points
	// pass, 2,001 don't.
	for n, want := range map[int]int{2000: 0, 2001: 400} {
		report["reason"] = strings.Repeat("é", n)
		body, _ := wire.Marshal(map[string]any{"report": report})
		_, err := sa.V2().fed.Call(context.Background(), "b.test", "report", body)
		var st *fed.ErrStatus
		if want == 0 && err != nil || want != 0 && (!errors.As(err, &st) || st.Status != want || st.Code != wire.ErrCodeBadRequest) {
			t.Errorf("forwarded reason of %d characters: %v", n, err)
		}
	}
}
