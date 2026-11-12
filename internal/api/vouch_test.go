package api

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// threeServers starts a.test, b.test, and c.test, federating over http (dev mode).
func threeServers(t *testing.T) (ts map[string]*httptest.Server, srv map[string]*Server) {
	t.Helper()
	ts, srv = map[string]*httptest.Server{}, map[string]*Server{}
	peers := map[string]string{}
	for _, n := range []string{"a.test", "b.test", "c.test"} {
		ts[n] = httptest.NewUnstartedServer(nil)
		peers[n] = "http://" + ts[n].Listener.Addr().String()
	}
	for n, h := range ts {
		key, _ := serverkey.LoadOrCreate(t.TempDir())
		cfg := &config.Config{Name: n, PublicURL: peers[n], Handles: n, Registration: "invite", RegistrationCode: testRegCode, Dev: true, Peers: peers}
		s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), newStore(t))
		h.Config.Handler = s.Handler()
		h.Start()
		t.Cleanup(h.Close)
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go s.RunOutbox(ctx)
		srv[n] = s
	}
	return
}

// chainOf returns a local identity's entries as its home stores them.
func chainOf(t *testing.T, s *Server, id string) [][]byte {
	t.Helper()
	raw, err := s.st.Chains().Entries(context.Background(), id, -1)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// nextEntry signs the entry after `raw` with `key`, dated `ts`.
func nextEntry(t *testing.T, id string, raw [][]byte, ts int64, key ed25519.PrivateKey, ops ...map[string]any) []byte {
	t.Helper()
	last, _ := wire.DecodeSigned(raw[len(raw)-1])
	head, _ := last.Hash()
	opsAny := make([]any, len(ops))
	for i, o := range ops {
		opsAny[i] = o
	}
	return signed(t, "chain-entry", map[string]any{"id": id, "seq": len(raw), "prev": head, "ts": ts, "ops": opsAny}, key)
}

func push(t *testing.T, from *Server, to, id string, raw [][]byte) {
	t.Helper()
	entries := make([]wire.Raw, len(raw))
	for i, e := range raw {
		entries[i] = e
	}
	body, _ := wire.Marshal(map[string]any{"id": id, "entries": entries})
	from.fed.Call(context.Background(), to, "identity/push", body) // refusals are the point
}

func cachedLen(t *testing.T, s *Server, id string) (int, string) {
	t.Helper()
	home, raw, err := s.st.Remote().Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return len(raw), home
}

// SPEC §6.5: a device-signed entry counts only if the home before it appended it.
func TestChainEntriesNeedTheirHome(t *testing.T) {
	ts, srv := threeServers(t)
	kat := newUserOn(t, ts["a.test"], "kat", "a.test")
	bob := newUserOn(t, ts["b.test"], "bob", "b.test")
	// Kat asks Bob, so b.test caches her chain.
	call(t, ts["a.test"], "GET", "resolve/bob.b.test", kat.token, nil, nil)
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	call(t, ts["a.test"], "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil)
	bob.eventually(1)
	n0, home := cachedLen(t, srv["b.test"], kat.id)
	if home != "a.test" {
		t.Fatalf("cached home %q", home)
	}

	// A thief with Kat's device key signs a move to c.test, backdated to just after her
	// last entry, and has c.test push it straight to Bob's server. a.test never sees it.
	raw := chainOf(t, srv["a.test"], kat.id)
	// Backdated as far as the chain allows: the genesis ts.
	g, _ := wire.DecodeSigned(raw[0])
	var gb struct {
		TS int64 `json:"ts"`
	}
	g.Open(&gb)
	theft := nextEntry(t, kat.id, raw, gb.TS, kat.dev, map[string]any{"op": "set-home", "home": "c.test"})
	push(t, srv["c.test"], "b.test", kat.id, append(append([][]byte{}, raw...), theft))
	if n, home := cachedLen(t, srv["b.test"], kat.id); n != n0 || home != "a.test" {
		t.Fatalf("b.test took the thief's move: %d entries, home %q", n, home)
	}

	// An entry a.test really appended is accepted even when another server relays it:
	// b.test confirms it with a.test.
	_, dev2, _ := ed25519.GenerateKey(nil)
	add := nextEntry(t, kat.id, raw, time.Now().Unix(), kat.dev, map[string]any{"op": "add-device", "key": []byte(dev2.Public().(ed25519.PublicKey)), "name": "desktop"})
	var e wire.Error
	if c := call(t, ts["a.test"], "POST", "chain/append", kat.token, map[string]any{"entry": wire.Raw(add)}, &e); c != 200 {
		t.Fatalf("append: %d %v", c, e)
	}
	push(t, srv["c.test"], "b.test", kat.id, chainOf(t, srv["a.test"], kat.id))
	if n, _ := cachedLen(t, srv["b.test"], kat.id); n != n0+1 {
		t.Fatalf("a confirmed entry relayed by c.test wasn't taken: %d entries", n)
	}

	// A recovery-signed move counts from anywhere (SPEC §6.6): that's how you leave a
	// dead or hostile home.
	raw = chainOf(t, srv["a.test"], kat.id)
	nextRecPub, _, _ := ed25519.GenerateKey(nil)
	commit := sha256Sum(nextRecPub)
	move := nextEntry(t, kat.id, raw, time.Now().Unix(), kat.rec,
		map[string]any{"op": "set-home", "home": "c.test"},
		map[string]any{"op": "set-recovery", "next": commit})
	push(t, srv["c.test"], "b.test", kat.id, append(append([][]byte{}, raw...), move))
	if n, home := cachedLen(t, srv["b.test"], kat.id); n != n0+2 || home != "c.test" {
		t.Fatalf("recovery-signed move from c.test: %d entries, home %q", n, home)
	}
}

// SPEC §6.6: deliveries from the previous home count for 72 hours after a move.
func TestGraceWindow(t *testing.T) {
	_, dev, _ := ed25519.GenerateKey(nil)
	recPub, _, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	genesis := signed(t, "chain-entry", map[string]any{"seq": 0, "ts": now - 100*3600, "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey))},
		map[string]any{"op": "set-home", "home": "a.test"},
		map[string]any{"op": "set-handle", "handle": "kat.a.test"},
		map[string]any{"op": "set-recovery", "next": sha256Sum(recPub)},
	}}, dev)
	g, _ := wire.DecodeSigned(genesis)
	enc, _ := g.Encode()
	id := wire.IdentityID(enc)
	raw := [][]byte{genesis}
	for _, c := range []struct {
		movedAgo int64
		oldOK    bool
	}{{3600, true}, {71 * 3600, true}, {73 * 3600, false}} {
		chain := append(append([][]byte{}, raw...), nextEntry(t, id, raw, now-c.movedAgo, dev, map[string]any{"op": "set-home", "home": "b.test"}))
		if !fromHome(chain, "b.test", now, true) {
			t.Fatal("the new home must count")
		}
		if got := fromHome(chain, "a.test", now, true); got != c.oldOK {
			t.Errorf("moved %dh ago: old home counts = %v, want %v", c.movedAgo/3600, got, c.oldOK)
		}
	}
}

func sha256Sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// SPEC §6.5: on a first fetch, a device-signed move is confirmed with the home before it.
func TestFirstFetchChecksMoves(t *testing.T) {
	ts, srv := threeServers(t)
	ctx := context.Background()
	kat := newUserOn(t, ts["a.test"], "kat", "a.test")
	raw := chainOf(t, srv["a.test"], kat.id)
	g, _ := wire.DecodeSigned(raw[0])
	var gb struct {
		TS int64 `json:"ts"`
	}
	g.Open(&gb)
	// The thief's server holds Kat's chain plus a backdated move to itself, made behind a.test's back.
	theft := nextEntry(t, kat.id, raw, gb.TS, kat.dev, map[string]any{"op": "set-home", "home": "c.test"})
	cs := srv["c.test"].st.Chains()
	if err := cs.Create(ctx, kat.id, raw[0], "kat.a.test"); err != nil {
		t.Fatal(err)
	}
	if err := cs.Append(ctx, kat.id, 0, theft); err != nil {
		t.Fatal(err)
	}
	// b.test has never seen Kat. a.test answers, and doesn't know the move: refused.
	if _, _, err := srv["b.test"].fetchRemote(ctx, kat.id, "c.test", false); err == nil {
		t.Fatal("b.test took a move that Kat's home never appended")
	}
	// With a.test unreachable, there's nobody to confirm it, and that isn't a yes:
	// still refused. A home gone for good means the move needs the recovery code.
	ts["a.test"].Close()
	if _, _, err := srv["b.test"].fetchRemote(ctx, kat.id, "c.test", false); err == nil {
		t.Fatal("with the old home unreachable, b.test took the unconfirmed move")
	}
}

// SPEC §6.5, §6.6, §10.2: Kat moves a.test → c.test, Bob's server misses the push, and a.test
// dies. Bob's server can't confirm the move, says wrong-home, and accepts it once a
// recovery-signed entry vouches for everything before it.
func TestDeadOldHomeRecoveredByRecoveryCode(t *testing.T) {
	ts, srv := threeServers(t)
	ctx := context.Background()
	kat := newUserOn(t, ts["a.test"], "kat", "a.test")
	bob := newUserOn(t, ts["b.test"], "bob", "b.test")
	call(t, ts["a.test"], "GET", "resolve/bob.b.test", kat.token, nil, nil)
	req := signed(t, "contact-request", map[string]any{"from": kat.id, "to": bob.id, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": bob.invite(false)}, kat.dev)
	call(t, ts["a.test"], "POST", "contacts/request", kat.token, map[string]any{"request": req}, nil)
	bob.eventually(1)

	// The move, appended on a.test, but b.test never hears of it. c.test has the chain.
	raw := chainOf(t, srv["a.test"], kat.id)
	move := nextEntry(t, kat.id, raw, time.Now().Unix(), kat.dev, map[string]any{"op": "set-home", "home": "c.test"})
	if err := srv["a.test"].st.Chains().Append(ctx, kat.id, 0, move); err != nil {
		t.Fatal(err)
	}
	raw = chainOf(t, srv["a.test"], kat.id)
	cs := srv["c.test"].st.Chains()
	cs.Create(ctx, kat.id, raw[0], "kat.a.test")
	cs.Append(ctx, kat.id, 0, raw[1])
	ts["a.test"].Close() // a.test is gone for good

	deliver := func() error {
		body, _ := wire.Marshal(map[string]any{"deliveries": []delivery{{ID: randBytes(16), Kind: "mls", From: kat.id, To: []string{bob.id}, Group: randBytes(32), Epoch: 1, MLS: "app", Data: []byte("hi")}}})
		_, err := srv["c.test"].fed.Call(ctx, "b.test", "deliver", body)
		return err
	}
	// b.test can't confirm the move with a dead a.test: it refuses, and says why.
	var es *fed.ErrStatus
	if err := deliver(); !errors.As(err, &es) || es.Code != wire.ErrCodeWrongHome {
		t.Fatalf("delivery before the re-sign: %v, want wrong-home", err)
	}
	// Kat appends a recovery-signed entry on c.test: it vouches for the move.
	nextRec, _, _ := ed25519.GenerateKey(nil)
	resign := nextEntry(t, kat.id, raw, time.Now().Unix(), kat.rec, map[string]any{"op": "set-recovery", "next": sha256Sum(nextRec)})
	if err := cs.Append(ctx, kat.id, 1, resign); err != nil {
		t.Fatal(err)
	}
	push(t, srv["c.test"], "b.test", kat.id, chainOf(t, srv["c.test"], kat.id))
	if n, home := cachedLen(t, srv["b.test"], kat.id); n != 3 || home != "c.test" {
		t.Fatalf("after the recovery re-sign: %d entries, home %q", n, home)
	}
	if err := deliver(); err != nil {
		t.Fatalf("delivery after the re-sign: %v", err)
	}
}

// SPEC §6.5: on a first fetch, a previous home that answers 404 (it doesn't know the
// identity, or has forgotten it) is skipped, like an unreachable one.
func TestFirstFetchSkips404(t *testing.T) {
	_, srv := threeServers(t)
	ctx := context.Background()
	// A chain whose genesis says a.test, which has never heard of it, then a device-signed move to c.test.
	_, dev, _ := ed25519.GenerateKey(nil)
	recPub, _, _ := ed25519.GenerateKey(nil)
	genesis := signed(t, "chain-entry", map[string]any{"seq": 0, "ts": time.Now().Unix() - 3600, "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey))},
		map[string]any{"op": "set-home", "home": "a.test"},
		map[string]any{"op": "set-handle", "handle": "old.a.test"},
		map[string]any{"op": "set-recovery", "next": sha256Sum(recPub)},
	}}, dev)
	g, _ := wire.DecodeSigned(genesis)
	enc, _ := g.Encode()
	id := wire.IdentityID(enc)
	move := nextEntry(t, id, [][]byte{genesis}, time.Now().Unix(), dev, map[string]any{"op": "set-home", "home": "c.test"})
	cs := srv["c.test"].st.Chains()
	cs.Create(ctx, id, genesis, "old.a.test")
	cs.Append(ctx, id, 0, move)
	if st, _, err := srv["b.test"].fetchRemote(ctx, id, "c.test", false); err != nil || st.Home != "c.test" {
		t.Fatalf("a 404 from the old home should be skipped: %v", err)
	}
}

// spec/vectors/vouch.json through the real acceptance path (SPEC §6.5).
func TestVectorVouch(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/vouch.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ID    string `json:"identity_id"`
		Cases []struct {
			Name      string          `json:"name"`
			Cached    []string        `json:"cached"`
			Candidate []string        `json:"candidate"`
			From      string          `json:"from"`
			Previous  json.RawMessage `json:"previous_home"`
			Accepted  json.RawMessage `json:"accepted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	bytesOf := func(xs []string) [][]byte {
		out := make([][]byte, len(xs))
		for i, x := range xs {
			out[i] = []byte(x)
		}
		return out
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			key, _ := serverkey.LoadOrCreate(t.TempDir())
			cfg := &config.Config{Name: "b.example", Handles: "b.example", Registration: "closed"}
			s := New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), newStore(t))
			var prev struct {
				Server  string          `json:"server"`
				Answers json.RawMessage `json:"answers"`
			}
			json.Unmarshal(c.Previous, &prev)
			s.homeAsker = func(_ context.Context, home, _ string) ([][]byte, error) {
				if home != prev.Server {
					return nil, errors.New("unexpected home " + home)
				}
				var word string
				if json.Unmarshal(prev.Answers, &word) == nil {
					if word == "404" {
						return nil, &fed.ErrStatus{Status: 404, Code: "not-found"}
					}
					return nil, errors.New("unreachable")
				}
				var ch struct {
					Chain []string `json:"chain"`
				}
				json.Unmarshal(prev.Answers, &ch)
				return bytesOf(ch.Chain), nil
			}
			ctx := context.Background()
			if c.Cached != nil {
				s.st.Remote().Put(ctx, v.ID, "a.example", bytesOf(c.Cached))
			}
			_, got, _, err := s.acceptChain(ctx, v.ID, bytesOf(c.Candidate), c.From)
			var want int
			if json.Unmarshal(c.Accepted, &want) != nil { // "reject"
				if err == nil {
					t.Fatalf("accepted %d entries, want a rejection", len(got))
				}
				return
			}
			if err != nil || len(got) != want {
				t.Fatalf("accepted %d entries (err %v), want %d", len(got), err, want)
			}
		})
	}
}

// spec/api/s2s-stage2.md: a server that doesn't host an identity may answer identity/fetch
// from its cache, marked "cached", so group members on servers that never met can find
// each other. A cached answer is only a pointer: it never vouches for a move (SPEC §6.5).
func TestCachedFetchDoesntVouch(t *testing.T) {
	a, _, sa, sb := twoServers(t)
	kat := newUserOn(t, a, "kat", "a.test")
	ctx := context.Background()
	if _, _, err := sb.lookup(ctx, kat.id, "a.test"); err != nil {
		t.Fatalf("b.test caches kat: %v", err)
	}
	raw, cached, err := sa.fetchChain(ctx, "b.test", kat.id)
	if err != nil || !cached || len(raw) == 0 {
		t.Fatalf("b.test's answer for kat: %d entries, cached %v, %v", len(raw), cached, err)
	}
	var st *fed.ErrStatus
	if _, err := sa.askHome(ctx, "b.test", kat.id); !errors.As(err, &st) || st.Status != 404 {
		t.Fatalf("a cached answer counted as the home's: %v", err)
	}
	if _, cached, err := sb.fetchChain(ctx, "a.test", kat.id); err != nil || cached {
		t.Fatalf("kat's real home: cached %v, %v", cached, err)
	}
}
