package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// benchServer is a server on a real database file with synchronous=FULL, as in
// production, so fsyncs count.
func benchServer(b *testing.B) *Server {
	b.Helper()
	st, err := sqlite.Open(filepath.Join(b.TempDir(), "rerouted.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { st.Close() })
	key, err := serverkey.LoadOrCreate(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	cfg := &config.Config{Name: "chat.test", Handles: "chat.test", Registration: "invite", RegistrationCode: testRegCode}
	return New(cfg, key, slog.New(slog.NewTextHandler(io.Discard, nil)), st)
}

// benchIdentity stores a local identity whose chain has a genesis entry and `extra`
// more entries, each adding a device, and returns its ID.
func benchIdentity(b *testing.B, s *Server, name string, extra int) string {
	b.Helper()
	ctx := context.Background()
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	recPub, _, _ := ed25519.GenerateKey(rand.Reader)
	commit := sha256.Sum256(recPub)
	handle := name + ".chat.test"
	sig := func(body any) wire.Signed {
		s, err := wire.Sign("chain-entry", body, dev)
		if err != nil {
			b.Fatal(err)
		}
		return s
	}
	g := sig(map[string]any{"seq": 0, "ts": time.Now().Unix(), "ops": []any{
		map[string]any{"op": "add-device", "key": []byte(dev.Public().(ed25519.PublicKey)), "name": name + "'s laptop"},
		map[string]any{"op": "set-home", "home": "chat.test"},
		map[string]any{"op": "set-handle", "handle": handle},
		map[string]any{"op": "set-recovery", "next": commit[:]},
	}})
	enc, _ := g.Encode()
	st, err := decodeChain([][]byte{enc})
	if err != nil {
		b.Fatal(err)
	}
	if err := s.st.Chains().Create(ctx, st.ID, enc, handle); err != nil {
		b.Fatal(err)
	}
	prev := sha256.Sum256(enc)
	for i := range extra {
		k, _, _ := ed25519.GenerateKey(rand.Reader)
		e := sig(map[string]any{"id": st.ID, "seq": i + 1, "prev": prev[:], "ts": time.Now().Unix(), "ops": []any{
			map[string]any{"op": "add-device", "key": []byte(k), "name": fmt.Sprintf("device %d", i)},
		}})
		enc, _ := e.Encode()
		if err := s.st.Chains().Append(ctx, st.ID, uint64(i), enc); err != nil {
			b.Fatal(err)
		}
		prev = sha256.Sum256(enc)
	}
	if _, _, err := s.identity(ctx, st.ID); err != nil {
		b.Fatal("benchmark chain doesn't validate: ", err)
	}
	return st.ID
}

// One group message to a group of 25 members on this server (SPEC §10.3 caps groups at
// 25): the time from the sender's POST send storing it to the last member's copy.
func BenchmarkGroupDeliverLocal(b *testing.B) {
	s := benchServer(b)
	ctx := context.Background()
	group := randBytes(32)
	sender := benchIdentity(b, s, "sender", 3)
	to := []string{sender}
	for i := range 24 {
		id := benchIdentity(b, s, fmt.Sprintf("member%d", i), 3)
		if err := s.st.Contacts().AllowGroup(ctx, id, group); err != nil {
			b.Fatal(err)
		}
		to = append(to, id)
	}
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		s.limits.mu.Lock()
		s.limits.m = map[string][]int64{} // stay under the per-group rate limit
		s.limits.mu.Unlock()
		b.StartTimer()
		d := delivery{ID: randBytes(16), Kind: "mls", From: sender, To: to, Group: group, Epoch: 1, MLS: "app", Data: []byte("hello, group")}
		if err := s.deliver(ctx, d); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if items, _, _, err := s.st.Inbox().List(ctx, to[24], nil, "", 1); err != nil || len(items) == 0 {
		b.Fatal("the last member got nothing: ", err)
	}
}

// Loading and validating a local identity's chain, which sending does several times
// per recipient.
func BenchmarkIdentity(b *testing.B) {
	s := benchServer(b)
	id := benchIdentity(b, s, "kat", 5)
	ctx := context.Background()
	for b.Loop() {
		if _, _, err := s.identity(ctx, id); err != nil {
			b.Fatal(err)
		}
	}
}
