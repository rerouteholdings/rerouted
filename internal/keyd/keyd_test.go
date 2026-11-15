package keyd

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/fed"
	"github.com/rerouteholdings/rerouted/internal/ipc"
	"github.com/rerouteholdings/rerouted/internal/serverkey"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// serve starts an rerouted-keyd for keys on a new socket, answering its path.
func serve(t *testing.T, keys *Keys, uid int) (string, net.Listener) {
	t.Helper()
	// A short path: a unix socket's is limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "kd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&Server{Keys: keys, UID: uid, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Serve(l)
	return sock, l
}

func TestSignThroughKeyd(t *testing.T) {
	dir := t.TempDir()
	keys, err := LoadDir(dir, "chat.test", []string{"chat.test", "club.test"})
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := serve(t, keys, -1)
	k, err := Load(sock, "chat.test")
	if err != nil {
		t.Fatal(err)
	}
	// The same keys as the files, and the same invite code key, but none of them here.
	files, _ := serverkey.LoadOrCreate(dir)
	club, _ := serverkey.LoadOrCreateComposite(dir, serverkey.CommunityFile("club.test"))
	if k.Priv != nil || k.V2.Priv != nil || k.KID != files.KID || !k.Public().Equal(files.Public()) ||
		k.V2.KID != files.V2.KID || !k.V2.Public().Equal(files.V2.Public()) ||
		string(k.InviteKey) != string(files.InviteKey) || len(k.Communities) != 1 || k.Communities["club.test"].KID != club.KID {
		t.Fatalf("keys from rerouted-keyd differ from the files: %+v", k)
	}
	now := time.Now().Unix()
	s, err := k.SignKID("s2s", map[string]any{"from": "chat.test", "to": "b.test", "path": "/x", "ts": now})
	if err != nil || s.Verify("s2s", files.Public()) != nil || s.KID != files.KID {
		t.Fatalf("version 1 S2S request: %v", err)
	}
	s, err = k.V2.SignKID("commit-receipt", map[string]any{"hub": "chat.test", "ts": now})
	if err != nil || s.VerifyComposite("commit-receipt", files.V2.Public()) != nil || s.KID != files.V2.KID {
		t.Fatalf("version 2 receipt: %v", err)
	}
	s, err = k.Communities["club.test"].SignKID("community-move-reservation", map[string]any{"server": "club.test", "exp": now + 600})
	if err != nil || s.VerifyComposite("community-move-reservation", club.Public()) != nil {
		t.Fatalf("community reservation: %v", err)
	}
}

// rerouted-keyd signs only what a server signs with its own key, for itself, now.
func TestKeydRefuses(t *testing.T) {
	keys, err := LoadDir(t.TempDir(), "chat.test", []string{"club.test"})
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := serve(t, keys, -1)
	k, err := Load(sock, "chat.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	club := k.Communities["club.test"]
	for _, c := range []struct {
		name string
		sign func() (wire.Signed, error)
	}{
		{"another type", func() (wire.Signed, error) { return k.SignKID("chain-entry", map[string]any{"from": "chat.test"}) }},
		{"S2S from another server", func() (wire.Signed, error) {
			return k.SignKID("s2s", map[string]any{"from": "evil.test", "ts": now})
		}},
		{"S2S from the past", func() (wire.Signed, error) {
			return k.SignKID("s2s", map[string]any{"from": "chat.test", "ts": now - 3600})
		}},
		{"S2S from the future", func() (wire.Signed, error) {
			return k.V2.SignKID("s2s", map[string]any{"from": "chat.test", "ts": now + 3600})
		}},
		{"S2S as the homeserver with a community's key", func() (wire.Signed, error) {
			return club.SignKID("s2s", map[string]any{"from": "chat.test", "ts": now})
		}},
		{"a receipt from another hub", func() (wire.Signed, error) {
			return k.SignKID("commit-receipt", map[string]any{"hub": "evil.test", "ts": now})
		}},
		{"a reservation for another server", func() (wire.Signed, error) {
			return k.SignKID("move-reservation", map[string]any{"server": "evil.test", "exp": now + 600})
		}},
		{"a reservation for a day", func() (wire.Signed, error) {
			return k.SignKID("move-reservation", map[string]any{"server": "chat.test", "exp": now + 86400})
		}},
		{"a community reservation with a version 1 key", func() (wire.Signed, error) {
			return k.SignKID("community-move-reservation", map[string]any{"server": "chat.test", "exp": now + 600})
		}},
	} {
		if _, err := c.sign(); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Errorf("%s: %v, want refused", c.name, err)
		}
	}
	// Bytes that aren't canonical JSON, and a key it doesn't have, from a client that
	// doesn't go through serverkey.
	cl := k.Remote.(*Client)
	ts := strconv.FormatInt(now, 10)
	for _, b := range []string{`{"from":"chat.test", "ts":` + ts + `}`, `{"ts":` + ts + `,"from":"chat.test"}`, `{"from":"chat.test","from":"evil.test","ts":` + ts + `}`} {
		if _, err := cl.Sign(k.KID, "s2s", b); err == nil || !strings.Contains(err.Error(), "canonical") {
			t.Errorf("non-canonical %s: %v", b, err)
		}
	}
	if _, err := cl.Sign(k.KID, "s2s", `{"from":"chat.test","ts":`+ts+`}`); err != nil {
		t.Errorf("the canonical form: %v", err)
	}
	if _, err := cl.Sign("0000000000000000", "s2s", `{"from":"chat.test","ts":1}`); err == nil || !strings.Contains(err.Error(), "no key") {
		t.Errorf("unknown key: %v", err)
	}
}

// A client whose connections went stale, rerouted-keyd having restarted, makes new ones.
func TestKeydRestart(t *testing.T) {
	keys, err := LoadDir(t.TempDir(), "chat.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	sock, l := serve(t, keys, -1)
	k, err := Load(sock, "chat.test")
	if err != nil {
		t.Fatal(err)
	}
	body := func() any { return map[string]any{"from": "chat.test", "ts": time.Now().Unix()} }
	if _, err := k.SignKID("s2s", body()); err != nil {
		t.Fatal(err)
	}
	l.Close()
	// Close the connection the server side holds: a restarted rerouted-keyd has none.
	cl := k.Remote.(*Client)
	conn := <-cl.idle
	conn.Close()
	cl.idle <- conn
	if _, err := k.SignKID("s2s", body()); err == nil {
		t.Fatal("signed with rerouted-keyd down")
	}
	os.Remove(sock)
	l2, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	go (&Server{Keys: keys, UID: -1, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Serve(l2)
	if _, err := k.SignKID("s2s", body()); err != nil {
		t.Fatalf("after the restart: %v", err)
	}
}

// Only the allowed user may connect.
func TestKeydPeerUID(t *testing.T) {
	if !ipc.PeerCheckSupported {
		t.Skip("no SO_PEERCRED here")
	}
	keys, err := LoadDir(t.TempDir(), "chat.test", nil)
	if err != nil {
		t.Fatal(err)
	}
	sock, _ := serve(t, keys, os.Getuid()+1)
	if _, err := Load(sock, "chat.test"); err == nil {
		t.Fatal("another user's connection was served")
	}
	sock, _ = serve(t, keys, os.Getuid())
	if _, err := Load(sock, "chat.test"); err != nil {
		t.Fatalf("the allowed user: %v", err)
	}
}

func TestBundle(t *testing.T) {
	old := t.TempDir()
	if _, err := serverkey.LoadOrCreate(old); err != nil {
		t.Fatal(err)
	}
	if _, err := serverkey.LoadOrCreateComposite(old, serverkey.CommunityFile("gone.test")); err != nil {
		t.Fatal(err)
	}
	files, _ := serverkey.LoadOrCreate(old)
	// A data directory's keys are imported, and a missing community's key is made.
	b, done, err := MakeBundle(nil, []string{old}, "chat.test", []string{"club.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 2 || done[0] != filepath.Join(old, serverkey.FileV1) || done[1] != filepath.Join(old, serverkey.FileV2) {
		t.Fatalf("imported %v: the key of a community no longer configured must stay", done)
	}
	keys, err := LoadBundle(b, "chat.test", []string{"club.test"})
	if err != nil {
		t.Fatal(err)
	}
	if keys.pubs[0].KID != files.KID || keys.pubs[1].KID != files.V2.KID || keys.pubs[2].Name != "club.test" {
		t.Fatalf("bundle keys %+v", keys.pubs)
	}
	// Bundling again changes nothing; a new community gets a key, and the others are kept.
	again, done, err := MakeBundle(b, []string{old}, "chat.test", []string{"club.test"})
	if err != nil || string(again) != string(b) || len(done) != 2 {
		t.Fatalf("bundling again: %v, %d files", err, len(done))
	}
	more, _, err := MakeBundle(b, nil, "chat.test", []string{"club.test", "new.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(more, "chat.test", []string{"club.test", "new.test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(b, "chat.test", []string{"new.test"}); err == nil {
		t.Fatal("a bundle without a configured community's key loaded")
	}
	// A different key under the same name is never replaced.
	other := t.TempDir()
	serverkey.LoadOrCreate(other)
	if _, _, err := MakeBundle(b, []string{other}, "chat.test", nil); err == nil || !strings.Contains(err.Error(), "isn't the") {
		t.Fatalf("a conflicting key: %v", err)
	}
	// Unbundled, the keys are the same files again, and existing ones are kept.
	out := t.TempDir()
	if err := Unbundle(more, out); err != nil {
		t.Fatal(err)
	}
	back, err := serverkey.LoadOrCreate(out)
	if err != nil || back.KID != files.KID || back.V2.KID != files.V2.KID {
		t.Fatalf("unbundled keys: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, serverkey.CommunityFile("new.test"))); err != nil {
		t.Fatal(err)
	}
	if err := Unbundle(more, out); err == nil {
		t.Fatal("unbundle replaced existing files")
	}
}

// keyd doesn't import fed, to keep rerouted-keyd small, but the window must be the same.
func TestMaxSkewIsFeds(t *testing.T) {
	if maxSkew != fed.MaxSkew {
		t.Fatalf("maxSkew %d, fed.MaxSkew %d", maxSkew, fed.MaxSkew)
	}
}
