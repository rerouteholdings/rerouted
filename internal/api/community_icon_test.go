package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Community icons (SPEC §16.2.3, spec/api/community.md): upload, name in set-name, fetch
// without a session, the preview, and retention.
func TestCommunityIcon(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat, ravi := e.user("kat"), e.user("ravi")
	m := kat.create("chat.test", false)
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{7}, 200)...)
	sum := sha256.Sum256(png)
	h64 := base64.RawURLEncoding.EncodeToString(sum[:])

	// Upload: administrate, a known type, the right magic, at most 256 KiB.
	if c, _ := e.do("POST", "icon/upload", "", "image/png", png, nil); c != 401 {
		t.Fatalf("anonymous upload: %d", c)
	}
	if c, _ := e.do("POST", "icon/upload", ravi.tok, "image/png", png, nil); c != 403 {
		t.Fatalf("a non-member's upload: %d", c)
	}
	if c, _ := e.do("POST", "icon/upload", kat.tok, "image/gif", []byte("GIF89a"), nil); c != 400 {
		t.Fatalf("a gif: %d", c)
	}
	if c, _ := e.do("POST", "icon/upload", kat.tok, "image/webp", png, nil); c != 400 {
		t.Fatalf("png bytes as webp: %d", c)
	}
	big := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, cchain.MaxIconSize)...)
	if c, b := e.do("POST", "icon/upload", kat.tok, "image/png", big, nil); c != 413 || !strings.Contains(string(b), wire.ErrCodeTooLarge) {
		t.Fatalf("over 256 KiB: %d %s", c, b)
	}
	var up struct {
		Hash wire.Bytes `json:"hash"`
	}
	if c, _ := e.do("POST", "icon/upload", kat.tok, "image/png", png, &up); c != 200 || !bytes.Equal(up.Hash, sum[:]) {
		t.Fatalf("upload: %d %x", c, up.Hash)
	}
	// Not served until the state names it.
	if c, _ := e.do("GET", "icon/"+h64, "", "", nil, nil); c != 404 {
		t.Fatalf("an unnamed icon was served: %d", c)
	}
	icon := map[string]any{"mime": "image/png", "hash": sum[:], "size": len(png)}
	kat.mustAppend(m.ch, map[string]any{"op": "set-name", "name": "Night shift", "icon": icon})
	c, b := e.do("GET", "icon/"+h64, "", "", nil, nil)
	if c != 200 || !bytes.Equal(b, png) {
		t.Fatalf("GET icon: %d", c)
	}
	if c, _ := e.do("GET", "icon/"+base64.RawURLEncoding.EncodeToString(randB(32)), "", "", nil, nil); c != 404 {
		t.Fatalf("another hash: %d", c)
	}
	var pv struct {
		Icon *struct {
			Mime string     `json:"mime"`
			Hash wire.Bytes `json:"hash"`
			Size int        `json:"size"`
		} `json:"icon"`
	}
	if c := e.call("GET", "preview", "", nil, &pv); c != 200 || pv.Icon == nil || pv.Icon.Mime != "image/png" || pv.Icon.Size != len(png) || !bytes.Equal(pv.Icon.Hash, sum[:]) {
		t.Fatalf("preview: %d %+v", c, pv.Icon)
	}
	// A bad icon in set-name is refused by the chain rules.
	if c, code := kat.appendOps(m.ch, map[string]any{"op": "set-name", "name": "x", "icon": map[string]any{"mime": "image/gif", "hash": sum[:], "size": 5}}); c != 400 || code != wire.ErrCodeBadRequest {
		t.Fatalf("a gif icon: %d %s", c, code)
	}

	// Retention: past 24 hours, only the named icon stays.
	webp := append([]byte("RIFF\x10\x00\x00\x00WEBPVP8 "), bytes.Repeat([]byte{1}, 50)...)
	if c, _ := e.do("POST", "icon/upload", kat.tok, "image/webp", webp, &up); c != 200 {
		t.Fatalf("webp upload: %d", c)
	}
	other := up.Hash
	ctx := context.Background()
	cs := e.st.Communities()
	if n, err := cs.PruneIcons(ctx, "chat.test", sum[:], now()+iconKeep+1); err != nil || n != 1 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if _, _, err := cs.Icon(ctx, "chat.test", other); err == nil {
		t.Fatal("the unnamed icon outlived 24 hours")
	}
	if _, _, err := cs.Icon(ctx, "chat.test", sum[:]); err != nil {
		t.Fatalf("the named icon was pruned: %v", err)
	}
	// Removing it: a set-name without icon.
	kat.mustAppend(m.ch, map[string]any{"op": "set-name", "name": "Night shift"})
	if c, _ := e.do("GET", "icon/"+h64, "", "", nil, nil); c != 404 {
		t.Fatalf("a removed icon was served: %d", c)
	}
	pv.Icon = nil
	if c := e.call("GET", "preview", "", nil, &pv); c != 200 || pv.Icon != nil {
		t.Fatalf("preview after removal: %d %+v", c, pv.Icon)
	}
}
