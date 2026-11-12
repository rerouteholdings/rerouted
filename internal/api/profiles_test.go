package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

func profile(t *testing.T, u *testUser, v int64, key ed25519.PrivateKey, extra map[string]any) wire.Raw {
	body := map[string]any{"id": u.id, "v": v, "ts": time.Now().Unix(), "name": "Kat"}
	for k, x := range extra {
		body[k] = x
	}
	return signed(t, "profile", body, key)
}

// SPEC §13.1: profiles are signed by a current device, versions only go up, and the limits hold.
func TestProfiles(t *testing.T) {
	ts := testServer(t)
	kat, bob := newUser(t, ts, "kat"), newUser(t, ts, "bob")
	post := func(p wire.Raw) int {
		return call(t, ts, "POST", "profile", kat.token, map[string]any{"profile": p}, nil)
	}
	if c := post(profile(t, kat, 1, kat.dev, nil)); c != 204 {
		t.Fatalf("publish: %d", c)
	}
	if c := post(profile(t, kat, 1, kat.dev, nil)); c != 409 {
		t.Fatalf("the same version again: %d, want 409", c)
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if c := post(profile(t, kat, 2, stranger, nil)); c != 403 {
		t.Fatalf("signed by a key that isn't her device: %d, want 403", c)
	}
	if c := post(profile(t, kat, 2, kat.dev, map[string]any{"name": strings.Repeat("k", 65)})); c != 400 {
		t.Fatalf("a 65-character name: %d, want 400", c)
	}
	if c := post(profile(t, kat, 2, kat.dev, map[string]any{"links": []string{"http://example.com"}})); c != 400 {
		t.Fatalf("a non-https link: %d, want 400", c)
	}
	if c := post(profile(t, kat, 2, kat.dev, map[string]any{"invite": "NotHerCode"})); c != 400 {
		t.Fatalf("an invite that isn't hers: %d, want 400", c)
	}
	if c := post(profile(t, kat, 2, kat.dev, map[string]any{"invite": kat.invite(true)})); c != 204 {
		t.Fatalf("with her public invite: %d", c)
	}
	var got struct {
		Profile wire.Raw `json:"profile"`
	}
	if c := call(t, ts, "GET", "profile/"+kat.id, bob.token, nil, &got); c != 200 {
		t.Fatalf("bob reads kat's profile: %d", c)
	}
	sig, _ := wire.DecodeSigned(got.Profile)
	if _, err := sig.VerifySelf("profile"); err != nil || !strings.Contains(sig.B, `"v":2`) {
		t.Fatalf("served profile: %s", sig.B)
	}
	if c := call(t, ts, "GET", "profile/"+bob.id, kat.token, nil, nil); c != 404 {
		t.Fatalf("no profile yet: %d, want 404", c)
	}
}

// Profiles cross servers through profile/fetch.
func TestRemoteProfile(t *testing.T) {
	a, b, _, _ := twoServers(t)
	kat, bob := newUserOn(t, a, "kat", "a.test"), newUserOn(t, b, "bob", "b.test")
	call(t, b, "POST", "profile", bob.token, map[string]any{"profile": profile(t, bob, 1, bob.dev, nil)}, nil)
	call(t, a, "GET", "resolve/bob.b.test", kat.token, nil, nil)
	if c := call(t, a, "GET", "profile/"+bob.id, kat.token, nil, nil); c != 200 {
		t.Fatalf("kat reads bob's profile across servers: %d", c)
	}
}

// SPEC §13.1: profile pictures are images, at most 1 MB, and a profile can only name one
// its identity uploaded.
func TestProfilePictures(t *testing.T) {
	ts := testServer(t)
	kat := newUser(t, ts, "kat")
	png := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 100)...)
	c, b := upload(t, ts, kat.token, "media/upload-public", "image/png", png)
	if c != 200 {
		t.Fatalf("upload: %d %s", c, b)
	}
	var res struct {
		Media map[string]any `json:"media"`
	}
	wire.Unmarshal(b, &res)
	if c := call(t, ts, "POST", "profile", kat.token, map[string]any{"profile": profile(t, kat, 1, kat.dev, map[string]any{"avatar": res.Media})}, nil); c != 204 {
		t.Fatalf("profile with the picture: %d", c)
	}
	if c, _ := upload(t, ts, kat.token, "media/upload-public", "image/png", []byte("not a png at all")); c != 400 {
		t.Fatalf("bytes that aren't a PNG: %d, want 400", c)
	}
	if c, _ := upload(t, ts, kat.token, "media/upload-public", "text/html", []byte("<script>")); c != 415 {
		t.Fatalf("an HTML 'picture': %d, want 415", c)
	}
	if c, _ := upload(t, ts, kat.token, "media/upload-public", "image/png", append(png, make([]byte, 1_000_000)...)); c != 413 {
		t.Fatalf("over 1 MB: %d, want 413", c)
	}
	id := res.Media["id"].(string)
	code, ctype, _ := download(t, ts, kat.token, "media/chat.test/"+id)
	if code != 200 || ctype != "image/png" {
		t.Fatalf("download: %d %s", code, ctype)
	}
}
