package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/cchain"
	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// emojiUp uploads an emoji blob and returns its ID.
func (u *cmUser) emojiUp(data []byte) []byte {
	u.t.Helper()
	var up struct {
		ID     wire.Bytes `json:"id"`
		SHA256 wire.Bytes `json:"sha256"`
		Size   int64      `json:"size"`
	}
	if c, b := u.e.do("POST", "emoji/upload", u.tok, "application/octet-stream", data, &up); c != 200 || len(up.ID) != 16 || !bytes.Equal(up.SHA256, sha256Of(data)) || up.Size != int64(len(data)) {
		u.t.Fatalf("emoji/upload: %d %s", c, b)
	}
	return up.ID
}

// emojiBody is a community-emoji body for blob data uploaded as id.
func (u *cmUser) emojiBody(m *made, id, data []byte) map[string]any {
	return map[string]any{"community": m.ch.id, "blob": id, "sha256": sha256Of(data), "size": len(data) - 16,
		"head": m.ch.head, "ts": time.Now().Unix(), "by": u.id, "emoji": sealed()}
}

func (u *cmUser) emojiPut(rec wire.Raw) (int, string) {
	u.t.Helper()
	return u.e.errOf("POST", "emoji/put", u.tok, map[string]any{"emoji": rec})
}

func (e *cmEnv) emojiList(tok string) []wire.Raw {
	e.t.Helper()
	var res struct {
		Items []wire.Raw `json:"items"`
	}
	if c := e.call("GET", "emoji", tok, nil, &res); c != 200 {
		e.t.Fatalf("GET emoji: %d", c)
	}
	return res.Items
}

func (e *cmEnv) emojiGet(id []byte) (int, []byte) {
	e.t.Helper()
	return e.do("GET", "emoji/"+base64.RawURLEncoding.EncodeToString(id), "", "", nil, nil)
}

// Custom emoji on the community server (SPEC §16.9, spec/api/community.md): uploads and
// records from members with administrate, the list for members, and blobs for anyone, but
// only emoji blobs.
func TestCommunityEmoji(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi := e.user("ravi")
	kat, m := joined(t, e, ravi)
	png := append([]byte("ciphertext of a png"), make([]byte, 16)...)

	// Uploads: administrate, raw bytes, 17 to 262,160 of them.
	if c, _ := e.do("POST", "emoji/upload", "", "application/octet-stream", png, nil); c != 401 {
		t.Fatalf("anonymous upload: %d", c)
	}
	if c, _ := e.do("POST", "emoji/upload", ravi.tok, "application/octet-stream", png, nil); c != 403 {
		t.Fatalf("a member without administrate: %d", c)
	}
	if c, _ := e.do("POST", "emoji/upload", kat.tok, "image/png", png, nil); c != 415 {
		t.Fatalf("image/png: %d", c)
	}
	if c, _ := e.do("POST", "emoji/upload", kat.tok, "application/octet-stream", make([]byte, maxEmojiBlob+1), nil); c != 413 {
		t.Fatalf("over the cap: %d", c)
	}
	if c, _ := e.do("POST", "emoji/upload", kat.tok, "application/octet-stream", make([]byte, 16), nil); c != 400 {
		t.Fatalf("only a tag: %d", c)
	}
	id := kat.emojiUp(png)

	// Not served, or listed, until a record names it.
	if c, _ := e.emojiGet(id); c != 404 {
		t.Fatalf("an unnamed upload was served: %d", c)
	}
	body := kat.emojiBody(m, id, png)
	if c, code := ravi.emojiPut(signed2(t, "community-emoji", body, ravi.dev)); c != 403 {
		t.Fatalf("a put without administrate: %d %s", c, code)
	}

	// Refusals, in the order the server checks.
	bad := func(name string, status int, code string, change func(b map[string]any), sign func(b map[string]any) wire.Raw) {
		t.Helper()
		b := kat.emojiBody(m, id, png)
		change(b)
		rec := signed2(t, "community-emoji", b, kat.dev)
		if sign != nil {
			rec = sign(b)
		}
		if c, cd := kat.emojiPut(rec); c != status || cd != code {
			t.Fatalf("%s: %d %s, want %d %s", name, c, cd, status, code)
		}
	}
	none := func(map[string]any) {}
	bad("an unknown member", 400, wire.ErrCodeBadRequest, func(b map[string]any) { b["name"] = "party" }, nil)
	bad("size 0", 400, wire.ErrCodeBadRequest, func(b map[string]any) { b["size"] = 0 }, nil)
	bad("another type", 400, wire.ErrCodeBadRequest, none, func(b map[string]any) wire.Raw { return signed2(t, "community-entry", b, kat.dev) })
	bad("another community", 400, wire.ErrCodeBadRequest, func(b map[string]any) { b["community"] = randB(32) }, nil)
	bad("by someone else", 403, wire.ErrCodeNotAllowed, func(b map[string]any) { b["by"] = ravi.id }, nil)
	bad("a key that isn't kat's device", 403, wire.ErrCodeNotAllowed, none, func(b map[string]any) wire.Raw { return signed2(t, "community-emoji", b, newComposite(t)) })
	bad("a bad signature", 400, wire.ErrCodeBadSignature, none, func(b map[string]any) wire.Raw {
		s, _ := wire.SignComposite("community-emoji", b, kat.dev)
		s.S[10] ^= 1
		enc, _ := s.Encode()
		return enc
	})
	bad("a skewed ts", 400, wire.ErrCodeClockSkew, func(b map[string]any) { b["ts"] = time.Now().Unix() - 3600 }, nil)
	bad("an unknown head", 400, wire.ErrCodeBadRequest, func(b map[string]any) { b["head"] = randB(32) }, nil)
	bad("an unknown blob", 404, wire.ErrCodeNotFound, func(b map[string]any) { b["blob"] = randB(16) }, nil)
	bad("a wrong size", 400, wire.ErrCodeBadRequest, func(b map[string]any) { b["size"] = len(png) }, nil)
	bad("a wrong hash", 400, wire.ErrCodeBadRequest, func(b map[string]any) { b["sha256"] = randB(32) }, nil)

	// A channel file is never an emoji.
	var file struct {
		ID wire.Bytes `json:"id"`
	}
	if c, _ := e.do("POST", "media/upload", kat.tok, "application/octet-stream", png, &file); c != 200 {
		t.Fatalf("media/upload: %d", c)
	}
	bad("a channel file", 404, wire.ErrCodeNotFound, func(b map[string]any) { b["blob"] = []byte(file.ID) }, nil)
	if c, _ := e.emojiGet(file.ID); c != 404 {
		t.Fatalf("a channel file was served as an emoji: %d", c)
	}

	// A good record, on an older head too.
	oldHead := m.ch.head
	kat.mustAppend(m.ch, map[string]any{"op": "set-name", "name": "Night shift"})
	body = kat.emojiBody(m, id, png)
	body["head"] = oldHead
	first := signed2(t, "community-emoji", body, kat.dev)
	if c, cd := kat.emojiPut(first); c != 204 {
		t.Fatalf("put: %d %s", c, cd)
	}
	if c, b := e.emojiGet(id); c != 200 || !bytes.Equal(b, png) {
		t.Fatalf("anonymous GET emoji/{id}: %d", c)
	}
	resp := e.raw("GET", "emoji/"+base64.RawURLEncoding.EncodeToString(id), "")
	resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/octet-stream" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", resp.Header)
	}

	// The list: members only, in the order first named; a re-put replaces in place.
	gif := append([]byte("ciphertext of a gif"), make([]byte, 16)...)
	id2 := kat.emojiUp(gif)
	if c, cd := kat.emojiPut(signed2(t, "community-emoji", kat.emojiBody(m, id2, gif), kat.dev)); c != 204 {
		t.Fatalf("second put: %d %s", c, cd)
	}
	renamed := signed2(t, "community-emoji", kat.emojiBody(m, id, png), kat.dev)
	if c, cd := kat.emojiPut(renamed); c != 204 {
		t.Fatalf("re-put: %d %s", c, cd)
	}
	list := e.emojiList(ravi.tok)
	if len(list) != 2 || !bytes.Equal(list[0], renamed) {
		t.Fatalf("the list: %d items", len(list))
	}
	stranger := e.user("sam")
	if c, _ := e.errOf("GET", "emoji", stranger.tok, nil); c != 403 {
		t.Fatalf("a non-member listed emoji: %d", c)
	}

	// The limit: a new emoji past it is refused, a re-put isn't.
	defer func(n int) { maxEmoji = n }(maxEmoji)
	maxEmoji = 2
	webp := append([]byte("ciphertext of a webp"), make([]byte, 16)...)
	id3 := kat.emojiUp(webp)
	if c, cd := kat.emojiPut(signed2(t, "community-emoji", kat.emojiBody(m, id3, webp), kat.dev)); c != 403 || cd != wire.ErrCodeNotAllowed {
		t.Fatalf("past the limit: %d %s", c, cd)
	}
	if c, cd := kat.emojiPut(signed2(t, "community-emoji", kat.emojiBody(m, id2, gif), kat.dev)); c != 204 {
		t.Fatalf("a re-put at the limit: %d %s", c, cd)
	}

	// Deleting: gone from the list, still served, then a tombstone after 30 days.
	if c, _ := e.errOf("POST", "emoji/delete", ravi.tok, map[string]any{"id": id2}); c != 403 {
		t.Fatalf("a delete without administrate: %d", c)
	}
	if c, _ := e.errOf("POST", "emoji/delete", kat.tok, map[string]any{"id": id2}); c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if c, cd := e.errOf("POST", "emoji/delete", kat.tok, map[string]any{"id": id2}); c != 404 || cd != wire.ErrCodeNotFound {
		t.Fatalf("a second delete: %d %s", c, cd)
	}
	if len(e.emojiList(kat.tok)) != 1 {
		t.Fatal("a deleted emoji is still listed")
	}
	if c, b := e.emojiGet(id2); c != 200 || !bytes.Equal(b, gif) {
		t.Fatalf("a deleted emoji within 30 days: %d", c)
	}
	if c, cd := kat.emojiPut(signed2(t, "community-emoji", kat.emojiBody(m, id2, gif), kat.dev)); c != 404 {
		t.Fatalf("naming a deleted blob again: %d %s", c, cd)
	}
	c := e.srv.comm.byName["chat.test"]
	ctx := context.Background()
	if err := c.maintainEmoji(ctx, now()+emojiUnnamedKeep+1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Communities().EmojiBlob(ctx, "chat.test", id3); err == nil {
		t.Fatal("an unnamed upload outlived 24 hours")
	}
	if c, _ := e.emojiGet(id); c != 200 {
		t.Fatalf("a current emoji was pruned: %d", c)
	}
	if err := c.maintainEmoji(ctx, now()+emojiDeletedKeep+1); err != nil {
		t.Fatal(err)
	}
	if c, b := e.emojiGet(id2); c != 410 || !bytes.Contains(b, []byte(wire.ErrCodeExpired)) {
		t.Fatalf("a deleted emoji past 30 days: %d %s", c, b)
	}
	if c, _ := e.emojiGet(id); c != 200 {
		t.Fatalf("a current emoji was tombstoned: %d", c)
	}

	// After a move, every emoji counts as deleted then, and is served 30 days more.
	c.mu.Lock()
	moved := c.state.Clone()
	moved.Server = "elsewhere.test"
	c.state = moved
	c.mu.Unlock()
	if err := c.maintainEmoji(ctx, now()); err != nil {
		t.Fatal(err)
	}
	if c, b := e.emojiGet(id); c != 200 || !bytes.Equal(b, png) {
		t.Fatalf("an emoji after the move: %d", c)
	}
	if recs, _ := e.st.Communities().EmojiRecords(ctx, "chat.test"); len(recs) != 0 {
		t.Fatalf("%d records survived the move", len(recs))
	}
	if err := c.maintainEmoji(ctx, now()+emojiDeletedKeep+1); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.emojiGet(id); c != 410 {
		t.Fatalf("an emoji 30 days after the move: %d", c)
	}
}

// community-emoji.json: the vector record parses as the community server reads it, verifies
// under the composite key chain.json's genesis adds for its signer, and names the vector
// blob, whose length and hash match.
func TestVectorCommunityEmoji(t *testing.T) {
	var cv struct {
		Entries []struct {
			Signed struct {
				Signed string `json:"signed"`
			} `json:"signed"`
		} `json:"entries"`
	}
	var ev struct {
		Community string `json:"community_id_hex"`
		BlobID    string `json:"blob_id_hex"`
		Blob      string `json:"blob_hex"`
		Image     string `json:"image_hex"`
		Record    struct {
			Signed string `json:"signed"`
		} `json:"record"`
	}
	for f, v := range map[string]any{"chain.json": &cv, "community-emoji.json": &ev} {
		raw, err := os.ReadFile("../../testdata/vectors/v2/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatal(err)
		}
	}
	var raws [][]byte
	for _, e := range cv.Entries {
		raws = append(raws, []byte(e.Signed.Signed))
	}
	st, err := decodeChainFor(wire.V2, raws)
	if err != nil {
		t.Fatal(err)
	}
	em, perr := cchain.ParseEmoji([]byte(ev.Record.Signed))
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	pub := everDevice(raws, em.Sig.K)
	if pub == nil || em.Sig.VerifyComposite(cchain.TypeEmoji, pub) != nil {
		t.Fatal("the record doesn't verify under its signer's composite key")
	}
	blob, _ := hex.DecodeString(ev.Blob)
	img, _ := hex.DecodeString(ev.Image)
	sum := sha256.Sum256(blob)
	if em.By != st.ID || hex.EncodeToString(em.Community) != ev.Community || hex.EncodeToString(em.Blob) != ev.BlobID ||
		!bytes.Equal(em.SHA256, sum[:]) || em.Size != int64(len(img)) || int64(len(blob)) != em.Size+16 {
		t.Fatalf("record: %+v", em)
	}
}
