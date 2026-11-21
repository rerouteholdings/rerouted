package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// POST groups/undo (SPEC §16.5, Undoing a refused commit): the owner, or a member with
// administrate, sets a group back to the epoch of a commit every member refused. The
// community server checks the signer, the commit's hash, and that nothing came after it;
// tells the group's devices first; lists the undo with the commits; and doesn't take the
// undone commit again.
func TestCommunityUndo(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	ravi := e.user("ravi")
	kat, m := joined(t, e, ravi)
	kat.inbox()
	epoch, key := m.epoch, m.ekey

	// ravi gets a junk commit sequenced.
	junk := privMsg("junk")
	sum := sha256.Sum256(junk)
	var next *wire.CompositePrivateKey
	commitWith := func(u *cmUser, data []byte, epoch uint64, key *wire.CompositePrivateKey) cResult {
		h := sha256.Sum256(data)
		next = newComposite(t)
		creq := signedFull2(t, "commit-request", map[string]any{"group": m.group, "epoch": epoch, "hash": h[:], "next": next.Public().Bytes()}, key)
		return u.send(map[string]any{"id": randB(16), "kind": "mls", "group": m.group, "epoch": epoch, "mls": "commit", "data": data, "commit": creq, "info": []byte("info"), "tree": u.uploadTree("tree-" + string(data))})
	}
	if r := commitWith(ravi, junk, epoch, key); r.Status != "sent" {
		t.Fatalf("the junk commit: %+v", r)
	}
	undo := func(u *cmUser, body map[string]any) (int, string) {
		b := map[string]any{"community": m.ch.id, "group": m.group, "epoch": epoch, "hash": sum[:], "by": u.id, "ts": time.Now().Unix()}
		for k, v := range body {
			b[k] = v
		}
		return e.errOf("POST", "groups/undo", u.tok, map[string]any{"undo": signed2(t, "commit-undo", b, u.dev)})
	}
	for _, c := range []struct {
		why  string
		u    *cmUser
		body map[string]any
		code int
		err  string
	}{
		{"by a member without administrate", ravi, nil, 403, wire.ErrCodeNotAllowed},
		{"by another identity", kat, map[string]any{"by": ravi.id}, 403, wire.ErrCodeNotAllowed},
		{"for another community", kat, map[string]any{"community": randB(32)}, 400, wire.ErrCodeBadRequest},
		{"a wrong hash", kat, map[string]any{"hash": randB(32)}, 404, wire.ErrCodeNotFound},
		{"a wrong epoch", kat, map[string]any{"epoch": epoch + 1}, 404, wire.ErrCodeNotFound},
		{"no such group", kat, map[string]any{"group": randB(32)}, 404, wire.ErrCodeNotFound},
	} {
		if code, err := undo(c.u, c.body); code != c.code || err != c.err {
			t.Errorf("%s: %d %s, want %d %s", c.why, code, err, c.code, c.err)
		}
	}
	if code, err := undo(kat, nil); code != 200 {
		t.Fatalf("the owner's undo: %d %s", code, err)
	}
	if code, _ := undo(kat, nil); code != 200 {
		t.Fatalf("the same undo again: %d", code)
	}
	// Every registered device hears of it, and commits lists it in place of the commit.
	found := false
	for _, it := range kat.inbox() {
		found = found || strings.Contains(string(it.Notice), `"t":"commit-undo"`)
	}
	if !found {
		t.Fatal("no commit-undo notice")
	}
	var res struct {
		Items []map[string]any `json:"items"`
		Undos []wire.Raw       `json:"undos"`
	}
	if c := e.call("GET", "groups/"+b64(m.group)+"/commits?after="+strconv.FormatInt(int64(epoch)-1, 10), kat.tok, nil, &res); c != 200 || len(res.Items) != 0 || len(res.Undos) != 1 {
		t.Fatalf("commits after the undo: %d %+v", c, res)
	}
	// The undone commit can't come back, but another commit for the epoch, signed with the
	// epoch's key again, goes in.
	if r := commitWith(ravi, junk, epoch, key); r.Status == "sent" {
		t.Fatal("the undone commit was sequenced again")
	}
	good := privMsg("good")
	if r := commitWith(kat, good, epoch, key); r.Status != "sent" {
		t.Fatalf("a commit after the undo: %+v", r)
	}
	// Once a commit for the next epoch is in, it's too late: a member applied the one before.
	gsum := sha256.Sum256(good)
	if r := commitWith(kat, privMsg("after"), epoch+1, next); r.Status != "sent" {
		t.Fatalf("the next epoch's commit: %+v", r)
	}
	if code, err := undo(kat, map[string]any{"hash": gsum[:]}); code != 409 || err != wire.ErrCodeStaleEpoch {
		t.Fatalf("an undo with the next epoch's commit in: %d %s", code, err)
	}
}

// commit-undo.json: the vector undo verifies under the composite key that chain.json's
// genesis adds for its signer, and names the stand-in community, group, and commit.
func TestVectorCommitUndo(t *testing.T) {
	var cv struct {
		Entries []struct {
			Signed struct {
				Signed string `json:"signed"`
			} `json:"signed"`
		} `json:"entries"`
	}
	var uv struct {
		Commit struct {
			SHA256Hex string `json:"sha256_hex"`
		} `json:"commit"`
		Community string `json:"community_id_hex"`
		Group     string `json:"group_id_hex"`
		Undo      struct {
			Signed string `json:"signed"`
		} `json:"undo"`
	}
	for f, v := range map[string]any{"chain.json": &cv, "commit-undo.json": &uv} {
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
	sig, err := wire.DecodeSignedV2([]byte(uv.Undo.Signed))
	if err != nil || sig.T != "commit-undo" {
		t.Fatalf("decode: %v", err)
	}
	pub := everDevice(raws, sig.K)
	if pub == nil || sig.VerifyComposite("commit-undo", pub) != nil {
		t.Fatal("the undo doesn't verify under its signer's composite key")
	}
	var b struct {
		Community wire.Bytes `json:"community"`
		Group     wire.Bytes `json:"group"`
		Epoch     uint64     `json:"epoch"`
		Hash      wire.Bytes `json:"hash"`
		By        string     `json:"by"`
		TS        int64      `json:"ts"`
	}
	if err := sig.OpenClosed(&b); err != nil || b.By != st.ID || hex.EncodeToString(b.Community) != uv.Community || hex.EncodeToString(b.Group) != uv.Group || hex.EncodeToString(b.Hash) != uv.Commit.SHA256Hex {
		t.Fatalf("body: %v %+v", err, b)
	}
}
