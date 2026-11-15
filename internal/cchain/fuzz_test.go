package cchain

import (
	"bytes"
	"crypto/sha256"
	"strconv"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// fuzzCommunity is a staffed community with a text channel, a voice channel, and a code,
// and the identities fuzz inputs name as "@0" (owner) to "@4": admin, mod, member, and
// someone who isn't a member.
func fuzzCommunity(f *testing.F) (*harness, []*ident) {
	h, owner, admin, mod, member := staffed(f)
	h.ok(admin, textChannel(1, []uint64{0}, []uint64{0}), voiceChannel(2, 10, 1),
		map[string]any{"op": "add-code", "key": newCode(f), "exp": testNow + 600, "uses": 3})
	stranger := h.add(newIdent(f, "d.example.org"))
	return h, []*ident{owner, admin, mod, member, stranger}
}

// withIDs puts the identities' IDs where the input says "@0" to "@4".
func withIDs(b []byte, ids []*ident) []byte {
	for i, id := range ids {
		b = bytes.ReplaceAll(b, []byte(`"@`+strconv.Itoa(i)+`"`), []byte(`"`+id.id+`"`))
	}
	return b
}

// checkApplied holds for every entry Apply accepts: the community chain with it replays,
// with or without signatures checked, to the same state, and the state moves on by one.
func checkApplied(t *testing.T, h *harness, raw []byte, st *State, a *Applied) {
	t.Helper()
	sum := sha256.Sum256(a.Enc)
	if a.Seq != h.st.Seq+1 || st.Seq != a.Seq || !bytes.Equal(a.Hash, sum[:]) || !bytes.Equal(st.Head, a.Hash) {
		t.Fatalf("accepted entry %d, hash %x: state at %d, head %x", a.Seq, a.Hash, st.Seq, st.Head)
	}
	raws := append(append([][]byte{}, h.raws...), raw)
	for _, mode := range []Mode{Replay, Import} {
		keys := h.keys
		if mode == Replay {
			keys = nil
		}
		re, err := ReplayChain(raws, testServer, keys, h.now, mode)
		if err != nil {
			t.Fatalf("accepted %s, but replay (mode %d) refuses it: %v", raw, mode, err)
		}
		if !sameState(re, st) {
			t.Fatalf("accepted %s, but replay (mode %d) gives another state", raw, mode)
		}
	}
}

// FuzzCommunityOps signs any list of ops, by any of five identities, at any time near now,
// and appends it. Apply never changes the state it's given, and what it accepts replays to
// the same state. Run it with go test -fuzz=FuzzCommunityOps ./internal/cchain.
func FuzzCommunityOps(f *testing.F) {
	h, ids := fuzzCommunity(f)
	for _, c := range []struct {
		ops string
		by  uint8
	}{
		{`[{"op":"set-name","name":"Day shift"}]`, 0},
		{`[{"op":"set-settings","public":false,"approval":true}]`, 1},
		{`[{"op":"add-role","id":4,"rank":20,"perms":["talk"],"name":{"key":"AAAA","ct":"AAAA"}}]`, 1},
		{`[{"op":"edit-role","id":3,"rank":11,"perms":["talk"]}]`, 1},
		{`[{"op":"remove-role","id":2}]`, 0},
		{`[{"op":"assign-roles","member":"@3","roles":[2]}]`, 1},
		{`[{"op":"timeout","member":"@3","until":1800000600}]`, 2},
		{`[{"op":"ban","member":"@3"}]`, 1},
		{`[{"op":"ban","domain":"c.example.org"}]`, 0},
		{`[{"op":"unban","member":"@3"}]`, 1},
		{`[{"op":"transfer-ownership","to":"@1"}]`, 0},
		{`[{"op":"set-home","server":"elsewhere.example.com"}]`, 0},
		{`[{"op":"remove-channel","id":1}]`, 1},
		{`[{"op":"order-channels","ids":[2,1]}]`, 1},
		{`[{"op":"edit-channel","id":1,"see":[0],"write":[3],"slow":5}]`, 1},
		{`[{"op":"revoke-code","key":"AAAA"}]`, 1},
		{`[{"op":"set-name","name":"x"},{"op":"set-name","name":"y"}]`, 3},
		{`[{"op":"promote"}]`, 4},
		{`[]`, 0},
	} {
		f.Add([]byte(c.ops), c.by, int16(0))
		f.Add([]byte(c.ops), c.by, int16(-700))
	}
	f.Fuzz(func(t *testing.T, opsJSON []byte, by uint8, dts int16) {
		var ops []map[string]any
		if wire.Unmarshal(withIDs(opsJSON, ids), &ops) != nil {
			return
		}
		signer := ids[int(by)%len(ids)]
		body := map[string]any{"community": h.st.ID, "seq": h.st.Seq + 1, "prev": h.st.Head, "ts": h.now + int64(dts), "by": signer.id, "ops": ops}
		sig, err := wire.SignComposite(TypeEntry, body, signer.key)
		if err != nil {
			return
		}
		raw, err := sig.Encode()
		if err != nil {
			t.Fatal(err)
		}
		before, _ := wire.Marshal(h.st)
		st, a, err := h.st.Apply(raw, h.keys, h.now, Append)
		if after, _ := wire.Marshal(h.st); !bytes.Equal(before, after) {
			t.Fatalf("Apply changed the state it was given (%v)", err)
		}
		if err == nil {
			checkApplied(t, h, raw, st, a)
		}
	})
}

// FuzzCommunityEntry gives Apply and Create any bytes as an entry.
func FuzzCommunityEntry(f *testing.F) {
	h, ids := fuzzCommunity(f)
	for _, raw := range h.raws {
		f.Add(raw)
	}
	f.Add(h.entry(ids[0], map[string]any{"op": "set-name", "name": "z"}))
	f.Add([]byte(`{"t":"community-entry","b":"{}","k":"AAAA","s":"AAAA"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		before, _ := wire.Marshal(h.st)
		st, a, err := h.st.Apply(raw, h.keys, h.now, Append)
		if after, _ := wire.Marshal(h.st); !bytes.Equal(before, after) {
			t.Fatalf("Apply changed the state it was given (%v)", err)
		}
		if err == nil {
			checkApplied(t, h, raw, st, a)
		}
		Create(raw, testServer, h.keys, h.now, Append)
		Create(raw, testServer, nil, h.now, Replay)
	})
}
