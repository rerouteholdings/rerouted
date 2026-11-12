package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Recovery-wrap lifecycle (SPEC §6.3, §7.4). These only use the client API.

// testCode is a recovery code's first keys: key i's commitment is SHA-256 of its public key.
type testCode struct{ keys [3]ed25519.PrivateKey }

func newTestCode() *testCode {
	c := &testCode{}
	for i := range c.keys {
		_, c.keys[i], _ = ed25519.GenerateKey(rand.Reader)
	}
	return c
}

// codeOf is the code kat's genesis commits to: key 1 is kat.rec, later keys are made up.
func codeOf(u *testUser) *testCode {
	c := newTestCode()
	c.keys[0] = u.rec
	return c
}

func (c *testCode) key(i int) ed25519.PrivateKey { return c.keys[i-1] }
func (c *testCode) commit(i int) []byte {
	sum := sha256.Sum256(c.keys[i-1].Public().(ed25519.PublicKey))
	return sum[:]
}

// recoveryEntry is an entry on the identity's head, signed by `by`, committing to `next`.
func recoveryEntry(t *testing.T, ts *httptest.Server, id string, by ed25519.PrivateKey, next []byte) wire.Raw {
	t.Helper()
	seq, prev := head(t, ts, id)
	return signed(t, "chain-entry", map[string]any{
		"id": id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-recovery", "next": next}},
	}, by)
}

// rotate appends a rotation (or an advance) through a device's session, as a client does.
func rotate(t *testing.T, ts *httptest.Server, u *testUser, by ed25519.PrivateKey, next []byte) int {
	t.Helper()
	return call(t, ts, "POST", "chain/append", u.token, map[string]any{"entry": recoveryEntry(t, ts, u.id, by, next)}, nil)
}

// recoverWith is a recovery from a new device, with no session (POST recover).
func recoverWith(t *testing.T, ts *httptest.Server, u *testUser, by ed25519.PrivateKey, next []byte) int {
	t.Helper()
	return call(t, ts, "POST", "recover", "", map[string]any{"entry": recoveryEntry(t, ts, u.id, by, next)}, nil)
}

func setWrap(t *testing.T, ts *httptest.Server, u *testUser, via string, commit []byte, ct string) int {
	t.Helper()
	w := map[string]any{"via": via, "ct": []byte(ct)}
	if commit != nil {
		w["commit"] = commit
	}
	return call(t, ts, "POST", "account/keys", u.token, map[string]any{"set": w}, nil)
}

func cleanupWraps(t *testing.T, ts *httptest.Server, u *testUser, commit []byte) int {
	t.Helper()
	req := map[string]any{"remove": "recovery-next"}
	if commit != nil {
		req["commit"] = commit
	}
	return call(t, ts, "POST", "account/keys", u.token, req, nil)
}

type listedWrap struct {
	Via    string     `json:"via"`
	CT     wire.Bytes `json:"ct"`
	Commit wire.Bytes `json:"commit"`
}

func listWraps(t *testing.T, ts *httptest.Server, u *testUser) []listedWrap {
	t.Helper()
	var res struct {
		Items []listedWrap `json:"items"`
	}
	if c := call(t, ts, "GET", "account/keys", u.token, nil, &res); c != 200 {
		t.Fatalf("account/keys: %d", c)
	}
	return res.Items
}

// current is the listed recovery wrap's ct, "" if none.
func currentWrap(t *testing.T, ts *httptest.Server, u *testUser) (ct string, commit []byte) {
	t.Helper()
	for _, w := range listWraps(t, ts, u) {
		if w.Via == "recovery" {
			return string(w.CT), w.Commit
		}
	}
	return "", nil
}

// opensWith reports whether a client holding the code with this key-1 commitment finds a
// wrap for it: the recovery wrap or a staged one naming it (what recover_account_key tries).
func opensWith(t *testing.T, ts *httptest.Server, u *testUser, commit []byte) bool {
	t.Helper()
	for _, w := range listWraps(t, ts, u) {
		if (w.Via == "recovery" || w.Via == "recovery-next") && bytes.Equal(w.Commit, commit) {
			return true
		}
	}
	return false
}

// Two devices rotate at once; the winner's staged wrap survives the loser's cleanup (both
// kinds), the loser's stale promotion, ordinary advancement, and the winner's loss.
func TestRecoveryWrapCompetingRotations(t *testing.T) {
	ts := testServerWith(t, newStore(t))
	kat := newUser(t, ts, "kat")
	a, b, c := codeOf(kat), newTestCode(), newTestCode()
	if code := setWrap(t, ts, kat, "recovery", a.commit(1), "A"); code != 204 {
		t.Fatalf("set the first recovery wrap: %d", code)
	}
	loser := recoveryEntry(t, ts, kat.id, a.key(1), c.commit(1)) // signed before the winner's lands
	if setWrap(t, ts, kat, "recovery-next", b.commit(1), "B staged") != 204 || setWrap(t, ts, kat, "recovery-next", c.commit(1), "C staged") != 204 {
		t.Fatal("staging")
	}
	if code := rotate(t, ts, kat, a.key(1), b.commit(1)); code != 200 {
		t.Fatalf("the winner's rotation: %d", code)
	}
	if code := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": loser}, nil); code != 409 {
		t.Fatalf("the loser's rotation: %d, want 409", code)
	}
	// The loser tidies up, by commitment and then without one, as older clients do.
	if cleanupWraps(t, ts, kat, c.commit(1)) != 204 || cleanupWraps(t, ts, kat, nil) != 204 {
		t.Fatal("cleanup")
	}
	if !opensWith(t, ts, kat, b.commit(1)) {
		t.Fatal("the loser's cleanup deleted the winner's staged wrap")
	}
	if code := setWrap(t, ts, kat, "recovery", c.commit(1), "C promoted"); code == 204 {
		t.Fatal("the loser promoted a code the chain doesn't commit to")
	}
	if ct, _ := currentWrap(t, ts, kat); ct != "A" {
		t.Fatalf("the recovery wrap after a refused promotion: %q", ct)
	}
	// The winner is lost before promoting. A new device recovers with the new code,
	// which advances the commitment; cleanup by another device runs again.
	if code := recoverWith(t, ts, kat, b.key(1), b.commit(2)); code != 200 {
		t.Fatalf("recover with the new code: %d", code)
	}
	cleanupWraps(t, ts, kat, nil)
	if !opensWith(t, ts, kat, b.commit(1)) {
		t.Fatal("cleanup after the recovery advanced the commitment deleted the new code's only wrap")
	}
	if code := setWrap(t, ts, kat, "recovery", b.commit(1), "B promoted"); code != 204 {
		t.Fatalf("promote the new code: %d", code)
	}
	if code := setWrap(t, ts, kat, "recovery", a.commit(1), "A again"); code == 204 {
		t.Fatal("a stale promotion of the old code replaced the new one")
	}
	if code := setWrap(t, ts, kat, "recovery", b.commit(1), "B promoted twice"); code != 204 {
		t.Fatalf("promoting the current code again: %d, want 204", code)
	}
	if ct, commit := currentWrap(t, ts, kat); ct != "B promoted" || !bytes.Equal(commit, b.commit(1)) {
		t.Fatalf("the recovery wrap: %q", ct)
	}
	// Promoted, the staged copy can go.
	cleanupWraps(t, ts, kat, nil)
	for _, w := range listWraps(t, ts, kat) {
		if w.Via == "recovery-next" && bytes.Equal(w.Commit, b.commit(1)) {
			t.Fatal("the promoted code's staged wrap stayed after cleanup")
		}
	}
}

// A rotation stopped at each step, then every device holding its pending state is lost
// for good: whichever code the chain commits to still finds its wrap, through other
// devices' cleanup and a recovery that advances the commitment.
func TestRecoveryWrapInterruptions(t *testing.T) {
	for _, stop := range []string{"staged", "appended", "promoted", "cleaned"} {
		t.Run(stop, func(t *testing.T) {
			ts := testServerWith(t, newStore(t))
			kat := newUser(t, ts, "kat")
			a, b := codeOf(kat), newTestCode()
			setWrap(t, ts, kat, "recovery", a.commit(1), "A")
			steps := map[string]int{"staged": 1, "appended": 2, "promoted": 3, "cleaned": 4}[stop]
			if setWrap(t, ts, kat, "recovery-next", b.commit(1), "B staged") != 204 {
				t.Fatal("stage")
			}
			if steps >= 2 && rotate(t, ts, kat, a.key(1), b.commit(1)) != 200 {
				t.Fatal("append")
			}
			if steps >= 3 && setWrap(t, ts, kat, "recovery", b.commit(1), "B") != 204 {
				t.Fatal("promote")
			}
			if steps >= 4 && cleanupWraps(t, ts, kat, b.commit(1)) != 204 {
				t.Fatal("cleanup")
			}
			// The device is gone. Other devices tidy up; the user recovers.
			code := a
			if steps >= 2 {
				code = b
			}
			cleanupWraps(t, ts, kat, nil)
			if !opensWith(t, ts, kat, code.commit(1)) {
				t.Fatal("the code the chain commits to has no wrap after cleanup")
			}
			if c := recoverWith(t, ts, kat, code.key(1), code.commit(2)); c != 200 {
				t.Fatalf("recover: %d", c)
			}
			cleanupWraps(t, ts, kat, nil)
			if !opensWith(t, ts, kat, code.commit(1)) {
				t.Fatal("the code the chain commits to has no wrap after recovery and cleanup")
			}
			if c := setWrap(t, ts, kat, "recovery", code.commit(1), "promoted on recovery"); c != 204 {
				t.Fatalf("the recovering client promotes: %d", c)
			}
			if _, commit := currentWrap(t, ts, kat); !bytes.Equal(commit, code.commit(1)) {
				t.Fatal("the recovery wrap isn't the chain's code's")
			}
		})
	}
}

// A recovery fork (SPEC §6.4.1) that throws out device changes keeps every commitment the
// kept history made, so a staged wrap the chain still commits to is kept.
func TestRecoveryWrapForkKeepsReferencedWraps(t *testing.T) {
	ts := testServerWith(t, newStore(t))
	kat := newUser(t, ts, "kat")
	a, b := codeOf(kat), newTestCode()
	setWrap(t, ts, kat, "recovery", a.commit(1), "A")
	setWrap(t, ts, kat, "recovery-next", b.commit(1), "B staged")
	if rotate(t, ts, kat, a.key(1), b.commit(1)) != 200 {
		t.Fatal("rotation")
	}
	// A device change (a thief's, say), then a recovery fork that undoes it.
	_, thief, _ := ed25519.GenerateKey(rand.Reader)
	seq, prev := head(t, ts, kat.id)
	add := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "add-device", "key": []byte(thief.Public().(ed25519.PublicKey)), "name": "thief"}}}, kat.dev)
	if c := call(t, ts, "POST", "chain/append", kat.token, map[string]any{"entry": add}, nil); c != 200 {
		t.Fatalf("add a device: %d", c)
	}
	fork := signed(t, "chain-entry", map[string]any{"id": kat.id, "seq": seq + 1, "prev": prev, "ts": time.Now().Unix(),
		"ops": []any{map[string]any{"op": "set-recovery", "next": b.commit(2)}}}, b.key(1))
	if c := call(t, ts, "POST", "recover", "", map[string]any{"entry": fork}, nil); c != 200 {
		t.Fatalf("recovery fork: %d", c)
	}
	cleanupWraps(t, ts, kat, nil)
	if !opensWith(t, ts, kat, b.commit(1)) {
		t.Fatal("cleanup after a recovery fork deleted the new code's only wrap")
	}
	if c := setWrap(t, ts, kat, "recovery", b.commit(1), "B"); c != 204 {
		t.Fatalf("promote after the fork: %d", c)
	}
}

// Concurrent staging can't get past the cap, and nothing staged is evicted to make room.
func TestRecoveryWrapQuotaRace(t *testing.T) {
	ts := testServerWith(t, newStore(t))
	kat := newUser(t, ts, "kat")
	const n = 3 * maxStagedForTests
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = setWrap(t, ts, kat, "recovery-next", randBytes(32), "staged")
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		switch c {
		case 204:
			ok++
		case 429:
		default:
			t.Fatalf("staging: %d", c)
		}
	}
	staged := 0
	for _, w := range listWraps(t, ts, kat) {
		if w.Via == "recovery-next" {
			staged++
		}
	}
	if ok != maxStagedForTests || staged != maxStagedForTests {
		t.Fatalf("%d stagings accepted, %d stored; the cap is %d", ok, staged, maxStagedForTests)
	}
}

// maxStagedForTests is the staged-wrap cap the tests expect (maxStaged).
const maxStagedForTests = 8
