package api

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/store"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Forgetting older recovery codes (SPEC §7.4, client-stage4 `remove: "retained"`).

type forgetRes struct {
	Removed int    `json:"removed"`
	Waiting int    `json:"waiting"`
	Error   string `json:"error"`
	Retry   int64  `json:"retry"`
}

func forgetWraps(t *testing.T, u *testUser) (int, forgetRes) {
	t.Helper()
	var res forgetRes
	c := call(t, u.ts, "POST", "account/keys", u.token, map[string]any{"remove": "retained"}, &res)
	return c, res
}

// shiftWrapClock makes wrap decisions see a clock `by` seconds ahead, until the test ends.
// Chain appends and sessions keep the real clock, so entries are still dated now.
func shiftWrapClock(t *testing.T, by int64) {
	t.Helper()
	wrapClock = func() int64 { return now() + by }
	t.Cleanup(func() { wrapClock = now })
}

// storedCommits is every stored recovery wrap's slot, by the code it names ("" for none).
func storedCommits(t *testing.T, st store.Store, id string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := st.Account().UpdateKeys(context.Background(), id, func(_ [][]byte, slots []store.KeySlot) ([]store.KeyChange, error) {
		for _, k := range slots {
			if !store.IsRecoverySlot(k.Slot) {
				continue
			}
			var w wrappedKey
			wire.Unmarshal(k.Wrapped, &w)
			out[k.Slot] = string(w.Commit)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// holds reports whether any stored wrap, of any kind, names this code.
func holds(t *testing.T, st store.Store, id string, commit []byte) bool {
	t.Helper()
	for _, c := range storedCommits(t, st, id) {
		if c == string(commit) {
			return true
		}
	}
	return false
}

func retainedCount(t *testing.T, st store.Store, id string) int {
	t.Helper()
	n := 0
	for slot := range storedCommits(t, st, id) {
		if strings.HasPrefix(slot, retainedPrefix) {
			n++
		}
	}
	return n
}

// fullRotation stages, appends, promotes, and cleans up, as reroute-core does.
func fullRotation(t *testing.T, u *testUser, from, to *testCode, ct string) {
	t.Helper()
	if c := setWrap(t, u.ts, u, "recovery-next", to.commit(1), ct); c != 204 {
		t.Fatalf("stage: %d", c)
	}
	if c := rotate(t, u.ts, u, from.key(1), to.commit(1)); c != 200 {
		t.Fatalf("rotate: %d", c)
	}
	if c := setWrap(t, u.ts, u, "recovery", to.commit(1), ct); c != 204 {
		t.Fatalf("promote: %d", c)
	}
	cleanupWraps(t, u.ts, u, to.commit(1))
}

// Forgetting removes the superseded retained wraps (with and without commit) once the
// rotation is 72 hours old, refuses before that, and leaves the current code working.
func TestForgetRetainedWraps(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat := newUser(t, ts, "kat")
	a, b := codeOf(kat), newTestCode()
	if c, _ := forgetWraps(t, kat); c != 200 {
		t.Fatalf("forget with nothing stored: %d", c)
	}
	setWrap(t, ts, kat, "recovery", nil, "old")       // an older client's wrap, no commit
	setWrap(t, ts, kat, "recovery", a.commit(1), "A") // retains the old wrap
	fullRotation(t, kat, a, b, "B")                   // retains A
	if n := retainedCount(t, st, kat.id); n != 2 {
		t.Fatalf("%d retained wraps, want 2", n)
	}

	// Too new: refused, nothing deleted, and told when.
	c, res := forgetWraps(t, kat)
	if c != 429 || res.Error != wire.ErrCodeRateLimited || res.Retry < forgetAfter-120 || res.Retry > forgetAfter {
		t.Fatalf("forget inside the window: %d %+v, want 429 with retry about 72 hours", c, res)
	}
	shiftWrapClock(t, forgetAfter-600)
	if c, _ := forgetWraps(t, kat); c != 429 {
		t.Fatalf("forget 10 minutes before the window ends: %d", c)
	}
	if n := retainedCount(t, st, kat.id); n != 2 || !holds(t, st, kat.id, a.commit(1)) {
		t.Fatalf("a refused forget deleted something: %d retained", n)
	}

	shiftWrapClock(t, forgetAfter+60)
	c, res = forgetWraps(t, kat)
	if c != 200 || res.Removed != 2 || res.Waiting != 0 {
		t.Fatalf("forget after the window: %d %+v, want 200 with 2 removed", c, res)
	}
	if n := retainedCount(t, st, kat.id); n != 0 {
		t.Fatalf("%d retained wraps left", n)
	}
	// The old code no longer has a wrap anywhere; the current one still does.
	if holds(t, st, kat.id, a.commit(1)) {
		t.Fatal("the old code's wrap is still stored")
	}
	if ct, commit := currentWrap(t, ts, kat); ct != "B" || !bytes.Equal(commit, b.commit(1)) || !opensWith(t, ts, kat, b.commit(1)) {
		t.Fatalf("current wrap: %q", ct)
	}
	// Again: nothing left, nothing waiting.
	if c, res := forgetWraps(t, kat); c != 200 || res.Removed != 0 || res.Waiting != 0 {
		t.Fatalf("forget again: %d %+v", c, res)
	}
}

// Forgetting never deletes the current wrap, a staged wrap (appended or not), or a
// retained wrap for a code no older than the current one; the rotation in progress can
// still be promoted afterwards.
func TestForgetKeepsCurrentAndStaged(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat := newUser(t, ts, "kat")
	a, b, c, d := codeOf(kat), newTestCode(), newTestCode(), newTestCode()
	setWrap(t, ts, kat, "recovery", a.commit(1), "A")
	fullRotation(t, kat, a, b, "B") // current B, A retained
	// A rotation in progress: C staged and appended, not promoted; D staged only.
	setWrap(t, ts, kat, "recovery-next", c.commit(1), "C")
	if rotate(t, ts, kat, b.key(1), c.commit(1)) != 200 {
		t.Fatal("rotate to C")
	}
	setWrap(t, ts, kat, "recovery-next", d.commit(1), "D")
	// A retained wrap naming C, which the chain commits to after B: not superseded.
	raw, _ := wire.Marshal(map[string]any{"via": "recovery", "commit": c.commit(1), "ct": []byte("C'")})
	if err := st.Account().SetKey(context.Background(), kat.id, retainedPrefix+"c/odd", raw); err != nil {
		t.Fatal(err)
	}
	before := storedCommits(t, st, kat.id)

	shiftWrapClock(t, 10*forgetAfter) // even long after, these stay
	cnt, res := forgetWraps(t, kat)
	if cnt != 200 || res.Removed != 1 {
		t.Fatalf("forget: %d %+v, want only A's wrap removed", cnt, res)
	}
	after := storedCommits(t, st, kat.id)
	for slot, commit := range before {
		_, still := after[slot]
		if commit == string(a.commit(1)) {
			if still {
				t.Fatal("A's superseded wrap was kept")
			}
		} else if !still {
			t.Fatalf("forget deleted %s", slot)
		}
	}
	for _, x := range []*testCode{c, d} {
		if !hasSlot(t, st, kat.id, stagedSlot(x.commit(1))) {
			t.Fatal("a staged wrap was deleted")
		}
	}
	if ct, _ := currentWrap(t, ts, kat); ct != "B" {
		t.Fatalf("current wrap: %q", ct)
	}
	if code := setWrap(t, ts, kat, "recovery", c.commit(1), "C"); code != 204 {
		t.Fatalf("promoting the rotation in progress after a forget: %d", code)
	}
	if !opensWith(t, ts, kat, c.commit(1)) {
		t.Fatal("the new code doesn't open the account key")
	}
}

// Forgetting frees room under the cap: after 32 rotations staging is refused, after a
// forget it works again.
func TestForgetFreesTheCap(t *testing.T) {
	st := newStore(t)
	ts := testServerWith(t, st)
	kat := newUser(t, ts, "kat")
	cur := codeOf(kat)
	setWrap(t, ts, kat, "recovery", cur.commit(1), "code 0")
	for i := 0; i < maxRecoveryWraps; i++ {
		next := newTestCode()
		fullRotation(t, kat, cur, next, "promoted")
		cur = next
	}
	next := newTestCode()
	if c := setWrap(t, ts, kat, "recovery-next", next.commit(1), "staged"); c != 429 {
		t.Fatalf("staging at the cap: %d, want 429", c)
	}
	shiftWrapClock(t, forgetAfter+1)
	if c, res := forgetWraps(t, kat); c != 200 || res.Removed != maxRecoveryWraps {
		t.Fatalf("forget: %d %+v", c, res)
	}
	if c := setWrap(t, ts, kat, "recovery-next", next.commit(1), "staged"); c != 204 {
		t.Fatalf("staging after a forget: %d, want 204", c)
	}
	fullRotationAfterStage(t, kat, cur, next)
}

func fullRotationAfterStage(t *testing.T, u *testUser, from, to *testCode) {
	t.Helper()
	if rotate(t, u.ts, u, from.key(1), to.commit(1)) != 200 || setWrap(t, u.ts, u, "recovery", to.commit(1), "promoted") != 204 {
		t.Fatal("finishing the rotation after a forget")
	}
}

// A forget decides against the chain and the wraps as they are when its changes land:
// a rotation (chain append) and a promotion each wait for it, and neither loses anything.
func TestForgetRacesRotationAndPromotion(t *testing.T) {
	for _, racer := range []string{"append", "promote"} {
		t.Run(racer, func(t *testing.T) {
			base := newStore(t)
			ts := testServerWith(t, base)
			kat := newUser(t, ts, "kat")
			a, b, c := codeOf(kat), newTestCode(), newTestCode()
			setWrap(t, ts, kat, "recovery", a.commit(1), "A")
			fullRotation(t, kat, a, b, "B")
			setWrap(t, ts, kat, "recovery-next", c.commit(1), "C")
			if racer == "promote" && rotate(t, ts, kat, b.key(1), c.commit(1)) != 200 {
				t.Fatal("rotate to C")
			}
			shiftWrapClock(t, forgetAfter+60) // A→B is old enough (and, on this clock, B→C)
			// A second server on the same store, whose first wrap decision pauses.
			p2 := newPausingAccount(base.Account())
			ts2 := testServerWith(t, accountFaultStore{base, p2})
			kat.ts = ts2

			type result struct {
				c   int
				res forgetRes
			}
			forgot := make(chan result, 1)
			go func() { c, r := forgetWraps(t, kat); forgot <- result{c, r} }()
			select { // the forget has read the chain and the wraps
			case <-p2.reached:
			case f := <-forgot:
				t.Fatalf("forget answered %d without a wrap decision", f.c)
			}
			raced := make(chan int, 1)
			go func() {
				if racer == "append" {
					raced <- call(t, ts2, "POST", "chain/append", kat.token, map[string]any{"entry": recoveryEntry(t, ts2, kat.id, b.key(1), c.commit(1))}, nil)
				} else {
					raced <- setWrap(t, ts2, kat, "recovery", c.commit(1), "C")
				}
			}()
			select {
			case code := <-raced:
				t.Fatalf("a %s (%d) completed inside a forget's decision", racer, code)
			case <-time.After(300 * time.Millisecond):
			}
			close(p2.proceed)
			f := <-forgot
			if f.c != 200 || f.res.Removed != 1 {
				t.Fatalf("forget: %d %+v, want A's wrap removed", f.c, f.res)
			}
			want := map[string]int{"append": 200, "promote": 204}[racer]
			if code := <-raced; code != want {
				t.Fatalf("%s after the forget: %d, want %d", racer, code, want)
			}
			if holds(t, base, kat.id, a.commit(1)) {
				t.Fatal("A's wrap survived")
			}
			if !holds(t, base, kat.id, b.commit(1)) || !holds(t, base, kat.id, c.commit(1)) {
				t.Fatal("the forget lost B's or C's wrap")
			}
			if racer == "append" {
				if !hasSlot(t, base, kat.id, stagedSlot(c.commit(1))) || setWrap(t, ts2, kat, "recovery", c.commit(1), "C") != 204 {
					t.Fatal("the staged rotation can't be finished after the forget")
				}
			}
			// C's entry is new on the real clock: forgetting B now has to wait.
			wrapClock = now
			if code, _ := forgetWraps(t, kat); code != 429 {
				t.Fatalf("forget right after the rotation to C: %d, want 429", code)
			}
			if !holds(t, base, kat.id, b.commit(1)) {
				t.Fatal("B's wrap was forgotten inside the window")
			}
		})
	}
}
