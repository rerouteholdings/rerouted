package api

import (
	"bytes"
	"net/http"
	"strconv"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// challengeFrom asks for a community sign-in challenge as a caller at addr.
func (e *cmEnv) challengeFrom(addr, id string, key []byte) int {
	e.t.Helper()
	b, _ := wire.Marshal(map[string]any{"id": id, "key": key, "home": "chat.test"})
	req, _ := http.NewRequest("POST", e.ts.URL+cmBase+"auth/challenge", bytes.NewReader(b))
	req.Header.Set("Content-Type", wire.MediaType)
	req.Header.Set("X-Forwarded-For", addr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Sign-in challenges (spec/api/community.md, Rate limits): only issued ones count against an
// identity's 30 an hour. Refusals count per claimed identity and key, and per caller address,
// so a removed device or a stranger can't use up the identity's budget.
func TestCommunityChallengeLimits(t *testing.T) {
	e := newCommunityEnv(t, func(*config.Config) {})
	kat := e.user("kat")
	kat.create("chat.test", false)
	removed := edOf(newComposite(t))

	// A device that isn't current, retrying: refused 10 times, then held back.
	for i := range refusedChallengesPerKey {
		if c := e.challengeFrom("192.0.2.1", kat.id, removed); c != 403 {
			t.Fatalf("refused challenge %d: %d", i, c)
		}
	}
	if c := e.challengeFrom("192.0.2.2", kat.id, removed); c != 429 {
		t.Fatalf("the same identity and key past its refusals: %d", c)
	}
	// A stranger at one address, trying many keys: held back after 100 refusals.
	for i := range refusedChallengesPerAddress - refusedChallengesPerKey {
		if c := e.challengeFrom("192.0.2.1", kat.id, edOf(newComposite(t))); c != 403 {
			t.Fatalf("stranger's challenge %d: %d", i, c)
		}
	}
	if c := e.challengeFrom("192.0.2.1", kat.id, edOf(newComposite(t))); c != 429 {
		t.Fatalf("an address past its refusals: %d", c)
	}
	// An IPv6 caller counts by its /64.
	if addressKey("2001:db8:1:2::5") != addressKey("2001:db8:1:2:ffff::9") || addressKey("2001:db8:1:2::5") == addressKey("2001:db8:1:3::5") {
		t.Fatal("IPv6 addresses aren't counted by their /64")
	}

	// None of that touched kat's own budget: her device gets 30 challenges an hour, one of
	// them used when she signed in.
	for i := range challengesPerID - 1 {
		if c := e.challengeFrom("198.51.100."+strconv.Itoa(i), kat.id, edOf(kat.dev)); c != 200 {
			t.Fatalf("kat's challenge %d: %d", i, c)
		}
	}
	if c := e.challengeFrom("198.51.100.200", kat.id, edOf(kat.dev)); c != 429 {
		t.Fatalf("past 30 issued challenges: %d", c)
	}
}
