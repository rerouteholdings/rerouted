package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"
)

// federatedGroup makes kat (a.test) and bob (b.test) contacts, with a direct group whose hub
// is b.test and one accepted commit (epoch 0).
func federatedGroup(t *testing.T) (a, b *httptest.Server, sa, sb *Server, kat, bob *testUser, group []byte) {
	t.Helper()
	a, b, sa, sb = twoServers(t)
	kat, bob = newUserOn(t, a, "kat", "a.test"), newUserOn(t, b, "bob", "b.test")
	call(t, a, "GET", "resolve/bob.b.test", kat.token, nil, nil)
	kat.request(bob, bob.invite(false))
	bob.eventually(1)
	call(t, b, "POST", "contacts/accept", bob.token, map[string]any{"id": kat.id}, nil)
	group = randBytes(32)
	ek0Pub, ek0, _ := ed25519.GenerateKey(rand.Reader)
	ek1Pub, _, _ := ed25519.GenerateKey(rand.Reader)
	call(t, b, "POST", "groups/create", bob.token, map[string]any{"group": group, "kind": "direct", "epoch-key": []byte(ek0Pub)}, nil)
	data := []byte("mls-commit-add-kat")
	sum := sha256.Sum256(data)
	cr := signed(t, "commit-request", map[string]any{"group": group, "epoch": 0, "hash": sum[:], "next": []byte(ek1Pub)}, ek0)
	var sent struct {
		Results []sendResult `json:"results"`
	}
	out := map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{bob.id}, "group": group, "epoch": 0, "mls": "commit", "data": data, "commit": cr,
		"welcomes": []any{map[string]any{"id": randBytes(16), "to": []string{kat.id}, "data": []byte("mls-welcome")}}}
	if call(t, b, "POST", "send", bob.token, map[string]any{"deliveries": []any{out}}, &sent); sent.Results[0].Status != "sent" {
		t.Fatalf("commit: %+v", sent.Results[0])
	}
	kat.eventually(1)
	call(t, a, "POST", "groups/register", kat.token, map[string]any{"group": group}, nil)
	return
}

// SPEC §11.6: a member whose homeserver isn't the hub fetches missed commits through it
// (S2S commit/fetch), and gets 410 expired for epochs the hub no longer holds.
func TestCommitFetchThroughRemoteHub(t *testing.T) {
	a, _, _, sb, kat, _, group := federatedGroup(t)
	path := "groups/" + b64(group) + "/commits?after=-1&hub=b.test"
	var got struct {
		Items []struct {
			Epoch int `json:"epoch"`
		} `json:"items"`
	}
	if c := call(t, a, "GET", path, kat.token, nil, &got); c != 200 || len(got.Items) != 1 || got.Items[0].Epoch != 0 {
		t.Fatalf("commits through a.test from b.test: %d %+v", c, got)
	}
	if c := call(t, a, "GET", "groups/"+b64(group)+"/commits?after=-1", kat.token, nil, nil); c != 404 {
		t.Fatalf("without hub, from a server that isn't the hub: %d, want 404", c)
	}
	// 30 days on, the hub has pruned epoch 0.
	if err := sb.st.Hub().PruneCommits(context.Background(), time.Now().Unix()+1); err != nil {
		t.Fatal(err)
	}
	if c := call(t, a, "GET", path, kat.token, nil, nil); c != 410 {
		t.Fatalf("a pruned epoch: %d, want 410 expired", c)
	}
	if c := call(t, a, "GET", "groups/"+b64(group)+"/commits?after=0&hub=b.test", kat.token, nil, &got); c != 200 || len(got.Items) != 0 {
		t.Fatalf("nothing missed since epoch 0: %d %+v", c, got)
	}
}

// SPEC §11.11: a hub handoff registers the group with the new hub over S2S. The hub takes
// it only from servers its users have contacts on (spec/api/s2s-stage2.md).
func TestHubHandoffRegistersRemotely(t *testing.T) {
	a, b, _, sb, kat, bob, _ := federatedGroup(t)
	newGroup := randBytes(32)
	ek, _, _ := ed25519.GenerateKey(rand.Reader)
	body := map[string]any{"group": newGroup, "kind": "group", "epoch": 7, "epoch-key": []byte(ek), "hub": "b.test"}

	// b.test's only contact on a.test is kat, and she's a full contact of bob: allowed.
	if c := call(t, a, "POST", "groups/create", kat.token, body, nil); c != 204 {
		t.Fatalf("handoff to b.test: %d", c)
	}
	g, err := sb.st.Hub().Group(context.Background(), newGroup)
	if err != nil || g.Epoch != 7 {
		t.Fatalf("b.test's hub state: %+v %v", g, err)
	}
	if c := call(t, a, "POST", "groups/create", kat.token, body, nil); c != 409 {
		t.Fatalf("registering the same group again: %d, want 409", c)
	}

	// Once bob removes kat, b.test has no contacts on a.test, and refuses.
	call(t, b, "POST", "contacts/remove", bob.token, map[string]any{"id": kat.id}, nil)
	body["group"] = randBytes(32)
	if c := call(t, a, "POST", "groups/create", kat.token, body, nil); c != 403 {
		t.Fatalf("a handoff from a server with no contacts: %d, want 403", c)
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
