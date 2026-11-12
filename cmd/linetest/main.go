// Command linetest places a test call through two Tieroute homeservers: a scripted
// wire-version-1 client that exercises the server side of the protocol over HTTP.
//
//	linetest -a a.test=http://127.0.0.1:18091 -b b.test=http://127.0.0.1:18092
//
// It does everything a client does except MLS: discovery, registration, invite codes,
// contact requests, key packages, group registration, commits through the hub, and
// deliveries. Where a real client sends MLS ciphertext, linetest sends placeholder
// bytes; servers never read them either way (SPEC §2.3). End-to-end encryption needs
// the Reroute client.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

var verbose = flag.Bool("v", false, "print every request and response")

func main() {
	a := flag.String("a", "a.test=http://127.0.0.1:18091", "first server: name=well-known origin")
	b := flag.String("b", "b.test=http://127.0.0.1:18092", "second server: name=well-known origin")
	flag.Parse()
	srvA, srvB := discover(*a), discover(*b)

	step("Kat registers on %s and Ravi on %s, each with the server's published invite", srvA.name, srvB.name)
	kat, ravi := register(srvA, "kat"), register(srvB, "ravi")

	step("Without an invite code, Kat can't even ask")
	kat.contactRequest(ravi, "")
	kat.contactRequest(ravi, "WRONGCODE1")
	time.Sleep(time.Second)
	if n := len(ravi.inbox()); n != 0 {
		fail("ravi got %d items from requests without a valid code", n)
	}
	say("both requests answered 202, and nothing reached Ravi (SPEC §9.1, §10.3)")

	step("Ravi makes a one-use invite code and gives it to Kat")
	var inv struct {
		Code string `json:"code"`
	}
	ravi.call("POST", "invites/create", map[string]any{"uses": 1}, &inv)
	say("Ravi's code: @%s::%s", ravi.handle, inv.Code)
	kat.contactRequest(ravi, inv.Code)
	req := ravi.waitFor(func(it item) bool { return it.Notice != nil })
	say("Ravi's server delivered the request: %s", oneLine(req.Notice))

	step("Ravi accepts, claims Kat's key packages through %s, and starts a direct chat with %s as hub", srvB.name, srvB.name)
	ravi.call("POST", "contacts/accept", map[string]any{"id": kat.id}, nil)
	var kps struct {
		Packages []struct {
			KP wire.Bytes `json:"kp"`
		} `json:"packages"`
	}
	ravi.call("POST", "keypackages/claim", map[string]any{"id": kat.id}, &kps)
	if len(kps.Packages) != 1 {
		fail("claimed %d key packages, want 1", len(kps.Packages))
	}
	say("claimed Kat's key package: %q", kps.Packages[0].KP)
	group := randBytes(32)
	epoch0 := ed25519.NewKeyFromSeed(randBytes(32)) // stands in for MLS-Exporter("tieroute hub", ...) (SPEC §11.6)
	ravi.call("POST", "groups/create", map[string]any{"group": group, "kind": "direct", "epoch-key": epoch0.Public()}, nil)
	epoch1 := ed25519.NewKeyFromSeed(randBytes(32))
	commit := []byte("placeholder MLS commit adding kat")
	sum := sha256.Sum256(commit)
	cr, _ := wire.Sign("commit-request", map[string]any{"group": group, "epoch": 0, "hash": sum[:], "next": epoch1.Public()}, epoch0)
	res := ravi.send(map[string]any{
		"id": randBytes(16), "kind": "mls", "to": []string{ravi.id, kat.id}, "group": group, "epoch": 0, "mls": "commit",
		"data": commit, "commit": cr,
		"welcomes": []any{map[string]any{"id": randBytes(16), "to": []string{kat.id}, "data": []byte("placeholder MLS Welcome")}},
	})
	say("the hub accepted epoch 0 and signed a receipt: %s", oneLine(res["receipt"]))

	step("Kat's server takes the Welcome, because it comes from someone Kat asked")
	welcome := kat.waitFor(func(it item) bool { return it.Delivery != nil && it.Delivery.MLS == "welcome" })
	say("Welcome from %s: %q", welcome.Delivery.From, welcome.Delivery.Data)
	kat.call("POST", "groups/register", map[string]any{"group": group}, nil)

	step("They talk across servers")
	kat.send(map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id, ravi.id}, "group": group, "epoch": 1, "mls": "app", "data": []byte("placeholder ciphertext: hi ravi")})
	got := ravi.waitFor(func(it item) bool {
		return it.Delivery != nil && it.Delivery.MLS == "app" && it.Delivery.From == kat.id
	})
	say("Ravi received %q from %s", got.Delivery.Data, got.Delivery.From)
	ravi.send(map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{ravi.id, kat.id}, "group": group, "epoch": 1, "mls": "app", "data": []byte("placeholder ciphertext: hi kat")})
	got = kat.waitFor(func(it item) bool {
		return it.Delivery != nil && it.Delivery.MLS == "app" && it.Delivery.From == ravi.id
	})
	say("Kat received %q from %s", got.Delivery.Data, got.Delivery.From)

	step("A stale commit loses: the hub accepts one commit per epoch (SPEC §11.6)")
	late, _ := wire.Sign("commit-request", map[string]any{"group": group, "epoch": 0, "hash": sum[:], "next": epoch1.Public()}, epoch0)
	r := kat.sendRaw(map[string]any{"id": randBytes(16), "kind": "mls", "to": []string{kat.id, ravi.id}, "group": group, "epoch": 0, "mls": "commit", "data": commit, "commit": late, "hub": srvB.name})
	say("Kat's commit for epoch 0 through %s's hub: %s %s", srvB.name, r["status"], r["error"])

	step("What a delivery looks like on the wire: plain JSON, with MLS bytes in base64url")
	raw, _ := json.MarshalIndent(got.raw, "  ", "  ")
	fmt.Printf("  %s\n", raw)

	fmt.Println("\nLine test passed: two homeservers federated on wire version 1.")
}

// ---- servers and users ----

type server struct {
	name, origin string
	client       string // client API base, from the server document
	invite       string // published registration invite
}

func discover(arg string) server {
	name, origin, ok := strings.Cut(arg, "=")
	if !ok {
		fail("want name=origin, got %q", arg)
	}
	step("Discovering %s: GET %s/.well-known/tieroute/server", name, origin)
	b := get(origin + "/.well-known/tieroute/server")
	var doc struct {
		Name string `json:"name"`
		APIs []struct {
			V      int    `json:"v"`
			Client string `json:"client"`
			S2S    string `json:"s2s"`
		} `json:"apis"`
		Registration string `json:"registration"`
		Invite       string `json:"invite"`
	}
	must(wire.Unmarshal(b, &doc))
	s := server{name: doc.Name, origin: origin, invite: doc.Invite}
	for _, a := range doc.APIs {
		if a.V == 1 {
			s.client = a.Client
			say("v1 client API: %s", a.Client)
			say("v1 S2S API:    %s", a.S2S)
		}
	}
	if s.client == "" || doc.Name != name {
		fail("%s doesn't publish a v1 client API", name)
	}
	say("registration: %s, public invite: %q", doc.Registration, doc.Invite)
	return s
}

type user struct {
	srv        server
	id, handle string
	dev        ed25519.PrivateKey
	token      string
	after      string
	pending    []item
}

type item struct {
	Cursor   string    `json:"cursor"`
	Delivery *delivery `json:"delivery"`
	Notice   wire.Raw  `json:"notice"`
	raw      any
}

type delivery struct {
	ID   wire.Bytes `json:"id"`
	From string     `json:"from"`
	MLS  string     `json:"mls"`
	Data wire.Bytes `json:"data"`
}

func register(s server, name string) *user {
	u := &user{srv: s, dev: ed25519.NewKeyFromSeed(randBytes(32)), handle: name + "." + s.name}
	rec := ed25519.NewKeyFromSeed(randBytes(32))
	commit := sha256.Sum256(rec.Public().(ed25519.PublicKey))
	genesis, _ := wire.Sign("chain-entry", map[string]any{
		"seq": 0, "ts": time.Now().Unix(),
		"ops": []any{
			map[string]any{"op": "add-device", "key": u.dev.Public(), "name": name + "'s line test"},
			map[string]any{"op": "set-home", "home": s.name},
			map[string]any{"op": "set-handle", "handle": u.handle},
			map[string]any{"op": "set-recovery", "next": commit[:]},
		},
	}, u.dev)
	var reg struct {
		ID string `json:"id"`
	}
	u.call("POST", "register", map[string]any{"genesis": genesis, "invite": s.invite}, &reg)
	u.id = reg.ID
	var ch struct {
		Nonce wire.Bytes `json:"nonce"`
	}
	u.call("POST", "auth/challenge", map[string]any{"id": u.id, "key": u.dev.Public()}, &ch)
	auth, _ := wire.Sign("auth", map[string]any{"id": u.id, "nonce": ch.Nonce, "server": s.name, "ts": time.Now().Unix()}, u.dev)
	var sess struct {
		Token string `json:"token"`
	}
	u.call("POST", "auth/session", map[string]any{"auth": auth}, &sess)
	u.token = sess.Token
	u.call("POST", "keypackages/upload", map[string]any{"packages": [][]byte{[]byte("placeholder key package for " + name)}}, nil)
	say("@%s is %s", u.handle, u.id)
	return u
}

func (u *user) contactRequest(to *user, code string) {
	var res struct {
		ID string `json:"id"`
	}
	u.call("GET", "resolve/"+url.PathEscape(to.handle), nil, &res)
	body := map[string]any{"from": u.id, "to": res.ID, "ts": time.Now().Unix(), "nonce": randBytes(16), "invite": code}
	req, _ := wire.Sign("contact-request", body, u.dev)
	st := u.call("POST", "contacts/request", map[string]any{"request": req}, nil)
	say("contact request with invite %q: %d", code, st)
}

func (u *user) send(d map[string]any) map[string]any {
	r := u.sendRaw(d)
	if r["status"] != "sent" {
		fail("send: %v", r)
	}
	return r
}

func (u *user) sendRaw(d map[string]any) map[string]any {
	var res struct {
		Results []map[string]any `json:"results"`
	}
	u.call("POST", "send", map[string]any{"deliveries": []any{d}}, &res)
	return res.Results[0]
}

func (u *user) inbox() []item {
	var res struct {
		Items []json.RawMessage `json:"items"`
		Next  string            `json:"next"`
	}
	path := "inbox"
	if u.after != "" {
		path += "?after=" + url.QueryEscape(u.after)
	}
	u.call("GET", path, nil, &res)
	var out []item
	for _, raw := range res.Items {
		var it item
		must(wire.Unmarshal(raw, &it))
		json.Unmarshal(raw, &it.raw)
		out = append(out, it)
		u.after = it.Cursor
	}
	return out
}

func (u *user) waitFor(match func(item) bool) item {
	for range 100 {
		u.pending = append(u.pending, u.inbox()...)
		for i, it := range u.pending {
			if match(it) {
				u.pending = append(u.pending[:i:i], u.pending[i+1:]...)
				return it
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	fail("@%s: the expected inbox item never arrived", u.handle)
	return item{}
}

// call makes a client API request relative to the base the server document gave.
func (u *user) call(method, path string, body, out any) int {
	var rd io.Reader
	var b []byte
	if body != nil {
		var err error
		b, err = wire.Marshal(body)
		must(err)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, u.srv.client+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", wire.MediaType)
	}
	if u.token != "" {
		req.Header.Set("Authorization", "Bearer "+u.token)
	}
	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if *verbose {
		fmt.Printf("    > %s %s %s\n    < %d %s\n", method, path, b, resp.StatusCode, rb)
	}
	if resp.StatusCode/100 != 2 {
		fail("%s %s: %d %s", method, path, resp.StatusCode, rb)
	}
	if out != nil && len(rb) > 0 {
		must(wire.Unmarshal(rb, out))
	}
	return resp.StatusCode
}

// ---- helpers ----

func get(u string) []byte {
	resp, err := http.Get(u)
	must(err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != wire.MediaType {
		fail("GET %s: %d %s", u, resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	return b
}

func oneLine(v any) string {
	b, _ := json.Marshal(v)
	if raw, ok := v.(wire.Raw); ok {
		b = raw
	}
	if s := string(b); len(s) > 140 {
		return s[:140] + "…"
	} else {
		return s
	}
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func step(f string, a ...any) { fmt.Printf("\n\033[1m== "+f+"\033[0m\n", a...) }
func say(f string, a ...any)  { fmt.Printf("  "+f+"\n", a...) }

func must(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "\nline test FAILED: "+f+"\n", a...)
	os.Exit(1)
}
