package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestVectorSigned(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/signed.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Signer struct {
			SeedHex   string `json:"seed_hex"`
			PublicHex string `json:"public_hex"`
		} `json:"signer"`
		Signed struct {
			Type     string `json:"type"`
			Body     string `json:"body"`
			SigInput string `json:"sig_input"`
			Signed   string `json:"signed"`
			SHA256   string `json:"signed_sha256"`
		} `json:"signed"`
		Reject []struct {
			Note   string `json:"note"`
			Signed string `json:"signed"`
		} `json:"reject"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(v.Signer.PublicHex)
	s, err := DecodeSigned([]byte(v.Signed.Signed))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(v.Signed.Type, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, r := range v.Reject {
		if _, err := DecodeSigned([]byte(r.Signed)); err == nil {
			t.Errorf("accepted: %s", r.Note)
		}
	}
	if in, _ := sigInput(s.T, s.B); string(in) != v.Signed.SigInput {
		t.Fatalf("signature input:\n got %s\nwant %s", in, v.Signed.SigInput)
	}
	if h, _ := s.Hash(); hex.EncodeToString(h) != v.Signed.SHA256 {
		t.Fatal("hash differs")
	}
	// Signing the same body with the same key reproduces the vector exactly
	// (Ed25519 is deterministic, and JCS is canonical).
	seed, _ := hex.DecodeString(v.Signer.SeedHex)
	var body map[string]any
	if err := s.Open(&body); err != nil {
		t.Fatal(err)
	}
	again, err := Sign(v.Signed.Type, body, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	if again.B != v.Signed.Body {
		t.Fatalf("body:\n got %s\nwant %s", again.B, v.Signed.Body)
	}
	if enc, _ := again.Encode(); string(enc) != v.Signed.Signed {
		t.Fatalf("re-signed envelope differs:\n got %s\nwant %s", enc, v.Signed.Signed)
	}
	// The type tag is part of the signature input: a different tag fails.
	if s.Verify("contact-request", pub) == nil {
		t.Fatal("verified under the wrong type tag")
	}
}

// A signed object may travel in any layout; its hash is over JCS (SPEC §4.3).
func TestSignedLayoutIndependent(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	s, _ := Sign("auth", map[string]any{"b": 1, "a": "x"}, priv)
	enc, _ := s.Encode()
	var m map[string]any
	json.Unmarshal(enc, &m)
	pretty, _ := json.MarshalIndent(m, "", "    ")
	again, err := CanonicalSigned(pretty)
	if err != nil || string(again) != string(enc) {
		t.Fatalf("re-canonicalized: %v\n%s\n%s", err, again, enc)
	}
}

func TestIJSONRules(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{`{"a":1}`, true},
		{` { "b" : [1, {"c": null}], "a": "x" } `, true},
		{`{"a":1,"a":2}`, false},          // duplicate names, anywhere
		{`{"a":{"b":1,"b":2}}`, false},    // nested too
		{`[{"a":1},{"a":1}]`, true},       // separate objects may share names
		{`{"a":1.5}`, false},              // integers only
		{`{"a":1e3}`, false},              // no exponents
		{`{"a":9007199254740992}`, false}, // beyond ±(2^53 − 1)
		{`{"a":1} {"b":2}`, false},        // one value only
		{"{\"a\":\"\xff\"}", false},       // invalid UTF-8
	} {
		var v any
		err := Unmarshal([]byte(c.in), &v)
		if (err == nil) != c.ok {
			t.Errorf("%q: err = %v, want ok = %v", c.in, err, c.ok)
		}
	}
	var v any
	if err := Unmarshal([]byte(`{"a":1,"a":2}`), &v); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("duplicate names: %v", err)
	}
}

func TestJCS(t *testing.T) {
	// Member names sort by UTF-16 code units; strings escape like JSON.stringify.
	got, err := Marshal(map[string]any{"b": "<&> é\n\x01", "a": []any{true, nil, int64(-5)}, "\U0001F600": 1, "￿": 2})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[true,null,-5],"b":"<&>` + " é" + `\n\u0001","` + "\U0001F600" + `":1,"` + "￿" + `":2}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestBytesBase64URL(t *testing.T) {
	enc, _ := Marshal(map[string]any{"k": []byte{0xfb, 0xff}})
	if string(enc) != `{"k":"-_8"}` {
		t.Fatalf("got %s", enc)
	}
	var v struct {
		K Bytes `json:"k"`
	}
	for _, bad := range []string{`{"k":"-_8="}`, `{"k":"+/8"}`, `{"k":"-_9"}`} { // padding, std alphabet, non-canonical bits
		if Unmarshal([]byte(bad), &v) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := Unmarshal(enc, &v); err != nil || string(v.K) != "\xfb\xff" {
		t.Fatalf("round trip: %v %x", err, v.K)
	}
}

func TestIdentityIDFormat(t *testing.T) {
	if id := IdentityID([]byte("anything")); !ValidIdentityID(id) {
		t.Fatalf("%s isn't a valid identifier", id)
	}
}

// SPEC §4.3: every implementation must agree on these, or chains split.
func TestVectorEd25519(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors/ed25519.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Name  string `json:"name"`
			Pub   string `json:"public_hex"`
			Msg   string `json:"message_hex"`
			Sig   string `json:"signature_hex"`
			Valid bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		pub, _ := hex.DecodeString(c.Pub)
		msg, _ := hex.DecodeString(c.Msg)
		sig, _ := hex.DecodeString(c.Sig)
		if got := VerifyStrict(pub, msg, sig); got != c.Valid {
			t.Errorf("%s: valid = %v, want %v", c.Name, got, c.Valid)
		}
		// Why the small-order rule exists: the plain check accepts the all-zero forgery.
		if c.Name == "identity key and identity R, S = 0" && !ed25519.Verify(pub, msg, sig) {
			t.Log("note: this crypto/ed25519 already rejects the identity forgery")
		}
	}
}
