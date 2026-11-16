package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
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

// A lone surrogate isn't I-JSON (RFC 7493 §2.1), and encoding/json would read it as U+FFFD,
// so a body with one means something else to other readers. A pair is a character.
func TestLoneSurrogate(t *testing.T) {
	for _, s := range []string{`"\ud800"`, `"\uDBFF"`, `"\udc00"`, `"x\ud800y"`, `"\ud800A"`, `"\ud800\ud800"`, `{"\ud800":1}`, `["\\", "\udfff"]`} {
		if err := CheckIJSON([]byte(s)); !errors.Is(err, ErrSurrogate) {
			t.Errorf("%s: %v, want ErrSurrogate", s, err)
		}
	}
	for _, s := range []string{`"😀"`, `"😀"`, `"\\ud800"`, `"\\\\"`, `"é"`, `"�"`, `"\"😀"`, "\"￾\""} {
		if err := CheckIJSON([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

// Member names are matched exactly: encoding/json alone would take "ID" for "id", and an
// object a stricter reader refuses would be accepted here.
func TestMemberNamesExact(t *testing.T) {
	type inner struct {
		Op  string `json:"op"`
		Key Bytes  `json:"key,omitempty"`
	}
	type embedded struct {
		Extra int `json:"extra"`
	}
	type outer struct {
		embedded
		ID    string           `json:"id"`
		Ops   []inner          `json:"ops"`
		ByKey map[string]inner `json:"by_key"`
		Ptr   *inner           `json:"ptr"`
		Raw   Raw              `json:"raw"`
		Any   any              `json:"any"`
		Plain string
		skip  int
	}
	_ = outer{}.skip
	for _, s := range []string{
		`{"ID":"x"}`, `{"Id":"x"}`, `{"id":"x","ID":"y"}`, `{"ops":[{"OP":"a"}]}`, `{"ops":[{"op":"a"},{"Op":"b"}]}`,
		`{"by_key":{"k":{"OP":"a"}}}`, `{"ptr":{"Key":"AA"}}`, `{"EXTRA":1}`, `{"plain":"x"}`, `{"By_Key":{}}`,
	} {
		var v outer
		if err := Unmarshal([]byte(s), &v); !errors.Is(err, ErrMemberCase) {
			t.Errorf("Unmarshal %s: %v, want ErrMemberCase", s, err)
		}
		if err := UnmarshalClosed([]byte(s), &v); !errors.Is(err, ErrMemberCase) {
			t.Errorf("UnmarshalClosed %s: %v, want ErrMemberCase", s, err)
		}
	}
	// Exact names decode as ever. What isn't decoded here isn't judged here: map keys, raw
	// members (checked when they're decoded), and any.
	var v outer
	ok := `{"id":"x","extra":2,"ops":[{"op":"a","key":"AA"}],"by_key":{"OP":{"op":"b"}},"ptr":{"op":"c"},"raw":{"ID":1},"any":{"ID":1},"Plain":"p","other":{"ID":1}}`
	if err := Unmarshal([]byte(ok), &v); err != nil || v.ID != "x" || v.Extra != 2 || len(v.Ops) != 1 || v.ByKey["OP"].Op != "b" || v.Ptr.Op != "c" || v.Plain != "p" {
		t.Fatalf("exact names: %v %+v", err, v)
	}
	var e ChainEntry
	if err := UnmarshalClosed([]byte(`{"ID":"tr:x","SEQ":3,"Ops":[]}`), &e); !errors.Is(err, ErrMemberCase) {
		t.Fatalf("a chain entry with its names in capitals: %v", err)
	}
	var m map[string]any
	if err := Unmarshal([]byte(`{"ID":1,"id":2}`), &m); err != nil || len(m) != 2 {
		t.Fatalf("a map keeps both: %v", err)
	}
}

// A value may nest MaxDepth deep, and no deeper: each level costs memory to check.
func TestMaxDepth(t *testing.T) {
	deep := func(n int) []byte {
		return []byte(strings.Repeat("[", n) + strings.Repeat("]", n))
	}
	if err := CheckIJSON(deep(MaxDepth)); err != nil {
		t.Fatalf("%d levels: %v", MaxDepth, err)
	}
	if err := CheckIJSON(deep(MaxDepth + 1)); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("%d levels: %v", MaxDepth+1, err)
	}
	if err := CheckIJSON([]byte(strings.Repeat(`{"a":`, MaxDepth+1) + "1" + strings.Repeat("}", MaxDepth+1))); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("objects: %v", err)
	}
	if err := CheckIJSON([]byte(strings.Repeat("[", 1<<20))); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("a megabyte of [: %v", err)
	}
}
