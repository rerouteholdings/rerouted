package wire

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"unicode/utf8"
)

// Fuzz targets for what arrives from the network: any body, any envelope, any key. Run one
// with go test -fuzz=FuzzIJSON ./internal/wire; plain go test runs the seeds.

// seedVectors adds every string in the spec's vectors that looks like JSON: bodies,
// envelopes, and signature inputs.
func seedVectors(f *testing.F, files ...string) {
	for _, name := range files {
		b, err := os.ReadFile("../../testdata/vectors/" + name)
		if err != nil {
			f.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			f.Fatal(err)
		}
		var walk func(any)
		walk = func(v any) {
			switch v := v.(type) {
			case map[string]any:
				for _, e := range v {
					walk(e)
				}
			case []any:
				for _, e := range v {
					walk(e)
				}
			case string:
				if len(v) > 1 && (v[0] == '{' || v[0] == '[') {
					f.Add([]byte(v))
				}
			}
		}
		walk(v)
	}
}

// decodeAny decodes b with numbers as their values, so -0 and 0 compare equal, as JCS has them.
func decodeAny(t *testing.T, b []byte) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatalf("%q: %v", b, err)
	}
	var norm func(any) any
	norm = func(v any) any {
		switch v := v.(type) {
		case json.Number:
			i, err := parseInt(v)
			if err != nil {
				t.Fatalf("%q: %v", b, err)
			}
			return i
		case map[string]any:
			for k, e := range v {
				v[k] = norm(e)
			}
		case []any:
			for i, e := range v {
				v[i] = norm(e)
			}
		}
		return v
	}
	return norm(v)
}

// Anything CheckIJSON accepts canonicalizes, to the same value, as JCS that is its own
// canonical form; anything it refuses doesn't.
func FuzzIJSON(f *testing.F) {
	for _, s := range []string{
		`{}`, `[]`, `0`, `-0`, `"x"`, `null`, `true`, `{"a":1,"b":[1,2,{"c":null}]}`,
		`{"b":1,"a":2}`, `{"a":1,"a":2}`, `9007199254740991`, `9007199254740992`, `1.5`, `1e3`,
		`"é😀"`, `"\ud800"`, `"\u0000"`, `{"a":1,"a":2}`, `[1] [2]`, ` {"a" : [ ] } `,
		"\"\xff\"", `{"a":" "}`, `[[[[[[[[[[]]]]]]]]]]`,
	} {
		f.Add([]byte(s))
	}
	seedVectors(f, "chain.json", "v2/signed.json", "v2/s2s.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		checkErr := CheckIJSON(data)
		c, err := Canonical(data)
		if checkErr != nil {
			if err == nil {
				t.Fatalf("CheckIJSON refused %q (%v), but Canonical accepted it", data, checkErr)
			}
			return
		}
		if err != nil {
			t.Fatalf("CheckIJSON accepted %q, but Canonical refused it: %v", data, err)
		}
		if err := CheckIJSON(c); err != nil {
			t.Fatalf("canonical form %q isn't I-JSON: %v", c, err)
		}
		if again, err := Canonical(c); err != nil || !bytes.Equal(again, c) {
			t.Fatalf("not idempotent: %q, then %q (%v)", c, again, err)
		}
		if !reflect.DeepEqual(decodeAny(t, data), decodeAny(t, c)) {
			t.Fatalf("canonicalizing %q changed its value: %q", data, c)
		}
		var v any
		if err := Unmarshal(data, &v); err != nil {
			t.Fatalf("Unmarshal refused what CheckIJSON accepted: %v", err)
		}
		// Nothing was replaced on the way in: U+FFFD only where the input has one.
		if bytes.ContainsRune(c, utf8.RuneError) && !bytes.ContainsRune(data, utf8.RuneError) &&
			!bytes.Contains(bytes.ToLower(data), []byte(`\ufffd`)) {
			t.Fatalf("%q read as %q: something became U+FFFD", data, c)
		}
	})
}

// A decoded envelope encodes to JCS that decodes to the same envelope, under either wire
// version's rules, and never verifies against a key that didn't sign it.
func FuzzDecodeSigned(f *testing.F) {
	seedVectors(f, "chain.json", "recovery.json", "v2/signed.json", "v2/chain.json", "v2/s2s.json")
	f.Add([]byte(`{"t":"x","b":"{}","kid":"k","s":""}`))
	other, err := GenerateCompositeKey()
	if err != nil {
		f.Fatal(err)
	}
	ed := other.Public().Ed25519()
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, v := range []int{V1, V2} {
			s, err := DecodeSignedFor(v, data)
			if err != nil {
				continue
			}
			enc, err := s.Encode()
			if err != nil {
				t.Fatalf("v%d: decoded %q but can't encode it: %v", v, data, err)
			}
			s2, err := DecodeSignedFor(v, enc)
			if err != nil {
				t.Fatalf("v%d: re-encoded %q doesn't decode: %v", v, enc, err)
			}
			enc2, _ := s2.Encode()
			if !bytes.Equal(enc, enc2) || s.T != s2.T || s.B != s2.B || s.KID != s2.KID ||
				!bytes.Equal(s.K, s2.K) || !bytes.Equal(s.S, s2.S) {
				t.Fatalf("v%d: round trip changed it: %q, then %q", v, enc, enc2)
			}
			if c, err := CanonicalSignedFor(v, data); err != nil || !bytes.Equal(c, enc) {
				t.Fatalf("v%d: CanonicalSignedFor disagrees with Encode: %v", v, err)
			}
			if _, err := s.Hash(); err != nil {
				t.Fatalf("v%d: Hash: %v", v, err)
			}
			if s.Verify("", ed) == nil || s.VerifyComposite("", other.Public()) == nil || s.VerifyMessageKey("", ed) == nil {
				t.Fatalf("v%d: %q verifies with a key that never signed anything", v, data)
			}
			s.VerifySelf("")
			s.VerifyCompositeSelf("")
		}
	})
}

// A composite public key parses only from its exact encoding, and nothing random verifies.
func FuzzCompositePublicKey(f *testing.F) {
	k, err := GenerateCompositeKey()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(k.Public().Bytes(), []byte("message"), make([]byte, CompositeSignatureSize))
	f.Add(make([]byte, CompositePublicKeySize), []byte{}, []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, pubBytes, msg, sig []byte) {
		pub, err := ParseCompositePublicKey(pubBytes)
		if err != nil {
			return
		}
		if !bytes.Equal(pub.Bytes(), pubBytes) || len(pub.Ed25519()) != 32 {
			t.Fatalf("parsed key doesn't encode back to its input")
		}
		s := Signed{T: "x", B: string(msg), K: Bytes(pub.Ed25519()), S: sig}
		if s.VerifyComposite("x", pub) == nil {
			t.Fatalf("a signature nobody made verifies")
		}
	})
}
