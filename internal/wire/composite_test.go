package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// readVector decodes a wire version 2 vector file into v.
func readVector(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/vectors/v2/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vectorKey is a composite key as the vectors give it: its seeds, and what they must produce.
type vectorKey struct {
	MLDSASeed    string `json:"mldsa_seed_hex"`
	Ed25519Seed  string `json:"ed25519_seed_hex"`
	RecoverySeed string `json:"recovery_seed_hex"`
	Public       string `json:"public_hex"`
	Ed25519Pub   string `json:"ed25519_public"`
	Commitment   string `json:"commitment_sha256"`
}

// key builds the key from its seeds and checks it against the vector's public key.
func (k vectorKey) key(t *testing.T) *CompositePrivateKey {
	t.Helper()
	edSeed := k.Ed25519Seed
	if edSeed == "" {
		edSeed = k.RecoverySeed
	}
	priv, err := NewCompositeKey(unhex(t, k.MLDSASeed), unhex(t, edSeed))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(priv.Public().Bytes()) != k.Public {
		t.Fatal("composite public key doesn't match the vector")
	}
	if hex.EncodeToString(priv.Public().Ed25519()) != k.Ed25519Pub {
		t.Fatal("Ed25519 component doesn't match the vector")
	}
	return priv
}

// SPEC §3.2.1: the construction, checked first against RFC 10073's own known answers.
func TestVectorComposite(t *testing.T) {
	var v struct {
		Construction struct {
			Prefix    string `json:"prefix_hex"`
			Label     string `json:"label_hex"`
			PubBytes  int    `json:"public_key_bytes"`
			SigBytes  int    `json:"signature_bytes"`
			MLDSACtx  string `json:"mldsa_context"`
			AppCtx    string `json:"application_ctx"`
			PreHash   string `json:"pre_hash"`
			Algorithm string `json:"oid"`
		} `json:"construction"`
		Representative struct {
			Message string `json:"message_hex"`
			SHA512  string `json:"sha512_hex"`
			MPrime  string `json:"m_prime_hex"`
		} `json:"message_representative"`
		RFC struct {
			Message string `json:"message"`
			Ctx     string `json:"ctx"`
			PK      string `json:"pk_hex"`
			SK      string `json:"sk_hex"`
			Sig     string `json:"signature_hex"`
			SigCtx  string `json:"signature_with_ctx_hex"`
		} `json:"rfc10073"`
	}
	readVector(t, "composite.json", &v)

	pk, sk := unhex(t, v.RFC.PK), unhex(t, v.RFC.SK)
	msg, ctx := []byte(v.RFC.Message), []byte(v.RFC.Ctx)
	sig, sigCtx := unhex(t, v.RFC.Sig), unhex(t, v.RFC.SigCtx)
	priv, err := NewCompositeKey(sk[:32], sk[32:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.Public().Bytes(), pk) {
		t.Fatal("RFC 10073 key doesn't regenerate from its seeds")
	}
	pub, err := ParseCompositePublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(msg, sig) {
		t.Fatal("RFC 10073 signature doesn't verify")
	}
	if !pub.verify(msg, sigCtx, ctx) {
		t.Fatal("RFC 10073 signature with ctx doesn't verify")
	}
	if pub.Verify(msg, sigCtx) || pub.verify(msg, sig, ctx) {
		t.Fatal("a signature verified under the wrong ctx")
	}

	c := v.Construction
	if c.Prefix != hex.EncodeToString([]byte(compositePrefix)) || c.Label != hex.EncodeToString([]byte(compositeLabel)) ||
		c.MLDSACtx != compositeLabel || c.AppCtx != "" || c.PreHash != "SHA-512" {
		t.Fatal("construction constants differ")
	}
	if c.PubBytes != CompositePublicKeySize || c.SigBytes != CompositeSignatureSize {
		t.Fatal("sizes differ")
	}
	m := compositeMessage(unhex(t, v.Representative.Message), nil)
	if hex.EncodeToString(m) != v.Representative.MPrime {
		t.Fatalf("M':\n got %x\nwant %s", m, v.Representative.MPrime)
	}
	if !bytes.HasSuffix(m, unhex(t, v.Representative.SHA512)) {
		t.Fatal("M' doesn't end in SHA-512(M)")
	}
}

func TestCompositeSignVerify(t *testing.T) {
	k, err := GenerateCompositeKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("tieroute")
	sig, err := k.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != CompositeSignatureSize || !k.Public().Verify(msg, sig) {
		t.Fatal("hedged signature doesn't verify")
	}
	if k.Public().Verify([]byte("tieroutf"), sig) {
		t.Fatal("verified over another message")
	}
	if _, err := ParseCompositePublicKey(k.Public().Bytes()[1:]); err == nil {
		t.Fatal("accepted a short key")
	}
	if _, err := NewCompositeKey(make([]byte, 31), make([]byte, 32)); err == nil {
		t.Fatal("accepted a short seed")
	}
}

// SPEC §6.1, §6.3: composite recovery keys from the recovery code, and their commitments.
func TestVectorRecoveryV2(t *testing.T) {
	var v struct {
		Code string    `json:"code_hex"`
		K1   vectorKey `json:"recovery_key_1"`
		K2   vectorKey `json:"recovery_key_2"`
		K3   vectorKey `json:"recovery_key_3"`
		// prk_hex, recovery_wrap_hex, and code_words are client-side (the account key wrap
		// and BIP-39); rerouted never sees them, so they're not checked here.
	}
	readVector(t, "recovery.json", &v)
	code := unhex(t, v.Code)
	for i, want := range []vectorKey{v.K1, v.K2, v.K3} {
		k, err := RecoveryKey(code, uint32(i+1))
		if err != nil {
			t.Fatal(err)
		}
		if got := want.key(t); !got.Public().Equal(k.Public()) {
			t.Fatalf("recovery key %d differs from its seeds", i+1)
		}
		if hex.EncodeToString(k.Public().Hash()) != want.Commitment {
			t.Fatalf("recovery key %d: commitment differs", i+1)
		}
	}
}
