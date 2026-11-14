package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The wire version 2 vectors, as far as this layer goes: envelopes, composite signatures,
// msg-key, and kp-binding. Not checked here, and why:
//   - chain.json's final state, fork.json's cases, and migrate.json's cases need wire
//     version 2 chain validation (SPEC §6.4, §6.4.1, §6.8) in internal/chain, the next phase.
//     Their signatures, identifiers, and links are checked below.
//   - code.json's Argon2id and HKDF derivation of the code key belongs to community servers
//     (SPEC §16.6), a later phase; its join proof's signature is checked below.
//   - s2s.json's request rules (SPEC §8.3) and server document key wait for wire version 2
//     federation in internal/fed; its signature is checked below.
//   - codes.json has no signature: verification codes (SPEC §6.7) are computed by clients
//     alone, and rerouted never computes one.

// vectorSigned is a signed object as the vectors give it.
type vectorSigned struct {
	Type     string `json:"type"`
	Body     string `json:"body"`
	SigInput string `json:"sig_input"`
	SigHex   string `json:"signature_hex"`
	Signed   string `json:"signed"`
	SHA256   string `json:"signed_sha256"`
}

// decode decodes the envelope and checks every byte the vector pins: the body, the
// signature input, the signature, the envelope's JCS, and its hash.
func (v vectorSigned) decode(t *testing.T) Signed {
	t.Helper()
	s, err := DecodeSignedV2([]byte(v.Signed))
	if err != nil {
		t.Fatalf("%s: %v", v.Type, err)
	}
	if s.T != v.Type || s.B != v.Body {
		t.Fatalf("%s: type or body differs", v.Type)
	}
	if in, _ := SigInputV2(s.T, s.B); string(in) != v.SigInput {
		t.Fatalf("%s: signature input:\n got %s\nwant %s", v.Type, in, v.SigInput)
	}
	if hex.EncodeToString(s.S) != v.SigHex {
		t.Fatalf("%s: signature differs", v.Type)
	}
	if enc, _ := s.Encode(); string(enc) != v.Signed {
		t.Fatalf("%s: JCS of the envelope differs", v.Type)
	}
	if h, _ := s.Hash(); hex.EncodeToString(h) != v.SHA256 {
		t.Fatalf("%s: hash differs", v.Type)
	}
	return s
}

// resign signs the vector's body again, deterministically, as the generator did, and
// checks the envelope comes out byte for byte the same.
func (v vectorSigned) resign(t *testing.T, s Signed, priv *CompositePrivateKey) {
	t.Helper()
	var body any
	if err := s.Open(&body); err != nil {
		t.Fatal(err)
	}
	again, err := signV2(s.T, body, priv, s.K, s.KID, true)
	if err != nil {
		t.Fatal(err)
	}
	if enc, _ := again.Encode(); string(enc) != v.Signed {
		t.Fatalf("%s: re-signed envelope differs", v.Type)
	}
}

func mustDecodeV2(t *testing.T, text string) Signed {
	t.Helper()
	s, err := DecodeSignedV2([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// SPEC §3.2.2, §4.3.
func TestVectorSignedV2(t *testing.T) {
	var v struct {
		Signer    vectorKey    `json:"signer"`
		Signed    vectorSigned `json:"signed"`
		Composite struct {
			SHA512  string `json:"sha512_hex"`
			MPrime  string `json:"m_prime_hex"`
			MLDSA   string `json:"mldsa_signature_hex"`
			Ed25519 string `json:"ed25519_signature_hex"`
		} `json:"composite"`
		MessageKey struct {
			Seed   string `json:"seed_hex"`
			Public string `json:"public_hex"`
		} `json:"message_key"`
		MessageKeySigned vectorSigned `json:"message_key_signed"`
		Reject           []struct {
			Note   string `json:"note"`
			Signed string `json:"signed"`
		} `json:"reject"`
	}
	readVector(t, "signed.json", &v)
	priv := v.Signer.key(t)
	pub := priv.Public()

	s := v.Signed.decode(t)
	if !bytes.Equal(s.K, pub.Ed25519()) {
		t.Fatal("k isn't the device's Ed25519 component")
	}
	if err := s.VerifyComposite("auth", pub); err != nil {
		t.Fatalf("VerifyComposite: %v", err)
	}
	if s.VerifyComposite("contact-request", pub) == nil {
		t.Fatal("verified under the wrong type tag")
	}
	in, _ := SigInputV2(s.T, s.B)
	if hex.EncodeToString(compositeMessage(in, nil)) != v.Composite.MPrime {
		t.Fatal("M' differs")
	}
	if hex.EncodeToString(s.S[:mldsa.MLDSA65SignatureSize]) != v.Composite.MLDSA ||
		hex.EncodeToString(s.S[mldsa.MLDSA65SignatureSize:]) != v.Composite.Ed25519 {
		t.Fatal("components differ")
	}
	v.Signed.resign(t, s, priv)
	// Version 1 doesn't take a version 2 envelope.
	if _, err := DecodeSigned([]byte(v.Signed.Signed)); err == nil {
		t.Fatal("DecodeSigned accepted a composite signature")
	}

	mk := ed25519.NewKeyFromSeed(unhex(t, v.MessageKey.Seed)).Public().(ed25519.PublicKey)
	if hex.EncodeToString(mk) != v.MessageKey.Public {
		t.Fatal("message key differs")
	}
	m := v.MessageKeySigned.decode(t)
	if err := m.VerifyMessageKey("app-message", mk); err != nil {
		t.Fatalf("VerifyMessageKey: %v", err)
	}
	if m.VerifyMessageKey("app-message", pub.Ed25519()) == nil || m.VerifyComposite("app-message", pub) == nil {
		t.Fatal("a message key's signature verified as something else")
	}
	if s.VerifyMessageKey("auth", pub.Ed25519()) == nil {
		t.Fatal("a composite signature verified as a message key's")
	}

	if len(v.Reject) != 6 {
		t.Fatalf("%d rejects, want 6", len(v.Reject))
	}
	for _, r := range v.Reject {
		bad, err := DecodeSignedV2([]byte(r.Signed))
		if err == nil && bad.VerifyComposite("auth", pub) == nil {
			t.Errorf("accepted: %s", r.Note)
		}
	}
}

func TestSignedV2Shape(t *testing.T) {
	priv, err := GenerateCompositeKey()
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"x": 1}
	full, err := SignCompositeFull("t", body, priv)
	if err != nil {
		t.Fatal(err)
	}
	if pub, err := full.VerifyCompositeSelf("t"); err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("VerifyCompositeSelf: %v", err)
	}
	kid, err := SignCompositeKID("t", body, priv, "k1")
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := kid.Encode()
	if _, err := DecodeSignedV2(enc); err != nil {
		t.Fatal(err)
	}
	if kid.VerifyComposite("t", priv.Public()) != nil {
		t.Fatal("kid envelope doesn't verify")
	}
	// k must name the key verified against.
	other, _ := GenerateCompositeKey()
	if full.VerifyComposite("t", other.Public()) == nil {
		t.Fatal("verified against a key k doesn't name")
	}
	// Only a message key, with a 32-byte k, signs with Ed25519 alone.
	edOnly := Signed{T: "t", B: "{}", K: priv.Public().Bytes(), S: make([]byte, 64)}
	enc, _ = edOnly.Encode()
	if _, err := DecodeSignedV2(enc); err == nil {
		t.Fatal("accepted an Ed25519 signature with a composite k")
	}
	edOnly.K, edOnly.KID = nil, "k1"
	enc, _ = edOnly.Encode()
	if _, err := DecodeSignedV2(enc); err == nil {
		t.Fatal("accepted an Ed25519 signature from a server key")
	}
}

// chainKeys holds chain.json's device keys and recovery.json's recovery keys, by the
// names the vectors use.
func chainKeys(t *testing.T) (map[string]*CompositePrivateKey, string) {
	t.Helper()
	var c struct {
		Keys struct {
			D1 vectorKey `json:"device_1"`
			D2 vectorKey `json:"device_2"`
			D3 vectorKey `json:"device_3"`
		} `json:"keys"`
		ID string `json:"identity_id"`
	}
	readVector(t, "chain.json", &c)
	var r struct {
		Code string `json:"code_hex"`
	}
	readVector(t, "recovery.json", &r)
	keys := map[string]*CompositePrivateKey{
		"device_1": c.Keys.D1.key(t), "device_2": c.Keys.D2.key(t), "device_3": c.Keys.D3.key(t),
	}
	for i := uint32(1); i <= 3; i++ {
		k, err := RecoveryKey(unhex(t, r.Code), i)
		if err != nil {
			t.Fatal(err)
		}
		keys["recovery_key_"+string(rune('0'+i))] = k
	}
	return keys, c.ID
}

// v2Op is a wire version 2 chain op, as far as these tests read it.
type v2Op struct {
	Op   string `json:"op"`
	Key  Bytes  `json:"key"`
	Pub  Bytes  `json:"pub"`
	Next Bytes  `json:"next"`
	To   Bytes  `json:"to"`
}

type v2Entry struct {
	ID   string `json:"id"`
	Prev Bytes  `json:"prev"`
	Ops  []v2Op `json:"ops"`
}

// verifyEntry checks a chain entry's signature by the named signer: a device by its
// Ed25519 component in k, a recovery key by the whole composite key in k (SPEC §3.2.2).
// In add-device, key must be pub's Ed25519 component.
func verifyEntry(t *testing.T, name string, s Signed, signer *CompositePrivateKey) v2Entry {
	t.Helper()
	if strings.HasPrefix(name, "recovery_key_") {
		pub, err := s.VerifyCompositeSelf(TypeChainEntry)
		if err != nil || !pub.Equal(signer.Public()) {
			t.Fatalf("%s: recovery-signed entry doesn't verify: %v", name, err)
		}
	} else if err := s.VerifyComposite(TypeChainEntry, signer.Public()); err != nil {
		t.Fatalf("%s: device-signed entry doesn't verify: %v", name, err)
	}
	var e v2Entry
	if err := s.Open(&e); err != nil {
		t.Fatal(err)
	}
	for _, op := range e.Ops {
		if op.Op == OpAddDevice {
			pub, err := ParseCompositePublicKey(op.Pub)
			if err != nil || !bytes.Equal(op.Key, pub.Ed25519()) {
				t.Fatalf("%s: add-device key isn't pub's Ed25519 component", name)
			}
		}
	}
	return e
}

// SPEC §6.2 to §6.4: the signatures, identifier, links, and recovery commitment.
func TestVectorChainV2(t *testing.T) {
	keys, id := chainKeys(t)
	var v struct {
		Entries []struct {
			Signer string       `json:"signer"`
			Signed vectorSigned `json:"signed"`
		} `json:"entries"`
		Final struct {
			Commitment string `json:"recovery_commitment"`
			Head       string `json:"head_sha256"`
		} `json:"final_state"`
	}
	readVector(t, "chain.json", &v)
	var prev []byte
	var commitment []byte
	for i, ve := range v.Entries {
		s := ve.Signed.decode(t)
		e := verifyEntry(t, ve.Signer, s, keys[ve.Signer])
		ve.Signed.resign(t, s, keys[ve.Signer])
		if i == 0 {
			enc, _ := s.Encode()
			if IdentityID(enc) != id {
				t.Fatal("identifier differs")
			}
		} else if e.ID != id || !bytes.Equal(e.Prev, prev) {
			t.Fatalf("entry %d: id or prev link differs", i)
		}
		if strings.HasPrefix(ve.Signer, "recovery_key_") && !bytes.Equal(keys[ve.Signer].Public().Hash(), commitment) {
			t.Fatalf("entry %d: recovery key doesn't match the commitment", i)
		}
		for _, op := range e.Ops {
			if op.Op == OpSetRecovery {
				commitment = op.Next
			}
		}
		prev, _ = s.Hash()
	}
	if hex.EncodeToString(prev) != v.Final.Head || hex.EncodeToString(commitment) != v.Final.Commitment {
		t.Fatal("head or commitment differs")
	}
}

// SPEC §6.4.1: every entry's signature. The cases themselves wait for wire version 2
// chain validation in internal/chain (next phase).
func TestVectorForkV2Signatures(t *testing.T) {
	keys, _ := chainKeys(t)
	var v struct {
		Keys struct {
			D4 vectorKey `json:"device_4"`
			D5 vectorKey `json:"device_5"`
			D6 vectorKey `json:"device_6"`
		} `json:"keys"`
		Entries map[string]struct {
			Signer string       `json:"signer"`
			Signed vectorSigned `json:"signed"`
		} `json:"entries"`
	}
	readVector(t, "fork.json", &v)
	keys["device_4"], keys["device_5"], keys["device_6"] = v.Keys.D4.key(t), v.Keys.D5.key(t), v.Keys.D6.key(t)
	if len(v.Entries) != 11 {
		t.Fatalf("%d entries, want 11", len(v.Entries))
	}
	for name, ve := range v.Entries {
		signer := keys[ve.Signer]
		if signer == nil {
			t.Fatalf("%s: unknown signer %s", name, ve.Signer)
		}
		verifyEntry(t, ve.Signer, ve.Signed.decode(t), signer)
	}
}

// SPEC §3.2.2, §3.2.3.
func TestVectorMsgKey(t *testing.T) {
	keys, id := chainKeys(t)
	dev1 := keys["device_1"]
	var v struct {
		ID  string `json:"identity_id"`
		MK1 struct {
			Seed   string `json:"seed_hex"`
			Public string `json:"public_hex"`
		} `json:"message_key_1"`
		MK2 struct {
			Public string `json:"public_hex"`
		} `json:"message_key_2"`
		Cert1      vectorSigned `json:"msg_key_1"`
		Cert2      vectorSigned `json:"msg_key_2"`
		KeyPackage struct {
			Bytes string `json:"bytes_utf8"`
			SHA   string `json:"sha256_hex"`
		} `json:"key_package"`
		Binding vectorSigned `json:"kp_binding"`
		Reject  []struct {
			Note   string `json:"note"`
			Signed string `json:"signed"`
		} `json:"reject"`
	}
	readVector(t, "msgkey.json", &v)
	if v.ID != id {
		t.Fatal("identifier differs from chain.json")
	}
	for n, c := range []struct {
		cert vectorSigned
		pub  string
	}{{v.Cert1, v.MK1.Public}, {v.Cert2, v.MK2.Public}} {
		s := c.cert.decode(t)
		m, err := VerifyMsgKey(s, id, dev1.Public())
		if err != nil {
			t.Fatalf("msg_key_%d: %v", n+1, err)
		}
		if hex.EncodeToString(m.Key) != c.pub || m.N != uint64(n+1) {
			t.Fatalf("msg_key_%d: key or n differs", n+1)
		}
		c.cert.resign(t, s, dev1)
		if _, err := VerifyMsgKey(s, id, keys["device_2"].Public()); err == nil {
			t.Fatalf("msg_key_%d verified against another device", n+1)
		}
		if _, err := VerifyMsgKey(s, "tr:aaaaaaaaaaaaaaaaaaaaaaaa", dev1.Public()); err == nil {
			t.Fatalf("msg_key_%d verified for another identity", n+1)
		}
	}

	kp := []byte(v.KeyPackage.Bytes)
	if sum := sha256.Sum256(kp); hex.EncodeToString(sum[:]) != v.KeyPackage.SHA {
		t.Fatal("key package hash differs")
	}
	b := v.Binding.decode(t)
	if err := VerifyKPBinding(b, id, dev1.Public(), kp); err != nil {
		t.Fatalf("VerifyKPBinding: %v", err)
	}
	v.Binding.resign(t, b, dev1)
	if VerifyKPBinding(b, id, dev1.Public(), append(kp, '!')) == nil {
		t.Fatal("kp-binding verified for another key package")
	}
	if VerifyKPBinding(b, id, keys["device_2"].Public(), kp) == nil {
		t.Fatal("kp-binding verified against another device")
	}

	if len(v.Reject) != 2 {
		t.Fatalf("%d rejects, want 2", len(v.Reject))
	}
	for _, r := range v.Reject {
		s, err := DecodeSignedV2([]byte(r.Signed))
		if err != nil {
			continue
		}
		if _, err := VerifyMsgKey(s, id, dev1.Public()); err == nil {
			t.Errorf("accepted: %s", r.Note)
		}
	}
}

// SPEC §7.2: link proofs carry the new device's composite key in k.
func TestVectorLinkV2(t *testing.T) {
	var v struct {
		Device vectorKey `json:"device"`
		Full   struct {
			HPKESHA string `json:"hpke_sha256_hex"`
		} `json:"full"`
		Parked vectorSigned `json:"parked_proof"`
		Proof  vectorSigned `json:"proof"`
		// The link code itself is made and read by clients; rerouted never sees it.
	}
	readVector(t, "link.json", &v)
	dev := v.Device.key(t)
	for _, p := range []vectorSigned{v.Parked, v.Proof} {
		s := p.decode(t)
		pub, err := s.VerifyCompositeSelf("link-proof")
		if err != nil || !pub.Equal(dev.Public()) {
			t.Fatalf("link proof doesn't verify: %v", err)
		}
		p.resign(t, s, dev)
	}
	var parked struct {
		HPKE Bytes `json:"hpke"`
	}
	if err := mustDecodeV2(t, v.Parked.Signed).Open(&parked); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(parked.HPKE); hex.EncodeToString(sum[:]) != v.Full.HPKESHA {
		t.Fatal("HPKE key hash differs")
	}
}

// SPEC §16.6: the join proof's signature. Deriving the code key (Argon2id, then HKDF)
// belongs to community servers, a later phase.
func TestVectorJoinProofSignature(t *testing.T) {
	var v struct {
		CodeKey vectorKey `json:"code_key"`
		Commit  struct {
			SHA string `json:"sha256_hex"`
		} `json:"commit"`
		Join vectorSigned `json:"join_proof"`
	}
	readVector(t, "code.json", &v)
	key := v.CodeKey.key(t)
	s := v.Join.decode(t)
	pub, err := s.VerifyCompositeSelf("join-proof")
	if err != nil || !pub.Equal(key.Public()) {
		t.Fatalf("join proof doesn't verify: %v", err)
	}
	v.Join.resign(t, s, key)
	var body struct {
		Commit Bytes `json:"commit"`
	}
	if err := s.Open(&body); err != nil || hex.EncodeToString(body.Commit) != v.Commit.SHA {
		t.Fatal("commit hash differs")
	}
}

// SPEC §5.1, §8.3: an S2S request signed with a composite server key named by kid. The
// request's own rules wait for wire version 2 federation in internal/fed (a later phase).
func TestVectorS2SV2Signature(t *testing.T) {
	var v struct {
		ServerKey vectorKey `json:"server_key"`
		DocKey    struct {
			KID string `json:"kid"`
			Pub string `json:"pub"`
		} `json:"server_document_key"`
		Request vectorSigned `json:"request"`
	}
	readVector(t, "s2s.json", &v)
	key := v.ServerKey.key(t)
	raw, err := DecodeB64(v.DocKey.Pub)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseCompositePublicKey(raw)
	if err != nil || !pub.Equal(key.Public()) {
		t.Fatal("server document key differs")
	}
	s := v.Request.decode(t)
	if kid, ok := s.KeyID(); !ok || kid != v.DocKey.KID {
		t.Fatal("kid differs")
	}
	if err := s.VerifyComposite("s2s", pub); err != nil {
		t.Fatalf("VerifyComposite: %v", err)
	}
	v.Request.resign(t, s, key)
}

// SPEC §6.8: the version 2 genesis and the version 1 migrate entry, each under its own
// version's rules, and the link from migrate to the genesis. Accepting or refusing each
// pair waits for wire version 2 chain validation in internal/chain (next phase).
func TestVectorMigrateSignatures(t *testing.T) {
	var v struct {
		V1ID string `json:"v1_identity_id"`
		V2ID string `json:"v2_identity_id"`
		Keys struct {
			V2Device vectorKey `json:"v2_device"`
			Stranger vectorKey `json:"stranger"`
		} `json:"keys"`
		Genesis  vectorSigned `json:"v2_genesis"`
		Stranger vectorSigned `json:"stranger_genesis"`
		Migrate  vectorSigned `json:"migrate_entry"`
		After    vectorSigned `json:"after_migrate"`
		Removed  vectorSigned `json:"by_removed"`
	}
	readVector(t, "migrate.json", &v)
	dev, stranger := v.Keys.V2Device.key(t), v.Keys.Stranger.key(t)

	g := v.Genesis.decode(t)
	verifyEntry(t, "v2_device", g, dev)
	genc, _ := g.Encode()
	if IdentityID(genc) != v.V2ID {
		t.Fatal("version 2 identifier differs")
	}
	verifyEntry(t, "stranger", v.Stranger.decode(t), stranger)

	for _, e := range []vectorSigned{v.Migrate, v.After, v.Removed} {
		s, err := DecodeSigned([]byte(e.Signed))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.VerifySelf(TypeChainEntry); err != nil {
			t.Fatalf("version 1 entry doesn't verify under tieroute/v1: %v", err)
		}
		// The same envelope read as version 2 doesn't verify: the contexts differ.
		if s.VerifyMessageKey(TypeChainEntry, ed25519.PublicKey(s.K)) == nil {
			t.Fatal("a tieroute/v1 signature verified under tieroute/v2")
		}
	}
	var m v2Entry
	if err := mustDecodeV2(t, v.Migrate.Signed).Open(&m); err != nil {
		t.Fatal(err)
	}
	gh, _ := g.Hash()
	if m.ID != v.V1ID || len(m.Ops) != 1 || m.Ops[0].Op != "migrate" || !bytes.Equal(m.Ops[0].To, gh) {
		t.Fatal("migrate doesn't name the version 2 genesis")
	}
}
