package cchain

import (
	"encoding/json"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// Custom emoji records (SPEC §16.9, spec/api/community.md). A community's emoji list lives
// on its community server, outside the chain: a new chain op would be an unknown op, which
// every older client rejects. Each record is a signed community-emoji, made by a member with
// administrate. The server reads its structure and never opens the sealed name and key.

// TypeEmoji is the signed type tag of an emoji record.
const TypeEmoji = "community-emoji"

const (
	// MaxEmoji is how many current emoji a community can have.
	MaxEmoji = 200
	// MaxEmojiSize is an emoji's largest plaintext, in bytes. Its blob is 16 bytes more.
	MaxEmojiSize = 262144
)

// Emoji is a decoded emoji record.
type Emoji struct {
	Community []byte
	Blob      []byte // the emoji blob's ID on the community server
	SHA256    []byte // of the blob
	Size      int64  // plaintext bytes
	Head      []byte // a community chain entry's hash
	TS        int64
	By        string
	Sig       wire.Signed
	Enc       []byte // JCS(signed)
}

// ParseEmoji decodes a signed community-emoji, checking its form: the envelope, a composite
// signature by a device key, and a closed body. It doesn't verify the signature.
func ParseEmoji(raw []byte) (*Emoji, *Error) {
	sig, err := wire.DecodeSignedV2(raw)
	if err != nil {
		return nil, badRequest("signed object: " + err.Error())
	}
	if sig.T != TypeEmoji {
		return nil, badRequest("t must be " + TypeEmoji)
	}
	if sig.KID != "" || len(sig.K) != 32 || len(sig.S) != wire.CompositeSignatureSize {
		return nil, badRequest("k must name a device by its 32-byte key, with a composite signature")
	}
	if err := wire.CheckIJSON([]byte(sig.B)); err != nil {
		return nil, badRequest("body: " + err.Error())
	}
	f, e := newFields(json.RawMessage(sig.B), TypeEmoji)
	if e != nil {
		return nil, e
	}
	em := &Emoji{Sig: sig}
	em.Community, _ = f.bytesN("community", 32, true)
	em.Blob, _ = f.bytesN("blob", 16, true)
	em.SHA256, _ = f.bytesN("sha256", 32, true)
	if n, ok := f.uint("size", true); ok {
		if n < 1 || n > MaxEmojiSize {
			f.fail(badRequest(TypeEmoji + ": size is 1 to 262144"))
		}
		em.Size = int64(n)
	}
	em.Head, _ = f.bytesN("head", 32, true)
	if ts, ok := f.uint("ts", true); ok {
		em.TS = int64(ts)
	}
	em.By, _ = f.identifier("by", true)
	f.sealed("emoji", true, false)
	f.closed()
	if f.err != nil {
		return nil, f.err
	}
	if em.Enc, err = sig.Encode(); err != nil {
		return nil, badRequest(err.Error())
	}
	return em, nil
}
