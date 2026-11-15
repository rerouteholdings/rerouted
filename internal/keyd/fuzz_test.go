package keyd

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

const fuzzNow = 1_800_000_000

func framed(t testing.TB, v any) []byte {
	b, err := wire.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

// FuzzKeydRequest feeds a connection any bytes. rerouted-keyd answers or hangs up, and
// every signature it gives is one its policy allows: a type it signs, over canonical JSON
// naming the key's own server, that verifies with that key. Run it with
// go test -fuzz=FuzzKeydRequest ./internal/keyd.
func FuzzKeydRequest(f *testing.F) {
	keys, err := LoadDir(f.TempDir(), "chat.test", []string{"club.test"})
	if err != nil {
		f.Fatal(err)
	}
	srv := &Server{Keys: keys, UID: -1, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() int64 { return fuzzNow }}
	v1, v2, club := keys.pubs[0].KID, keys.pubs[1].KID, keys.pubs[2].KID
	f.Add(framed(f, request{Op: "keys"}))
	for _, r := range []request{
		{Op: "sign", KID: v1, T: "s2s", B: `{"from":"chat.test","ts":1800000000}`},
		{Op: "sign", KID: v2, T: "commit-receipt", B: `{"hub":"chat.test","ts":1800000010}`},
		{Op: "sign", KID: v1, T: "move-reservation", B: `{"exp":1800000600,"server":"chat.test"}`},
		{Op: "sign", KID: club, T: "community-move-reservation", B: `{"exp":1800000600,"server":"club.test"}`},
		{Op: "sign", KID: v1, T: "s2s", B: `{"from":"evil.test","ts":1800000000}`},
		{Op: "sign", KID: v2, T: "chain-entry", B: `{}`},
	} {
		f.Add(framed(f, r))
		f.Add(append(framed(f, r), framed(f, request{Op: "keys"})...))
	}
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		// The connection loop: it reads until the bytes run out or don't make a request.
		c, s := net.Pipe()
		done := make(chan struct{})
		go func() { srv.serve(s); close(done) }()
		go io.Copy(io.Discard, c)
		c.Write(data)
		c.Close()
		<-done

		// Each request in the bytes, answered.
		r := bytes.NewReader(data)
		for {
			var req request
			if readMsg(r, &req) != nil {
				return
			}
			resp := srv.handle(req)
			if resp.S == nil {
				continue
			}
			h, ok := keys.byKID[req.KID]
			if !ok || req.Op != "sign" || policy[req.T] == nil {
				t.Fatalf("signed %+v", req)
			}
			if c, err := wire.Canonical([]byte(req.B)); err != nil || !bytes.Equal(c, []byte(req.B)) {
				t.Fatalf("signed a body that isn't canonical: %q", req.B)
			}
			var names struct{ From, Hub, Server string }
			wire.Unmarshal([]byte(req.B), &names)
			name := map[string]string{"s2s": names.From, "commit-receipt": names.Hub}[req.T]
			if name == "" {
				name = names.Server
			}
			if name != h.name {
				t.Fatalf("signed %s %q with %s's key", req.T, req.B, h.name)
			}
			s := wire.Signed{T: req.T, B: req.B, KID: req.KID, S: resp.S}
			var verr error
			if h.v2 != nil {
				verr = s.VerifyComposite(req.T, h.v2.Public())
			} else {
				verr = s.Verify(req.T, h.v1.Public().(ed25519.PublicKey))
			}
			if verr != nil {
				t.Fatalf("a signature that doesn't verify: %v", verr)
			}
		}
	})
}
