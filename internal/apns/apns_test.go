package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// verifyToken checks a provider token's format and ES256 signature, and returns its
// header and claims.
func verifyToken(t *testing.T, tok string, pub *ecdsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("not base64url without padding: %q", s)
		}
		return b
	}
	var h, c map[string]any
	if err := json.Unmarshal(dec(parts[0]), &h); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(dec(parts[1]), &c); err != nil {
		t.Fatal(err)
	}
	sig := dec(parts[2])
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64 (r||s)", len(sig))
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the signature doesn't verify")
	}
	return h, c
}

func TestProviderToken(t *testing.T) {
	k, _ := newKey(t)
	iat := time.Unix(1_800_000_000, 0)
	tok, err := ProviderToken(k, "ABC123DEFG", "TEAM123456", iat)
	if err != nil {
		t.Fatal(err)
	}
	h, c := verifyToken(t, tok, &k.PublicKey)
	if len(h) != 2 || h["alg"] != "ES256" || h["kid"] != "ABC123DEFG" {
		t.Fatalf("header: %v", h)
	}
	if len(c) != 2 || c["iss"] != "TEAM123456" || c["iat"] != float64(1_800_000_000) {
		t.Fatalf("claims: %v", c)
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	k, p8 := newKey(t)
	good := filepath.Join(dir, "AuthKey.p8")
	os.WriteFile(good, p8, 0o600)
	got, err := LoadKey(good)
	if err != nil || !got.Equal(k) {
		t.Fatalf("LoadKey: %v", err)
	}
	// Another curve, another kind of key, and not PEM at all.
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k384)
	for name, b := range map[string][]byte{
		"p384": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"junk": []byte("not a key"),
		"sec1": func() []byte {
			d, _ := x509.MarshalECPrivateKey(k)
			return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: d})
		}(),
	} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		if _, err := LoadKey(p); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := LoadKey(filepath.Join(dir, "missing.p8")); err == nil {
		t.Error("a missing file loaded")
	}
}

// Send speaks HTTP/2 to the APNs server, with the headers and payload as given, and the
// cached provider token.
func TestSend(t *testing.T) {
	k, _ := newKey(t)
	var calls atomic.Int32
	var tokens []string
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.ProtoMajor != 2 {
			t.Errorf("HTTP/%d, want 2", r.ProtoMajor)
		}
		tok, _ := strings.CutPrefix(r.Header.Get("authorization"), "bearer ")
		tokens = append(tokens, tok)
		verifyToken(t, tok, &k.PublicKey)
		if r.Header.Get("apns-topic") != "llc.example.app" || r.Header.Get("apns-push-type") != "alert" ||
			r.Header.Get("apns-priority") != "10" || r.Header.Get("apns-collapse-id") != "c" || r.Header.Get("apns-expiration") != "1800000000" {
			t.Errorf("headers: %v", r.Header)
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"aps":{}}` {
			t.Errorf("payload %s", b)
		}
		switch r.URL.Path {
		case "/3/device/aaaa":
			w.WriteHeader(200)
		case "/3/device/gone":
			w.WriteHeader(410)
			w.Write([]byte(`{"reason":"Unregistered","timestamp":1}`))
		default:
			w.WriteHeader(400)
			w.Write([]byte(`{"reason":"BadDeviceToken"}`))
		}
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	c := New(k, "ABC123DEFG", "TEAM123456", "llc.example.app")
	c.UseServer(ts.URL, ts.Client())
	n := Notification{Env: Sandbox, Payload: []byte(`{"aps":{}}`), PushType: "alert", Priority: 10, CollapseID: "c", Expiration: time.Unix(1_800_000_000, 0)}
	for tok, want := range map[string]Result{"aaaa": {Status: 200}, "gone": {Status: 410, Reason: "Unregistered"}, "bad": {Status: 400, Reason: "BadDeviceToken"}} {
		n.Token = tok
		res, err := c.Send(context.Background(), n)
		if err != nil || res != want {
			t.Fatalf("%s: %+v %v, want %+v", tok, res, err, want)
		}
		if res.TokenGone() == res.OK() {
			t.Fatalf("%s: OK %v, TokenGone %v", tok, res.OK(), res.TokenGone())
		}
	}
	if calls.Load() != 3 || tokens[0] != tokens[1] || tokens[1] != tokens[2] {
		t.Fatal("the provider token wasn't reused")
	}
	if (Result{Status: 400, Reason: "DeviceTokenNotForTopic"}).TokenGone() != true || (Result{Status: 400, Reason: "BadTopic"}).TokenGone() {
		t.Fatal("TokenGone")
	}
	if _, err := c.Send(context.Background(), Notification{Env: "staging", Token: "aaaa"}); err == nil {
		t.Fatal("an unknown environment was sent")
	}
}
