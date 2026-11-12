package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rerouteholdings/rerouted/internal/config"
	"github.com/rerouteholdings/rerouted/internal/wire"
)

// upload posts raw bytes to path with a content type, and returns the status and body.
func upload(t *testing.T, ts *httptest.Server, token, path, ctype string, data []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/.well-known/tieroute/v1/client/"+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func download(t *testing.T, ts *httptest.Server, token, path string) (int, string, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/.well-known/tieroute/v1/client/"+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), b
}

// SPEC §14: files go up as raw bytes and come back through any homeserver; removed and
// expired files answer 410 with the reason.
func TestFiles(t *testing.T) {
	a, b, sa, _ := twoServers(t)
	kat, bob := newUserOn(t, a, "kat", "a.test"), newUserOn(t, b, "bob", "b.test")
	data := []byte("pretend this is AES-GCM ciphertext")
	if c, _ := upload(t, a, kat.token, "media/upload", "application/tieroute+json", data); c != 415 {
		t.Fatalf("a file as JSON: %d, want 415", c)
	}
	c, body := upload(t, a, kat.token, "media/upload", "application/octet-stream", data)
	var res struct {
		ID     string     `json:"id"`
		SHA256 wire.Bytes `json:"sha256"`
	}
	wire.Unmarshal(body, &res)
	if c != 200 || len(res.SHA256) != 32 {
		t.Fatalf("upload: %d %s", c, body)
	}
	code, _, got := download(t, b, bob.token, "media/a.test/"+res.ID)
	if code != 200 || !bytes.Equal(got, data) {
		t.Fatalf("bob fetches it through b.test: %d %q", code, got)
	}
	id, _ := base64.RawURLEncoding.DecodeString(res.ID)
	sa.st.Media().Remove(context.Background(), id)
	if code, _, body := download(t, b, bob.token, "media/a.test/"+res.ID); code != 410 || !strings.Contains(string(body), "removed") {
		t.Fatalf("a removed file: %d %s, want 410 removed", code, body)
	}
	_, body = upload(t, a, kat.token, "media/upload", "application/octet-stream", data)
	wire.Unmarshal(body, &res)
	sa.st.Media().Expire(context.Background(), time.Now().Unix()+1)
	if code, _, body := download(t, a, kat.token, "media/a.test/"+res.ID); code != 410 || !strings.Contains(string(body), "expired") {
		t.Fatalf("an expired file: %d %s, want 410 expired", code, body)
	}
}

func TestMediaQuota(t *testing.T) {
	ts := testServerCfg(t, newStore(t), func(c *config.Config) { c.MediaQuota = 100 })
	kat := newUser(t, ts, "kat")
	if c, _ := upload(t, ts, kat.token, "media/upload", "application/octet-stream", make([]byte, 80)); c != 200 {
		t.Fatalf("under quota: %d", c)
	}
	if c, b := upload(t, ts, kat.token, "media/upload", "application/octet-stream", make([]byte, 80)); c != 413 || !strings.Contains(string(b), "over-quota") {
		t.Fatalf("over quota: %d %s", c, b)
	}
}
