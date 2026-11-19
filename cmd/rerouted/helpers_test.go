package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/rerouteholdings/rerouted/internal/store/sqlite"
)

// addVectorChain stores the test vectors' chain: kat.chat.example, one device, home
// chat.example.
func addVectorChain(t *testing.T, st *sqlite.Store) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/vectors/chain.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		IdentityID string `json:"identity_id"`
		Entries    []struct {
			Signed struct {
				Signed string `json:"signed"`
			} `json:"signed"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i, e := range v.Entries {
		if i == 0 {
			err = st.Chains().Create(ctx, v.IdentityID, []byte(e.Signed.Signed), "kat.chat.example")
		} else {
			err = st.Chains().Append(ctx, v.IdentityID, uint64(i-1), []byte(e.Signed.Signed))
		}
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
}

// writeTestArchive writes a .tar.gz holding files, in map order after backup.json.
func writeTestArchive(path string, files map[string]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)
	write := func(name, body string) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write([]byte(body))
		return err
	}
	if m, ok := files[manifestName]; ok {
		if err := write(manifestName, m); err != nil {
			return err
		}
	}
	for name, body := range files {
		if name == manifestName {
			continue
		}
		if err := write(name, body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return zw.Close()
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
