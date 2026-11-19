package main

import (
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

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}
