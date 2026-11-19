package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWriteShape(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, Status{Version: "0.2.0", PID: 42, Name: "chat.example", Listen: "127.0.0.1:8080"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := []string{"listen", "metrics", "name", "outbox", "pid", "restart_pending", "started", "turn", "update_available", "updated", "version", "voice_participants", "voice_rooms"}
	if !slices.Equal(keys, want) {
		t.Fatalf("keys %v, want %v", keys, want)
	}
	if s, err := Read(dir); err != nil || s.PID != 42 {
		t.Fatal(s, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("left %d files behind", len(entries))
	}
	if err := Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := Remove(dir); err != nil {
		t.Fatal("removing twice:", err)
	}
}
