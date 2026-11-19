package sqlite

import "testing"

func TestStats(t *testing.T) {
	st, err := OpenTemp()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.db.Exec("INSERT INTO handles (handle, id) VALUES ('kat.chat.example', 'tr:kat'), ('old.chat.example', 'tr:kat')"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("INSERT INTO outbox (dest, path, body, next, created) VALUES ('b.example', 'deliver', x'00', 0, 0)"); err != nil {
		t.Fatal(err)
	}
	s, err := st.Stats(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if s.Identities != 1 || s.Outbox != 1 || s.Communities != 0 || s.Bytes <= 0 {
		t.Fatalf("%+v", s)
	}
}
