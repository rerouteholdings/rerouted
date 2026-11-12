package api

import "testing"

// sendLink sends a link delivery to u's own inbox: the simplest delivery to store, with no
// contacts or groups involved. It returns the HTTP status and the delivery's result.
func sendLink(u *testUser, id []byte) (int, sendResult) {
	var res struct {
		Results []sendResult `json:"results"`
	}
	c := call(u.t, u.ts, "POST", "send", u.token, map[string]any{"deliveries": []any{
		map[string]any{"id": id, "kind": "link", "to": []string{u.id}, "data": []byte("bundle")},
	}}, &res)
	if c != 200 || len(res.Results) != 1 {
		return c, sendResult{}
	}
	return c, res.Results[0]
}

// A page's limit has to be a whole number from 1 up. A larger one than the maximum gets
// the maximum (spec/api/conventions.md, Pagination).
func TestListLimits(t *testing.T) {
	kat := newUser(t, testServer(t), "kat")
	for range 2 {
		if c, res := sendLink(kat, randBytes(16)); c != 200 || res.Status != "sent" {
			t.Fatalf("send: %d %+v", c, res)
		}
	}
	for _, path := range []string{"inbox", "contacts"} {
		for _, bad := range []string{"0", "-1", "two", "1.5"} {
			if c := call(t, kat.ts, "GET", path+"?limit="+bad, kat.token, nil, nil); c != 400 {
				t.Errorf("%s?limit=%s: %d, want 400", path, bad, c)
			}
		}
		if c := call(t, kat.ts, "GET", path+"?limit=100000", kat.token, nil, nil); c != 200 {
			t.Errorf("%s?limit=100000: %d, want 200", path, c)
		}
	}
	var page struct {
		Items []inboxItem `json:"items"`
		Next  string      `json:"next"`
	}
	if c := call(t, kat.ts, "GET", "inbox?limit=1", kat.token, nil, &page); c != 200 || len(page.Items) != 1 || page.Next == "" {
		t.Fatalf("inbox?limit=1: %d, %d items, next %q", c, len(page.Items), page.Next)
	}
}
