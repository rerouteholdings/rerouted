package sqlite

import (
	"context"
	"database/sql"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// Push notification tokens (store.Push): a rerouted feature for the Reroute app, outside
// the Tieroute spec. A token is registered for one device, and a device has at most one.
const pushSchema = `
CREATE TABLE IF NOT EXISTS apns_tokens (token TEXT PRIMARY KEY, id TEXT NOT NULL, device BLOB NOT NULL, env TEXT NOT NULL, updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS apns_tokens_device ON apns_tokens (id, device);
`

type push struct{ db, rdb *sql.DB }

func (p push) PutAPNS(ctx context.Context, t store.APNSToken) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM apns_tokens WHERE id = ? AND device = ? AND token <> ?", t.ID, t.Device, t.Token); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO apns_tokens (token, id, device, env, updated) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (token) DO UPDATE SET id = excluded.id, device = excluded.device, env = excluded.env, updated = excluded.updated`,
		t.Token, t.ID, t.Device, t.Env, t.Updated); err != nil {
		return err
	}
	return tx.Commit()
}

func (p push) DeleteAPNS(ctx context.Context, id, token string) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM apns_tokens WHERE id = ? AND token = ?", id, token)
	return err
}

func (p push) DropAPNSToken(ctx context.Context, token string) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM apns_tokens WHERE token = ?", token)
	return err
}

func (p push) DropAPNSDevice(ctx context.Context, id string, device []byte) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM apns_tokens WHERE id = ? AND device = ?", id, device)
	return err
}

func (p push) DropAPNSIdentity(ctx context.Context, id string) error {
	_, err := p.db.ExecContext(ctx, "DELETE FROM apns_tokens WHERE id = ?", id)
	return err
}

func (p push) APNS(ctx context.Context, id string) ([]store.APNSToken, error) {
	rows, err := p.rdb.QueryContext(ctx, "SELECT token, device, env, updated FROM apns_tokens WHERE id = ? ORDER BY token", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.APNSToken
	for rows.Next() {
		t := store.APNSToken{ID: id}
		if err := rows.Scan(&t.Token, &t.Device, &t.Env, &t.Updated); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
