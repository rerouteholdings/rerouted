package sqlite

import (
	"context"
	"database/sql"

	"github.com/rerouteholdings/rerouted/internal/store"
)

// ---- reports ----

type reports struct{ db *sql.DB }

func (r reports) Add(ctx context.Context, rep store.Report) error {
	_, err := r.db.ExecContext(ctx, "INSERT INTO reports (received, origin, reporter, reported, body) VALUES (?, ?, ?, ?, ?)",
		rep.Received, rep.Origin, rep.Reporter, rep.Reported, rep.Body)
	return err
}

func (r reports) List(ctx context.Context, limit int) ([]store.Report, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT received, origin, reporter, reported, body FROM reports ORDER BY n DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Report
	for rows.Next() {
		var rep store.Report
		if err := rows.Scan(&rep.Received, &rep.Origin, &rep.Reporter, &rep.Reported, &rep.Body); err != nil {
			return nil, err
		}
		out = append(out, rep)
	}
	return out, rows.Err()
}
