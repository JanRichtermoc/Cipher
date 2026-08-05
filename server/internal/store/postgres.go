// Package store owns the PostgreSQL connection pool and schema migration.
//
// The schema itself lives in migrations/, not here. This package's job in the
// P4.S02 scaffold is to connect, apply migrations, and answer whether the
// database is reachable — the endpoints that use it arrive in P4.S03 onward.
//
// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationFS embeds the SQL so the binary carries its own schema.
//
// Embedding rather than reading from disk at runtime means the image cannot
// drift from the code that expects it: there is no configuration that points at
// the wrong migrations directory, and no deployment where the files were not
// copied.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// DB wraps the pool. A named type rather than a bare *pgxpool.Pool so the
// surface stays deliberate — every query the relay runs is a method here, which
// is what keeps "the server never parses into the ciphertext" checkable by
// reading one package.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects and verifies the connection before returning.
//
// pgxpool is lazy: NewWithConfig succeeds against a database that does not
// exist. A constructor that returns a handle to nothing turns a configuration
// error into a runtime error at the first request, so this pings.
func Open(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	// Bounded so a request storm cannot open connections until Postgres refuses
	// them, which fails the whole service rather than the excess requests.
	cfg.MaxConns = 16
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		// The error is not wrapped with the URL: it carries the password.
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &DB{pool: pool}, nil
}

// Close releases the pool.
func (db *DB) Close() { db.pool.Close() }

// Ping reports whether the database is reachable. Used by readiness only.
func (db *DB) Ping(ctx context.Context) error { return db.pool.Ping(ctx) }

// Migrate applies every migration that has not been applied, in filename order.
//
// Deliberately minimal — no down-migrations, no checksums of applied files.
// Down-migrations on a schema whose entire point is that data does not persist
// are close to meaningless, and every migration tool is a dependency. If this
// outgrows a single-digit number of files it should be replaced, not extended.
func (db *DB) Migrate(ctx context.Context) ([]string, error) {
	if _, err := db.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT        PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)

	var applied []string
	for _, name := range entries {
		// Each migration runs in its own transaction, with the bookkeeping row
		// written inside it. A migration that fails half way therefore leaves
		// neither partial schema nor a row claiming it succeeded.
		tx, err := db.pool.Begin(ctx)
		if err != nil {
			return applied, fmt.Errorf("begin %s: %w", name, err)
		}

		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`,
			name).Scan(&exists); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("check %s: %w", name, err)
		}
		if exists {
			_ = tx.Rollback(ctx)
			continue
		}

		sqlBytes, err := migrationFS.ReadFile(name)
		if err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("read %s: %w", name, err)
		}
		if statement, found := transactionControlIn(string(sqlBytes)); found {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf(
				"%s: %w: %q", name, ErrMigrationControlsTransaction, statement)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, fmt.Errorf("commit %s: %w", name, err)
		}
		applied = append(applied, name)
	}
	return applied, nil
}

// ErrMigrationControlsTransaction reports a migration that manages its own
// transaction, which silently breaks the one Migrate wraps it in.
var ErrMigrationControlsTransaction = errors.New(
	"store: a migration must not contain transaction control")

// transactionControlRE matches a statement-leading transaction-control keyword.
//
// Anchored to the start of a statement — beginning of file, or after a `;` —
// rather than searched for anywhere, so a column called `begin_at` or a string
// literal containing the word is not a match. No migration here defines a
// PL/pgSQL body, where `BEGIN` is block structure rather than transaction
// control; one that did would need this rule reconsidered rather than widened.
var transactionControlRE = regexp.MustCompile(
	`(?is)(?:\A|;)\s*(BEGIN|COMMIT|ROLLBACK|END|START\s+TRANSACTION|SAVEPOINT)\b`)

// transactionControlIn reports the first transaction-control statement in sql.
//
// # Why the check exists at all
//
// PostgreSQL has no nested transactions. `BEGIN` inside an open transaction is a
// warning and a no-op; the matching `COMMIT` therefore ends the transaction
// *Migrate* opened, and everything after it — including the `schema_migrations`
// row — runs outside any transaction. The atomicity this runner documents was
// then a property of the runner and not of what actually executed, and the
// failure was invisible: the schema applied, the bookkeeping row did not, and
// the next boot reapplied the file against objects that already existed.
//
// # Comments are stripped first
//
// AUDIT **R3**: the prose explaining this rule names the very keywords it
// forbids, and 0001_init.sql now carries a paragraph doing exactly that. A
// scanner that read comments would fire on the documentation of the control it
// enforces, which is a gate that cries wolf and therefore a gate that gets
// deleted (**R2**).
func transactionControlIn(sql string) (string, bool) {
	match := transactionControlRE.FindStringSubmatch(stripSQLComments(sql))
	if match == nil {
		return "", false
	}
	return strings.ToUpper(strings.Join(strings.Fields(match[1]), " ")), true
}

// stripSQLComments replaces comment bytes with spaces, preserving every offset
// so a reported position still names the same place in the file.
func stripSQLComments(sql string) string {
	out := []byte(sql)
	for i := 0; i < len(out); {
		switch {
		case out[i] == '-' && i+1 < len(out) && out[i+1] == '-':
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '*':
			for i < len(out) {
				closing := out[i] == '*' && i+1 < len(out) && out[i+1] == '/'
				out[i] = ' '
				i++
				if closing {
					out[i] = ' '
					i++
					break
				}
			}
		default:
			i++
		}
	}
	return string(out)
}
