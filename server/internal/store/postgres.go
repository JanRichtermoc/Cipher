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
	"fmt"
	"io/fs"
	"sort"
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
