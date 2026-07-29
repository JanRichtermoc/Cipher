// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// Introspection helpers used by the integration suite to ask the *database* what
// it actually holds, rather than asking the migration file what it was told to
// create. Nothing on a request path calls any of this.
//
// The distinction matters. `server/internal/store/migrations_test.go` reads the
// SQL and can only see what this repository's migrations declare; these read
// information_schema and the rows themselves, so a column added by a later
// migration, or a value written by a code path nobody audited, is still caught.

package store

import (
	"context"
	"fmt"
)

// ColumnsOf returns the column names of a table, as the database has them.
func (db *DB) ColumnsOf(ctx context.Context, table string) ([]string, error) {
	rows, err := db.pool.Query(ctx,
		`SELECT column_name FROM information_schema.columns
		  WHERE table_schema = 'public' AND table_name = $1
		  ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, fmt.Errorf("columns of %s: %w", table, err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("columns of %s: %w", table, err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// SessionTokenAppearsInPlaintext reports whether the raw token is anywhere in
// session_tokens.
//
// The point is to answer the question by *searching*, not by trusting that
// CreateSession was called with a hash. Looking the token up by its hash would
// only demonstrate that hashing works; this asks whether the raw value is
// present in any column, under any name — including one added later by someone
// who thought a plaintext copy would be convenient for debugging.
//
// Every column is cast to text and compared, so a token stored in a BYTEA, a
// TEXT, or a column that does not exist yet is all covered by the same query.
func (db *DB) SessionTokenAppearsInPlaintext(ctx context.Context, token string) (bool, error) {
	columns, err := db.ColumnsOf(ctx, "session_tokens")
	if err != nil {
		return false, err
	}

	for _, column := range columns {
		// The column name comes from information_schema, not from a caller, so
		// it cannot carry an injection — but it is still quoted, because "this
		// input is trusted" is the sentence that precedes most injections.
		query := fmt.Sprintf(
			`SELECT EXISTS (
			   SELECT 1 FROM session_tokens
			    WHERE %s::text = $1
			       OR encode(%s::text::bytea, 'escape') = $1
			 )`, quoteIdent(column), quoteIdent(column))

		var found bool
		if err := db.pool.QueryRow(ctx, query, token).Scan(&found); err != nil {
			// A column whose type cannot be cast is not a match; skip rather
			// than fail, so adding a column of some exotic type does not break
			// the check into silence.
			continue
		}
		if found {
			return true, nil
		}
	}
	return false, nil
}

// quoteIdent wraps an identifier in double quotes, doubling any it contains.
func quoteIdent(s string) string {
	out := make([]rune, 0, len(s)+2)
	out = append(out, '"')
	for _, r := range s {
		if r == '"' {
			out = append(out, '"')
		}
		out = append(out, r)
	}
	return string(append(out, '"'))
}
