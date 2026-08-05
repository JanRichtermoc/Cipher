// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// AUDIT 5.27. These need no database: the property is a property of the
// migration text and of the scanner that reads it, so they run in the fast gate.

package store

import (
	"io/fs"
	"strings"
	"testing"
)

// --- The runner's transaction is the only transaction -----------------------

func TestEmbeddedMigrationsContainNoTransactionControl(t *testing.T) {
	// The finding itself. 0001_init.sql opened with BEGIN and closed with
	// COMMIT while Migrate had already opened a transaction — and PostgreSQL has
	// no nested transactions, so that COMMIT ended the runner's. Everything
	// after it, including the schema_migrations INSERT, ran unprotected.
	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		t.Fatalf("list migrations: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("no migrations were read, so this test proved nothing")
	}
	for _, name := range names {
		sql, err := migrationFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if statement, found := transactionControlIn(string(sql)); found {
			t.Fatalf("%s contains transaction control (%q); the runner owns the transaction",
				name, statement)
		}
	}
}

func TestTransactionControlIsDetected(t *testing.T) {
	// The positive control for the test above: the scanner must actually fire,
	// or "no migration contains transaction control" is what a broken scanner
	// reports too (AUDIT R2).
	cases := map[string]string{
		"BEGIN":             "BEGIN;\nCREATE TABLE t (a INT);\n",
		"COMMIT":            "CREATE TABLE t (a INT);\nCOMMIT;\n",
		"ROLLBACK":          "CREATE TABLE t (a INT); ROLLBACK;",
		"START TRANSACTION": "start transaction;\nCREATE TABLE t (a INT);\n",
		"SAVEPOINT":         "CREATE TABLE t (a INT);\nSAVEPOINT s;",
		"END":               "CREATE TABLE t (a INT);\nEND;",
	}
	for want, sql := range cases {
		statement, found := transactionControlIn(sql)
		if !found {
			t.Fatalf("%q was not detected in %q", want, sql)
		}
		if statement != want {
			t.Fatalf("detected %q, want %q", statement, want)
		}
	}
}

func TestTransactionControlIgnoresComments(t *testing.T) {
	// AUDIT R3: 0001_init.sql now carries a paragraph explaining why it must not
	// contain BEGIN or COMMIT, and naming them. A scanner that read comments
	// would fire on the documentation of the rule it enforces.
	sql := `
-- No BEGIN/COMMIT here: the runner owns the transaction.
/* Also not COMMIT, and not ROLLBACK. */
CREATE TABLE t (a INT);
`
	if statement, found := transactionControlIn(sql); found {
		t.Fatalf("fired on a comment: %q", statement)
	}
}

func TestTransactionControlIgnoresIdentifiersAndLiterals(t *testing.T) {
	// A column named begin_at, or the word inside a string, is not transaction
	// control. The pattern is anchored to a statement start for this reason.
	sql := `
CREATE TABLE t (begin_at TIMESTAMPTZ, commit_note TEXT DEFAULT 'commit');
INSERT INTO t (commit_note) VALUES ('begin');
`
	if statement, found := transactionControlIn(sql); found {
		t.Fatalf("fired on an identifier or literal: %q", statement)
	}
}

func TestStripSQLCommentsPreservesOffsets(t *testing.T) {
	// Replacing comment bytes with spaces rather than deleting them keeps every
	// later byte at the same offset, so a position reported against the stripped
	// text still names the same place in the file.
	in := "SELECT 1; -- a line comment\n/* block */ SELECT 2;\n"
	out := stripSQLComments(in)
	if len(out) != len(in) {
		t.Fatalf("length changed: %d -> %d", len(in), len(out))
	}
	if strings.Contains(out, "comment") || strings.Contains(out, "block") {
		t.Fatalf("comment text survived: %q", out)
	}
	if !strings.Contains(out, "SELECT 1;") || !strings.Contains(out, "SELECT 2;") {
		t.Fatalf("code was eaten: %q", out)
	}
}
