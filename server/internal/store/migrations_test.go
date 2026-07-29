// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// These tests read the embedded migration SQL as text. They need no database,
// which is the point: they run in the fast gate, on every verification, rather
// than only when someone has Docker up.
//
// What they defend is not correctness of SQL — Postgres does that — but the
// privacy-regression rule in the P4 phase header: every table and every column
// must be justified in docs/BACKEND.md §2 against THREAT_MODEL.md §1.1. A table
// that appears without a decision behind it is the failure mode, and it is silent.

package store

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// documentedTables is the exact set justified in docs/BACKEND.md §2.
//
// Adding a table here is deliberately annoying: it fails this test until the
// name is added, and the name should not be added until §2 explains what the
// table holds and what a seized database would learn from it.
var documentedTables = []string{
	"accounts",
	"attachments",
	"invites",
	"kyber_prekeys",
	"messages",
	"one_time_prekeys",
	"push_tokens",
	"session_tokens",
	"signed_prekeys",
}

func migrationSQL(t *testing.T) string {
	t.Helper()
	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil || len(names) == 0 {
		t.Fatalf("no migrations embedded: %v", err)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		data, err := migrationFS.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

// migrationCode returns the SQL with `--` line comments stripped.
//
// Every scan below MUST use this rather than the raw text. The migration's
// comments deliberately name the columns that are absent — "no sender_aci",
// "created_by is absent on purpose" — so a scan of the raw file finds every
// forbidden term and fails on the documentation that exists to explain why the
// schema is correct.
//
// This is the same defect as docs/AUDIT.md 6.7, inverted: there, a gate passed
// by matching its own comment; here, a check failed by matching its own comment.
// Both come from scanning a file that mixes assertion and explanation without
// separating them, and both were caught only by running the check.
func migrationCode(t *testing.T) string {
	t.Helper()

	var b strings.Builder
	for _, line := range strings.Split(migrationSQL(t), "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

var createTableRE = regexp.MustCompile(`(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)

func tablesInMigrations(t *testing.T) []string {
	t.Helper()
	var found []string
	for _, m := range createTableRE.FindAllStringSubmatch(migrationCode(t), -1) {
		found = append(found, m[1])
	}
	sort.Strings(found)
	return found
}

func TestEveryTableIsDocumented(t *testing.T) {
	found := tablesInMigrations(t)

	documented := make(map[string]bool, len(documentedTables))
	for _, name := range documentedTables {
		documented[name] = true
	}

	seen := make(map[string]bool, len(found))
	for _, name := range found {
		seen[name] = true
		if !documented[name] {
			t.Errorf("table %q is created by a migration but is not justified in "+
				"docs/BACKEND.md §2. Add the justification — what it holds, and what "+
				"a seized database would learn from it — before adding it here.", name)
		}
	}
	for _, name := range documentedTables {
		if !seen[name] {
			t.Errorf("table %q is documented in BACKEND.md §2 but no migration "+
				"creates it", name)
		}
	}
}

func TestTableCountMatchesTheDocumentedTotal(t *testing.T) {
	// BACKEND.md §2 opens by stating a count, and a stated count that drifts is
	// worse than no count: it reads as verified. The first version of that
	// sentence said "eight tables, thirty-one columns" and the schema had nine
	// and thirty-two, which was found by querying a live database rather than by
	// reading. This makes the next drift fail in the fast gate instead.
	if got, want := len(tablesInMigrations(t)), len(documentedTables); got != want {
		t.Fatalf("migrations create %d tables, BACKEND.md §2 documents %d", got, want)
	}
}

func TestNoPlaintextMessageColumn(t *testing.T) {
	// THREAT_MODEL.md prohibition 7: no plaintext message content on the server,
	// in any column, at any time — including "temporary" ones. A grep is not a
	// proof, but the realistic failure is a column named for what it holds.
	sql := strings.ToLower(migrationCode(t))
	for _, forbidden := range []string{
		"plaintext", "message_text", "message_body", "content text", "body text",
		"subject", "preview",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("the schema mentions %q — prohibition 7 forbids any plaintext "+
				"message column", forbidden)
		}
	}
}

func TestNoSoftDeleteColumns(t *testing.T) {
	// The retention policy (BACKEND.md §4) is enforced by DELETE. A flag is a
	// record that outlives the thing it describes, so delivered-means-deleted
	// stops being true the moment one appears.
	sql := strings.ToLower(migrationCode(t))
	for _, forbidden := range []string{
		"deleted_at", "is_deleted", "is_revoked", "revoked_at", "delivered",
		"archived", "soft_delete",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("the schema contains %q — deletion is by DELETE, never by flag "+
				"(BACKEND.md §4)", forbidden)
		}
	}
}

func TestNoSenderColumnOnMessages(t *testing.T) {
	// Deriving a sender requires parsing the envelope, which no delivery decision
	// needs and which §1 forbids. The cleartext sender inside the envelope bytes
	// is a stated residual (BACKEND.md §2.7); a *column* would be a new record,
	// indexed and queryable, which is a different and much worse thing.
	sql := strings.ToLower(migrationCode(t))
	if strings.Contains(sql, "sender_aci") || strings.Contains(sql, "sender_id") {
		t.Error("messages must have no sender column — see BACKEND.md §2.7")
	}
}

func TestInvitesDoNotRecordTheInviter(t *testing.T) {
	// The invite graph is the social graph of a closed circle and is the single
	// most valuable thing a seizure could recover. BACKEND.md §2.2 refuses it.
	sql := strings.ToLower(migrationCode(t))
	for _, forbidden := range []string{"created_by", "inviter", "issued_by"} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("the schema contains %q — the invite graph is deliberately not "+
				"stored (BACKEND.md §2.2)", forbidden)
		}
	}
}

func TestAttachmentsRecordNoOwner(t *testing.T) {
	// The slot id is the capability, so the server never needs to know who
	// uploaded a blob or who may read it — and therefore never records the edge.
	sql := migrationCode(t)
	start := strings.Index(sql, "CREATE TABLE attachments")
	if start < 0 {
		t.Fatal("attachments table not found")
	}
	end := strings.Index(sql[start:], ");")
	if end < 0 {
		t.Fatal("attachments table definition is not terminated")
	}
	block := strings.ToLower(sql[start : start+end])

	for _, forbidden := range []string{"owner", "uploader", "aci"} {
		if strings.Contains(block, forbidden) {
			t.Errorf("the attachments table contains %q — the id is the capability "+
				"and the ownership edge is deliberately not recorded (BACKEND.md §2.8)",
				forbidden)
		}
	}
}
