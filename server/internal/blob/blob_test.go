// Copyright (C) 2026 Jan Richter
// SPDX-License-Identifier: AGPL-3.0-only
//
// AUDIT 5.27, the durability half: a rename is not durable until the directory
// holding the new name is itself flushed.

package blob

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, root
}

// --- Put ---------------------------------------------------------------------

func TestPutStoresTheBytes(t *testing.T) {
	// The positive control for the failure test below: an ordinary Put must
	// succeed, or "Put returned an error" proves nothing about the directory.
	s, _ := testStore(t)
	id := uuid.MustParse("aabb0000-0000-4000-8000-000000000001")
	payload := []byte("ciphertext")

	n, err := s.Put(id, bytes.NewReader(payload), 1024)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("wrote %d bytes, want %d", n, len(payload))
	}
	if !s.Exists(id) {
		t.Fatal("the blob is not on disk after a successful Put")
	}
}

func TestPutFailsWhenTheDirectoryCannotBeFlushed(t *testing.T) {
	// Proves Put actually calls syncDir, rather than only that syncDir works.
	//
	// Mode 0o300 is the isolating trick: write and search let os.Rename put the
	// file into the directory, while the missing read bit makes os.Open of the
	// directory itself fail — so the only step that can refuse is the flush.
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the directory permission this test relies on")
	}

	s, root := testStore(t)
	// Two ids sharing the first four hex digits share a fan-out directory, so
	// the first Put creates the directory the second one is refused by.
	first := uuid.MustParse("aabb0000-0000-4000-8000-000000000001")
	second := uuid.MustParse("aabb0000-0000-4000-8000-000000000002")

	if _, err := s.Put(first, strings.NewReader("one"), 1024); err != nil {
		t.Fatalf("first put: %v", err)
	}

	dir := filepath.Join(root, "aa", "bb")
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := s.Put(second, strings.NewReader("two"), 1024); err == nil {
		t.Fatal("Put reported success without flushing the directory holding the new name")
	}
}

// --- syncDir -------------------------------------------------------------------

func TestSyncDirFlushesARealDirectory(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir on a real directory: %v", err)
	}
}

func TestSyncDirReportsAMissingDirectory(t *testing.T) {
	if err := syncDir(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("syncDir reported success for a directory that does not exist")
	}
}
