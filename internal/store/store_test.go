package store

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// spec: DEP-003
func TestOpenFileWALAndMigrations(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "x.db")
	migs := []string{`CREATE TABLE a (id INTEGER)`, `ALTER TABLE a ADD COLUMN name TEXT`}
	db, err := Open(ctx, path, migs)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal mode %q %v", mode, err)
	}
	if _, err := db.Exec(`INSERT INTO a(id, name) VALUES (1, 'x')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	// Reopen with one more migration: only the new one runs.
	db, err = Open(ctx, path, append(migs, `CREATE TABLE b (id INTEGER)`))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n)
	if n != 3 {
		t.Fatalf("migrations recorded = %d", n)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o600 {
			t.Errorf("db file mode %v, want 0600", st.Mode().Perm())
		}
	}
}

func TestBadMigrationRollsBack(t *testing.T) {
	_, err := Open(context.Background(), ":memory:", []string{`CREATE TABLE ok (id INTEGER)`, `NOT SQL`})
	if err == nil {
		t.Fatal("expected migration error")
	}
}
