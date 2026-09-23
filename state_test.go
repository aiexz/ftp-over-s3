package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestState_TwoOwnerExclusion(t *testing.T) {
	dir := t.TempDir()
	backend := "test-backend-1"

	s1, err := OpenState(dir, backend, 1024*1024)
	if err != nil {
		t.Fatalf("first OpenState failed: %v", err)
	}
	defer s1.Close()

	// Second open on the same directory must fail due to exclusive flock
	s2, err := OpenState(dir, backend, 1024*1024)
	if err == nil {
		s2.Close()
		t.Fatalf("expected second OpenState to fail due to lock, but succeeded")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Errorf("expected lock error, got: %v", err)
	}

	// Release first lock
	if err := s1.Close(); err != nil {
		t.Fatalf("failed to close first state: %v", err)
	}

	// Third open after close must succeed
	s3, err := OpenState(dir, backend, 1024*1024)
	if err != nil {
		t.Fatalf("expected OpenState to succeed after release, got: %v", err)
	}
	defer s3.Close()
}

func TestState_BackendBindingAndReuse(t *testing.T) {
	dir := t.TempDir()

	// Initial open with backend alpha
	s1, err := OpenState(dir, "backend-alpha", 1024*1024)
	if err != nil {
		t.Fatalf("initial OpenState failed: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("failed to close s1: %v", err)
	}

	// Reopen with identical backend must succeed
	s2, err := OpenState(dir, "backend-alpha", 1024*1024)
	if err != nil {
		t.Fatalf("reopen with matching backend failed: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("failed to close s2: %v", err)
	}

	// Reopen with conflicting backend must fail
	s3, err := OpenState(dir, "backend-beta", 1024*1024)
	if err == nil {
		s3.Close()
		t.Fatalf("expected conflicting backend open to fail, but succeeded")
	}
	if !strings.Contains(err.Error(), "cannot be reused") {
		t.Errorf("expected conflict message in error, got: %v", err)
	}
}

func TestState_CorruptOrEmptyBackendMarker(t *testing.T) {
	dir := t.TempDir()

	// Pre-create empty backend.id
	markerPath := filepath.Join(dir, "backend.id")
	if err := os.WriteFile(markerPath, []byte("   \n"), 0600); err != nil {
		t.Fatalf("failed to write empty marker: %v", err)
	}

	_, err := OpenState(dir, "backend-1", 1024*1024)
	if err == nil {
		t.Fatalf("expected OpenState to fail on empty backend marker, but succeeded")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty marker error, got: %v", err)
	}
}

func TestState_SymlinkRejectionAndPermissionTightening(t *testing.T) {
	parent := t.TempDir()
	targetDir := filepath.Join(parent, "real_target")
	if err := os.Mkdir(targetDir, 0777); err != nil {
		t.Fatalf("failed to create real_target: %v", err)
	}

	// Case 1: Symlink directory must be rejected
	symlinkPath := filepath.Join(parent, "symlink_dir")
	if err := os.Symlink(targetDir, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	_, err := OpenState(symlinkPath, "backend-1", 1024*1024)
	if err == nil {
		t.Fatalf("expected OpenState to reject symlink directory, but succeeded")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink rejection error, got: %v", err)
	}

	// Case 2: Pre-existing directory with loose permissions (0777) must be tightened to 0700
	s, err := OpenState(targetDir, "backend-1", 1024*1024)
	if err != nil {
		t.Fatalf("OpenState on real_target failed: %v", err)
	}
	defer s.Close()

	fi, err := os.Lstat(targetDir)
	if err != nil {
		t.Fatalf("failed to lstat targetDir: %v", err)
	}
	if fi.Mode().Perm()&0077 != 0 {
		t.Errorf("expected permissions to be tightened to 0700, got: %04o", fi.Mode().Perm())
	}
}

func TestState_SpoolCleanupOnStartup(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate spool dir with abandoned temp files from prior crashed process
	spoolDir := filepath.Join(dir, "spool")
	if err := os.MkdirAll(spoolDir, 0700); err != nil {
		t.Fatalf("failed to create spool dir: %v", err)
	}
	abandonedFile := filepath.Join(spoolDir, "abandoned.tmp")
	if err := os.WriteFile(abandonedFile, []byte("stale-spool-data"), 0600); err != nil {
		t.Fatalf("failed to create abandoned file: %v", err)
	}

	// Pre-populate objects dir to ensure persistent state is preserved
	objectsDir := filepath.Join(dir, "objects")
	if err := os.MkdirAll(objectsDir, 0700); err != nil {
		t.Fatalf("failed to create objects dir: %v", err)
	}
	persistentFile := filepath.Join(objectsDir, "meta.json")
	if err := os.WriteFile(persistentFile, []byte("durable-meta"), 0600); err != nil {
		t.Fatalf("failed to create persistent file: %v", err)
	}

	// OpenState must clean spool under exclusive lock, but preserve objects
	state, err := OpenState(dir, "backend-1", 1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}
	defer state.Close()

	if _, err := os.Stat(abandonedFile); !os.IsNotExist(err) {
		t.Errorf("expected abandoned spool file to be removed, but still exists: %v", err)
	}
	if _, err := os.Stat(persistentFile); err != nil {
		t.Errorf("expected persistent metadata to remain, but got error: %v", err)
	}
}

func TestBackendID_Normalization(t *testing.T) {
	cfg1 := &Config{
		FTPHost:           "FTP.Example.COM",
		FTPPort:           21,
		FTPUser:           "Alice",
		FTPPassword:       "pass1",
		FTPTLS:            true,
		FTPMaxConnections: 8,
	}
	cfg2 := &Config{
		FTPHost:           "ftp.example.com",
		FTPPort:           21,
		FTPUser:           "Alice",
		FTPPassword:       "different-pass",
		FTPTLS:            false,
		FTPMaxConnections: 2,
	}
	cfg3 := &Config{
		FTPHost: "ftp.example.com",
		FTPPort: 21,
		FTPUser: "alice", // username casing difference
	}

	id1 := backendID(cfg1)
	id2 := backendID(cfg2)
	id3 := backendID(cfg3)

	if id1 == "" || id2 == "" || id3 == "" {
		t.Fatalf("expected non-empty backend IDs")
	}
	if id1 != id2 {
		t.Errorf("expected host normalization and transport independence to produce same ID: %s != %s", id1, id2)
	}
	if id1 == id3 {
		t.Errorf("expected username casing difference to produce distinct ID")
	}
}

func TestWriteJSONAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.json")

	type record struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	val := record{Name: "gateway", Count: 42}
	if err := writeJSONAtomic(path, val); err != nil {
		t.Fatalf("writeJSONAtomic failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if !strings.Contains(string(data), `"name": "gateway"`) {
		t.Errorf("unexpected content: %s", string(data))
	}
}
