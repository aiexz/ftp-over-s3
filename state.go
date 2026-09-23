package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// State represents the durable gateway state directory, holding exclusive process lock,
// disk budget tracking, and subdirectories for metadata, uploads, and temporary spools.
type State struct {
	Root     string
	Budget   *DiskBudget
	lockFile *os.File
	closed   bool
	mu       sync.Mutex
}

// SpoolDir returns the path to the temporary spool directory.
func (s *State) SpoolDir() string {
	return filepath.Join(s.Root, "spool")
}

// ObjectsDir returns the path to the durable metadata directory.
func (s *State) ObjectsDir() string {
	return filepath.Join(s.Root, "objects")
}

// UploadsDir returns the path to the durable multipart uploads directory.
func (s *State) UploadsDir() string {
	return filepath.Join(s.Root, "uploads")
}

// backendID generates a non-secret canonical identifier for the remote backend
// based on normalized backend kind, host, port, and username. Transport
// security and connection limits do not alter the logical storage root, and
// passwords are never included.
func backendID(config *Config) string {
	if config == nil {
		return ""
	}
	backend := strings.ToLower(strings.TrimSpace(config.Backend))
	if backend == "" {
		backend = "ftp"
	}
	host := strings.ToLower(strings.TrimSpace(config.FTPHost))
	port := config.FTPPort
	user := config.FTPUser
	raw := fmt.Sprintf("%s:%s:%d:%s", backend, host, port, user)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// ensurePrivateDir validates that path exists, is not a symlink, is a directory,
// and enforces 0700 private permissions so other local users cannot inspect state.
func ensurePrivateDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", path, err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %s is a symlink; symlinks are rejected for state directory", path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("path %s is not a directory", path)
	}

	if fi.Mode().Perm()&0077 != 0 {
		if err := os.Chmod(path, 0700); err != nil {
			return fmt.Errorf("failed to enforce private permissions on %s: %w", path, err)
		}
		fi2, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("failed to re-stat %s after chmod: %w", path, err)
		}
		if fi2.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("directory %s has unsafe permissions %04o (must be 0700)", path, fi2.Mode().Perm())
		}
	}
	return nil
}

// writeBackendIDAtomic writes backendID to markerPath atomically using a temp file,
// fsync, atomic rename, and directory sync.
func writeBackendIDAtomic(markerPath, id string) error {
	dir := filepath.Dir(markerPath)
	tmpFile, err := os.CreateTemp(dir, ".backend-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary backend marker: %w", err)
	}
	tmpName := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmpFile.WriteString(id + "\n"); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write backend ID: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to fsync backend marker: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close backend marker: %w", err)
	}
	if err := os.Rename(tmpName, markerPath); err != nil {
		return fmt.Errorf("failed to rename backend marker: %w", err)
	}
	cleanup = false

	if err := syncDir(dir); err != nil {
		return fmt.Errorf("failed to sync directory after writing backend marker: %w", err)
	}
	return nil
}

// OpenState initializes or reopens a durable state directory with exclusive process locking,
// backend binding validation, directory layout creation, and abandoned spool cleanup.
// ErrBackendMismatch is returned when a state directory is bound to a
// different backend. Rebinding requires an explicit operator opt-in
// (ForceBackendID) so an accidental backend switch never silently reuses
// another backend's metadata.
var ErrBackendMismatch = errors.New("state directory bound to a different backend")

// ForceBackendID rewrites the backend marker, rebinding a state directory
// to a new backend. Committed object metadata stays usable (ETags are
// revalidated against remote stat); caller must ensure no gateway process
// holds the directory (exclusive lock is taken during the rewrite).
func ForceBackendID(dir, backendID string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute state directory: %w", err)
	}
	lockPath := filepath.Join(absDir, ".lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("state directory %s is locked by another process: %w", absDir, err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	if backendID == "" {
		return errors.New("backend ID cannot be empty")
	}
	if err := writeBackendIDAtomic(filepath.Join(absDir, "backend.id"), backendID); err != nil {
		return err
	}
	return nil
}

// OpenState initializes or reopens a durable state directory with exclusive process locking,
// backend binding validation, directory layout creation, and abandoned spool cleanup.
func OpenState(dir, backendID string, maxBytes int64) (*State, error) {
	if dir == "" {
		return nil, errors.New("state directory cannot be empty")
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute state directory: %w", err)
	}

	if err := os.MkdirAll(absDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create state directory %s: %w", absDir, err)
	}
	if err := ensurePrivateDir(absDir); err != nil {
		return nil, err
	}

	// Exclusive process lock (Linux/macOS syscall.Flock)
	lockPath := filepath.Join(absDir, ".lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("state directory %s is locked by another process: %w", absDir, err)
		}
		return nil, fmt.Errorf("failed to acquire exclusive lock on %s: %w", lockPath, err)
	}

	// Backend binding check (fail closed on empty marker or conflict)
	markerPath := filepath.Join(absDir, "backend.id")
	if existingBytes, err := os.ReadFile(markerPath); err == nil {
		existing := strings.TrimSpace(string(existingBytes))
		if existing == "" {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			_ = lockFile.Close()
			return nil, fmt.Errorf("corrupt backend marker in %s: marker file is empty", markerPath)
		}
		if backendID != "" && existing != backendID {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			_ = lockFile.Close()
			return nil, fmt.Errorf("%w: state directory %s bound to backend %s, cannot be reused for backend %s (see -force-backend / ForceBackendID)", ErrBackendMismatch, absDir, existing, backendID)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if backendID == "" {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			_ = lockFile.Close()
			return nil, errors.New("backend ID cannot be empty when initializing new state directory")
		}
		if err := writeBackendIDAtomic(markerPath, backendID); err != nil {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			_ = lockFile.Close()
			return nil, fmt.Errorf("failed to write backend marker: %w", err)
		}
	} else {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		return nil, fmt.Errorf("failed to read backend marker: %w", err)
	}

	// Subdirectories creation and private permission validation
	subdirs := []string{"objects", "uploads", "spool"}
	for _, sub := range subdirs {
		subPath := filepath.Join(absDir, sub)
		if err := os.MkdirAll(subPath, 0700); err != nil {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			_ = lockFile.Close()
			return nil, fmt.Errorf("failed to create %s directory: %w", sub, err)
		}
		if err := ensurePrivateDir(subPath); err != nil {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			_ = lockFile.Close()
			return nil, err
		}
	}
	if err := syncDir(absDir); err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		return nil, fmt.Errorf("failed to sync state root after creating subdirectories: %w", err)
	}

	// Clean abandoned spool files under exclusive lock (fail closed on cleanup error)
	spoolDir := filepath.Join(absDir, "spool")
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		return nil, fmt.Errorf("failed to read spool directory %s during startup: %w", spoolDir, err)
	}
	for _, entry := range entries {
		entryPath := filepath.Join(spoolDir, entry.Name())
		if err := os.RemoveAll(entryPath); err != nil {
			_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
			_ = lockFile.Close()
			return nil, fmt.Errorf("failed to clean abandoned spool file %s: %w", entryPath, err)
		}
	}
	if err := syncDir(spoolDir); err != nil {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		return nil, fmt.Errorf("failed to sync spool directory after cleanup: %w", err)
	}

	budget := NewDiskBudget(maxBytes)

	return &State{
		Root:     absDir,
		Budget:   budget,
		lockFile: lockFile,
	}, nil
}

// Close releases the process lock. It does NOT purge persisted state (objects or uploads).
func (s *State) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lockFile != nil {
		_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
		err := s.lockFile.Close()
		s.lockFile = nil
		return err
	}
	return nil
}

// writeJSONAtomic writes value as formatted JSON to a temporary file in the same directory,
// fsyncs the file, atomically renames it over destination path, and fsyncs the parent directory.
func writeJSONAtomic(path string, value any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file in %s: %w", dir, err)
	}
	tmpName := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write to %s: %w", tmpName, err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to fsync %s: %w", tmpName, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", tmpName, path, err)
	}
	cleanup = false

	if err := syncDir(dir); err != nil {
		return fmt.Errorf("failed to sync directory %s after rename: %w", dir, err)
	}
	return nil
}

// syncDir opens dir and calls Sync to ensure directory modifications are durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("failed to open directory %s for sync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("failed to fsync directory %s: %w", dir, err)
	}
	return nil
}
