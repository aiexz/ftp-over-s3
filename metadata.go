package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxMetadataRecordBytes = 64 * 1024 // 64 KiB ceiling for durable metadata JSON records
	maxUserMetadataEntries = 100
	maxUserMetadataKeyLen  = 1024
	maxUserMetadataValLen  = 4096
	maxHeaderValueLen      = 1024
	maxETagLen             = 256
)

// ObjectMetadata represents durable S3 object metadata, ETag, and user-defined metadata.
type ObjectMetadata struct {
	ETag               string            `json:"etag"`
	Size               int64             `json:"size"`
	ModTime            time.Time         `json:"mod_time"`
	ContentType        string            `json:"content_type,omitempty"`
	CacheControl       string            `json:"cache_control,omitempty"`
	ContentDisposition string            `json:"content_disposition,omitempty"`
	ContentEncoding    string            `json:"content_encoding,omitempty"`
	ContentLanguage    string            `json:"content_language,omitempty"`
	Expires            string            `json:"expires,omitempty"`
	UserMetadata       map[string]string `json:"user_metadata,omitempty"`
}

type pendingMarker struct {
	Key       string    `json:"key"`
	Timestamp time.Time `json:"timestamp"`
}

// MetadataStore manages durable per-key metadata records on disk.
type MetadataStore struct {
	dir string
	mu  sync.RWMutex
}

// NewMetadataStore initializes a MetadataStore in the state's objects directory.
func NewMetadataStore(state *State) *MetadataStore {
	dir := filepath.Join(state.Root, "objects")
	_ = os.MkdirAll(dir, 0700)
	return &MetadataStore{
		dir: dir,
	}
}

func (m *MetadataStore) keyHash(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func (m *MetadataStore) metaPath(key string) string {
	return filepath.Join(m.dir, m.keyHash(key)+".json")
}

func (m *MetadataStore) pendingPath(key string) string {
	return filepath.Join(m.dir, m.keyHash(key)+".pending")
}

// HasPending reports whether a pending write marker exists for key.
func (m *MetadataStore) HasPending(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, err := os.Stat(m.pendingPath(key))
	return err == nil
}

func validateMetadata(meta ObjectMetadata) error {
	if len(meta.ETag) > maxETagLen {
		return fmt.Errorf("etag length %d exceeds maximum %d", len(meta.ETag), maxETagLen)
	}
	if len(meta.ContentType) > maxHeaderValueLen {
		return fmt.Errorf("content-type length %d exceeds maximum %d", len(meta.ContentType), maxHeaderValueLen)
	}
	if len(meta.CacheControl) > maxHeaderValueLen {
		return fmt.Errorf("cache-control length %d exceeds maximum %d", len(meta.CacheControl), maxHeaderValueLen)
	}
	if len(meta.ContentDisposition) > maxHeaderValueLen {
		return fmt.Errorf("content-disposition length %d exceeds maximum %d", len(meta.ContentDisposition), maxHeaderValueLen)
	}
	if len(meta.ContentEncoding) > maxHeaderValueLen {
		return fmt.Errorf("content-encoding length %d exceeds maximum %d", len(meta.ContentEncoding), maxHeaderValueLen)
	}
	if len(meta.ContentLanguage) > maxHeaderValueLen {
		return fmt.Errorf("content-language length %d exceeds maximum %d", len(meta.ContentLanguage), maxHeaderValueLen)
	}
	if len(meta.Expires) > maxHeaderValueLen {
		return fmt.Errorf("expires length %d exceeds maximum %d", len(meta.Expires), maxHeaderValueLen)
	}
	if len(meta.UserMetadata) > maxUserMetadataEntries {
		return fmt.Errorf("user metadata entry count %d exceeds maximum %d", len(meta.UserMetadata), maxUserMetadataEntries)
	}
	for k, v := range meta.UserMetadata {
		if len(k) > maxUserMetadataKeyLen {
			return fmt.Errorf("user metadata key %q exceeds maximum length %d", k, maxUserMetadataKeyLen)
		}
		if len(v) > maxUserMetadataValLen {
			return fmt.Errorf("user metadata value for key %q exceeds maximum length %d", k, maxUserMetadataValLen)
		}
	}
	return nil
}

// Begin writes a durable pending marker for key before remote mutation begins.
func (m *MetadataStore) Begin(key string) error {
	if key == "" {
		return errors.New("empty key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	marker := pendingMarker{
		Key:       key,
		Timestamp: time.Now().UTC(),
	}
	return writeJSONAtomic(m.pendingPath(key), marker)
}

// Abort removes the durable pending marker on a known failed mutation, preserving any prior record.
func (m *MetadataStore) Abort(key string) error {
	if key == "" {
		return errors.New("empty key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	path := m.pendingPath(key)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(m.dir)
}

// Save atomically persists the metadata record and removes any pending marker.
func (m *MetadataStore) Save(key string, meta ObjectMetadata) error {
	if key == "" {
		return errors.New("empty key")
	}
	if err := validateMetadata(meta); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Clone user metadata to prevent caller mutation race
	if meta.UserMetadata != nil {
		cloned := make(map[string]string, len(meta.UserMetadata))
		for k, v := range meta.UserMetadata {
			cloned[k] = v
		}
		meta.UserMetadata = cloned
	}

	metaPath := m.metaPath(key)
	if err := writeJSONAtomic(metaPath, meta); err != nil {
		return err
	}

	pendingPath := m.pendingPath(key)
	if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(m.dir)
}

// Delete removes the persisted metadata record and any pending marker.
func (m *MetadataStore) Delete(key string) error {
	if key == "" {
		return errors.New("empty key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	if err := os.Remove(m.metaPath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if err := os.Remove(m.pendingPath(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	if err := syncDir(m.dir); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Load retrieves persisted metadata for key, validating it against info.
// Returns false if record is absent, stale (stat mismatch), or invalid due to an uncommitted pending write.
// Returns an error if the persisted record is corrupted, has trailing data, or violates validation rules.
func (m *MetadataStore) Load(key string, info *FileInfo) (ObjectMetadata, bool, error) {
	if key == "" {
		return ObjectMetadata{}, false, errors.New("empty key")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. Pending marker check: uncommitted mutation after crash must never attach old metadata
	// to potentially modified remote bytes. Report ambiguous state and treat as absent.
	pendingPath := m.pendingPath(key)
	if _, err := os.Stat(pendingPath); err == nil {
		slog.Warn("metadata pending marker present; returning absent record due to uncommitted mutation",
			"key", key, "marker", pendingPath)
		return ObjectMetadata{}, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ObjectMetadata{}, false, fmt.Errorf("failed to stat pending marker: %w", err)
	}

	// 2. Read metadata file
	metaPath := m.metaPath(key)
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ObjectMetadata{}, false, nil
		}
		return ObjectMetadata{}, false, fmt.Errorf("failed to read metadata file: %w", err)
	}

	if int64(len(data)) > maxMetadataRecordBytes {
		return ObjectMetadata{}, false, fmt.Errorf("corrupt metadata for key %q: size %d exceeds maximum %d",
			key, len(data), maxMetadataRecordBytes)
	}

	// 3. Strict JSON decode (fail closed on corruption or trailing data)
	var meta ObjectMetadata
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return ObjectMetadata{}, false, fmt.Errorf("corrupt metadata for key %q: %w", key, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ObjectMetadata{}, false, fmt.Errorf("corrupt metadata for key %q: trailing data after JSON object", key)
	}
	if err := validateMetadata(meta); err != nil {
		return ObjectMetadata{}, false, fmt.Errorf("corrupt metadata for key %q: invalid metadata: %w", key, err)
	}

	// 4. Bind stats to actual FTP object
	if info == nil {
		return ObjectMetadata{}, false, nil
	}
	if meta.Size != info.Size || !modTimeMatches(meta.ModTime, info.ModTime) {
		// Stat mismatch: remote file changed or does not match metadata
		return ObjectMetadata{}, false, nil
	}

	return meta, true, nil
}

func modTimeMatches(t1, t2 time.Time) bool {
	if t1.Equal(t2) {
		return true
	}
	// Tolerant match when FTP server or serialization truncated to second precision
	return t1.Unix() == t2.Unix() && (t1.Nanosecond() == 0 || t2.Nanosecond() == 0)
}
