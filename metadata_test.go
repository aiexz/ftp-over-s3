package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestMetadataStore_SuccessfulSaveAndReopen(t *testing.T) {
	dir := t.TempDir()
	state, err := OpenState(dir, "backend-1", 10*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}
	defer state.Close()

	store := NewMetadataStore(state)
	key := "photos/vacation.jpg"
	modTime := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

	orig := ObjectMetadata{
		ETag:               "\"d41d8cd98f00b204e9800998ecf8427e\"",
		Size:               12345,
		ModTime:            modTime,
		ContentType:        "image/jpeg",
		CacheControl:       "public, max-age=86400",
		ContentDisposition: "attachment; filename=\"vacation.jpg\"",
		ContentEncoding:    "gzip",
		ContentLanguage:    "en-US",
		Expires:            "Thu, 01 Dec 2026 16:00:00 GMT",
		UserMetadata: map[string]string{
			"author": "Alice",
			"camera": "Sony A7IV",
		},
	}

	if err := store.Save(key, orig); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info := &FileInfo{
		Name:    "vacation.jpg",
		Size:    12345,
		ModTime: modTime,
	}

	loaded, ok, err := store.Load(key, info)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !ok {
		t.Fatalf("expected metadata to be found, got ok=false")
	}

	if loaded.ETag != orig.ETag || loaded.Size != orig.Size || !loaded.ModTime.Equal(orig.ModTime) {
		t.Errorf("metadata mismatch on core fields: %+v vs %+v", loaded, orig)
	}
	if loaded.ContentType != orig.ContentType || loaded.CacheControl != orig.CacheControl {
		t.Errorf("metadata mismatch on standard headers")
	}
	if len(loaded.UserMetadata) != 2 || loaded.UserMetadata["author"] != "Alice" {
		t.Errorf("metadata mismatch on user metadata: %+v", loaded.UserMetadata)
	}

	// Delete and verify absent
	if err := store.Delete(key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, ok, err = store.Load(key, info)
	if err != nil {
		t.Fatalf("Load after delete returned error: %v", err)
	}
	if ok {
		t.Errorf("expected ok=false after delete, got true")
	}
}

func TestMetadataStore_CorruptMetadataRejection(t *testing.T) {
	dir := t.TempDir()
	state, err := OpenState(dir, "backend-1", 10*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}
	defer state.Close()

	store := NewMetadataStore(state)
	key := "corrupt.txt"

	// Case 1: Malformed JSON syntax
	metaPath := store.metaPath(key)
	if err := os.WriteFile(metaPath, []byte(`{"etag": "incomplete`), 0600); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	info := &FileInfo{Name: "corrupt.txt", Size: 10}
	_, ok, err := store.Load(key, info)
	if err == nil {
		t.Fatalf("expected error on corrupt JSON, got nil (ok=%v)", ok)
	}
	if !strings.Contains(err.Error(), "corrupt metadata") {
		t.Errorf("expected corrupt metadata error, got: %v", err)
	}

	// Case 2: Oversized metadata file exceeding maximum allowed size
	oversizedPath := store.metaPath("oversized.txt")
	junk := make([]byte, maxMetadataRecordBytes+100)
	if err := os.WriteFile(oversizedPath, junk, 0600); err != nil {
		t.Fatalf("failed to write oversized file: %v", err)
	}
	_, _, err = store.Load("oversized.txt", info)
	if err == nil {
		t.Fatalf("expected error on oversized metadata record, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("expected exceeds maximum error, got: %v", err)
	}

	// Case 3: Trailing data after valid JSON object
	trailingPath := store.metaPath("trailing.txt")
	validWithTrailing := []byte(`{"etag": "\"valid\"", "size": 10, "mod_time": "2026-09-22T10:00:00Z"} {"extra": 123}`)
	if err := os.WriteFile(trailingPath, validWithTrailing, 0600); err != nil {
		t.Fatalf("failed to write trailing JSON file: %v", err)
	}
	_, _, err = store.Load("trailing.txt", info)
	if err == nil {
		t.Fatalf("expected error on metadata record with trailing JSON, got nil")
	}
	if !strings.Contains(err.Error(), "trailing data") {
		t.Errorf("expected trailing data error, got: %v", err)
	}
}

func TestMetadataStore_StatMismatchInvalidation(t *testing.T) {
	dir := t.TempDir()
	state, err := OpenState(dir, "backend-1", 10*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}
	defer state.Close()

	store := NewMetadataStore(state)
	key := "file.bin"
	modTime := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	meta := ObjectMetadata{
		ETag:    "\"original-etag\"",
		Size:    1000,
		ModTime: modTime,
	}
	if err := store.Save(key, meta); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Case 1: Size mismatch
	infoWrongSize := &FileInfo{Name: "file.bin", Size: 1001, ModTime: modTime}
	_, ok, err := store.Load(key, infoWrongSize)
	if err != nil {
		t.Fatalf("unexpected error on size mismatch: %v", err)
	}
	if ok {
		t.Errorf("expected ok=false on size mismatch, got true")
	}

	// Case 2: ModTime mismatch
	infoWrongTime := &FileInfo{Name: "file.bin", Size: 1000, ModTime: modTime.Add(2 * time.Hour)}
	_, ok, err = store.Load(key, infoWrongTime)
	if err != nil {
		t.Fatalf("unexpected error on modTime mismatch: %v", err)
	}
	if ok {
		t.Errorf("expected ok=false on modTime mismatch, got true")
	}

	// Case 3: Nil info
	_, ok, err = store.Load(key, nil)
	if err != nil {
		t.Fatalf("unexpected error on nil info: %v", err)
	}
	if ok {
		t.Errorf("expected ok=false on nil info, got true")
	}

	// Case 4: Correct match
	infoMatch := &FileInfo{Name: "file.bin", Size: 1000, ModTime: modTime}
	loaded, ok, err := store.Load(key, infoMatch)
	if err != nil {
		t.Fatalf("unexpected error on match: %v", err)
	}
	if !ok || loaded.ETag != "\"original-etag\"" {
		t.Errorf("expected match with original-etag, got ok=%v, etag=%s", ok, loaded.ETag)
	}
}

func TestMetadataStore_PendingWriteAmbiguity(t *testing.T) {
	dir := t.TempDir()
	state, err := OpenState(dir, "backend-1", 10*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}
	defer state.Close()

	store := NewMetadataStore(state)
	key := "data.dat"
	t1 := time.Date(2026, 9, 22, 8, 0, 0, 0, time.UTC)
	meta1 := ObjectMetadata{
		ETag:    "\"etag-v1\"",
		Size:    100,
		ModTime: t1,
	}

	// Persist initial valid metadata
	if err := store.Save(key, meta1); err != nil {
		t.Fatalf("Save meta1 failed: %v", err)
	}
	info1 := &FileInfo{Name: "data.dat", Size: 100, ModTime: t1}

	// 1. Begin mutation -> pending marker written
	if err := store.Begin(key); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	if !store.HasPending(key) {
		t.Errorf("expected HasPending=true after Begin")
	}

	// 2. Uncommitted crash state: Load must NEVER attach old metadata to potentially new bytes
	_, ok, err := store.Load(key, info1)
	if err != nil {
		t.Fatalf("unexpected error checking ambiguous load: %v", err)
	}
	if ok {
		t.Errorf("expected ok=false during pending write ambiguity, but old record was returned")
	}

	// 3. Known failure -> Abort removes pending marker and preserves prior record
	if err := store.Abort(key); err != nil {
		t.Fatalf("Abort failed: %v", err)
	}
	if store.HasPending(key) {
		t.Errorf("expected HasPending=false after Abort")
	}

	loaded, ok, err := store.Load(key, info1)
	if err != nil || !ok || loaded.ETag != "\"etag-v1\"" {
		t.Errorf("expected prior metadata restored after Abort, got ok=%v, etag=%s, err=%v", ok, loaded.ETag, err)
	}

	// 4. Completed mutation -> Begin, then Save clears marker and updates metadata
	if err := store.Begin(key); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	t2 := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	meta2 := ObjectMetadata{
		ETag:    "\"etag-v2\"",
		Size:    200,
		ModTime: t2,
	}
	if err := store.Save(key, meta2); err != nil {
		t.Fatalf("Save meta2 failed: %v", err)
	}
	if store.HasPending(key) {
		t.Errorf("expected HasPending=false after Save")
	}

	info2 := &FileInfo{Name: "data.dat", Size: 200, ModTime: t2}
	loaded2, ok, err := store.Load(key, info2)
	if err != nil || !ok || loaded2.ETag != "\"etag-v2\"" {
		t.Errorf("expected new metadata after Save, got ok=%v, etag=%s, err=%v", ok, loaded2.ETag, err)
	}
}

func TestMetadataStore_HeaderValidationLimits(t *testing.T) {
	dir := t.TempDir()
	state, err := OpenState(dir, "backend-1", 10*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}
	defer state.Close()

	store := NewMetadataStore(state)
	key := "validation.txt"

	// Oversized ETag
	metaBadETag := ObjectMetadata{
		ETag: strings.Repeat("x", maxETagLen+1),
	}
	if err := store.Save(key, metaBadETag); err == nil {
		t.Errorf("expected error for oversized ETag, got nil")
	}

	// Too many user metadata entries
	tooManyEntries := make(map[string]string)
	for i := 0; i <= maxUserMetadataEntries; i++ {
		tooManyEntries[strings.Repeat("k", i+1)] = "v"
	}
	metaTooMany := ObjectMetadata{
		UserMetadata: tooManyEntries,
	}
	if err := store.Save(key, metaTooMany); err == nil {
		t.Errorf("expected error for exceeding user metadata count limit, got nil")
	}
}
