package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidPartOrder     = errors.New("InvalidPartOrder")
	ErrInvalidPart          = errors.New("InvalidPart")
	ErrEntityTooSmall       = errors.New("EntityTooSmall")
	ErrEntityTooLarge       = errors.New("EntityTooLarge")
	ErrNoSuchUpload         = errors.New("NoSuchUpload")
	ErrStagingLimitExceeded = errors.New("StagingLimitExceeded")
	ErrUploadClosed         = errors.New("UploadClosed")
)

const (
	MaxConcurrentUploads = 100
	MaxPartSizeBytes     = int64(5 * 1024 * 1024 * 1024) // 5 GiB per-part cap
)

// PartInfo represents an uploaded part of a multipart upload.
type PartInfo struct {
	PartNumber     int       `json:"part_number"`
	ETag           string    `json:"etag"` // Quoted hex MD5, e.g. "\"a1b2c3...\""
	Size           int64     `json:"size"`
	ModTime        time.Time `json:"mod_time"`
	RawMD5         []byte    `json:"raw_md5"` // 16 bytes raw binary MD5
	Path           string    `json:"path"`    // Local file path on disk
	ChecksumCRC32  string    `json:"checksum_crc32,omitempty"`
	ChecksumCRC32C string    `json:"checksum_crc32c,omitempty"`
	ChecksumSHA1   string    `json:"checksum_sha1,omitempty"`
	ChecksumSHA256 string    `json:"checksum_sha256,omitempty"`
}

// MultipartUploadSession represents an in-progress multipart upload session.
type MultipartUploadSession struct {
	mu        sync.Mutex
	UploadID  string
	Bucket    string
	Key       string
	Initiated time.Time
	Metadata  ObjectMetadata
	Dir       string
	Parts     map[int]*PartInfo
	Aborted   bool
	Completed bool
}

type sessionManifest struct {
	UploadID  string            `json:"upload_id"`
	Bucket    string            `json:"bucket"`
	Key       string            `json:"key"`
	Initiated time.Time         `json:"initiated"`
	Metadata  ObjectMetadata    `json:"metadata"`
	Parts     map[int]*PartInfo `json:"parts"`
}

// MultipartManager manages multipart uploads with durable disk persistence and budget accounting.
type MultipartManager struct {
	mu        sync.RWMutex
	uploads   map[string]*MultipartUploadSession
	inFlight  int
	state     *State
	dir       string
	closeChan chan struct{}
	doneChan  chan struct{}
}

// NewMultipartManager initializes or recovers durable multipart uploads from state.UploadsDir().
func NewMultipartManager(state *State) (*MultipartManager, error) {
	if state == nil || state.Root == "" {
		return nil, errors.New("state with Root is required")
	}
	uploadsDir := state.UploadsDir()
	if err := os.MkdirAll(uploadsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create uploads dir: %w", err)
	}

	m := &MultipartManager{
		uploads:   make(map[string]*MultipartUploadSession),
		state:     state,
		dir:       uploadsDir,
		closeChan: make(chan struct{}),
		doneChan:  make(chan struct{}),
	}

	if err := m.recoverSessions(); err != nil {
		return nil, err
	}

	go m.cleanupLoop()
	return m, nil
}

func (m *MultipartManager) recoverSessions() error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return fmt.Errorf("failed to read uploads dir: %w", err)
	}

	var totalRecoveredBytes int64

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		uploadID := entry.Name()
		sessionDir := filepath.Join(m.dir, uploadID)
		manifestPath := filepath.Join(sessionDir, "manifest.json")

		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			// Missing or corrupt manifests fail closed without deleting recoverable data.
			return fmt.Errorf("upload session %s: missing or unreadable manifest: %w", uploadID, err)
		}

		var mf sessionManifest
		if err := json.Unmarshal(raw, &mf); err != nil {
			// Missing or corrupt manifests fail closed without deleting recoverable data.
			return fmt.Errorf("upload session %s: corrupt manifest JSON: %w", uploadID, err)
		}

		if mf.UploadID == "" || mf.UploadID != uploadID || mf.Bucket == "" || mf.Key == "" {
			return fmt.Errorf("upload session %s: invalid manifest header fields", uploadID)
		}

		if mf.Parts == nil {
			mf.Parts = make(map[int]*PartInfo)
		}

		declaredPaths := make(map[string]bool)
		cleanSessionDir := filepath.Clean(sessionDir) + string(filepath.Separator)

		for partNum, part := range mf.Parts {
			if partNum < 1 || partNum > 10000 || part == nil {
				return fmt.Errorf("upload session %s: invalid part number %d", uploadID, partNum)
			}
			if part.PartNumber != partNum {
				return fmt.Errorf("upload session %s: part number mismatch: key %d, embedded %d", uploadID, partNum, part.PartNumber)
			}
			cleanPath := filepath.Clean(part.Path)
			if !strings.HasPrefix(cleanPath, cleanSessionDir) {
				return fmt.Errorf("upload session %s part %d: path safety violation: %s", uploadID, partNum, part.Path)
			}
			fi, err := os.Stat(cleanPath)
			if err != nil {
				return fmt.Errorf("upload session %s part %d: file missing: %w", uploadID, partNum, err)
			}
			if fi.Size() != part.Size {
				return fmt.Errorf("upload session %s part %d: size mismatch (manifest: %d, disk: %d)", uploadID, partNum, part.Size, fi.Size())
			}

			// Require valid raw MD5 of declared part
			if len(part.RawMD5) != md5.Size {
				return fmt.Errorf("upload session %s part %d: invalid RawMD5 length: expected %d, got %d", uploadID, partNum, md5.Size, len(part.RawMD5))
			}

			// Validate MD5 checksum of declared part on disk
			f, err := os.Open(cleanPath)
			if err != nil {
				return fmt.Errorf("upload session %s part %d: failed to open: %w", uploadID, partNum, err)
			}
			h := md5.New()
			if _, err := io.Copy(h, f); err != nil {
				_ = f.Close()
				return fmt.Errorf("upload session %s part %d: failed to read: %w", uploadID, partNum, err)
			}
			_ = f.Close()
			computedMD5 := h.Sum(nil)
			if !bytes.Equal(computedMD5, part.RawMD5) {
				return fmt.Errorf("upload session %s part %d: MD5 checksum mismatch", uploadID, partNum)
			}
			computedETag := fmt.Sprintf("\"%x\"", computedMD5)
			if strings.Trim(part.ETag, "\"") != strings.Trim(computedETag, "\"") {
				return fmt.Errorf("upload session %s part %d: ETag mismatch", uploadID, partNum)
			}

			// Reserve budget for recovered part
			if m.state != nil && m.state.Budget != nil {
				if err := m.state.Budget.Reserve(part.Size); err != nil {
					m.state.Budget.Release(totalRecoveredBytes)
					return fmt.Errorf("%w: startup recovery exceeded storage limit for part %d: %w", ErrStagingLimitExceeded, partNum, err)
				}
				totalRecoveredBytes += part.Size
			}

			declaredPaths[cleanPath] = true
		}

		// Clean up orphan files only in this owned session directory if manifest and declared parts are valid.
		manifestClean := filepath.Clean(manifestPath)
		dirEntries, err := os.ReadDir(sessionDir)
		if err != nil {
			return fmt.Errorf("upload session %s: failed to read directory for orphan cleanup: %w", uploadID, err)
		}
		var cleanedOrphans bool
		for _, de := range dirEntries {
			entryPath := filepath.Clean(filepath.Join(sessionDir, de.Name()))
			if entryPath == manifestClean {
				continue
			}
			if !declaredPaths[entryPath] {
				if err := os.RemoveAll(entryPath); err != nil {
					return fmt.Errorf("upload session %s: failed to remove orphan file %s: %w", uploadID, entryPath, err)
				}
				cleanedOrphans = true
			}
		}
		if cleanedOrphans {
			if err := syncDir(sessionDir); err != nil {
				return fmt.Errorf("upload session %s: failed to sync directory after orphan cleanup: %w", uploadID, err)
			}
		}

		session := &MultipartUploadSession{
			UploadID:  mf.UploadID,
			Bucket:    mf.Bucket,
			Key:       mf.Key,
			Initiated: mf.Initiated,
			Metadata:  mf.Metadata,
			Dir:       sessionDir,
			Parts:     mf.Parts,
		}
		m.uploads[session.UploadID] = session
	}

	return nil
}

func (m *MultipartManager) cleanupLoop() {
	defer close(m.doneChan)
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.cleanupExpired(24 * time.Hour)
		case <-m.closeChan:
			return
		}
	}
}

func (m *MultipartManager) cleanupExpired(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	var candidates []*MultipartUploadSession

	m.mu.RLock()
	for _, session := range m.uploads {
		if session.Initiated.Before(cutoff) {
			candidates = append(candidates, session)
		}
	}
	m.mu.RUnlock()

	for _, session := range candidates {
		session.mu.Lock()
		if session.Aborted || session.Completed || !session.Initiated.Before(cutoff) {
			session.mu.Unlock()
			continue
		}

		// Delete staging directory on disk first
		if err := os.RemoveAll(session.Dir); err != nil {
			session.mu.Unlock()
			continue
		}
		if err := syncDir(m.dir); err != nil {
			session.mu.Unlock()
			continue
		}

		session.Aborted = true

		m.mu.Lock()
		delete(m.uploads, session.UploadID)
		m.mu.Unlock()

		if m.state != nil && m.state.Budget != nil {
			var freed int64
			for _, p := range session.Parts {
				freed += p.Size
			}
			m.state.Budget.Release(freed)
		}
		session.mu.Unlock()
	}
}

// Close gracefully stops the background cleanup loop without aborting or deleting active sessions.
func (m *MultipartManager) Close() error {
	m.mu.Lock()
	select {
	case <-m.closeChan:
		m.mu.Unlock()
		return nil
	default:
		close(m.closeChan)
	}
	m.mu.Unlock()

	<-m.doneChan
	return nil
}

// CreateUpload initiates a new multipart upload session and writes its initial durable manifest.
func (m *MultipartManager) CreateUpload(bucket, key string, meta ObjectMetadata) (*MultipartUploadSession, error) {
	if err := validateMetadata(meta); err != nil {
		return nil, fmt.Errorf("invalid multipart metadata: %w", err)
	}

	m.mu.Lock()
	if len(m.uploads)+m.inFlight >= MaxConcurrentUploads {
		m.mu.Unlock()
		return nil, errors.New("too many active multipart uploads")
	}
	m.inFlight++
	m.mu.Unlock()

	var success bool
	defer func() {
		if !success {
			m.mu.Lock()
			m.inFlight--
			m.mu.Unlock()
		}
	}()

	randBytes := make([]byte, 16)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("failed to generate upload ID: %w", err)
	}
	uploadID := fmt.Sprintf("%016x%016x", time.Now().UnixNano(), randBytes)

	sessionDir := filepath.Join(m.dir, uploadID)
	if err := os.Mkdir(sessionDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create staging directory: %w", err)
	}

	session := &MultipartUploadSession{
		UploadID:  uploadID,
		Bucket:    bucket,
		Key:       key,
		Initiated: time.Now().UTC(),
		Metadata:  meta,
		Dir:       sessionDir,
		Parts:     make(map[int]*PartInfo),
	}

	manifest := sessionManifest{
		UploadID:  session.UploadID,
		Bucket:    session.Bucket,
		Key:       session.Key,
		Initiated: session.Initiated,
		Metadata:  session.Metadata,
		Parts:     session.Parts,
	}
	manifestPath := filepath.Join(sessionDir, "manifest.json")
	if err := writeJSONAtomic(manifestPath, manifest); err != nil {
		_ = os.RemoveAll(sessionDir)
		return nil, fmt.Errorf("failed to write initial multipart manifest: %w", err)
	}

	if err := syncDir(m.dir); err != nil {
		_ = os.RemoveAll(sessionDir)
		return nil, fmt.Errorf("failed to sync uploads directory after creating session: %w", err)
	}

	m.mu.Lock()
	m.inFlight--
	m.uploads[uploadID] = session
	success = true
	m.mu.Unlock()

	return session, nil
}

// GetUpload returns the session for the given upload ID if present.
func (m *MultipartManager) GetUpload(uploadID string) (*MultipartUploadSession, bool) {
	m.mu.RLock()
	s, ok := m.uploads[uploadID]
	m.mu.RUnlock()
	return s, ok
}

// AbortUpload terminates the session, releases its disk budget, and removes all staging files.
func (m *MultipartManager) AbortUpload(uploadID string) error {
	m.mu.RLock()
	session, ok := m.uploads[uploadID]
	m.mu.RUnlock()
	if !ok {
		return ErrNoSuchUpload
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.Aborted || session.Completed {
		return ErrNoSuchUpload
	}

	// Delete staging directory on disk first
	if err := os.RemoveAll(session.Dir); err != nil {
		return fmt.Errorf("failed to remove staging directory: %w", err)
	}
	if err := syncDir(m.dir); err != nil {
		return fmt.Errorf("failed to sync uploads directory after abort: %w", err)
	}

	session.Aborted = true

	m.mu.Lock()
	delete(m.uploads, uploadID)
	m.mu.Unlock()

	if m.state != nil && m.state.Budget != nil {
		var freed int64
		for _, p := range session.Parts {
			freed += p.Size
		}
		m.state.Budget.Release(freed)
	}

	return nil
}

type budgetPartWriter struct {
	w        io.Writer
	budget   *DiskBudget
	reserved int64
	written  int64
	maxBytes int64
}

func (bw *budgetPartWriter) Write(p []byte) (int, error) {
	n := int64(len(p))
	if bw.written+n > bw.maxBytes {
		return 0, ErrEntityTooLarge
	}
	if bw.written+n > bw.reserved {
		toReserve := (bw.written + n) - bw.reserved
		if bw.budget != nil {
			if err := bw.budget.Reserve(toReserve); err != nil {
				return 0, fmt.Errorf("%w: %w", ErrStagingLimitExceeded, err)
			}
		}
		bw.reserved += toReserve
	}
	written, err := bw.w.Write(p)
	bw.written += int64(written)
	if int64(written) < n && bw.budget != nil {
		unwritten := n - int64(written)
		bw.budget.Release(unwritten)
		bw.reserved -= unwritten
	}
	return written, err
}

// UploadPart writes an immutable part file to disk, commits the session manifest atomically,
// and deletes any superseded part after manifest durability is guaranteed.
func (m *MultipartManager) UploadPart(
	session *MultipartUploadSession,
	partNumber int,
	body io.Reader,
	contentLength int64,
	hexMD5 string,
	checksumCRC32, checksumCRC32C, checksumSHA1, checksumSHA256 string,
) (*PartInfo, error) {
	if partNumber < 1 || partNumber > 10000 {
		return nil, errors.New("part number must be between 1 and 10000")
	}
	if contentLength > MaxPartSizeBytes {
		return nil, ErrEntityTooLarge
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.Aborted || session.Completed {
		return nil, ErrNoSuchUpload
	}

	var oldSize int64
	var oldPath string
	oldPart, hasOld := session.Parts[partNumber]
	if hasOld {
		oldSize = oldPart.Size
		oldPath = oldPart.Path
	}

	var initialReserve int64
	if contentLength > 0 {
		initialReserve = contentLength
		if m.state != nil && m.state.Budget != nil {
			if err := m.state.Budget.Reserve(initialReserve); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrStagingLimitExceeded, err)
			}
		}
	}

	tmpFile, err := os.CreateTemp(session.Dir, fmt.Sprintf("part-%d-tmp-*", partNumber))
	if err != nil {
		if initialReserve > 0 && m.state != nil && m.state.Budget != nil {
			m.state.Budget.Release(initialReserve)
		}
		return nil, fmt.Errorf("failed to create temp part file: %w", err)
	}
	tmpPath := tmpFile.Name()

	var budget *DiskBudget
	if m.state != nil {
		budget = m.state.Budget
	}
	rollbackQuota := func(allocated int64) {
		if allocated > 0 && budget != nil {
			budget.Release(allocated)
		}
	}
	bw := &budgetPartWriter{
		w:        tmpFile,
		budget:   budget,
		reserved: initialReserve,
		maxBytes: MaxPartSizeBytes,
	}

	md5Hash := md5.New()
	writers := []io.Writer{bw, md5Hash}

	var crc32Hash hash.Hash32
	if checksumCRC32 != "" {
		crc32Hash = crc32.NewIEEE()
		writers = append(writers, crc32Hash)
	}
	var crc32cHash hash.Hash32
	if checksumCRC32C != "" {
		crc32cHash = crc32.New(crc32.MakeTable(crc32.Castagnoli))
		writers = append(writers, crc32cHash)
	}
	var sha1Hash hash.Hash
	if checksumSHA1 != "" {
		sha1Hash = sha1.New()
		writers = append(writers, sha1Hash)
	}
	var sha256Hash hash.Hash
	if checksumSHA256 != "" {
		sha256Hash = sha256.New()
		writers = append(writers, sha256Hash)
	}

	mw := io.MultiWriter(writers...)
	lr := io.LimitReader(body, MaxPartSizeBytes+1)
	_, copyErr := io.Copy(mw, lr)
	if copyErr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		if bw.reserved > 0 && budget != nil {
			budget.Release(bw.reserved)
		}
		return nil, fmt.Errorf("failed to write part data: %w", copyErr)
	}

	if bw.written > MaxPartSizeBytes {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		if bw.reserved > 0 && budget != nil {
			budget.Release(bw.reserved)
		}
		return nil, ErrEntityTooLarge
	}

	if bw.written < bw.reserved && budget != nil {
		budget.Release(bw.reserved - bw.written)
		bw.reserved = bw.written
	}
	totalAllocated := bw.written

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		rollbackQuota(totalAllocated)
		return nil, fmt.Errorf("failed to sync temp part file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		rollbackQuota(totalAllocated)
		return nil, fmt.Errorf("failed to close temp part file: %w", err)
	}

	rawMD5 := md5Hash.Sum(nil)
	computedHexMD5 := hex.EncodeToString(rawMD5)

	if hexMD5 != "" && !strings.EqualFold(hexMD5, computedHexMD5) {
		_ = os.Remove(tmpPath)
		rollbackQuota(totalAllocated)
		return nil, errors.New("MD5 checksum mismatch")
	}

	if checksumCRC32 != "" {
		encodedCRC32 := base64.StdEncoding.EncodeToString(crc32Hash.Sum(nil))
		if encodedCRC32 != checksumCRC32 {
			_ = os.Remove(tmpPath)
			rollbackQuota(totalAllocated)
			return nil, errors.New("CRC32 checksum mismatch")
		}
	}
	if checksumCRC32C != "" {
		encodedCRC32C := base64.StdEncoding.EncodeToString(crc32cHash.Sum(nil))
		if encodedCRC32C != checksumCRC32C {
			_ = os.Remove(tmpPath)
			rollbackQuota(totalAllocated)
			return nil, errors.New("CRC32C checksum mismatch")
		}
	}
	if checksumSHA1 != "" {
		encodedSHA1 := base64.StdEncoding.EncodeToString(sha1Hash.Sum(nil))
		if encodedSHA1 != checksumSHA1 {
			_ = os.Remove(tmpPath)
			rollbackQuota(totalAllocated)
			return nil, errors.New("SHA1 checksum mismatch")
		}
	}
	if checksumSHA256 != "" {
		encodedSHA256 := base64.StdEncoding.EncodeToString(sha256Hash.Sum(nil))
		if encodedSHA256 != checksumSHA256 {
			_ = os.Remove(tmpPath)
			rollbackQuota(totalAllocated)
			return nil, errors.New("SHA256 checksum mismatch")
		}
	}

	// Immutable part filename containing MD5 prefix and timestamp nanoseconds
	partFileName := fmt.Sprintf("part-%d-%s-%d.dat", partNumber, computedHexMD5[:min(8, len(computedHexMD5))], time.Now().UnixNano())
	finalPath := filepath.Join(session.Dir, partFileName)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		rollbackQuota(totalAllocated)
		return nil, fmt.Errorf("failed to rename part file: %w", err)
	}

	newPart := &PartInfo{
		PartNumber:     partNumber,
		ETag:           fmt.Sprintf("\"%s\"", computedHexMD5),
		Size:           totalAllocated,
		ModTime:        time.Now().UTC(),
		RawMD5:         rawMD5,
		Path:           finalPath,
		ChecksumCRC32:  checksumCRC32,
		ChecksumCRC32C: checksumCRC32C,
		ChecksumSHA1:   checksumSHA1,
		ChecksumSHA256: checksumSHA256,
	}

	// Atomically replace manifest
	updatedParts := make(map[int]*PartInfo, len(session.Parts)+1)
	for k, v := range session.Parts {
		updatedParts[k] = v
	}
	updatedParts[partNumber] = newPart

	manifest := sessionManifest{
		UploadID:  session.UploadID,
		Bucket:    session.Bucket,
		Key:       session.Key,
		Initiated: session.Initiated,
		Metadata:  session.Metadata,
		Parts:     updatedParts,
	}
	manifestPath := filepath.Join(session.Dir, "manifest.json")
	if err := writeJSONAtomic(manifestPath, manifest); err != nil {
		// Verify whether manifest on disk was actually committed despite error (e.g. syncDir failure after rename).
		committed := false
		if raw, readErr := os.ReadFile(manifestPath); readErr == nil {
			var checkMf sessionManifest
			if json.Unmarshal(raw, &checkMf) == nil && checkMf.Parts != nil {
				if p, ok := checkMf.Parts[partNumber]; ok && p != nil && p.Path == finalPath {
					committed = true
				}
			}
		}

		if committed {
			// Manifest was atomically committed before sync error. Retain consistent state,
			// clean up old part, and propagate durability failure to caller.
			session.Parts[partNumber] = newPart
			if hasOld && oldPath != "" && oldPath != finalPath {
				if err := os.Remove(oldPath); err == nil {
					if m.state != nil && m.state.Budget != nil {
						m.state.Budget.Release(oldSize)
					}
				}
			}
			return nil, fmt.Errorf("multipart manifest commit sync failure: %w", err)
		}

		_ = os.Remove(finalPath)
		rollbackQuota(totalAllocated)
		return nil, fmt.Errorf("failed to commit multipart manifest: %w", err)
	}

	session.Parts[partNumber] = newPart

	// Atomic manifest replacement precedes deleting superseded part
	if hasOld && oldPath != "" && oldPath != finalPath {
		if err := os.Remove(oldPath); err == nil {
			if m.state != nil && m.state.Budget != nil {
				m.state.Budget.Release(oldSize)
			}
		}
	}

	return newPart, nil
}

// AssembleStream validates requested parts and returns an io.ReadCloser streaming them in order without duplicating disk storage.
func (m *MultipartManager) AssembleStream(session *MultipartUploadSession, requestedParts []CompletedPart) (stream io.ReadCloser, s3ETag string, totalSize int64, err error) {
	if len(requestedParts) == 0 {
		return nil, "", 0, ErrInvalidPart
	}

	for i := range requestedParts {
		if i > 0 && requestedParts[i].PartNumber <= requestedParts[i-1].PartNumber {
			return nil, "", 0, ErrInvalidPartOrder
		}
	}

	for i, req := range requestedParts {
		storedPart, ok := session.Parts[req.PartNumber]
		if !ok {
			return nil, "", 0, ErrInvalidPart
		}
		reqETag := strings.Trim(req.ETag, "\"")
		storedETag := strings.Trim(storedPart.ETag, "\"")
		if reqETag == "" || !strings.EqualFold(reqETag, storedETag) {
			return nil, "", 0, ErrInvalidPart
		}
		if req.ChecksumCRC32 != "" && req.ChecksumCRC32 != storedPart.ChecksumCRC32 {
			return nil, "", 0, ErrInvalidPart
		}
		if req.ChecksumCRC32C != "" && req.ChecksumCRC32C != storedPart.ChecksumCRC32C {
			return nil, "", 0, ErrInvalidPart
		}
		if req.ChecksumSHA1 != "" && req.ChecksumSHA1 != storedPart.ChecksumSHA1 {
			return nil, "", 0, ErrInvalidPart
		}
		if req.ChecksumSHA256 != "" && req.ChecksumSHA256 != storedPart.ChecksumSHA256 {
			return nil, "", 0, ErrInvalidPart
		}
		if i < len(requestedParts)-1 && storedPart.Size < 5*1024*1024 {
			return nil, "", 0, ErrEntityTooSmall
		}

		// Validate that the part file exists on disk and its size matches
		fi, err := os.Stat(storedPart.Path)
		if err != nil || fi.Size() != storedPart.Size {
			return nil, "", 0, ErrInvalidPart
		}
	}

	paths := make([]string, len(requestedParts))
	h := md5.New()

	for i, req := range requestedParts {
		storedPart := session.Parts[req.PartNumber]
		h.Write(storedPart.RawMD5)
		totalSize += storedPart.Size
		paths[i] = storedPart.Path
	}

	s3ETag = fmt.Sprintf("\"%x-%d\"", h.Sum(nil), len(requestedParts))
	return &sequentialPartReader{paths: paths}, s3ETag, totalSize, nil
}

type sequentialPartReader struct {
	paths        []string
	currentIndex int
	currentFile  *os.File
}

func (s *sequentialPartReader) Read(p []byte) (n int, err error) {
	for {
		if s.currentFile == nil {
			if s.currentIndex >= len(s.paths) {
				return 0, io.EOF
			}
			f, err := os.Open(s.paths[s.currentIndex])
			if err != nil {
				return 0, err
			}
			s.currentFile = f
		}
		n, err = s.currentFile.Read(p)
		if err == io.EOF {
			_ = s.currentFile.Close()
			s.currentFile = nil
			s.currentIndex++
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (s *sequentialPartReader) Close() error {
	if s.currentFile != nil {
		err := s.currentFile.Close()
		s.currentFile = nil
		return err
	}
	return nil
}

// FinalizeCompleteLocked marks session completed, frees staging directory and unaccounts staged bytes,
// assuming session.mu is already held by the caller.
func (m *MultipartManager) FinalizeCompleteLocked(session *MultipartUploadSession) error {
	if session.Aborted || session.Completed {
		return ErrNoSuchUpload
	}

	// Delete staging directory on disk first
	if err := os.RemoveAll(session.Dir); err != nil {
		return fmt.Errorf("failed to remove staging directory: %w", err)
	}
	if err := syncDir(m.dir); err != nil {
		return fmt.Errorf("failed to sync uploads directory after complete: %w", err)
	}

	session.Completed = true

	m.mu.Lock()
	delete(m.uploads, session.UploadID)
	m.mu.Unlock()

	if m.state != nil && m.state.Budget != nil {
		var freed int64
		for _, p := range session.Parts {
			freed += p.Size
		}
		m.state.Budget.Release(freed)
	}

	return nil
}

// FinalizeComplete marks session completed, frees staging directory and unaccounts staged bytes.
func (m *MultipartManager) FinalizeComplete(session *MultipartUploadSession) error {
	session.mu.Lock()
	defer session.mu.Unlock()
	return m.FinalizeCompleteLocked(session)
}

func (m *MultipartManager) ListParts(session *MultipartUploadSession, maxParts, partNumberMarker int) (parts []PartInfo, isTruncated bool, nextMarker int, err error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	if session.Aborted || session.Completed {
		return nil, false, 0, ErrNoSuchUpload
	}

	var allParts []PartInfo
	for _, p := range session.Parts {
		if p.PartNumber > partNumberMarker {
			allParts = append(allParts, *p)
		}
	}
	sort.Slice(allParts, func(i, j int) bool {
		return allParts[i].PartNumber < allParts[j].PartNumber
	})

	if maxParts <= 0 {
		maxParts = 1000
	}
	if len(allParts) > maxParts {
		isTruncated = true
		parts = allParts[:maxParts]
		nextMarker = parts[len(parts)-1].PartNumber
	} else {
		parts = allParts
		nextMarker = 0
	}
	return parts, isTruncated, nextMarker, nil
}

type UploadListItemInfo struct {
	Key          string
	UploadID     string
	Initiated    time.Time
	StorageClass string
}

func (m *MultipartManager) ListUploads(bucket, prefix, delimiter, keyMarker, uploadIDMarker string, maxUploads int) (uploads []UploadListItemInfo, commonPrefixes []string, isTruncated bool, nextKeyMarker, nextUploadIDMarker string) {
	m.mu.RLock()
	var allSessions []*MultipartUploadSession
	for _, s := range m.uploads {
		if s.Bucket == bucket {
			allSessions = append(allSessions, s)
		}
	}
	m.mu.RUnlock()

	sort.Slice(allSessions, func(i, j int) bool {
		if allSessions[i].Key != allSessions[j].Key {
			return allSessions[i].Key < allSessions[j].Key
		}
		return allSessions[i].UploadID < allSessions[j].UploadID
	})

	if maxUploads <= 0 {
		maxUploads = 1000
	}

	cpMap := make(map[string]bool)
	var matched []UploadListItemInfo

	for _, s := range allSessions {
		sessionKey := s.Key
		uploadID := s.UploadID
		initiated := s.Initiated

		if keyMarker != "" {
			if sessionKey < keyMarker {
				continue
			}
			if sessionKey == keyMarker && uploadIDMarker != "" && uploadID <= uploadIDMarker {
				continue
			}
		}

		if prefix != "" && !strings.HasPrefix(sessionKey, prefix) {
			continue
		}

		if delimiter != "" {
			rest := strings.TrimPrefix(sessionKey, prefix)
			if idx := strings.Index(rest, delimiter); idx != -1 {
				cp := prefix + rest[:idx+len(delimiter)]
				cpMap[cp] = true
				continue
			}
		}

		matched = append(matched, UploadListItemInfo{
			Key:          sessionKey,
			UploadID:     uploadID,
			Initiated:    initiated,
			StorageClass: "STANDARD",
		})
	}

	for cp := range cpMap {
		commonPrefixes = append(commonPrefixes, cp)
	}
	sort.Strings(commonPrefixes)

	if len(matched) > maxUploads {
		isTruncated = true
		uploads = matched[:maxUploads]
		nextKeyMarker = uploads[len(uploads)-1].Key
		nextUploadIDMarker = uploads[len(uploads)-1].UploadID
	} else {
		uploads = matched
	}

	return uploads, commonPrefixes, isTruncated, nextKeyMarker, nextUploadIDMarker
}

// S3 XML structures for multipart
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadId string   `xml:"UploadId"`
}

type CompleteMultipartUploadRequest struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart `xml:"Part"`
}

type CompletedPart struct {
	PartNumber     int    `xml:"PartNumber"`
	ETag           string `xml:"ETag"`
	ChecksumCRC32  string `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C string `xml:"ChecksumCRC32C,omitempty"`
	ChecksumSHA1   string `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256 string `xml:"ChecksumSHA256,omitempty"`
}

type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

type ListPartsResult struct {
	XMLName              xml.Name       `xml:"ListPartsResult"`
	Xmlns                string         `xml:"xmlns,attr"`
	Bucket               string         `xml:"Bucket"`
	Key                  string         `xml:"Key"`
	UploadId             string         `xml:"UploadId"`
	PartNumberMarker     int            `xml:"PartNumberMarker"`
	NextPartNumberMarker int            `xml:"NextPartNumberMarker,omitempty"`
	MaxParts             int            `xml:"MaxParts"`
	IsTruncated          bool           `xml:"IsTruncated"`
	Parts                []ListPartItem `xml:"Part"`
}

type ListPartItem struct {
	PartNumber   int       `xml:"PartNumber"`
	LastModified time.Time `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
}

type ListMultipartUploadsResult struct {
	XMLName            xml.Name         `xml:"ListMultipartUploadsResult"`
	Xmlns              string           `xml:"xmlns,attr"`
	Bucket             string           `xml:"Bucket"`
	KeyMarker          string           `xml:"KeyMarker"`
	UploadIdMarker     string           `xml:"UploadIdMarker"`
	NextKeyMarker      string           `xml:"NextKeyMarker,omitempty"`
	NextUploadIdMarker string           `xml:"NextUploadIdMarker,omitempty"`
	MaxUploads         int              `xml:"MaxUploads"`
	IsTruncated        bool             `xml:"IsTruncated"`
	Uploads            []UploadListItem `xml:"Upload"`
	CommonPrefixes     []CommonPrefix   `xml:"CommonPrefixes,omitempty"`
}

type UploadListItem struct {
	Key          string    `xml:"Key"`
	UploadId     string    `xml:"UploadId"`
	Initiated    time.Time `xml:"Initiated"`
	StorageClass string    `xml:"StorageClass"`
}
