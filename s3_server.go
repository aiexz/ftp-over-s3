package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// S3 XML error response structure
type S3ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestId string   `xml:"RequestId,omitempty"`
}

// writeS3Error writes an S3-compliant XML error response. Shared across packages.
func writeS3Error(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	resource := ""
	if r != nil {
		resource = r.URL.Path
	}
	resp := S3ErrorResponse{
		Code:      code,
		Message:   message,
		Resource:  resource,
		RequestId: fmt.Sprintf("%016X", time.Now().UnixNano()),
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	if r == nil || r.Method != http.MethodHead {
		w.Write([]byte(xml.Header))
		_ = xml.NewEncoder(w).Encode(resp)
	}
}

type s3OperationError struct {
	Status  int
	Code    string
	Message string
}

func (e s3OperationError) Error() string {
	return fmt.Sprintf("%s: %s (status %d)", e.Code, e.Message, e.Status)
}

func writeOperationError(w http.ResponseWriter, r *http.Request, err error) {
	var opErr s3OperationError
	if errors.As(err, &opErr) {
		writeS3Error(w, r, opErr.Status, opErr.Code, opErr.Message)
		return
	}
	var opErrPtr *s3OperationError
	if errors.As(err, &opErrPtr) && opErrPtr != nil {
		writeS3Error(w, r, opErrPtr.Status, opErrPtr.Code, opErrPtr.Message)
		return
	}
	writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "An internal error occurred.")
}

func fileETag(size int64, modTime time.Time) string {
	h := md5.New()
	fmt.Fprintf(h, "%d:%d", size, modTime.UnixNano())
	return fmt.Sprintf("\"%x\"", h.Sum(nil))
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr *contextReader) Read(p []byte) (n int, err error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}

type S3Server struct {
	config     *Config
	ftp        *FTPClient
	state      *State
	metadata   *MetadataStore
	mpManager  *MultipartManager
	admission  *UploadAdmission
	mutationMu sync.Mutex
}

func NewS3Server(config *Config) (*S3Server, error) {
	if config == nil {
		config = &Config{}
	}
	stateDir := config.StateDir
	if stateDir == "" {
		stateDir = ".ftp-over-s3-state"
	}
	maxStagingBytes := config.MaxStagingBytes
	if maxStagingBytes <= 0 {
		maxStagingBytes = int64(20 * 1024 * 1024 * 1024)
	}
	maxConcurrentUploads := config.MaxConcurrentUploads
	if maxConcurrentUploads <= 0 {
		maxConcurrentUploads = 16
	}
	uploadTimeout := config.UploadTimeout
	if uploadTimeout <= 0 {
		uploadTimeout = 15 * time.Minute
	}

	bid := backendID(config)
	st, err := OpenState(stateDir, bid, maxStagingBytes)
	if err != nil {
		return nil, err
	}

	mp, err := NewMultipartManager(st)
	if err != nil {
		_ = st.Close()
		return nil, err
	}

	adm := NewUploadAdmission(st, maxConcurrentUploads, uploadTimeout)
	metaStore := NewMetadataStore(st)

	return &S3Server{
		config:    config,
		ftp:       NewFTPClient(config),
		state:     st,
		metadata:  metaStore,
		mpManager: mp,
		admission: adm,
	}, nil
}

func (s *S3Server) Close() error {
	var errs []error
	if s.mpManager != nil {
		if err := s.mpManager.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.state != nil {
		if err := s.state.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *S3Server) metadataFor(key string, info *FileInfo) (ObjectMetadata, error) {
	if info == nil {
		return ObjectMetadata{}, os.ErrNotExist
	}
	if s.metadata != nil {
		meta, ok, err := s.metadata.Load(key, info)
		if err != nil {
			return ObjectMetadata{}, err
		}
		if ok {
			return meta, nil
		}
	}
	return ObjectMetadata{
		ETag:        fileETag(info.Size, info.ModTime),
		Size:        info.Size,
		ModTime:     info.ModTime,
		ContentType: "application/octet-stream",
	}, nil
}

func extractMetadata(r *http.Request) (ObjectMetadata, error) {
	meta := ObjectMetadata{
		ContentType:        r.Header.Get("Content-Type"),
		CacheControl:       r.Header.Get("Cache-Control"),
		ContentDisposition: r.Header.Get("Content-Disposition"),
		ContentEncoding:    r.Header.Get("Content-Encoding"),
		ContentLanguage:    r.Header.Get("Content-Language"),
		Expires:            r.Header.Get("Expires"),
		UserMetadata:       make(map[string]string),
	}
	if meta.ContentType == "" {
		meta.ContentType = "application/octet-stream"
	}

	var totalUserMetaLen int
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-meta-") {
			userKey := strings.TrimPrefix(lk, "x-amz-meta-")
			if userKey == "" {
				return ObjectMetadata{}, &s3OperationError{
					Status:  http.StatusBadRequest,
					Code:    "InvalidArgument",
					Message: "Metadata key must not be empty.",
				}
			}
			if len(userKey) > maxUserMetadataKeyLen {
				return ObjectMetadata{}, &s3OperationError{
					Status:  http.StatusBadRequest,
					Code:    "MetadataTooLarge",
					Message: "Metadata header key exceeds maximum allowed length.",
				}
			}
			val := strings.Join(vals, ",")
			if len(val) > maxUserMetadataValLen {
				return ObjectMetadata{}, &s3OperationError{
					Status:  http.StatusBadRequest,
					Code:    "MetadataTooLarge",
					Message: "Metadata header value exceeds maximum allowed length.",
				}
			}
			totalUserMetaLen += len(userKey) + len(val)
			if totalUserMetaLen > maxMetadataRecordBytes {
				return ObjectMetadata{}, &s3OperationError{
					Status:  http.StatusBadRequest,
					Code:    "MetadataTooLarge",
					Message: "Total metadata size exceeds maximum allowed limit.",
				}
			}
			meta.UserMetadata[userKey] = val
		}
	}
	return meta, nil
}

func applyMetadataHeaders(w http.ResponseWriter, meta ObjectMetadata) {
	if meta.ContentType != "" {
		w.Header().Set("Content-Type", meta.ContentType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if meta.CacheControl != "" {
		w.Header().Set("Cache-Control", meta.CacheControl)
	}
	if meta.ContentDisposition != "" {
		w.Header().Set("Content-Disposition", meta.ContentDisposition)
	}
	if meta.ContentEncoding != "" {
		w.Header().Set("Content-Encoding", meta.ContentEncoding)
	}
	if meta.ContentLanguage != "" {
		w.Header().Set("Content-Language", meta.ContentLanguage)
	}
	if meta.Expires != "" {
		w.Header().Set("Expires", meta.Expires)
	}
	for k, v := range meta.UserMetadata {
		cleanKey := strings.ToLower(strings.TrimPrefix(k, "x-amz-meta-"))
		w.Header()["x-amz-meta-"+cleanKey] = []string{v}
	}
}

func (s *S3Server) checkWritePreconditions(r *http.Request, key string, info *FileInfo) error {
	if r == nil {
		return nil
	}
	ifMatch := r.Header.Get("If-Match")
	ifNoneMatch := r.Header.Get("If-None-Match")
	ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since")

	if ifMatch == "" && ifNoneMatch == "" && ifUnmodifiedSince == "" {
		return nil
	}

	exists := info != nil
	var currentMeta ObjectMetadata
	if exists {
		var err error
		currentMeta, err = s.metadataFor(key, info)
		if err != nil {
			return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to load metadata for precondition check."}
		}
	}

	if ifMatch != "" {
		if !exists || !matchETagStrong(ifMatch, currentMeta.ETag) {
			return &s3OperationError{Status: http.StatusPreconditionFailed, Code: "PreconditionFailed", Message: "At least one of the pre-conditions you specified did not hold."}
		}
	} else if ifUnmodifiedSince != "" && exists {
		if t, parseErr := http.ParseTime(ifUnmodifiedSince); parseErr == nil {
			if info.ModTime.Truncate(time.Second).After(t.Truncate(time.Second)) {
				return &s3OperationError{Status: http.StatusPreconditionFailed, Code: "PreconditionFailed", Message: "At least one of the pre-conditions you specified did not hold."}
			}
		}
	}

	if ifNoneMatch != "" {
		if exists {
			if ifNoneMatch == "*" || matchETagWeak(ifNoneMatch, currentMeta.ETag) {
				return &s3OperationError{Status: http.StatusPreconditionFailed, Code: "PreconditionFailed", Message: "At least one of the pre-conditions you specified did not hold."}
			}
		}
	}

	return nil
}

func (s *S3Server) commitObjectLocked(r *http.Request, key string, body io.Reader, meta ObjectMetadata) error {
	existingInfo, err := s.getFileInfo(key)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to inspect destination on FTP backend."}
	}
	if err := s.checkWritePreconditions(r, key, existingInfo); err != nil {
		return err
	}

	if s.metadata != nil {
		if err := s.metadata.Begin(key); err != nil {
			return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to begin metadata transaction."}
		}
	}

	var h hash.Hash
	bodyReader := body
	if meta.ETag == "" {
		h = md5.New()
		bodyReader = io.TeeReader(body, h)
	}

	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	ctxReader := &contextReader{ctx: ctx, r: bodyReader}

	if err := s.ftp.Put(key, ctxReader); err != nil {
		if s.metadata != nil {
			// Pre-publish failures and explicit 550 rename rejections provably never published.
			// Only retain pending marker on ambiguous publish outcomes (lost reply, connection drop during rename).
			if !errors.Is(err, ErrAmbiguousPublish) {
				_ = s.metadata.Abort(key)
			}
		}
		return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to store object to FTP backend."}
	}

	if meta.ETag == "" && h != nil {
		meta.ETag = fmt.Sprintf("\"%x\"", h.Sum(nil))
	}

	newInfo, statErr := s.getFileInfo(key)
	if statErr != nil {
		return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to stat object on FTP backend."}
	}

	meta.Size = newInfo.Size
	meta.ModTime = newInfo.ModTime
	if meta.ETag == "" {
		meta.ETag = fileETag(newInfo.Size, newInfo.ModTime)
	}

	if s.metadata != nil {
		if err := s.metadata.Save(key, meta); err != nil {
			return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to persist object metadata."}
		}
	}

	return nil
}

// ponytail: global lock, per-key/prefix locks if throughput matters
func (s *S3Server) commitObject(r *http.Request, key string, body io.Reader, meta ObjectMetadata) error {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	return s.commitObjectLocked(r, key, body, meta)
}

// ponytail: global lock, per-key/prefix locks if throughput matters
func (s *S3Server) deleteObject(r *http.Request, key string) error {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()

	info, err := s.getFileInfo(key)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to inspect object on FTP backend."}
	}

	if err := s.checkWritePreconditions(r, key, info); err != nil {
		return err
	}

	if info == nil {
		if s.metadata != nil {
			if delErr := s.metadata.Delete(key); delErr != nil {
				return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to delete object metadata."}
			}
		}
		return nil
	}

	if s.metadata != nil {
		if err := s.metadata.Begin(key); err != nil {
			return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to begin metadata operation."}
		}
	}

	if err := s.ftp.Delete(key); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if s.metadata != nil {
				if delErr := s.metadata.Delete(key); delErr != nil {
					return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to delete object metadata."}
				}
			}
			return nil
		}
		// Unexpected delete error: retain pending marker so metadata fails closed
		return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to delete object from FTP backend."}
	}

	if s.metadata != nil {
		if err := s.metadata.Delete(key); err != nil {
			return &s3OperationError{Status: http.StatusInternalServerError, Code: "InternalError", Message: "Failed to delete object metadata."}
		}
	}

	return nil
}

func validateKey(key string) error {
	if key == "" {
		return errors.New("empty key")
	}
	if strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") {
		return errors.New("key must not have leading or trailing slashes")
	}
	if strings.Contains(key, "\\") {
		return errors.New("key must not contain backslashes")
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 32 || key[i] == 127 {
			return errors.New("key contains control characters")
		}
	}
	if strings.HasPrefix(key, ".ftp-over-s3-") || strings.Contains(key, "/.ftp-over-s3-") {
		return errors.New("key prefix .ftp-over-s3- is reserved")
	}
	parts := strings.Split(key, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("key contains invalid path component %q", part)
		}
	}
	return nil
}

func (s *S3Server) parentDirExists(dir string) (bool, error) {
	if dir == "" || dir == "." || dir == "/" {
		return true, nil
	}
	parts := strings.Split(filepath.Clean(dir), "/")
	current := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		files, err := s.ftp.List(current)
		if err != nil {
			return false, err
		}
		found := false
		for _, f := range files {
			if f.Name == part {
				if !f.IsDir {
					return false, nil
				}
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
		if current == "" {
			current = part
		} else {
			current = current + "/" + part
		}
	}
	return true, nil
}

func (s *S3Server) getFileInfo(path string) (*FileInfo, error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if dir == "." || dir == "/" {
		dir = ""
	}
	files, err := s.ftp.List(dir)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, err
		}
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		if dir != "" {
			exists, pErr := s.parentDirExists(dir)
			if pErr == nil && !exists {
				return nil, os.ErrNotExist
			}
		}
		return nil, err
	}
	for _, file := range files {
		if file.Name == base {
			if file.IsDir {
				return nil, os.ErrNotExist
			}
			return &file, nil
		}
	}
	return nil, os.ErrNotExist
}

func mirrorChecksumHeaders(src *http.Request, dst http.ResponseWriter) {
	algos := map[string]string{
		"crc32":     "Crc32",
		"crc32c":    "Crc32c",
		"sha1":      "Sha1",
		"sha256":    "Sha256",
		"crc64nvme": "Crc64nvme",
	}
	for algo, suffix := range algos {
		respHdr := "x-amz-checksum-" + algo
		if val := src.Header.Get(respHdr); val != "" {
			dst.Header().Set(respHdr, val)
			continue
		}
		if val := src.Header.Get("X-Ftp-Checksum-" + suffix); val != "" {
			dst.Header().Set(respHdr, val)
		}
	}
}

func (s *S3Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Sanitize logs: do NOT log query parameters to prevent leaking presigned credentials
	slog.Debug("handling S3 request",
		"method", r.Method,
		"path", r.URL.Path,
	)

	// Health check
	if r.URL.Path == "/health" || r.URL.Path == "/healthz" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
			return
		}
		writeS3Error(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		return
	}

	// Service-level root requests
	if r.URL.Path == "/" {
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("list-type") == "2" {
				s.handleListObjectsV2(w, r, "default")
			} else if r.URL.Query().Has("prefix") {
				s.handleListObjects(w, r, "default")
			} else {
				s.handleListBuckets(w, r)
			}
		case http.MethodHead:
			w.WriteHeader(http.StatusOK)
		default:
			writeS3Error(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		}
		return
	}

	// Parse path-style bucket and key without aliasing slashes
	trimmed := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(trimmed, "/", 2)

	bucket := parts[0]
	var key string
	if len(parts) == 2 {
		key = parts[1]
	}

	// Single default bucket routing check
	if bucket != "default" {
		writeS3Error(w, r, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist.")
		return
	}

	// Bucket-level operations
	if key == "" {
		// Reject unsupported bucket subresources
		for _, param := range []string{
			"versioning", "versions", "acl", "cors", "lifecycle", "policy", "policyStatus",
			"tagging", "website", "logging", "notification", "replication", "analytics",
			"inventory", "metrics", "encryption", "publicAccessBlock",
		} {
			if r.URL.Query().Has(param) {
				writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", fmt.Sprintf("Bucket subresource %q is not implemented.", param))
				return
			}
		}

		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Has("location") {
				s.handleGetBucketLocation(w, r)
			} else if r.URL.Query().Has("uploads") {
				s.handleListMultipartUploads(w, r, bucket)
			} else if r.URL.Query().Get("list-type") == "2" {
				s.handleListObjectsV2(w, r, bucket)
			} else {
				s.handleListObjects(w, r, bucket)
			}
		case http.MethodHead:
			s.handleHeadBucket(w, r)
		case http.MethodPost:
			if r.URL.Query().Has("delete") {
				s.handleDeleteObjects(w, r, bucket)
			} else {
				writeS3Error(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
			}
		case http.MethodPut:
			writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Bucket creation is not supported; use default bucket.")
		case http.MethodDelete:
			writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Bucket deletion is not supported.")
		default:
			writeS3Error(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		}
		return
	}

	// Object-level operations: validate key format and reject aliasing/control chars
	if err := validateKey(key); err != nil {
		writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}

	// Explicit unsupported storage/security checks before storage
	if r.Header.Get("X-Amz-Acl") != "" {
		writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Canned ACLs are not supported.")
		return
	}
	if r.Header.Get("X-Amz-Tagging") != "" {
		writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Object tagging is not supported.")
		return
	}
	if r.Header.Get("X-Amz-Object-Lock-Mode") != "" || r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date") != "" || r.Header.Get("X-Amz-Object-Lock-Legal-Hold") != "" {
		writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Object Lock is not supported.")
		return
	}
	for k := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-server-side-encryption") {
			writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Server-side encryption is not supported.")
			return
		}
		if strings.HasPrefix(lk, "x-amz-grant-") {
			writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Canned ACLs and grants are not supported.")
			return
		}
	}
	if sc := r.Header.Get("X-Amz-Storage-Class"); sc != "" && !strings.EqualFold(sc, "STANDARD") {
		writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", "Storage class is not supported; only STANDARD is available.")
		return
	}
	for _, param := range []string{"acl", "tagging", "retention", "legal-hold", "restore", "torrent", "select", "select-type", "versionId"} {
		if r.URL.Query().Has(param) {
			writeS3Error(w, r, http.StatusNotImplemented, "NotImplemented", fmt.Sprintf("Object subresource %q is not implemented.", param))
			return
		}
	}

	uploadID := r.URL.Query().Get("uploadId")
	partNumber := r.URL.Query().Get("partNumber")
	hasUploads := r.URL.Query().Has("uploads")

	hasCopySource := r.Header.Get("X-Amz-Copy-Source") != ""

	switch r.Method {
	case http.MethodPost:
		if hasUploads {
			s.handleCreateMultipartUpload(w, r, bucket, key)
		} else if uploadID != "" {
			s.handleCompleteMultipartUpload(w, r, bucket, key, uploadID)
		} else {
			writeS3Error(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
		}
	case http.MethodPut:
		if hasCopySource {
			if uploadID != "" && partNumber != "" {
				s.handleUploadPartCopy(w, r, bucket, key, uploadID, partNumber)
			} else if uploadID != "" || partNumber != "" {
				writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Both uploadId and partNumber are required for uploading a part.")
			} else {
				s.handleCopyObject(w, r, bucket, key)
			}
		} else if uploadID != "" && partNumber != "" {
			s.handleUploadPart(w, r, bucket, key, uploadID, partNumber)
		} else if uploadID != "" || partNumber != "" {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Both uploadId and partNumber are required for uploading a part.")
		} else {
			s.handlePut(w, r, bucket, key)
		}
	case http.MethodGet:
		if uploadID != "" {
			s.handleListParts(w, r, bucket, key, uploadID)
		} else {
			s.handleGet(w, r, bucket, key)
		}
	case http.MethodHead:
		s.handleHead(w, r, bucket, key)
	case http.MethodDelete:
		if uploadID != "" {
			s.handleAbortMultipartUpload(w, r, bucket, key, uploadID)
		} else {
			s.handleDelete(w, r, bucket, key)
		}
	default:
		writeS3Error(w, r, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed")
	}
}

// S3 XML response structures
type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Xmlns   string   `xml:"xmlns,attr"`
	Owner   Owner    `xml:"Owner"`
	Buckets Buckets  `xml:"Buckets"`
}

type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type Buckets struct {
	Bucket []Bucket `xml:"Bucket"`
}

type Bucket struct {
	Name         string    `xml:"Name"`
	CreationDate time.Time `xml:"CreationDate"`
}

type ListBucketResult struct {
	XMLName        xml.Name       `xml:"ListBucketResult"`
	Xmlns          string         `xml:"xmlns,attr"`
	Name           string         `xml:"Name"`
	Prefix         string         `xml:"Prefix"`
	Marker         string         `xml:"Marker"`
	NextMarker     string         `xml:"NextMarker,omitempty"`
	MaxKeys        int            `xml:"MaxKeys"`
	Delimiter      string         `xml:"Delimiter,omitempty"`
	IsTruncated    bool           `xml:"IsTruncated"`
	EncodingType   string         `xml:"EncodingType,omitempty"`
	Contents       []S3Object     `xml:"Contents"`
	CommonPrefixes []CommonPrefix `xml:"CommonPrefixes,omitempty"`
}

type ListBucketV2Result struct {
	XMLName               xml.Name       `xml:"ListBucketResult"`
	Xmlns                 string         `xml:"xmlns,attr"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	StartAfter            string         `xml:"StartAfter,omitempty"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	KeyCount              int            `xml:"KeyCount"`
	MaxKeys               int            `xml:"MaxKeys"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	IsTruncated           bool           `xml:"IsTruncated"`
	EncodingType          string         `xml:"EncodingType,omitempty"`
	Contents              []S3Object     `xml:"Contents"`
	CommonPrefixes        []CommonPrefix `xml:"CommonPrefixes,omitempty"`
}

type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

type S3Object struct {
	Key          string    `xml:"Key"`
	LastModified time.Time `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	StorageClass string    `xml:"StorageClass"`
}

type listItem struct {
	isPrefix bool
	key      string
	obj      S3Object
}

func encodeIfURL(s, encodingType string) string {
	if encodingType == "url" && s != "" {
		return url.QueryEscape(s)
	}
	return s
}

func (s *S3Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	result := ListAllMyBucketsResult{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
		Owner: Owner{
			ID:          "ftp-over-s3",
			DisplayName: "ftp-over-s3",
		},
		Buckets: Buckets{
			Bucket: []Bucket{
				{
					Name:         "default",
					CreationDate: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		slog.Error("failed to encode XML response", "error", err)
	}
}

func (s *S3Server) handleHeadBucket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("x-amz-bucket-region", "us-east-1")
	w.WriteHeader(http.StatusOK)
}

func (s *S3Server) handleGetBucketLocation(w http.ResponseWriter, r *http.Request) {
	type LocationConstraint struct {
		XMLName xml.Name `xml:"LocationConstraint"`
		Xmlns   string   `xml:"xmlns,attr"`
		Value   string   `xml:",chardata"`
	}
	resp := LocationConstraint{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
		Value: "us-east-1",
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(resp)
}

func (s *S3Server) collectObjects(prefix, delimiter string) ([]S3Object, []string, error) {
	startDir := ""
	if idx := strings.LastIndex(prefix, "/"); idx != -1 {
		startDir = prefix[:idx]
	}

	visited := make(map[string]bool)
	queue := []string{startDir}
	visited[startDir] = true

	var objects []S3Object
	cpMap := make(map[string]bool)

	for len(queue) > 0 {
		currentDir := queue[0]
		queue = queue[1:]

		entries, err := s.ftp.List(currentDir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, nil, err
		}

		for _, entry := range entries {
			if entry.Name == "." || entry.Name == ".." {
				continue
			}
			if strings.HasPrefix(entry.Name, ".ftp-over-s3-") {
				continue
			}

			fullKey := entry.Name
			if currentDir != "" {
				fullKey = currentDir + "/" + entry.Name
			}

			if entry.IsDir {
				dirKey := fullKey + "/"
				if delimiter == "/" {
					if strings.HasPrefix(dirKey, prefix) {
						rest := strings.TrimPrefix(dirKey, prefix)
						slashIdx := strings.Index(rest, "/")
						cp := prefix + rest[:slashIdx+1]
						cpMap[cp] = true
					} else if strings.HasPrefix(prefix, dirKey) {
						if !visited[fullKey] {
							visited[fullKey] = true
							queue = append(queue, fullKey)
						}
					}
				} else {
					if strings.HasPrefix(dirKey, prefix) || strings.HasPrefix(prefix, dirKey) {
						if !visited[fullKey] {
							visited[fullKey] = true
							queue = append(queue, fullKey)
						}
					}
				}
			} else {
				if !strings.HasPrefix(fullKey, prefix) {
					continue
				}
				if delimiter != "" {
					rest := strings.TrimPrefix(fullKey, prefix)
					if idx := strings.Index(rest, delimiter); idx != -1 {
						cp := prefix + rest[:idx+len(delimiter)]
						cpMap[cp] = true
						continue
					}
				}
				meta, _ := s.metadataFor(fullKey, &entry)
				etag := meta.ETag
				if etag == "" {
					etag = fileETag(entry.Size, entry.ModTime)
				}
				objects = append(objects, S3Object{
					Key:          fullKey,
					LastModified: entry.ModTime.UTC(),
					Size:         entry.Size,
					ETag:         etag,
					StorageClass: "STANDARD",
				})
			}
		}
	}

	var commonPrefixes []string
	for cp := range cpMap {
		commonPrefixes = append(commonPrefixes, cp)
	}
	sort.Strings(commonPrefixes)

	return objects, commonPrefixes, nil
}

func (s *S3Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	encodingType := r.URL.Query().Get("encoding-type")
	if encodingType != "" && encodingType != "url" {
		writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Invalid Encoding Method specified in Request")
		return
	}

	maxKeys := 1000
	if mkStr := r.URL.Query().Get("max-keys"); mkStr != "" {
		mk, err := strconv.Atoi(mkStr)
		if err != nil || mk < 0 {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Argument max-keys must be an integer between 0 and 2147483647")
			return
		}
		if mk > 1000 {
			maxKeys = 1000
		} else {
			maxKeys = mk
		}
	}

	continuationToken := r.URL.Query().Get("continuation-token")
	var startAfterKey string
	if continuationToken != "" {
		decoded, err := base64.StdEncoding.DecodeString(continuationToken)
		if err != nil || len(decoded) == 0 {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "The continuation token provided is invalid.")
			return
		}
		parts := strings.Split(string(decoded), "\x00")
		if len(parts) == 3 {
			if parts[0] != prefix || parts[1] != delimiter {
				writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "The continuation token provided is invalid.")
				return
			}
			startAfterKey = parts[2]
		} else {
			startAfterKey = string(decoded)
		}
	} else {
		startAfterKey = r.URL.Query().Get("start-after")
	}

	objects, commonPrefixes, err := s.collectObjects(prefix, delimiter)
	if err != nil {
		slog.Error("failed to list FTP directory", "prefix", prefix, "error", err)
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to list objects.")
		return
	}

	var allItems []listItem
	for _, obj := range objects {
		allItems = append(allItems, listItem{isPrefix: false, key: obj.Key, obj: obj})
	}
	for _, cp := range commonPrefixes {
		allItems = append(allItems, listItem{isPrefix: true, key: cp})
	}
	sort.Slice(allItems, func(i, j int) bool {
		return allItems[i].key < allItems[j].key
	})

	var filteredItems []listItem
	for _, item := range allItems {
		if startAfterKey != "" && item.key <= startAfterKey {
			continue
		}
		filteredItems = append(filteredItems, item)
	}

	isTruncated := false
	var nextContinuationToken string
	if len(filteredItems) > maxKeys {
		isTruncated = true
		if maxKeys > 0 {
			lastKey := filteredItems[maxKeys-1].key
			tokenPayload := fmt.Sprintf("%s\x00%s\x00%s", prefix, delimiter, lastKey)
			nextContinuationToken = base64.StdEncoding.EncodeToString([]byte(tokenPayload))
			filteredItems = filteredItems[:maxKeys]
		} else {
			filteredItems = nil
		}
	}

	var contents []S3Object
	var resCommonPrefixes []CommonPrefix
	for _, item := range filteredItems {
		if item.isPrefix {
			resCommonPrefixes = append(resCommonPrefixes, CommonPrefix{Prefix: encodeIfURL(item.key, encodingType)})
		} else {
			obj := item.obj
			obj.Key = encodeIfURL(obj.Key, encodingType)
			contents = append(contents, obj)
		}
	}

	result := ListBucketV2Result{
		Xmlns:                 "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:                  bucket,
		Prefix:                encodeIfURL(prefix, encodingType),
		StartAfter:            encodeIfURL(r.URL.Query().Get("start-after"), encodingType),
		ContinuationToken:     continuationToken,
		NextContinuationToken: nextContinuationToken,
		KeyCount:              len(contents) + len(resCommonPrefixes),
		MaxKeys:               maxKeys,
		Delimiter:             encodeIfURL(delimiter, encodingType),
		IsTruncated:           isTruncated,
		EncodingType:          encodingType,
		Contents:              contents,
		CommonPrefixes:        resCommonPrefixes,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(result)
}

func (s *S3Server) handleListObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	encodingType := r.URL.Query().Get("encoding-type")
	if encodingType != "" && encodingType != "url" {
		writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Invalid Encoding Method specified in Request")
		return
	}

	maxKeys := 1000
	if mkStr := r.URL.Query().Get("max-keys"); mkStr != "" {
		mk, err := strconv.Atoi(mkStr)
		if err != nil || mk < 0 {
			writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Argument max-keys must be an integer between 0 and 2147483647")
			return
		}
		if mk > 1000 {
			maxKeys = 1000
		} else {
			maxKeys = mk
		}
	}

	marker := r.URL.Query().Get("marker")
	startAfterKey := marker

	objects, commonPrefixes, err := s.collectObjects(prefix, delimiter)
	if err != nil {
		slog.Error("failed to list FTP directory", "prefix", prefix, "error", err)
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to list objects.")
		return
	}

	var allItems []listItem
	for _, obj := range objects {
		allItems = append(allItems, listItem{isPrefix: false, key: obj.Key, obj: obj})
	}
	for _, cp := range commonPrefixes {
		allItems = append(allItems, listItem{isPrefix: true, key: cp})
	}
	sort.Slice(allItems, func(i, j int) bool {
		return allItems[i].key < allItems[j].key
	})

	var filteredItems []listItem
	for _, item := range allItems {
		if startAfterKey != "" && item.key <= startAfterKey {
			continue
		}
		filteredItems = append(filteredItems, item)
	}

	isTruncated := false
	var nextMarker string
	if len(filteredItems) > maxKeys {
		isTruncated = true
		if maxKeys > 0 {
			nextMarker = filteredItems[maxKeys-1].key
			filteredItems = filteredItems[:maxKeys]
		} else {
			filteredItems = nil
		}
	}

	var contents []S3Object
	var resCommonPrefixes []CommonPrefix
	for _, item := range filteredItems {
		if item.isPrefix {
			resCommonPrefixes = append(resCommonPrefixes, CommonPrefix{Prefix: encodeIfURL(item.key, encodingType)})
		} else {
			obj := item.obj
			obj.Key = encodeIfURL(obj.Key, encodingType)
			contents = append(contents, obj)
		}
	}

	result := ListBucketResult{
		Xmlns:          "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:           bucket,
		Prefix:         encodeIfURL(prefix, encodingType),
		Marker:         encodeIfURL(marker, encodingType),
		NextMarker:     encodeIfURL(nextMarker, encodingType),
		MaxKeys:        maxKeys,
		Delimiter:      encodeIfURL(delimiter, encodingType),
		IsTruncated:    isTruncated,
		EncodingType:   encodingType,
		Contents:       contents,
		CommonPrefixes: resCommonPrefixes,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(result)
}

func matchETagStrong(headerVal, currentETag string) bool {
	if headerVal == "*" {
		return currentETag != ""
	}
	if strings.HasPrefix(currentETag, "W/") {
		return false
	}
	cur := strings.Trim(currentETag, "\"")
	tags := strings.Split(headerVal, ",")
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "*" {
			return true
		}
		if strings.HasPrefix(tag, "W/") {
			continue
		}
		tag = strings.Trim(tag, "\"")
		if tag == cur {
			return true
		}
	}
	return false
}

func matchETagWeak(headerVal, currentETag string) bool {
	if headerVal == "*" {
		return true
	}
	cur := strings.Trim(strings.TrimPrefix(currentETag, "W/"), "\"")
	tags := strings.Split(headerVal, ",")
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		tag = strings.Trim(strings.TrimPrefix(tag, "W/"), "\"")
		if tag == cur || tag == "*" {
			return true
		}
	}
	return false
}

func matchETag(headerVal, currentETag string) bool {
	return matchETagWeak(headerVal, currentETag)
}

func parseRange(rangeHeader string, size int64) (start int64, length int64, ok bool) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(rangeHeader, "bytes=")
	if strings.Contains(spec, ",") {
		return 0, 0, false
	}
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return 0, 0, false
	}
	if parts[0] == "" {
		suffix, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffix < 0 {
			return 0, 0, false
		}
		if suffix == 0 {
			return 0, 0, false
		}
		if suffix > size {
			suffix = size
		}
		return size - suffix, suffix, true
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false
	}
	if start >= size {
		return 0, 0, false
	}
	if parts[1] == "" {
		return start, size - start, true
	}
	end, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || end < start {
		return 0, 0, false
	}
	if end >= size {
		end = size - 1
	}
	return start, end - start + 1, true
}

func (s *S3Server) handleGet(w http.ResponseWriter, r *http.Request, bucket, key string) {
	file, err := s.getFileInfo(key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to get file from FTP backend.")
		return
	}

	meta, err := s.metadataFor(key, file)
	if err != nil {
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to load object metadata.")
		return
	}
	etag := meta.ETag

	// Conditional read checks
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		if !matchETagStrong(ifMatch, etag) {
			writeS3Error(w, r, http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold.")
			return
		}
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		if matchETagWeak(ifNoneMatch, etag) {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" && r.Header.Get("If-None-Match") == "" {
		if t, parseErr := http.ParseTime(ifModifiedSince); parseErr == nil {
			if !file.ModTime.Truncate(time.Second).After(t.Truncate(time.Second)) {
				w.Header().Set("ETag", etag)
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	if ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since"); ifUnmodifiedSince != "" {
		if t, parseErr := http.ParseTime(ifUnmodifiedSince); parseErr == nil {
			if file.ModTime.Truncate(time.Second).After(t.Truncate(time.Second)) {
				writeS3Error(w, r, http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold.")
				return
			}
		}
	}

	// Always open FTP reader before sending headers to catch backend errors early
	reader, err := s.ftp.Get(key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to read file from FTP backend.")
		return
	}
	defer reader.Close()

	applyMetadataHeaders(w, meta)

	// Byte range check
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		start, length, ok := parseRange(rangeHeader, file.Size)
		if !ok {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", file.Size))
			writeS3Error(w, r, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", "The requested range cannot be satisfied.")
			return
		}

		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, start+length-1, file.Size))
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		w.Header().Set("Last-Modified", file.ModTime.UTC().Format(http.TimeFormat))
		w.Header().Set("ETag", etag)
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusPartialContent)

		if start > 0 {
			if _, err := io.CopyN(io.Discard, reader, start); err != nil {
				slog.Error("failed to seek to range start", "key", key, "error", err)
				panic(http.ErrAbortHandler)
			}
		}
		if _, err := io.CopyN(w, reader, length); err != nil {
			slog.Error("failed to stream range to client", "key", key, "error", err)
			panic(http.ErrAbortHandler)
		}
		return
	}

	// Full GET
	w.Header().Set("Content-Length", strconv.FormatInt(file.Size, 10))
	w.Header().Set("Last-Modified", file.ModTime.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", etag)
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)

	if _, err := io.Copy(w, reader); err != nil {
		slog.Error("failed to stream file to client", "key", key, "error", err)
		panic(http.ErrAbortHandler)
	}
}

func (s *S3Server) handlePut(w http.ResponseWriter, r *http.Request, bucket, key string) {
	meta, err := extractMetadata(r)
	if err != nil {
		writeOperationError(w, r, err)
		return
	}

	hexMD5 := r.Header.Get("X-Ftp-Content-Md5")
	var bodyReader io.Reader = r.Body
	var h hash.Hash
	if hexMD5 != "" {
		meta.ETag = fmt.Sprintf("\"%s\"", hexMD5)
	} else {
		h = md5.New()
		bodyReader = io.TeeReader(r.Body, h)
	}

	if err := s.commitObject(r, key, bodyReader, meta); err != nil {
		writeOperationError(w, r, err)
		return
	}

	etag := meta.ETag
	if etag == "" && h != nil {
		etag = fmt.Sprintf("\"%x\"", h.Sum(nil))
	}

	mirrorChecksumHeaders(r, w)
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (s *S3Server) handleDelete(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if err := s.deleteObject(r, key); err != nil {
		writeOperationError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *S3Server) handleHead(w http.ResponseWriter, r *http.Request, bucket, key string) {
	file, err := s.getFileInfo(key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to inspect file on FTP backend.")
		return
	}

	meta, err := s.metadataFor(key, file)
	if err != nil {
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to load object metadata.")
		return
	}
	etag := meta.ETag

	// Conditional read checks matching GET
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		if !matchETagStrong(ifMatch, etag) {
			writeS3Error(w, r, http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold.")
			return
		}
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		if matchETagWeak(ifNoneMatch, etag) {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	if ifModifiedSince := r.Header.Get("If-Modified-Since"); ifModifiedSince != "" && r.Header.Get("If-None-Match") == "" {
		if t, parseErr := http.ParseTime(ifModifiedSince); parseErr == nil {
			if !file.ModTime.Truncate(time.Second).After(t.Truncate(time.Second)) {
				w.Header().Set("ETag", etag)
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	if ifUnmodifiedSince := r.Header.Get("If-Unmodified-Since"); ifUnmodifiedSince != "" {
		if t, parseErr := http.ParseTime(ifUnmodifiedSince); parseErr == nil {
			if file.ModTime.Truncate(time.Second).After(t.Truncate(time.Second)) {
				writeS3Error(w, r, http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold.")
				return
			}
		}
	}

	applyMetadataHeaders(w, meta)
	w.Header().Set("Content-Length", strconv.FormatInt(file.Size, 10))
	w.Header().Set("Last-Modified", file.ModTime.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", etag)
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
}

func (s *S3Server) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	meta, err := extractMetadata(r)
	if err != nil {
		writeOperationError(w, r, err)
		return
	}
	session, err := s.mpManager.CreateUpload(bucket, key, meta)
	if err != nil {
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to initiate multipart upload.")
		return
	}
	resp := InitiateMultipartUploadResult{
		Xmlns:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:   bucket,
		Key:      key,
		UploadId: session.UploadID,
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(resp)
}

func (s *S3Server) handleUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID, partNumberStr string) {
	session, ok := s.mpManager.GetUpload(uploadID)
	if !ok {
		writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist.")
		return
	}
	if session.Bucket != bucket || session.Key != key {
		writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Upload ID does not match specified bucket and key.")
		return
	}
	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Part number must be an integer between 1 and 10000.")
		return
	}

	var checksumCRC32, checksumCRC32C, checksumSHA1, checksumSHA256 string
	if v := r.Header.Get("x-amz-checksum-crc32"); v != "" {
		checksumCRC32 = v
	} else if v := r.Header.Get("X-Ftp-Checksum-Crc32"); v != "" {
		checksumCRC32 = v
	}
	if v := r.Header.Get("x-amz-checksum-crc32c"); v != "" {
		checksumCRC32C = v
	} else if v := r.Header.Get("X-Ftp-Checksum-Crc32c"); v != "" {
		checksumCRC32C = v
	}
	if v := r.Header.Get("x-amz-checksum-sha1"); v != "" {
		checksumSHA1 = v
	} else if v := r.Header.Get("X-Ftp-Checksum-Sha1"); v != "" {
		checksumSHA1 = v
	}
	if v := r.Header.Get("x-amz-checksum-sha256"); v != "" {
		checksumSHA256 = v
	} else if v := r.Header.Get("X-Ftp-Checksum-Sha256"); v != "" {
		checksumSHA256 = v
	}

	hexMD5 := r.Header.Get("X-Ftp-Content-Md5")
	part, err := s.mpManager.UploadPart(session, partNumber, r.Body, r.ContentLength, hexMD5, checksumCRC32, checksumCRC32C, checksumSHA1, checksumSHA256)
	if err != nil {
		switch {
		case errors.Is(err, ErrEntityTooLarge):
			writeS3Error(w, r, http.StatusBadRequest, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size (5 GiB per part).")
		case errors.Is(err, ErrStagingLimitExceeded):
			writeS3Error(w, r, http.StatusServiceUnavailable, "SlowDown", "Aggregate multipart disk staging limit exceeded (20 GiB cap).")
		case errors.Is(err, ErrNoSuchUpload):
			writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist.")
		default:
			slog.Error("failed to upload part", "uploadID", uploadID, "part", partNumber, "error", err)
			writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to store upload part.")
		}
		return
	}

	mirrorChecksumHeaders(r, w)
	w.Header().Set("ETag", part.ETag)
	w.WriteHeader(http.StatusOK)
}

func (s *S3Server) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	session, ok := s.mpManager.GetUpload(uploadID)
	if !ok {
		writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist.")
		return
	}
	if session.Bucket != bucket || session.Key != key {
		writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Upload ID does not match specified bucket and key.")
		return
	}

	var req CompleteMultipartUploadRequest
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		writeS3Error(w, r, http.StatusBadRequest, "MalformedXML", "The XML you provided was not well-formed.")
		return
	}

	// Lock order: mutationMu BEFORE session.mu
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.Aborted || session.Completed {
		writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist.")
		return
	}

	stream, s3ETag, _, err := s.mpManager.AssembleStream(session, req.Parts)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidPartOrder):
			writeS3Error(w, r, http.StatusBadRequest, "InvalidPartOrder", "The list of parts was not in ascending order. The parts list must be specified in order by part number.")
		case errors.Is(err, ErrInvalidPart):
			writeS3Error(w, r, http.StatusBadRequest, "InvalidPart", "One or more of the specified parts could not be found or part ETag does not match.")
		case errors.Is(err, ErrEntityTooSmall):
			writeS3Error(w, r, http.StatusBadRequest, "EntityTooSmall", "Your proposed upload is smaller than the minimum allowed size. Each part must be at least 5 MB in size, except the last part.")
		default:
			writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "An internal error occurred.")
		}
		return
	}
	defer stream.Close()

	meta := session.Metadata
	meta.ETag = s3ETag

	if err := s.commitObjectLocked(r, key, stream, meta); err != nil {
		writeOperationError(w, r, err)
		return
	}

	if err := s.mpManager.FinalizeCompleteLocked(session); err != nil {
		slog.Warn("failed to finalize multipart session", "uploadID", uploadID, "error", err)
	}

	resp := CompleteMultipartUploadResult{
		Xmlns:    "http://s3.amazonaws.com/doc/2006-03-01/",
		Location: "/" + bucket + "/" + key,
		Bucket:   bucket,
		Key:      key,
		ETag:     s3ETag,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(resp)
}

func (s *S3Server) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	session, ok := s.mpManager.GetUpload(uploadID)
	if !ok {
		writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist.")
		return
	}
	if session.Bucket != bucket || session.Key != key {
		writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Upload ID does not match specified bucket and key.")
		return
	}
	if err := s.mpManager.AbortUpload(uploadID); err != nil {
		if errors.Is(err, ErrNoSuchUpload) {
			writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist.")
			return
		}
		writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Failed to abort multipart upload.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *S3Server) handleListParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	session, ok := s.mpManager.GetUpload(uploadID)
	if !ok {
		writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist.")
		return
	}
	if session.Bucket != bucket || session.Key != key {
		writeS3Error(w, r, http.StatusBadRequest, "InvalidArgument", "Upload ID does not match specified bucket and key.")
		return
	}

	maxParts := 1000
	if m := r.URL.Query().Get("max-parts"); m != "" {
		if mp, err := strconv.Atoi(m); err == nil && mp >= 0 {
			maxParts = mp
		}
	}
	partNumberMarker := 0
	if pm := r.URL.Query().Get("part-number-marker"); pm != "" {
		if pnm, err := strconv.Atoi(pm); err == nil && pnm >= 0 {
			partNumberMarker = pnm
		}
	}

	parts, isTruncated, nextMarker, err := s.mpManager.ListParts(session, maxParts, partNumberMarker)
	if err != nil {
		writeS3Error(w, r, http.StatusNotFound, "NoSuchUpload", "The specified multipart upload does not exist.")
		return
	}
	var xmlParts []ListPartItem
	for _, p := range parts {
		xmlParts = append(xmlParts, ListPartItem{
			PartNumber:   p.PartNumber,
			LastModified: p.ModTime,
			ETag:         p.ETag,
			Size:         p.Size,
		})
	}

	resp := ListPartsResult{
		Xmlns:                "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:               bucket,
		Key:                  key,
		UploadId:             uploadID,
		PartNumberMarker:     partNumberMarker,
		NextPartNumberMarker: nextMarker,
		MaxParts:             maxParts,
		IsTruncated:          isTruncated,
		Parts:                xmlParts,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(resp)
}

func (s *S3Server) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) {
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	keyMarker := r.URL.Query().Get("key-marker")
	uploadIDMarker := r.URL.Query().Get("upload-id-marker")
	maxUploads := 1000
	if m := r.URL.Query().Get("max-uploads"); m != "" {
		if mu, err := strconv.Atoi(m); err == nil && mu >= 0 {
			maxUploads = mu
		}
	}

	uploads, commonPrefixes, isTruncated, nextKeyMarker, nextUploadIDMarker := s.mpManager.ListUploads(bucket, prefix, delimiter, keyMarker, uploadIDMarker, maxUploads)

	var xmlUploads []UploadListItem
	for _, u := range uploads {
		xmlUploads = append(xmlUploads, UploadListItem{
			Key:          u.Key,
			UploadId:     u.UploadID,
			Initiated:    u.Initiated,
			StorageClass: u.StorageClass,
		})
	}

	var xmlCommonPrefixes []CommonPrefix
	for _, cp := range commonPrefixes {
		xmlCommonPrefixes = append(xmlCommonPrefixes, CommonPrefix{Prefix: cp})
	}

	resp := ListMultipartUploadsResult{
		Xmlns:              "http://s3.amazonaws.com/doc/2006-03-01/",
		Bucket:             bucket,
		KeyMarker:          keyMarker,
		UploadIdMarker:     uploadIDMarker,
		NextKeyMarker:      nextKeyMarker,
		NextUploadIdMarker: nextUploadIDMarker,
		MaxUploads:         maxUploads,
		IsTruncated:        isTruncated,
		Uploads:            xmlUploads,
		CommonPrefixes:     xmlCommonPrefixes,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(resp)
}
