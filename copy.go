package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CopyObjectResult represents the XML response for CopyObject.
type CopyObjectResult struct {
	XMLName        xml.Name `xml:"CopyObjectResult"`
	Xmlns          string   `xml:"xmlns,attr"`
	LastModified   string   `xml:"LastModified"`
	ETag           string   `xml:"ETag"`
	ChecksumCRC32  string   `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C string   `xml:"ChecksumCRC32C,omitempty"`
	ChecksumSHA1   string   `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256 string   `xml:"ChecksumSHA256,omitempty"`
}

// CopyPartResult represents the XML response for UploadPartCopy.
type CopyPartResult struct {
	XMLName        xml.Name `xml:"CopyPartResult"`
	Xmlns          string   `xml:"xmlns,attr"`
	LastModified   string   `xml:"LastModified"`
	ETag           string   `xml:"ETag"`
	ChecksumCRC32  string   `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C string   `xml:"ChecksumCRC32C,omitempty"`
	ChecksumSHA1   string   `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256 string   `xml:"ChecksumSHA256,omitempty"`
}

// parseCopySource safely extracts and validates the bucket and key from x-amz-copy-source.
// It strictly uses PathUnescape to preserve '+' without replacing with spaces.
func parseCopySource(rawSource string) (bucket, key string, err error) {
	if rawSource == "" {
		return "", "", s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "Copy Source must be specified.",
		}
	}

	sourceStr := rawSource
	// Check for versionId query parameter
	if idx := strings.Index(sourceStr, "?"); idx != -1 {
		query := sourceStr[idx+1:]
		sourceStr = sourceStr[:idx]
		vals, qErr := url.ParseQuery(query)
		if qErr != nil {
			return "", "", s3OperationError{
				Status:  http.StatusBadRequest,
				Code:    "InvalidArgument",
				Message: "Invalid query parameters in copy source.",
			}
		}
		if vals.Get("versionId") != "" || vals.Has("versionId") {
			return "", "", s3OperationError{
				Status:  http.StatusNotImplemented,
				Code:    "NotImplemented",
				Message: "Versioning is not supported",
			}
		}
	}

	sourceStr = strings.TrimPrefix(sourceStr, "/")
	parts := strings.SplitN(sourceStr, "/", 2)
	if len(parts) < 2 {
		return "", "", s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "Copy source must specify bucket and key.",
		}
	}

	srcBucket, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "Invalid copy source bucket encoding.",
		}
	}
	if srcBucket != "default" {
		return "", "", s3OperationError{
			Status:  http.StatusNotFound,
			Code:    "NoSuchBucket",
			Message: "The specified bucket does not exist.",
		}
	}

	srcKey, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "Invalid copy source key encoding.",
		}
	}

	if err := validateKey(srcKey); err != nil {
		return "", "", s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: fmt.Sprintf("Invalid copy source key: %v", err),
		}
	}

	return srcBucket, srcKey, nil
}

// parseCopySourceRange parses the x-amz-copy-source-range header (e.g. "bytes=first-last").
func parseCopySourceRange(rangeHdr string, sourceSize int64) (start, end int64, err error) {
	if rangeHdr == "" {
		if sourceSize == 0 {
			return 0, 0, nil
		}
		return 0, sourceSize - 1, nil
	}

	trimmed := strings.TrimSpace(rangeHdr)
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "bytes=") {
		return 0, 0, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The specified copy source range is not valid.",
		}
	}

	spec := strings.TrimSpace(trimmed[len("bytes="):])
	parts := strings.Split(spec, "-")
	if len(parts) != 2 {
		return 0, 0, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The specified copy source range is not valid.",
		}
	}

	p0 := strings.TrimSpace(parts[0])
	p1 := strings.TrimSpace(parts[1])
	if p0 == "" || p1 == "" {
		return 0, 0, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The specified copy source range is not valid.",
		}
	}

	s, err1 := strconv.ParseInt(p0, 10, 64)
	e, err2 := strconv.ParseInt(p1, 10, 64)
	if err1 != nil || err2 != nil || s < 0 || s > e {
		return 0, 0, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The specified copy source range is not valid.",
		}
	}

	if sourceSize == 0 {
		return 0, 0, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The specified copy source range is not valid.",
		}
	}

	if e >= sourceSize {
		return 0, 0, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The specified copy source range is not valid.",
		}
	}

	return s, e, nil
}

// checkSourcePreconditions checks x-amz-copy-source-if-* preconditions against source metadata.
func checkSourcePreconditions(r *http.Request, info *FileInfo, meta *ObjectMetadata) error {
	actualETag := meta.ETag
	if actualETag == "" {
		actualETag = fileETag(info.Size, info.ModTime)
	}

	ifMatchMatched := false
	if ifMatch := r.Header.Get("X-Amz-Copy-Source-If-Match"); ifMatch != "" {
		if !matchETagStrong(ifMatch, actualETag) {
			return s3OperationError{
				Status:  http.StatusPreconditionFailed,
				Code:    "PreconditionFailed",
				Message: "At least one of the pre-conditions you specified did not hold.",
			}
		}
		ifMatchMatched = true
	}

	if ifNoneMatch := r.Header.Get("X-Amz-Copy-Source-If-None-Match"); ifNoneMatch != "" {
		if matchETagWeak(ifNoneMatch, actualETag) {
			return s3OperationError{
				Status:  http.StatusPreconditionFailed,
				Code:    "PreconditionFailed",
				Message: "At least one of the pre-conditions you specified did not hold.",
			}
		}
	}

	if unmodSince := r.Header.Get("X-Amz-Copy-Source-If-Unmodified-Since"); unmodSince != "" {
		if !ifMatchMatched {
			if t, err := http.ParseTime(unmodSince); err == nil {
				if info.ModTime.Truncate(time.Second).After(t.Truncate(time.Second)) {
					return s3OperationError{
						Status:  http.StatusPreconditionFailed,
						Code:    "PreconditionFailed",
						Message: "At least one of the pre-conditions you specified did not hold.",
					}
				}
			}
		}
	}

	if modSince := r.Header.Get("X-Amz-Copy-Source-If-Modified-Since"); modSince != "" {
		if t, err := http.ParseTime(modSince); err == nil {
			if !info.ModTime.Truncate(time.Second).After(t.Truncate(time.Second)) {
				return s3OperationError{
					Status:  http.StatusPreconditionFailed,
					Code:    "PreconditionFailed",
					Message: "At least one of the pre-conditions you specified did not hold.",
				}
			}
		}
	}

	return nil
}

// handleCopyObject handles PUT requests with X-Amz-Copy-Source header.
func (s *S3Server) handleCopyObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	if bucket != "default" {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusNotFound,
			Code:    "NoSuchBucket",
			Message: "The specified bucket does not exist.",
		})
		return
	}

	srcBucket, srcKey, err := parseCopySource(r.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		writeOperationError(w, r, err)
		return
	}

	directive := strings.TrimSpace(r.Header.Get("X-Amz-Metadata-Directive"))
	if directive == "" {
		directive = "COPY"
	} else if !strings.EqualFold(directive, "COPY") && !strings.EqualFold(directive, "REPLACE") {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "Unknown metadata directive.",
		})
		return
	}

	// Source and destination same key COPY without metadata change is rejected
	if srcBucket == bucket && srcKey == key && strings.EqualFold(directive, "COPY") {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidRequest",
			Message: "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, or encryption attributes.",
		})
		return
	}

	// Hold mutationMu while inspecting source, evaluating preconditions, and spooling
	s.mutationMu.Lock()
	srcInfo, err := s.getFileInfo(srcKey)
	if err != nil {
		s.mutationMu.Unlock()
		if errors.Is(err, os.ErrNotExist) {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusNotFound,
				Code:    "NoSuchKey",
				Message: "The specified key does not exist.",
			})
			return
		}
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to locate copy source object.",
		})
		return
	}

	srcMeta, err := s.metadataFor(srcKey, srcInfo)
	if err != nil {
		s.mutationMu.Unlock()
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to read copy source metadata.",
		})
		return
	}

	if err := checkSourcePreconditions(r, srcInfo, &srcMeta); err != nil {
		s.mutationMu.Unlock()
		writeOperationError(w, r, err)
		return
	}

	if srcInfo.Size > MaxPartSizeBytes {
		s.mutationMu.Unlock()
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "EntityTooLarge",
			Message: "The copy source is too large (maximum 5 GiB).",
		})
		return
	}
	algo := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-checksum-algorithm")))
	var crc32Hash hash.Hash32
	var crc32cHash hash.Hash32
	var sha1Hash = sha1.New()
	var sha256Hash = sha256.New()

	switch algo {
	case "CRC32":
		crc32Hash = crc32.NewIEEE()
	case "CRC32C":
		crc32cHash = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "SHA1":
	case "SHA256":
	case "":
	default:
		s.mutationMu.Unlock()
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The value specified in x-amz-checksum-algorithm is invalid.",
		})
		return
	}

	var destMeta ObjectMetadata
	if strings.EqualFold(directive, "REPLACE") {
		destMeta, err = extractMetadata(r)
		if err != nil {
			s.mutationMu.Unlock()
			writeOperationError(w, r, err)
			return
		}
	} else {
		destMeta = srcMeta
		destMeta.ETag = ""
		destMeta.Size = 0
		destMeta.ModTime = time.Time{}
	}

	spoolDir := filepath.Join(s.state.Root, "spool")
	spool, err := NewSpoolFile(spoolDir, s.state.Budget)
	if err != nil {
		s.mutationMu.Unlock()
		if errors.Is(err, ErrStorageLimit) {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusServiceUnavailable,
				Code:    "SlowDown",
				Message: "Storage limit exceeded.",
			})
			return
		}
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to allocate spool for copy.",
		})
		return
	}
	defer spool.Close()

	if srcInfo.Size > 0 {
		rc, err := s.ftp.Get(srcKey)
		if err != nil {
			s.mutationMu.Unlock()
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Failed to retrieve copy source from FTP.",
			})
			return
		}

		writers := []io.Writer{spool}
		if crc32Hash != nil {
			writers = append(writers, crc32Hash)
		}
		if crc32cHash != nil {
			writers = append(writers, crc32cHash)
		}
		if algo == "SHA1" {
			writers = append(writers, sha1Hash)
		}
		if algo == "SHA256" {
			writers = append(writers, sha256Hash)
		}

		mw := io.MultiWriter(writers...)
		n, copyErr := io.Copy(mw, &contextReader{ctx: r.Context(), r: rc})
		closeErr := rc.Close()
		s.mutationMu.Unlock() // Release mutationMu immediately after FTP transfer finishes

		if copyErr != nil {
			if errors.Is(copyErr, ErrStorageLimit) {
				writeOperationError(w, r, s3OperationError{
					Status:  http.StatusServiceUnavailable,
					Code:    "SlowDown",
					Message: "Storage limit exceeded.",
				})
				return
			}
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Failed to read copy source stream.",
			})
			return
		}
		if closeErr != nil {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Failed to close copy source stream.",
			})
			return
		}
		if n != srcInfo.Size {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Incomplete read of copy source.",
			})
			return
		}
	} else {
		s.mutationMu.Unlock()
	}

	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to rewind spool file.",
		})
		return
	}

	// Commit object to destination and capture metadata under mutation lock
	s.mutationMu.Lock()
	if err := s.commitObjectLocked(r, key, spool, destMeta); err != nil {
		s.mutationMu.Unlock()
		writeOperationError(w, r, err)
		return
	}

	dstInfo, err := s.getFileInfo(key)
	if err != nil {
		s.mutationMu.Unlock()
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to stat committed object.",
		})
		return
	}

	committedMeta, err := s.metadataFor(key, dstInfo)
	s.mutationMu.Unlock()
	if err != nil {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to read committed object metadata.",
		})
		return
	}

	resp := CopyObjectResult{
		Xmlns:        "http://s3.amazonaws.com/doc/2006-03-01/",
		LastModified: committedMeta.ModTime.UTC().Format("2006-01-02T15:04:05.000Z"),
		ETag:         committedMeta.ETag,
	}

	if crc32Hash != nil {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, crc32Hash.Sum32())
		cs := base64.StdEncoding.EncodeToString(b)
		resp.ChecksumCRC32 = cs
		w.Header().Set("x-amz-checksum-crc32", cs)
	}
	if crc32cHash != nil {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, crc32cHash.Sum32())
		cs := base64.StdEncoding.EncodeToString(b)
		resp.ChecksumCRC32C = cs
		w.Header().Set("x-amz-checksum-crc32c", cs)
	}
	if algo == "SHA1" {
		cs := base64.StdEncoding.EncodeToString(sha1Hash.Sum(nil))
		resp.ChecksumSHA1 = cs
		w.Header().Set("x-amz-checksum-sha1", cs)
	}
	if algo == "SHA256" {
		cs := base64.StdEncoding.EncodeToString(sha256Hash.Sum(nil))
		resp.ChecksumSHA256 = cs
		w.Header().Set("x-amz-checksum-sha256", cs)
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("ETag", committedMeta.ETag)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(resp)
	return
}

// handleUploadPartCopy handles PUT requests with X-Amz-Copy-Source for multipart part upload.
func (s *S3Server) handleUploadPartCopy(w http.ResponseWriter, r *http.Request, bucket, key, uploadID, partNumberStr string) {
	if bucket != "default" {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusNotFound,
			Code:    "NoSuchBucket",
			Message: "The specified bucket does not exist.",
		})
		return
	}

	session, ok := s.mpManager.GetUpload(uploadID)
	if !ok {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusNotFound,
			Code:    "NoSuchUpload",
			Message: "The specified multipart upload does not exist.",
		})
		return
	}
	if session.Bucket != bucket || session.Key != key {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "Upload ID does not match specified bucket and key.",
		})
		return
	}

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "Part number must be an integer between 1 and 10000.",
		})
		return
	}

	srcBucket, srcKey, err := parseCopySource(r.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		writeOperationError(w, r, err)
		return
	}
	_ = srcBucket

	// Hold mutationMu while inspecting source, evaluating preconditions, and spooling range
	s.mutationMu.Lock()
	srcInfo, err := s.getFileInfo(srcKey)
	if err != nil {
		s.mutationMu.Unlock()
		if errors.Is(err, os.ErrNotExist) {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusNotFound,
				Code:    "NoSuchKey",
				Message: "The specified key does not exist.",
			})
			return
		}
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to locate copy source object.",
		})
		return
	}

	srcMeta, err := s.metadataFor(srcKey, srcInfo)
	if err != nil {
		s.mutationMu.Unlock()
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to read copy source metadata.",
		})
		return
	}

	if err := checkSourcePreconditions(r, srcInfo, &srcMeta); err != nil {
		s.mutationMu.Unlock()
		writeOperationError(w, r, err)
		return
	}

	start, end, err := parseCopySourceRange(r.Header.Get("X-Amz-Copy-Source-Range"), srcInfo.Size)
	if err != nil {
		s.mutationMu.Unlock()
		writeOperationError(w, r, err)
		return
	}

	var rangeLen int64
	if srcInfo.Size > 0 {
		rangeLen = end - start + 1
	}
	if rangeLen > MaxPartSizeBytes {
		s.mutationMu.Unlock()
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "EntityTooLarge",
			Message: "Your proposed upload exceeds the maximum allowed size (5 GiB per part).",
		})
		return
	}

	spoolDir := filepath.Join(s.state.Root, "spool")
	spool, err := NewSpoolFile(spoolDir, s.state.Budget)
	if err != nil {
		s.mutationMu.Unlock()
		if errors.Is(err, ErrStorageLimit) {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusServiceUnavailable,
				Code:    "SlowDown",
				Message: "Storage limit exceeded.",
			})
			return
		}
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to allocate spool for part copy.",
		})
		return
	}
	defer spool.Close()

	var hexMD5 string
	var checksumCRC32, checksumCRC32C, checksumSHA1, checksumSHA256 string

	algo := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-checksum-algorithm")))
	var crc32Hash hash.Hash32
	var crc32cHash hash.Hash32
	var sha1Hash = sha1.New()
	var sha256Hash = sha256.New()

	switch algo {
	case "CRC32":
		crc32Hash = crc32.NewIEEE()
	case "CRC32C":
		crc32cHash = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "SHA1":
		// already initialized
	case "SHA256":
		// already initialized
	case "":
		// no algorithm requested
	default:
		s.mutationMu.Unlock()
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The value specified in x-amz-checksum-algorithm is invalid.",
		})
		return
	}

	if rangeLen > 0 {
		rc, err := s.ftp.Get(srcKey)
		if err != nil {
			s.mutationMu.Unlock()
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Failed to retrieve copy source from FTP.",
			})
			return
		}

		cr := &contextReader{ctx: r.Context(), r: rc}
		if start > 0 {
			if _, err := io.CopyN(io.Discard, cr, start); err != nil {
				_ = rc.Close()
				s.mutationMu.Unlock()
				writeOperationError(w, r, s3OperationError{
					Status:  http.StatusInternalServerError,
					Code:    "InternalError",
					Message: "Failed to seek to copy source offset.",
				})
				return
			}
		}

		hMD5 := md5.New()
		writers := []io.Writer{spool, hMD5}
		if crc32Hash != nil {
			writers = append(writers, crc32Hash)
		}
		if crc32cHash != nil {
			writers = append(writers, crc32cHash)
		}
		if algo == "SHA1" {
			writers = append(writers, sha1Hash)
		}
		if algo == "SHA256" {
			writers = append(writers, sha256Hash)
		}

		mw := io.MultiWriter(writers...)
		n, copyErr := io.Copy(mw, io.LimitReader(cr, rangeLen))
		if copyErr == nil && n == rangeLen {
			// Drain remaining RETR bytes so FTP server sends clean 226 transfer complete
			_, _ = io.Copy(io.Discard, cr)
		}
		closeErr := rc.Close()
		s.mutationMu.Unlock() // Release mutationMu immediately after FTP transfer finishes

		if copyErr != nil {
			if errors.Is(copyErr, ErrStorageLimit) {
				writeOperationError(w, r, s3OperationError{
					Status:  http.StatusServiceUnavailable,
					Code:    "SlowDown",
					Message: "Storage limit exceeded.",
				})
				return
			}
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Failed to read copy source range.",
			})
			return
		}
		if closeErr != nil {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Failed to close copy source stream.",
			})
			return
		}
		if n != rangeLen {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Incomplete read of copy source range.",
			})
			return
		}

		rawMD5 := hMD5.Sum(nil)
		hexMD5 = hex.EncodeToString(rawMD5)

		if crc32Hash != nil {
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, crc32Hash.Sum32())
			checksumCRC32 = base64.StdEncoding.EncodeToString(b)
		}
		if crc32cHash != nil {
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, crc32cHash.Sum32())
			checksumCRC32C = base64.StdEncoding.EncodeToString(b)
		}
		if algo == "SHA1" {
			checksumSHA1 = base64.StdEncoding.EncodeToString(sha1Hash.Sum(nil))
		}
		if algo == "SHA256" {
			checksumSHA256 = base64.StdEncoding.EncodeToString(sha256Hash.Sum(nil))
		}
	} else {
		s.mutationMu.Unlock()
		hexMD5 = "d41d8cd98f00b204e9800998ecf8427e"
	}

	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusInternalServerError,
			Code:    "InternalError",
			Message: "Failed to rewind spool file.",
		})
		return
	}

	part, err := s.mpManager.UploadPart(session, partNumber, spool, rangeLen, hexMD5, checksumCRC32, checksumCRC32C, checksumSHA1, checksumSHA256)
	if err != nil {
		switch {
		case errors.Is(err, ErrEntityTooLarge):
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusBadRequest,
				Code:    "EntityTooLarge",
				Message: "Your proposed upload exceeds the maximum allowed size (5 GiB per part).",
			})
		case errors.Is(err, ErrStagingLimitExceeded):
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusServiceUnavailable,
				Code:    "SlowDown",
				Message: "Storage limit exceeded.",
			})
		case errors.Is(err, ErrNoSuchUpload):
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusNotFound,
				Code:    "NoSuchUpload",
				Message: "The specified multipart upload does not exist.",
			})
		default:
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusInternalServerError,
				Code:    "InternalError",
				Message: "Failed to store upload part.",
			})
		}
		return
	}

	resp := CopyPartResult{
		Xmlns:          "http://s3.amazonaws.com/doc/2006-03-01/",
		LastModified:   part.ModTime.UTC().Format("2006-01-02T15:04:05.000Z"),
		ETag:           part.ETag,
		ChecksumCRC32:  part.ChecksumCRC32,
		ChecksumCRC32C: part.ChecksumCRC32C,
		ChecksumSHA1:   part.ChecksumSHA1,
		ChecksumSHA256: part.ChecksumSHA256,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("ETag", part.ETag)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(resp)
}
