package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const (
	// maxSinglePUTSize is the maximum single PUT payload size supported by S3 (5 GiB).
	maxSinglePUTSize = int64(5 * 1024 * 1024 * 1024)
)

var (
	crc32CastagnoliTable = crc32.MakeTable(crc32.Castagnoli)
	crc64NVMETable       = crc64.MakeTable(0x9A6C9329AC4BC9B5)
)

// s3PayloadError represents an error during payload validation and spooling.
type s3PayloadError struct {
	status  int
	code    string
	message string
}

func (e *s3PayloadError) Error() string {
	return e.message
}

func newPayloadError(status int, code, message string) error {
	return &s3PayloadError{status: status, code: code, message: message}
}

// multiHasher computes all supported S3 checksums in a single pass.
type multiHasher struct {
	md5    hash.Hash
	sha256 hash.Hash
	sha1   hash.Hash
	crc32  hash.Hash32
	crc32c hash.Hash32
	crc64  hash.Hash64
}

func newMultiHasher() *multiHasher {
	return &multiHasher{
		md5:    md5.New(),
		sha256: sha256.New(),
		sha1:   sha1.New(),
		crc32:  crc32.NewIEEE(),
		crc32c: crc32.New(crc32CastagnoliTable),
		crc64:  crc64.New(crc64NVMETable),
	}
}

func (m *multiHasher) Write(p []byte) (n int, err error) {
	m.md5.Write(p)
	m.sha256.Write(p)
	m.sha1.Write(p)
	m.crc32.Write(p)
	m.crc32c.Write(p)
	m.crc64.Write(p)
	return len(p), nil
}

type countingReader struct {
	r     io.Reader
	count int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.count += int64(n)
	return n, err
}

func isHexStr(s string) bool {
	for i := range s {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// interruptibleReader ensures a slow or blocked incoming body read immediately unblocks
// and returns context.DeadlineExceeded or context.Canceled when the request context expires.
type interruptibleReader struct {
	ctx context.Context
	r   io.Reader
}

func (ir *interruptibleReader) Read(p []byte) (int, error) {
	if err := ir.ctx.Err(); err != nil {
		return 0, err
	}
	type readRes struct {
		n   int
		err error
	}
	ch := make(chan readRes, 1)
	go func() {
		n, err := ir.r.Read(p)
		ch <- readRes{n: n, err: err}
	}()
	select {
	case <-ir.ctx.Done():
		return 0, ir.ctx.Err()
	case res := <-ch:
		return res.n, res.err
	}
}

// preparePayload spools the request body to a quota-tracked spool file under spoolDir, validates lengths,
// verifies and computes checksums (MD5, SHA256, CRC32, CRC32C, CRC64NVME),
// decodes aws-chunked unsigned payloads with trailers, and replaces r.Body and r.ContentLength.
// It exposes computed MD5 in X-Ftp-Content-Md5 and trusted checksums in response-ready headers.
func preparePayload(r *http.Request, spoolDir string, budget *DiskBudget) (cleanup func(), err error) {
	// Delete all client-supplied X-Ftp-* headers to prevent spoofing
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-ftp-") {
			r.Header.Del(k)
		}
	}

	// Normalize nil or http.NoBody to an empty reader so it routes through full validation
	if r.Body == nil || r.Body == http.NoBody {
		r.Body = io.NopCloser(bytes.NewReader(nil))
		r.ContentLength = 0
	} else {
		r.Body = io.NopCloser(&interruptibleReader{ctx: r.Context(), r: r.Body})
	}

	// Validate x-amz-content-sha256 format
	contentSHA256 := strings.TrimSpace(r.Header.Get("x-amz-content-sha256"))
	if contentSHA256 != "" {
		if strings.EqualFold(contentSHA256, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") ||
			strings.EqualFold(contentSHA256, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER") {
			return nil, newPayloadError(http.StatusNotImplemented, "NotImplemented", "Signed streaming payloads are not supported")
		}
		if !strings.EqualFold(contentSHA256, "UNSIGNED-PAYLOAD") &&
			!strings.EqualFold(contentSHA256, "STREAMING-UNSIGNED-PAYLOAD-TRAILER") {
			if len(contentSHA256) != 64 || !isHexStr(contentSHA256) {
				return nil, newPayloadError(http.StatusBadRequest, "InvalidDigest", "The provided 'x-amz-content-sha256' header is invalid.")
			}
		}
	}

	if budget == nil || budget.Max() <= 0 {
		return nil, newPayloadError(http.StatusInternalServerError, "InternalError", "Storage staging budget is not configured")
	}

	// Create temporary quota-tracked spool file
	spool, err := NewSpoolFile(spoolDir, budget)
	if err != nil {
		return nil, newPayloadError(http.StatusInternalServerError, "InternalError", "Failed to create payload spool file")
	}

	var cleanupOnce sync.Once
	cleanupFn := func() {
		cleanupOnce.Do(func() {
			_ = spool.Close()
		})
	}

	// Ensure cleanup on failure; capture independent cleanupFn, not named return
	defer func() {
		if err != nil {
			cleanupFn()
		}
	}()

	hasher := newMultiHasher()
	writer := io.MultiWriter(spool, hasher)

	isAWSChunked := false
	for _, enc := range r.Header.Values("Content-Encoding") {
		for _, part := range strings.Split(enc, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "aws-chunked") {
				isAWSChunked = true
				break
			}
		}
	}

	var totalDecoded int64
	var trailers map[string]string

	if isAWSChunked {
		cr := &countingReader{r: r.Body}
		totalDecoded, trailers, err = readAWSChunked(cr, writer, maxSinglePUTSize)
		if err != nil {
			return nil, err
		}

		// Enforce raw Content-Length if specified
		if r.ContentLength > 0 && cr.count != r.ContentLength {
			return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Raw chunked stream length did not match Content-Length")
		}

		// Enforce decoded length if header present
		if decodedLenStr := r.Header.Get("x-amz-decoded-content-length"); decodedLenStr != "" {
			expectedLen, parseErr := strconv.ParseInt(strings.TrimSpace(decodedLenStr), 10, 64)
			if parseErr != nil || expectedLen < 0 || expectedLen != totalDecoded {
				return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Decoded payload size does not match x-amz-decoded-content-length")
			}
		}

		// Every checksum trailer must be explicitly announced, and every
		// announced trailer must occur exactly once in the stream.
		declaredSet := make(map[string]struct{})
		declared := strings.TrimSpace(r.Header.Get("x-amz-trailer"))
		if declared == "" && len(trailers) > 0 {
			return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Checksum trailer was not announced")
		}
		for _, decl := range strings.Split(declared, ",") {
			decl = strings.ToLower(strings.TrimSpace(decl))
			if decl == "" {
				continue
			}
			if _, duplicate := declaredSet[decl]; duplicate {
				return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", fmt.Sprintf("Duplicate declared trailer '%s'", decl))
			}
			declaredSet[decl] = struct{}{}
			if _, found := trailers[decl]; !found {
				return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", fmt.Sprintf("Declared trailer '%s' was not provided in stream", decl))
			}
		}
		for trailer := range trailers {
			if _, announced := declaredSet[trailer]; !announced {
				return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", fmt.Sprintf("Unannounced trailer '%s'", trailer))
			}
		}

		// Strip aws-chunked from Content-Encoding
		encodings := r.Header.Values("Content-Encoding")
		r.Header.Del("Content-Encoding")
		for _, enc := range encodings {
			var kept []string
			for _, p := range strings.Split(enc, ",") {
				trimmed := strings.TrimSpace(p)
				if !strings.EqualFold(trimmed, "aws-chunked") && trimmed != "" {
					kept = append(kept, trimmed)
				}
			}
			if len(kept) > 0 {
				r.Header.Add("Content-Encoding", strings.Join(kept, ", "))
			}
		}

		// Merge validated checksum trailers into request headers
		for k, v := range trailers {
			r.Header.Set(k, v)
		}
	} else {
		// Non-chunked upload: enforce Content-Length or read up to maxSinglePUTSize
		if r.ContentLength > maxSinglePUTSize {
			return nil, newPayloadError(http.StatusBadRequest, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
		}

		if r.ContentLength >= 0 {
			lr := io.LimitReader(r.Body, r.ContentLength+1)
			buf := make([]byte, 32*1024)
			for {
				n, rErr := lr.Read(buf)
				if n > 0 {
					totalDecoded += int64(n)
					if totalDecoded > r.ContentLength {
						return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Request entity larger than Content-Length")
					}
					if _, wErr := writer.Write(buf[:n]); wErr != nil {
						if errors.Is(wErr, ErrStorageLimit) {
							return nil, newPayloadError(http.StatusServiceUnavailable, "SlowDown", "Storage limit exceeded")
						}
						return nil, newPayloadError(http.StatusInternalServerError, "InternalError", "Failed to write payload to disk")
					}
				}
				if rErr == io.EOF {
					break
				}
				if rErr != nil {
					if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
						return nil, newPayloadError(http.StatusRequestTimeout, "RequestTimeout", "Your socket connection to the server was not read from or written to within the timeout period.")
					}
					if errors.Is(r.Context().Err(), context.Canceled) {
						return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Request context canceled")
					}
					return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Failed reading request body")
				}
			}
			if totalDecoded < r.ContentLength {
				return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header")
			}
		} else {
			// Chunked HTTP transfer encoding without Content-Length
			lr := io.LimitReader(r.Body, maxSinglePUTSize+1)
			buf := make([]byte, 32*1024)
			for {
				n, rErr := lr.Read(buf)
				if n > 0 {
					totalDecoded += int64(n)
					if totalDecoded > maxSinglePUTSize {
						return nil, newPayloadError(http.StatusBadRequest, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
					}
					if _, wErr := writer.Write(buf[:n]); wErr != nil {
						if errors.Is(wErr, ErrStorageLimit) {
							return nil, newPayloadError(http.StatusServiceUnavailable, "SlowDown", "Storage limit exceeded")
						}
						return nil, newPayloadError(http.StatusInternalServerError, "InternalError", "Failed to write payload to disk")
					}
				}
				if rErr == io.EOF {
					break
				}
				if rErr != nil {
					if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
						return nil, newPayloadError(http.StatusRequestTimeout, "RequestTimeout", "Your socket connection to the server was not read from or written to within the timeout period.")
					}
					if errors.Is(r.Context().Err(), context.Canceled) {
						return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Request context canceled")
					}
					return nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Failed reading request body")
				}
			}
		}
	}

	// Compute checksum results
	md5Bytes := hasher.md5.Sum(nil)
	md5Hex := fmt.Sprintf("%x", md5Bytes)
	r.Header.Set("X-Ftp-Content-Md5", md5Hex)

	sha256Bytes := hasher.sha256.Sum(nil)
	sha256Hex := fmt.Sprintf("%x", sha256Bytes)
	sha256Base64 := base64.StdEncoding.EncodeToString(sha256Bytes)

	sha1Bytes := hasher.sha1.Sum(nil)
	sha1Base64 := base64.StdEncoding.EncodeToString(sha1Bytes)

	crc32Val := hasher.crc32.Sum32()
	crc32Bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crc32Bytes, crc32Val)
	crc32Base64 := base64.StdEncoding.EncodeToString(crc32Bytes)

	crc32cVal := hasher.crc32c.Sum32()
	crc32cBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crc32cBytes, crc32cVal)
	crc32cBase64 := base64.StdEncoding.EncodeToString(crc32cBytes)

	crc64Val := hasher.crc64.Sum64()
	crc64Bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(crc64Bytes, crc64Val)
	crc64Base64 := base64.StdEncoding.EncodeToString(crc64Bytes)

	// Validate Content-MD5 if supplied
	if clientMD5Str := strings.TrimSpace(r.Header.Get("Content-MD5")); clientMD5Str != "" {
		expectedMD5, decErr := base64.StdEncoding.DecodeString(clientMD5Str)
		if decErr != nil || len(expectedMD5) != 16 {
			return nil, newPayloadError(http.StatusBadRequest, "InvalidDigest", "The Content-MD5 you specified is not valid.")
		}
		if !bytes.Equal(expectedMD5, md5Bytes) {
			return nil, newPayloadError(http.StatusBadRequest, "BadDigest", "The Content-MD5 you specified did not match what we received.")
		}
	}

	// Validate x-amz-content-sha256 if supplied as fixed hex string
	if len(contentSHA256) == 64 {
		if !strings.EqualFold(contentSHA256, sha256Hex) {
			return nil, newPayloadError(http.StatusBadRequest, "XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed.")
		}
	}

	// Validate explicit checksum headers or trailers
	if clientCRC32 := strings.TrimSpace(r.Header.Get("x-amz-checksum-crc32")); clientCRC32 != "" {
		dec, decErr := base64.StdEncoding.DecodeString(clientCRC32)
		if decErr != nil || len(dec) != 4 {
			return nil, newPayloadError(http.StatusBadRequest, "InvalidDigest", "The CRC32 checksum you specified is not valid.")
		}
		if !bytes.Equal(dec, crc32Bytes) {
			return nil, newPayloadError(http.StatusBadRequest, "BadDigest", "The CRC32 checksum you specified did not match what we received.")
		}
	}

	if clientCRC32C := strings.TrimSpace(r.Header.Get("x-amz-checksum-crc32c")); clientCRC32C != "" {
		dec, decErr := base64.StdEncoding.DecodeString(clientCRC32C)
		if decErr != nil || len(dec) != 4 {
			return nil, newPayloadError(http.StatusBadRequest, "InvalidDigest", "The CRC32C checksum you specified is not valid.")
		}
		if !bytes.Equal(dec, crc32cBytes) {
			return nil, newPayloadError(http.StatusBadRequest, "BadDigest", "The CRC32C checksum you specified did not match what we received.")
		}
	}

	if clientSHA1 := strings.TrimSpace(r.Header.Get("x-amz-checksum-sha1")); clientSHA1 != "" {
		dec, decErr := base64.StdEncoding.DecodeString(clientSHA1)
		if decErr != nil || len(dec) != 20 {
			return nil, newPayloadError(http.StatusBadRequest, "InvalidDigest", "The SHA1 checksum you specified is not valid.")
		}
		if !bytes.Equal(dec, sha1Bytes) {
			return nil, newPayloadError(http.StatusBadRequest, "BadDigest", "The SHA1 checksum you specified did not match what we received.")
		}
	}

	if clientSHA256 := strings.TrimSpace(r.Header.Get("x-amz-checksum-sha256")); clientSHA256 != "" {
		dec, decErr := base64.StdEncoding.DecodeString(clientSHA256)
		if decErr != nil || len(dec) != 32 {
			return nil, newPayloadError(http.StatusBadRequest, "InvalidDigest", "The SHA256 checksum you specified is not valid.")
		}
		if !bytes.Equal(dec, sha256Bytes) {
			return nil, newPayloadError(http.StatusBadRequest, "BadDigest", "The SHA256 checksum you specified did not match what we received.")
		}
	}

	if clientCRC64 := strings.TrimSpace(r.Header.Get("x-amz-checksum-crc64nvme")); clientCRC64 != "" {
		dec, decErr := base64.StdEncoding.DecodeString(clientCRC64)
		if decErr != nil || len(dec) != 8 {
			return nil, newPayloadError(http.StatusBadRequest, "InvalidDigest", "The CRC64NVME checksum you specified is not valid.")
		}
		if !bytes.Equal(dec, crc64Bytes) {
			return nil, newPayloadError(http.StatusBadRequest, "BadDigest", "The CRC64NVME checksum you specified did not match what we received.")
		}
	}

	// Validate requested checksum algorithm if explicitly provided
	algo := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-checksum-algorithm")))
	if algo != "" {
		switch algo {
		case "CRC32", "CRC32C", "SHA1", "SHA256", "CRC64NVME":
			// supported algorithm
		default:
			return nil, newPayloadError(http.StatusBadRequest, "InvalidRequest", fmt.Sprintf("The checksum algorithm '%s' is not supported.", algo))
		}
	}

	// Detect active checksum algorithm for response reflection
	if algo == "" {
		sdkAlgo := strings.ToUpper(strings.TrimSpace(r.Header.Get("x-amz-sdk-checksum-algorithm")))
		if sdkAlgo != "" {
			algo = sdkAlgo
		} else if r.Header.Get("x-amz-checksum-crc64nvme") != "" {
			algo = "CRC64NVME"
		} else if r.Header.Get("x-amz-checksum-crc32") != "" {
			algo = "CRC32"
		} else if r.Header.Get("x-amz-checksum-crc32c") != "" {
			algo = "CRC32C"
		} else if r.Header.Get("x-amz-checksum-sha1") != "" {
			algo = "SHA1"
		} else if r.Header.Get("x-amz-checksum-sha256") != "" {
			algo = "SHA256"
		}
	}

	// Set trusted headers for protocol response handlers
	r.Header.Set("X-Ftp-Checksum-Algorithm", algo)
	r.Header.Set("X-Ftp-Checksum-Crc32", crc32Base64)
	r.Header.Set("X-Ftp-Checksum-Crc32c", crc32cBase64)
	r.Header.Set("X-Ftp-Checksum-Sha1", sha1Base64)
	r.Header.Set("X-Ftp-Checksum-Sha256", sha256Base64)
	r.Header.Set("X-Ftp-Checksum-Crc64nvme", crc64Base64)

	switch algo {
	case "CRC32":
		r.Header.Set("x-amz-checksum-crc32", crc32Base64)
	case "CRC32C":
		r.Header.Set("x-amz-checksum-crc32c", crc32cBase64)
	case "SHA1":
		r.Header.Set("x-amz-checksum-sha1", sha1Base64)
	case "SHA256":
		r.Header.Set("x-amz-checksum-sha256", sha256Base64)
	case "CRC64NVME":
		r.Header.Set("x-amz-checksum-crc64nvme", crc64Base64)
	}

	// Rewind spooled file to start
	if _, seekErr := spool.Seek(0, io.SeekStart); seekErr != nil {
		return nil, newPayloadError(http.StatusInternalServerError, "InternalError", "Failed rewinding spooled payload")
	}

	r.ContentLength = totalDecoded
	r.Body = spool
	return cleanupFn, nil
}

// readAWSChunked decodes standard AWS chunked streams, enforces size limits,
// writes decoded data to dst, and returns total decoded bytes and parsed trailers.
func readAWSChunked(src io.Reader, dst io.Writer, maxSize int64) (int64, map[string]string, error) {
	br := bufio.NewReader(src)
	var totalBytes int64
	chunkBuf := make([]byte, 32*1024)

	for {
		line, err := readBoundedCRLFLine(br, 4096)
		if err != nil {
			return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Incomplete chunk header in aws-chunked stream")
		}

		// Strip optional chunk extensions e.g. "1A2B;chunk-signature=..."
		sizeStr := strings.SplitN(line, ";", 2)[0]
		sizeStr = strings.TrimSpace(sizeStr)
		if sizeStr == "" {
			return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Empty chunk size in aws-chunked stream")
		}

		chunkSize, parseErr := strconv.ParseInt(sizeStr, 16, 64)
		if parseErr != nil || chunkSize < 0 {
			return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", fmt.Sprintf("Invalid chunk size '%s'", sizeStr))
		}

		if chunkSize == 0 {
			// Chunk 0: end of chunks, now read trailers
			break
		}

		if totalBytes+chunkSize > maxSize {
			return 0, nil, newPayloadError(http.StatusBadRequest, "EntityTooLarge", "Your proposed upload exceeds the maximum allowed size")
		}

		// Read exactly chunkSize bytes
		var remaining = chunkSize
		for remaining > 0 {
			toRead := int64(len(chunkBuf))
			if toRead > remaining {
				toRead = remaining
			}
			n, rErr := io.ReadFull(br, chunkBuf[:toRead])
			if n > 0 {
				if _, wErr := dst.Write(chunkBuf[:n]); wErr != nil {
					if errors.Is(wErr, ErrStorageLimit) {
						return 0, nil, newPayloadError(http.StatusServiceUnavailable, "SlowDown", "Storage limit exceeded")
					}
					return 0, nil, newPayloadError(http.StatusInternalServerError, "InternalError", "Failed writing chunk to spool")
				}
				totalBytes += int64(n)
				remaining -= int64(n)
			}
			if rErr != nil {
				return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Incomplete chunk data")
			}
		}

		// Consume CRLF following chunk data
		crlf := make([]byte, 2)
		if _, crlfErr := io.ReadFull(br, crlf); crlfErr != nil || crlf[0] != '\r' || crlf[1] != '\n' {
			return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Missing CRLF after chunk data")
		}
	}

	// Read trailers until empty CRLF line
	trailers := make(map[string]string)
	for {
		trailerLine, tErr := readBoundedCRLFLine(br, 4096)
		if tErr != nil {
			return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Truncated trailer section in aws-chunked stream")
		}
		if trailerLine == "" {
			// Terminal blank line reached
			break
		}
		k, v, found := strings.Cut(trailerLine, ":")
		if !found {
			return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Malformed trailer line")
		}
		hdr := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		if _, exists := trailers[hdr]; exists {
			return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", fmt.Sprintf("Duplicate trailer header '%s'", hdr))
		}
		// Only permit supported checksum trailers
		switch hdr {
		case "x-amz-checksum-crc32", "x-amz-checksum-crc32c", "x-amz-checksum-sha1", "x-amz-checksum-sha256", "x-amz-checksum-crc64nvme":
			trailers[hdr] = val
		default:
			return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", fmt.Sprintf("Unsupported or unannounced trailer '%s'", hdr))
		}
	}

	// Verify no unexpected trailing data exists in the stream
	extra := make([]byte, 1)
	n, _ := br.Read(extra)
	if n > 0 {
		return 0, nil, newPayloadError(http.StatusBadRequest, "IncompleteBody", "Unexpected trailing data after aws-chunked stream")
	}

	return totalBytes, trailers, nil
}

// readBoundedCRLFLine reads up to \n, requires preceding \r, and enforces maxLen.
func readBoundedCRLFLine(br *bufio.Reader, maxLen int) (string, error) {
	var buf []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			if len(buf) > 0 && buf[len(buf)-1] == '\r' {
				return string(buf[:len(buf)-1]), nil
			}
			return "", newPayloadError(http.StatusBadRequest, "IncompleteBody", "Line does not end with CRLF")
		}
		buf = append(buf, b)
		if len(buf) > maxLen {
			return "", newPayloadError(http.StatusBadRequest, "IncompleteBody", "Line exceeds maximum allowed length")
		}
	}
}
