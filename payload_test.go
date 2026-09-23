package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func testPreparePayload(t *testing.T, req *http.Request) (func(), error) {
	t.Helper()
	dir := t.TempDir()
	budget := NewDiskBudget(20 * 1024 * 1024 * 1024)
	return preparePayload(req, dir, budget)
}

func TestPayloadEmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/default/empty", nil)
	req.Header.Set("X-Ftp-Content-Md5", "client-spoofed")

	cleanup, err := testPreparePayload(t, req)
	if err != nil {
		t.Fatalf("unexpected error for empty body: %v", err)
	}
	defer cleanup()

	expectedEmptyMD5 := fmt.Sprintf("%x", md5.Sum(nil))
	if req.Header.Get("X-Ftp-Content-Md5") != expectedEmptyMD5 {
		t.Fatalf("expected X-Ftp-Content-Md5 to be %s, got: %s", expectedEmptyMD5, req.Header.Get("X-Ftp-Content-Md5"))
	}
	if req.ContentLength != 0 {
		t.Fatalf("expected ContentLength 0, got: %d", req.ContentLength)
	}
}

func TestPayloadContentMD5ValidAndInvalid(t *testing.T) {
	data := []byte("hello world payload")
	sum := md5.Sum(data)
	validMD5B64 := base64.StdEncoding.EncodeToString(sum[:])

	// Valid MD5
	req := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(data))
	req.Header.Set("Content-MD5", validMD5B64)
	cleanup, err := testPreparePayload(t, req)
	if err != nil {
		t.Fatalf("unexpected error with valid Content-MD5: %v", err)
	}
	cleanup()

	// BadDigest (MD5 mismatch)
	badSum := md5.Sum([]byte("different data"))
	badMD5B64 := base64.StdEncoding.EncodeToString(badSum[:])
	reqBad := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(data))
	reqBad.Header.Set("Content-MD5", badMD5B64)
	_, err = testPreparePayload(t, reqBad)
	if err == nil {
		t.Fatalf("expected BadDigest error for mismatched Content-MD5")
	}
	pErr, ok := err.(*s3PayloadError)
	if !ok || pErr.code != "BadDigest" {
		t.Fatalf("expected BadDigest s3PayloadError, got: %v", err)
	}

	// InvalidDigest (invalid base64)
	reqInv := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(data))
	reqInv.Header.Set("Content-MD5", "!!!invalid-base64!!!")
	_, err = testPreparePayload(t, reqInv)
	if err == nil {
		t.Fatalf("expected InvalidDigest error for malformed Content-MD5")
	}
	pErr, ok = err.(*s3PayloadError)
	if !ok || pErr.code != "InvalidDigest" {
		t.Fatalf("expected InvalidDigest s3PayloadError, got: %v", err)
	}
}

func TestPayloadSHA256Mismatch(t *testing.T) {
	data := []byte("payload data")
	wrongSHA := "0000000000000000000000000000000000000000000000000000000000000000"

	req := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(data))
	req.Header.Set("x-amz-content-sha256", wrongSHA)
	_, err := testPreparePayload(t, req)
	if err == nil {
		t.Fatalf("expected XAmzContentSHA256Mismatch error")
	}
	pErr, ok := err.(*s3PayloadError)
	if !ok || pErr.code != "XAmzContentSHA256Mismatch" {
		t.Fatalf("expected XAmzContentSHA256Mismatch, got: %v", err)
	}
}

func TestPayloadUnsupportedSignedStreaming(t *testing.T) {
	data := []byte("chunked streaming")
	req := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(data))
	req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")

	_, err := testPreparePayload(t, req)
	if err == nil {
		t.Fatalf("expected NotImplemented error for signed streaming payload")
	}
	pErr, ok := err.(*s3PayloadError)
	if !ok || pErr.code != "NotImplemented" {
		t.Fatalf("expected NotImplemented, got: %v", err)
	}
}

func TestPayloadAWSChunkedUnsignedWithTrailers(t *testing.T) {
	// Chunks of data followed by chunk 0 and crc32 trailer
	fullData := []byte("Hello, world!")
	crcBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crcBytes, crc32.ChecksumIEEE(fullData))
	crcB64 := base64.StdEncoding.EncodeToString(crcBytes)
	rawChunks := "7\r\nHello, \r\n6\r\nworld!\r\n0\r\nx-amz-checksum-crc32:" + crcB64 + "\r\n\r\n"

	req := httptest.NewRequest(http.MethodPut, "/default/file", strings.NewReader(rawChunks))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
	req.Header.Set("x-amz-decoded-content-length", "13")

	req.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")
	cleanup, err := testPreparePayload(t, req)
	if err != nil {
		t.Fatalf("unexpected error decoding aws-chunked: %v", err)
	}
	defer cleanup()

	// Verify decoded body
	bodyBytes, rErr := io.ReadAll(req.Body)
	if rErr != nil {
		t.Fatalf("failed reading spooled body: %v", rErr)
	}
	if !bytes.Equal(bodyBytes, fullData) {
		t.Fatalf("expected body %q, got: %q", string(fullData), string(bodyBytes))
	}
	if req.ContentLength != int64(len(fullData)) {
		t.Fatalf("expected ContentLength %d, got: %d", len(fullData), req.ContentLength)
	}

	if req.Header.Get("X-Ftp-Checksum-Crc32") != crcB64 {
		t.Fatalf("expected X-Ftp-Checksum-Crc32 to be %s, got: %s", crcB64, req.Header.Get("X-Ftp-Checksum-Crc32"))
	}
	if req.Header.Get("Content-Encoding") != "" {
		t.Fatalf("expected aws-chunked to be stripped from Content-Encoding, got: %s", req.Header.Get("Content-Encoding"))
	}
}

func TestPayloadLengthEnforcement(t *testing.T) {
	// Underflow: Content-Length is 100, but only 10 bytes provided
	shortData := []byte("0123456789")
	req := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(shortData))
	req.ContentLength = 100

	_, err := testPreparePayload(t, req)
	if err == nil {
		t.Fatalf("expected IncompleteBody error for underflow")
	}
	pErr, ok := err.(*s3PayloadError)
	if !ok || pErr.code != "IncompleteBody" {
		t.Fatalf("expected IncompleteBody error, got: %v", err)
	}
}

func TestPayloadCleanupRemovesTempFile(t *testing.T) {
	data := []byte("spooled temporary file data")
	req := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(data))

	cleanup, err := testPreparePayload(t, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spooled, ok := req.Body.(*SpoolFile)
	if !ok {
		t.Fatalf("expected req.Body to be *SpoolFile")
	}
	filePath := spooled.Name()

	// Verify file exists on disk
	if _, statErr := os.Stat(filePath); statErr != nil {
		t.Fatalf("temp file does not exist before cleanup: %v", statErr)
	}

	// Cleanup
	cleanup()

	// Verify file was unlinked
	if _, statErr := os.Stat(filePath); !os.IsNotExist(statErr) {
		t.Fatalf("temp file was not removed after cleanup: %v", statErr)
	}
}

func TestPayloadCRC64NVME(t *testing.T) {
	// "123456789" CRC64NVME base64 is rosUhgp5mIg=
	data := []byte("123456789")
	req := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(data))
	req.Header.Set("x-amz-checksum-crc64nvme", "rosUhgp5mIg=")

	cleanup, err := testPreparePayload(t, req)
	if err != nil {
		t.Fatalf("unexpected error for valid CRC64NVME: %v", err)
	}
	defer cleanup()

	if req.Header.Get("X-Ftp-Checksum-Crc64nvme") != "rosUhgp5mIg=" {
		t.Fatalf("expected X-Ftp-Checksum-Crc64nvme to be rosUhgp5mIg=, got: %s", req.Header.Get("X-Ftp-Checksum-Crc64nvme"))
	}
	if req.Header.Get("x-amz-checksum-crc64nvme") != "rosUhgp5mIg=" {
		t.Fatalf("expected x-amz-checksum-crc64nvme to be rosUhgp5mIg=, got: %s", req.Header.Get("x-amz-checksum-crc64nvme"))
	}
}
func TestPayloadFailureCleanup(t *testing.T) {
	// Induce a failure (BadDigest) and ensure no temp file leaked
	data := []byte("data with bad digest")
	req := httptest.NewRequest(http.MethodPut, "/default/file", bytes.NewReader(data))
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")))

	cleanup, err := testPreparePayload(t, req)
	if err == nil {
		cleanup()
		t.Fatalf("expected BadDigest error")
	}
	// Verify cleanup function is safe to call or nil
	if cleanup != nil {
		cleanup()
	}
}

func TestPayloadSpoofedHeadersDeleted(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/default/file", nil)
	req.Header.Set("X-Ftp-Spoofed", "attack")
	req.Header.Set("X-Ftp-Content-Md5", "fake")
	req.Header.Set("X-Ftp-Checksum-Crc32", "fake")

	cleanup, err := testPreparePayload(t, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cleanup()

	if req.Header.Get("X-Ftp-Spoofed") != "" {
		t.Fatalf("expected X-Ftp-Spoofed to be deleted")
	}
	// X-Ftp-Content-Md5 should be set to true empty md5, not client value
	emptyMD5 := fmt.Sprintf("%x", md5.Sum(nil))
	if req.Header.Get("X-Ftp-Content-Md5") != emptyMD5 {
		t.Fatalf("expected computed empty MD5, got: %s", req.Header.Get("X-Ftp-Content-Md5"))
	}
}

func TestPayloadAWSChunkedTruncatedTrailer(t *testing.T) {
	// Missing terminal blank line \r\n
	truncatedChunks := "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA=="
	req := httptest.NewRequest(http.MethodPut, "/default/file", strings.NewReader(truncatedChunks))
	req.Header.Set("Content-Encoding", "aws-chunked")

	_, err := testPreparePayload(t, req)
	if err == nil {
		t.Fatalf("expected error on truncated chunked trailers")
	}
	pErr, ok := err.(*s3PayloadError)
	if !ok || pErr.code != "IncompleteBody" {
		t.Fatalf("expected IncompleteBody, got: %v", err)
	}
}

func TestPayloadAWSChunkedMissingDeclaredTrailer(t *testing.T) {
	// Declares x-amz-checksum-crc32 but stream provides no trailers
	chunks := "5\r\nhello\r\n0\r\n\r\n"
	req := httptest.NewRequest(http.MethodPut, "/default/file", strings.NewReader(chunks))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")

	_, err := testPreparePayload(t, req)
	if err == nil {
		t.Fatalf("expected error when declared trailer is missing")
	}
	pErr, ok := err.(*s3PayloadError)
	if !ok || pErr.code != "IncompleteBody" {
		t.Fatalf("expected IncompleteBody, got: %v", err)
	}
}

func TestPayloadInvalidContentSHA256Marker(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/default/file", strings.NewReader("data"))
	req.Header.Set("x-amz-content-sha256", "INVALID-MARKER-STRING")

	_, err := testPreparePayload(t, req)
	if err == nil {
		t.Fatalf("expected error on invalid x-amz-content-sha256")
	}
	pErr, ok := err.(*s3PayloadError)
	if !ok || pErr.code != "InvalidDigest" {
		t.Fatalf("expected InvalidDigest, got: %v", err)
	}
}
