package main

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestS3Server(t *testing.T, cfg *Config) *S3Server {
	t.Helper()
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.StateDir == "" {
		cfg.StateDir = t.TempDir()
	}
	if cfg.MaxStagingBytes <= 0 {
		cfg.MaxStagingBytes = 10 * 1024 * 1024
	}
	if cfg.MaxConcurrentUploads <= 0 {
		cfg.MaxConcurrentUploads = 8
	}
	if cfg.UploadTimeout <= 0 {
		cfg.UploadTimeout = 5 * time.Second
	}
	srv, err := NewS3Server(cfg)
	if err != nil {
		t.Fatalf("failed to create test S3Server: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
	})
	return srv
}

func TestValidateKey(t *testing.T) {
	validKeys := []string{
		"simple.txt",
		"nested/alpha.txt",
		"nested/deeper/data.bin",
		".hidden",
		"space + percent%/日本語.txt",
		"empty",
		"folder/file-123.jpg",
	}
	for _, key := range validKeys {
		if err := validateKey(key); err != nil {
			t.Errorf("expected valid key %q, got error: %v", key, err)
		}
	}

	invalidKeys := []struct {
		key    string
		reason string
	}{
		{"", "empty key"},
		{"foo/../bar", "path traversal .."},
		{"../root.txt", "path traversal leading .."},
		{"./local.txt", "path dot ."},
		{"foo/./bar", "nested path dot ."},
		{".ftp-over-s3-temp", "reserved prefix"},
		{"nested/.ftp-over-s3-temp", "nested reserved prefix"},
		{"control\x00null", "null byte"},
		{"control\nnewline", "newline byte"},
		{"control\rreturn", "carriage return"},
	}
	for _, tc := range invalidKeys {
		if err := validateKey(tc.key); err == nil {
			t.Errorf("expected invalid key %q (%s) to fail, got nil", tc.key, tc.reason)
		}
	}
}

func TestParseRange(t *testing.T) {
	fileSize := int64(100)

	// Valid ranges
	tests := []struct {
		header         string
		expectedStart  int64
		expectedLength int64
	}{
		{"bytes=0-49", 0, 50},
		{"bytes=2-8", 2, 7},
		{"bytes=50-", 50, 50},
		{"bytes=-7", 93, 7},
		{"bytes=-200", 0, 100}, // suffix larger than file
		{"bytes=99-99", 99, 1},
	}

	for _, tt := range tests {
		start, length, ok := parseRange(tt.header, fileSize)
		if !ok {
			t.Errorf("expected %q to be valid range", tt.header)
			continue
		}
		if start != tt.expectedStart || length != tt.expectedLength {
			t.Errorf("%q: expected start=%d, length=%d; got start=%d, length=%d",
				tt.header, tt.expectedStart, tt.expectedLength, start, length)
		}
	}

	// Invalid ranges
	invalid := []string{
		"bytes=100-",       // start == size
		"bytes=999999-",    // start > size
		"bytes=50-40",      // end < start
		"bytes=-0",         // 0 suffix
		"bytes=0-10,20-30", // multi-range not supported
		"characters=0-10",
		"bytes=",
		"bytes=abc-def",
	}

	for _, header := range invalid {
		if _, _, ok := parseRange(header, fileSize); ok {
			t.Errorf("expected %q to be rejected as invalid range", header)
		}
	}
}

func TestMatchETag(t *testing.T) {
	currentETag := "\"d41d8cd98f00b204e9800998ecf8427e\""

	if !matchETag(currentETag, currentETag) {
		t.Error("exact match failed")
	}
	if !matchETag("*", currentETag) {
		t.Error("wildcard match failed")
	}
	if !matchETag("\"wrong\", "+currentETag, currentETag) {
		t.Error("comma-separated list match failed")
	}
	if matchETag("\"wrong\"", currentETag) {
		t.Error("mismatch unexpectedly matched")
	}
}

func TestWriteS3Error(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/default/not-found", nil)

	writeS3Error(rec, req, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got %s", rec.Header().Get("Content-Type"))
	}

	var errResp S3ErrorResponse
	if err := xml.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse XML error response: %v", err)
	}
	if errResp.Code != "NoSuchKey" {
		t.Errorf("expected Code NoSuchKey, got %s", errResp.Code)
	}
	if errResp.Resource != "/default/not-found" {
		t.Errorf("expected Resource /default/not-found, got %s", errResp.Resource)
	}

	// HEAD request error should NOT write body
	headRec := httptest.NewRecorder()
	headReq := httptest.NewRequest(http.MethodHead, "/default/not-found", nil)
	writeS3Error(headRec, headReq, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")

	if headRec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404 for HEAD, got %d", headRec.Code)
	}
	if headRec.Body.Len() != 0 {
		t.Errorf("expected empty body for HEAD error, got %d bytes", headRec.Body.Len())
	}
}

func TestRoutingAndUnsupportedFeatures(t *testing.T) {
	server := newTestS3Server(t, &Config{
		FTPHost: "127.0.0.1",
		FTPPort: 2121,
	})

	// 1. Health check
	{
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
			t.Errorf("GET /health failed: code %d, body %s", rec.Code, rec.Body.String())
		}

		reqZ := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		recZ := httptest.NewRecorder()
		server.ServeHTTP(recZ, reqZ)
		if recZ.Code != http.StatusOK || recZ.Body.String() != "ok" {
			t.Errorf("GET /healthz failed: code %d, body %s", recZ.Code, recZ.Body.String())
		}
	}

	// 2. Head Bucket & Invalid Bucket
	{
		req := httptest.NewRequest(http.MethodHead, "/default", nil)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("HEAD /default expected 200, got %d", rec.Code)
		}

		reqOther := httptest.NewRequest(http.MethodHead, "/other", nil)
		recOther := httptest.NewRecorder()
		server.ServeHTTP(recOther, reqOther)
		if recOther.Code != http.StatusNotFound {
			t.Errorf("HEAD /other expected 404, got %d", recOther.Code)
		}
	}

	// 3. Bucket Location
	{
		req := httptest.NewRequest(http.MethodGet, "/default?location", nil)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /default?location expected 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "<LocationConstraint") {
			t.Errorf("expected LocationConstraint XML, got %s", rec.Body.String())
		}
	}

	// 4. Unsupported Bucket Operations (PUT/DELETE bucket)
	{
		reqPut := httptest.NewRequest(http.MethodPut, "/default", nil)
		recPut := httptest.NewRecorder()
		server.ServeHTTP(recPut, reqPut)
		if recPut.Code != http.StatusNotImplemented {
			t.Errorf("PUT /default expected 501, got %d", recPut.Code)
		}

		reqDel := httptest.NewRequest(http.MethodDelete, "/default", nil)
		recDel := httptest.NewRecorder()
		server.ServeHTTP(recDel, reqDel)
		if recDel.Code != http.StatusNotImplemented {
			t.Errorf("DELETE /default expected 501, got %d", recDel.Code)
		}
	}

	// 5. Unsupported Subresources
	{
		for _, param := range []string{"lifecycle", "cors", "acl", "tagging", "versioning"} {
			req := httptest.NewRequest(http.MethodGet, "/default?"+param, nil)
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented {
				t.Errorf("GET /default?%s expected 501, got %d", param, rec.Code)
			}
		}
	}

	// 6. Unsupported Headers (Server-side encryption, storage class, canned ACLs, tagging)
	{
		// SSE
		reqSSE := httptest.NewRequest(http.MethodPut, "/default/file.txt", strings.NewReader("data"))
		reqSSE.Header.Set("X-Amz-Server-Side-Encryption", "AES256")
		recSSE := httptest.NewRecorder()
		server.ServeHTTP(recSSE, reqSSE)
		if recSSE.Code != http.StatusNotImplemented {
			t.Errorf("PUT with SSE expected 501, got %d", recSSE.Code)
		}

		// Storage class
		reqSC := httptest.NewRequest(http.MethodPut, "/default/file.txt", strings.NewReader("data"))
		reqSC.Header.Set("X-Amz-Storage-Class", "GLACIER")
		recSC := httptest.NewRecorder()
		server.ServeHTTP(recSC, reqSC)
		if recSC.Code != http.StatusNotImplemented {
			t.Errorf("PUT with GLACIER expected 501, got %d", recSC.Code)
		}

		// Canned ACL
		reqACL := httptest.NewRequest(http.MethodPut, "/default/file.txt", strings.NewReader("data"))
		reqACL.Header.Set("X-Amz-Acl", "public-read")
		recACL := httptest.NewRecorder()
		server.ServeHTTP(recACL, reqACL)
		if recACL.Code != http.StatusNotImplemented {
			t.Errorf("PUT with X-Amz-Acl expected 501, got %d", recACL.Code)
		}

		// Tagging
		reqTag := httptest.NewRequest(http.MethodPut, "/default/file.txt", strings.NewReader("data"))
		reqTag.Header.Set("X-Amz-Tagging", "tag1=val1")
		recTag := httptest.NewRecorder()
		server.ServeHTTP(recTag, reqTag)
		if recTag.Code != http.StatusNotImplemented {
			t.Errorf("PUT with X-Amz-Tagging expected 501, got %d", recTag.Code)
		}
	}

	// 7. Invalid Key Shapes
	{
		for _, key := range []string{"foo/../bar", "./foo", ".ftp-over-s3-temp", "bad\x01byte"} {
			req := httptest.NewRequest(http.MethodGet, "/default/placeholder", nil)
			req.URL.Path = "/default/" + key
			req.URL.RawPath = ""
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("GET /default/%q expected 400, got %d", key, rec.Code)
			}
		}
	}

	// 8. ListMultipartUploads on empty bucket
	{
		req := httptest.NewRequest(http.MethodGet, "/default?uploads", nil)
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /default?uploads expected 200, got %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "<ListMultipartUploadsResult") {
			t.Errorf("expected ListMultipartUploadsResult XML, got %s", rec.Body.String())
		}
	}
}

func TestContinuationTokenBinding(t *testing.T) {
	server := newTestS3Server(t, &Config{})

	// 1. Invalid base64 continuation token
	reqBadB64 := httptest.NewRequest(http.MethodGet, "/default?list-type=2&continuation-token=!!!not-base64!!!", nil)
	recBadB64 := httptest.NewRecorder()
	server.ServeHTTP(recBadB64, reqBadB64)
	if recBadB64.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad base64 token, got %d", recBadB64.Code)
	}

	// 2. Token created for prefix="nested/" and delimiter="/"
	tokenPayload := fmt.Sprintf("%s\x00%s\x00%s", "nested/", "/", "nested/file.txt")
	validToken := base64.StdEncoding.EncodeToString([]byte(tokenPayload))

	// Re-query with different prefix -> must be rejected!
	reqCross := httptest.NewRequest(http.MethodGet, "/default?list-type=2&prefix=other/&delimiter=/&continuation-token="+validToken, nil)
	recCross := httptest.NewRecorder()
	server.ServeHTTP(recCross, reqCross)
	if recCross.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for cross-prefix continuation token, got %d", recCross.Code)
	}
}

func TestMetadataPersistenceAndHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/default/doc.txt", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "max-age=3600")
	req.Header.Set("Content-Disposition", "inline; filename=\"doc.txt\"")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Language", "en-US")
	req.Header.Set("Expires", "Wed, 21 Oct 2026 07:28:00 GMT")
	req.Header.Set("X-Amz-Meta-Author", "alice")
	req.Header.Set("X-Amz-Meta-Project", "ftp-over-s3")

	meta, err := extractMetadata(req)
	if err != nil {
		t.Fatalf("extractMetadata failed: %v", err)
	}

	if meta.ContentType != "application/json" {
		t.Errorf("expected ContentType application/json, got %s", meta.ContentType)
	}
	if meta.CacheControl != "max-age=3600" {
		t.Errorf("expected CacheControl max-age=3600, got %s", meta.CacheControl)
	}
	if meta.ContentDisposition != "inline; filename=\"doc.txt\"" {
		t.Errorf("expected ContentDisposition, got %s", meta.ContentDisposition)
	}
	if meta.ContentEncoding != "gzip" {
		t.Errorf("expected ContentEncoding gzip, got %s", meta.ContentEncoding)
	}
	if meta.ContentLanguage != "en-US" {
		t.Errorf("expected ContentLanguage en-US, got %s", meta.ContentLanguage)
	}
	if meta.Expires != "Wed, 21 Oct 2026 07:28:00 GMT" {
		t.Errorf("expected Expires, got %s", meta.Expires)
	}
	if meta.UserMetadata["author"] != "alice" {
		t.Errorf("expected user metadata author=alice, got %v", meta.UserMetadata)
	}
	if meta.UserMetadata["project"] != "ftp-over-s3" {
		t.Errorf("expected user metadata project=ftp-over-s3, got %v", meta.UserMetadata)
	}

	rec := httptest.NewRecorder()
	applyMetadataHeaders(rec, meta)
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected header Content-Type application/json, got %s", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "max-age=3600" {
		t.Errorf("expected header Cache-Control max-age=3600, got %s", rec.Header().Get("Cache-Control"))
	}
	if len(rec.Header()["x-amz-meta-author"]) == 0 || rec.Header()["x-amz-meta-author"][0] != "alice" {
		t.Errorf("expected lowercase wire header x-amz-meta-author alice, got %v", rec.Header())
	}

	reqLarge := httptest.NewRequest(http.MethodPut, "/default/large.txt", strings.NewReader("hello"))
	reqLarge.Header.Set("X-Amz-Meta-Huge", strings.Repeat("A", 70000))
	_, errLarge := extractMetadata(reqLarge)
	if errLarge == nil {
		t.Fatal("expected oversized metadata to be rejected, got nil")
	}
	var opErr *s3OperationError
	if !errors.As(errLarge, &opErr) || opErr.Status != http.StatusBadRequest {
		t.Errorf("expected 400 s3OperationError, got %v", errLarge)
	}
}

func TestCheckWritePreconditions(t *testing.T) {
	srv := newTestS3Server(t, nil)
	key := "test.txt"
	now := time.Now().Truncate(time.Second)
	info := &FileInfo{
		Name:    "test.txt",
		Size:    100,
		ModTime: now,
	}

	savedMeta := ObjectMetadata{
		ETag:        "\"match-etag\"",
		Size:        100,
		ModTime:     now,
		ContentType: "text/plain",
	}
	if err := srv.metadata.Save(key, savedMeta); err != nil {
		t.Fatalf("failed to save metadata: %v", err)
	}

	// 1. If-None-Match: * on existing object -> fail
	reqINM := httptest.NewRequest(http.MethodPut, "/default/"+key, nil)
	reqINM.Header.Set("If-None-Match", "*")
	if err := srv.checkWritePreconditions(reqINM, key, info); err == nil {
		t.Error("expected If-None-Match: * on existing object to fail")
	}

	// 2. If-None-Match: * on non-existing object -> succeed
	if err := srv.checkWritePreconditions(reqINM, "nonexistent.txt", nil); err != nil {
		t.Errorf("expected If-None-Match: * on nonexistent object to succeed, got %v", err)
	}

	// 3. If-Match: match -> succeed
	reqIM := httptest.NewRequest(http.MethodPut, "/default/"+key, nil)
	reqIM.Header.Set("If-Match", "\"match-etag\"")
	if err := srv.checkWritePreconditions(reqIM, key, info); err != nil {
		t.Errorf("expected If-Match to match, got %v", err)
	}

	// 4. If-Match: mismatch -> fail
	reqIMM := httptest.NewRequest(http.MethodPut, "/default/"+key, nil)
	reqIMM.Header.Set("If-Match", "\"wrong-etag\"")
	if err := srv.checkWritePreconditions(reqIMM, key, info); err == nil {
		t.Error("expected If-Match mismatch to fail")
	}

	// 5. If-Match on non-existing object -> fail
	if err := srv.checkWritePreconditions(reqIM, "nonexistent.txt", nil); err == nil {
		t.Error("expected If-Match on nonexistent object to fail")
	}

	// 6. If-Unmodified-Since in the past -> fail
	reqIUS := httptest.NewRequest(http.MethodPut, "/default/"+key, nil)
	reqIUS.Header.Set("If-Unmodified-Since", now.Add(-10*time.Second).UTC().Format(http.TimeFormat))
	if err := srv.checkWritePreconditions(reqIUS, key, info); err == nil {
		t.Error("expected If-Unmodified-Since in past to fail")
	}
}

func TestConcurrentCompetingConditionalWrites(t *testing.T) {
	srv := newTestS3Server(t, nil)
	key := "competing.txt"

	var (
		mu      sync.Mutex
		created bool
	)

	var wg sync.WaitGroup
	results := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPut, "/default/"+key, strings.NewReader("content"))
			req.Header.Set("If-None-Match", "*")

			srv.mutationMu.Lock()
			defer srv.mutationMu.Unlock()

			mu.Lock()
			var info *FileInfo
			if created {
				info = &FileInfo{
					Name:    key,
					Size:    7,
					ModTime: time.Now(),
				}
			}
			mu.Unlock()

			if err := srv.checkWritePreconditions(req, key, info); err != nil {
				results[idx] = err
				return
			}

			mu.Lock()
			created = true
			_ = srv.metadata.Save(key, ObjectMetadata{
				ETag:        "\"created-etag\"",
				Size:        7,
				ModTime:     time.Now(),
				ContentType: "text/plain",
			})
			mu.Unlock()
			results[idx] = nil
		}(i)
	}

	wg.Wait()

	var successes, failures int
	for _, res := range results {
		if res == nil {
			successes++
		} else {
			var opErr *s3OperationError
			if errors.As(res, &opErr) && opErr.Status == http.StatusPreconditionFailed {
				failures++
			} else {
				t.Errorf("unexpected error: %v", res)
			}
		}
	}

	if successes != 1 || failures != 1 {
		t.Fatalf("expected exactly 1 winner and 1 412 failure, got %d successes and %d failures", successes, failures)
	}
}

func TestPreconditionFailureDoesNotChangeMetadata(t *testing.T) {
	srv := newTestS3Server(t, nil)
	key := "locked.txt"
	now := time.Now().Truncate(time.Second)

	originalMeta := ObjectMetadata{
		ETag:         "\"initial-etag\"",
		Size:         42,
		ModTime:      now,
		ContentType:  "text/plain",
		CacheControl: "max-age=600",
		UserMetadata: map[string]string{"version": "1"},
	}
	if err := srv.metadata.Save(key, originalMeta); err != nil {
		t.Fatalf("failed to save initial metadata: %v", err)
	}

	info := &FileInfo{
		Name:    key,
		Size:    42,
		ModTime: now,
	}

	reqFail := httptest.NewRequest(http.MethodPut, "/default/"+key, strings.NewReader("new data"))
	reqFail.Header.Set("If-Match", "\"wrong-etag\"")
	reqFail.Header.Set("Content-Type", "application/json")
	reqFail.Header.Set("X-Amz-Meta-Version", "2")

	err := srv.checkWritePreconditions(reqFail, key, info)
	if err == nil {
		t.Fatal("expected precondition failure for wrong If-Match, got nil")
	}

	var opErr *s3OperationError
	if !errors.As(err, &opErr) || opErr.Status != http.StatusPreconditionFailed {
		t.Fatalf("expected PreconditionFailed (412), got %v", err)
	}

	loadedMeta, ok, loadErr := srv.metadata.Load(key, info)
	if loadErr != nil || !ok {
		t.Fatalf("failed to load metadata: %v, ok=%v", loadErr, ok)
	}
	if loadedMeta.ETag != originalMeta.ETag {
		t.Errorf("metadata ETag changed: expected %s, got %s", originalMeta.ETag, loadedMeta.ETag)
	}
	if loadedMeta.ContentType != "text/plain" {
		t.Errorf("metadata ContentType changed: expected text/plain, got %s", loadedMeta.ContentType)
	}
	if loadedMeta.UserMetadata["version"] != "1" {
		t.Errorf("metadata UserMetadata changed: expected version 1, got %v", loadedMeta.UserMetadata)
	}
}

func TestCopyAndDeleteRouting(t *testing.T) {
	srv := newTestS3Server(t, nil)

	// 1. PUT with X-Amz-Copy-Source routes to handleCopyObject
	reqCopy := httptest.NewRequest(http.MethodPut, "/default/dst.txt", nil)
	reqCopy.Header.Set("X-Amz-Copy-Source", "/default/src.txt")
	recCopy := httptest.NewRecorder()
	srv.ServeHTTP(recCopy, reqCopy)
	if recCopy.Code == http.StatusNotImplemented {
		t.Errorf("PUT with X-Amz-Copy-Source returned 501 NotImplemented; should be routed to handleCopyObject")
	}

	// 2. PUT with X-Amz-Copy-Source and partNumber/uploadId routes to handleUploadPartCopy
	reqPartCopy := httptest.NewRequest(http.MethodPut, "/default/dst.txt?uploadId=upload123&partNumber=1", nil)
	reqPartCopy.Header.Set("X-Amz-Copy-Source", "/default/src.txt")
	recPartCopy := httptest.NewRecorder()
	srv.ServeHTTP(recPartCopy, reqPartCopy)
	if recPartCopy.Code == http.StatusNotImplemented {
		t.Errorf("PUT part copy returned 501 NotImplemented; should be routed to handleUploadPartCopy")
	}

	// 3. POST /default?delete routes to handleDeleteObjects
	reqDeleteObjects := httptest.NewRequest(http.MethodPost, "/default?delete", strings.NewReader("<Delete></Delete>"))
	recDeleteObjects := httptest.NewRecorder()
	srv.ServeHTTP(recDeleteObjects, reqDeleteObjects)
	if recDeleteObjects.Code == http.StatusNotImplemented || recDeleteObjects.Code == http.StatusMethodNotAllowed {
		t.Errorf("POST /default?delete returned %d; should be routed to handleDeleteObjects", recDeleteObjects.Code)
	}
}

func TestPendingMarkerRetentionOnUncertainPublish(t *testing.T) {
	srv := newTestS3Server(t, nil)
	key := "publish_test.bin"
	now := time.Now().Truncate(time.Second)

	originalMeta := ObjectMetadata{
		ETag:         "\"initial-etag\"",
		Size:         100,
		ModTime:      now,
		ContentType:  "text/plain",
		UserMetadata: map[string]string{"preserved": "yes"},
	}
	if err := srv.metadata.Save(key, originalMeta); err != nil {
		t.Fatalf("failed to save initial metadata: %v", err)
	}

	info := &FileInfo{
		Name:    key,
		Size:    100,
		ModTime: now,
	}

	// 1. Proven pre-publish error (e.g. standard Stor/network error before rename):
	if err := srv.metadata.Begin(key); err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}
	if !srv.metadata.HasPending(key) {
		t.Fatal("expected pending marker to be present after Begin")
	}
	prePublishErr := errors.New("connection reset during STOR")
	if !errors.Is(prePublishErr, ErrAmbiguousPublish) {
		_ = srv.metadata.Abort(key)
	}
	if srv.metadata.HasPending(key) {
		t.Fatal("expected pending marker to be aborted on proven pre-publish error")
	}
	loaded, ok, err := srv.metadata.Load(key, info)
	if err != nil || !ok || loaded.ETag != "\"initial-etag\"" || loaded.UserMetadata["preserved"] != "yes" {
		t.Fatalf("expected previous metadata to remain intact on pre-publish abort, got ok=%v, meta=%v", ok, loaded)
	}

	// 2. Ambiguous publish error (ErrAmbiguousPublish, e.g. transport drop during rename):
	if err := srv.metadata.Begin(key); err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}
	ambiguousErr := fmt.Errorf("%w: timeout waiting for RNTO reply", ErrAmbiguousPublish)
	if !errors.Is(ambiguousErr, ErrAmbiguousPublish) {
		_ = srv.metadata.Abort(key)
	}
	// Marker MUST be retained
	if !srv.metadata.HasPending(key) {
		t.Fatal("expected pending marker to be retained on ambiguous publish outcome")
	}
	// Load MUST fail closed (return ok=false) due to uncommitted pending write
	_, ok, _ = srv.metadata.Load(key, info)
	if ok {
		t.Fatal("expected Load to fail closed and return ok=false while pending marker is retained")
	}
}

func TestStrongWeakETagAndDatePrecedence(t *testing.T) {
	curETag := "\"abc123\""

	// 1. Strong ETag comparison for If-Match
	if matchETagStrong("W/\"abc123\"", curETag) {
		t.Error("matchETagStrong must reject weak validator W/\"abc123\"")
	}
	if !matchETagStrong("\"abc123\"", curETag) {
		t.Error("matchETagStrong must accept exact strong match")
	}
	if !matchETagStrong("*", curETag) {
		t.Error("matchETagStrong must accept wildcard *")
	}

	// 2. Weak ETag comparison for If-None-Match
	if !matchETagWeak("W/\"abc123\"", curETag) {
		t.Error("matchETagWeak must accept weak validator W/\"abc123\"")
	}
	if !matchETagWeak("\"abc123\"", curETag) {
		t.Error("matchETagWeak must accept exact match")
	}

	// 3. Precedence: matching If-Match suppresses older If-Unmodified-Since
	srv := newTestS3Server(t, nil)
	key := "precedence.txt"
	now := time.Now().Truncate(time.Second)
	info := &FileInfo{
		Name:    key,
		Size:    10,
		ModTime: now,
	}
	if err := srv.metadata.Save(key, ObjectMetadata{
		ETag:    curETag,
		Size:    10,
		ModTime: now,
	}); err != nil {
		t.Fatalf("failed to save metadata: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/default/"+key, nil)
	req.Header.Set("If-Match", curETag)
	req.Header.Set("If-Unmodified-Since", now.Add(-10*time.Minute).UTC().Format(http.TimeFormat))

	if err := srv.checkWritePreconditions(req, key, info); err != nil {
		t.Errorf("matching If-Match must take precedence over older If-Unmodified-Since, got error: %v", err)
	}
}
