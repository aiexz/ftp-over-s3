package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// fixtureCanonicalURI mirrors the SigV4 rule of using the raw, already-encoded
// request path exactly as it arrived on the wire.
func fixtureCanonicalURI(r *http.Request) string {
	p := r.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// fixtureCanonicalQuery sorts the wire-encoded query pairs, dropping the
// signature parameter when the request is presigned.
func fixtureCanonicalQuery(r *http.Request, omitSignature bool) string {
	var pairs []string
	for _, kv := range strings.Split(r.URL.RawQuery, "&") {
		if kv == "" || (omitSignature && strings.HasPrefix(kv, "X-Amz-Signature=")) {
			continue
		}
		pairs = append(pairs, kv)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func fixtureHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.Header.Get("Host")
}

// fixtureSign derives the SigV4 signature from first principles so the tests do
// not depend on the implementation under test to build their own expectation.
func fixtureSign(r *http.Request, accessKey, secretKey, region string, t time.Time, signedList []string, payloadHash string) string {
	dateStr := t.UTC().Format("20060102T150405Z")
	dateOnly := dateStr[:8]

	sorted := append([]string(nil), signedList...)
	sort.Strings(sorted)
	signedHeaders := strings.Join(sorted, ";")

	var canonicalHeaders strings.Builder
	for _, h := range sorted {
		var val string
		if h == "host" {
			val = fixtureHost(r)
		} else {
			val = strings.Join(r.Header.Values(h), ",")
		}
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.Join(strings.Fields(val), " "))
		canonicalHeaders.WriteByte('\n')
	}

	canonicalRequest := r.Method + "\n" +
		fixtureCanonicalURI(r) + "\n" +
		fixtureCanonicalQuery(r, false) + "\n" +
		canonicalHeaders.String() + "\n" +
		signedHeaders + "\n" +
		payloadHash

	canonicalRequestHash := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalRequest)))
	scope := fmt.Sprintf("%s/%s/s3/aws4_request", dateOnly, region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", dateStr, scope, canonicalRequestHash)

	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateOnly))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	sig := fmt.Sprintf("%x", hmacSHA256(kSigning, []byte(stringToSign)))

	r.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, scope, signedHeaders, sig))
	return sig
}

// signRequest signs a request including an x-amz-content-sha256 header.
func signRequest(r *http.Request, accessKey, secretKey, region string, t time.Time, payloadSHA string) {
	if payloadSHA == "" {
		payloadSHA = emptyPayloadSHA256
	}
	r.Header.Set("x-amz-date", t.UTC().Format("20060102T150405Z"))
	r.Header.Set("x-amz-content-sha256", payloadSHA)
	fixtureSign(r, accessKey, secretKey, region, t,
		[]string{"host", "x-amz-content-sha256", "x-amz-date"}, payloadSHA)
}

// signRequestWithoutChecksum signs only host and the date, leaving
// x-amz-content-sha256 entirely absent as some clients do.
func signRequestWithoutChecksum(r *http.Request, accessKey, secretKey, region string, t time.Time) {
	r.Header.Del("x-amz-content-sha256")
	r.Header.Set("x-amz-date", t.UTC().Format("20060102T150405Z"))
	fixtureSign(r, accessKey, secretKey, region, t, []string{"host", "x-amz-date"}, emptyPayloadSHA256)
}

// Helper to presign a test request URL
func presignRequestURL(rawURL, method, accessKey, secretKey, region string, t time.Time, expiresSec int) string {
	parsed, _ := url.Parse(rawURL)
	dateStr := t.UTC().Format("20060102T150405Z")
	dateOnly := dateStr[:8]
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", dateOnly, region, "s3")

	q := parsed.Query()
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+scope)
	q.Set("X-Amz-Date", dateStr)
	q.Set("X-Amz-Expires", strconv.Itoa(expiresSec))
	q.Set("X-Amz-SignedHeaders", "host")
	parsed.RawQuery = q.Encode()

	// Canonical Query String must use the wire-encoded key/value pairs
	// exactly as sent, excluding X-Amz-Signature.
	var wirePairs []string
	for _, kv := range strings.Split(parsed.RawQuery, "&") {
		if kv == "" || strings.HasPrefix(kv, "X-Amz-Signature=") {
			continue
		}
		wirePairs = append(wirePairs, kv)
	}
	sort.Strings(wirePairs)
	canonicalQuery := strings.Join(wirePairs, "&")

	canonicalURI := parsed.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalHeaders := "host:" + parsed.Host + "\n"
	signedHeaders := "host"
	payloadHash := "UNSIGNED-PAYLOAD"

	canonicalRequest := method + "\n" +
		canonicalURI + "\n" +
		canonicalQuery + "\n" +
		canonicalHeaders + "\n" +
		signedHeaders + "\n" +
		payloadHash

	canonicalRequestHash := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalRequest)))
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", dateStr, scope, canonicalRequestHash)

	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateOnly))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	sig := fmt.Sprintf("%x", hmacSHA256(kSigning, []byte(stringToSign)))

	// Append the signature without re-encoding, so the wire query string
	// used for verification stays byte-identical to the signed form.
	parsed.RawQuery = parsed.RawQuery + "&X-Amz-Signature=" + sig
	return parsed.String()
}

func setupTestAuth(t *testing.T) (*CredentialsStore, *AuthMiddleware, *bool) {
	store := NewCredentialsStore()
	store.AddCredentials("test-access", "test-secret")
	reached := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	dir := t.TempDir()
	budget := NewDiskBudget(20 * 1024 * 1024 * 1024)
	adm := NewUploadAdmission(&State{Root: dir, Budget: budget}, 16, 15*time.Minute)
	mw := NewAuthMiddleware(store, handler, adm)
	return store, mw, &reached
}

func TestHealthCheckBypass(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	// GET /health without auth should succeed
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !*reached || rec.Code != http.StatusOK {
		t.Fatalf("expected GET /health to bypass auth, code: %d", rec.Code)
	}

	// HEAD /health without auth should succeed
	*reached = false
	req = httptest.NewRequest(http.MethodHead, "/health", nil)
	rec = httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !*reached || rec.Code != http.StatusOK {
		t.Fatalf("expected HEAD /health to bypass auth, code: %d", rec.Code)
	}

	// POST /health without auth MUST NOT bypass
	*reached = false
	req = httptest.NewRequest(http.MethodPost, "/health", nil)
	rec = httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusForbidden {
		t.Fatalf("expected POST /health to require auth, code: %d", rec.Code)
	}
}

func TestAuthDisabledWhenNoCredentials(t *testing.T) {
	store := NewCredentialsStore()
	reached := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	dir := t.TempDir()
	budget := NewDiskBudget(20 * 1024 * 1024 * 1024)
	adm := NewUploadAdmission(&State{Root: dir, Budget: budget}, 16, 15*time.Minute)
	mw := NewAuthMiddleware(store, handler, adm)
	req := httptest.NewRequest(http.MethodGet, "/default/file.txt", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("expected request to pass when auth disabled, code: %d", rec.Code)
	}
}

func TestHeaderAuthLegitimate(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	now := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, "/default/file.txt", nil)
	req.Host = "127.0.0.1:18080"
	signRequest(req, "test-access", "test-secret", "us-east-1", now, "")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !*reached || rec.Code != http.StatusOK {
		t.Fatalf("expected legitimate signed request to pass, code: %d, body: %s", rec.Code, rec.Body.String())
	}
}

func TestHeaderAuthEncodedKeyAndQuery(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	now := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, "/default/space%20%2B%20percent%25/%E6%97%A5%E6%9C%AC%E8%AA%9E.txt?list-type=2&prefix=nested%2Fa", nil)
	req.Host = "127.0.0.1:18080"
	signRequest(req, "test-access", "test-secret", "us-east-1", now, "")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !*reached || rec.Code != http.StatusOK {
		t.Fatalf("expected encoded key/query signed request to pass, code: %d, body: %s", rec.Code, rec.Body.String())
	}
}

func TestHeaderAuthInvalidSignature(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	now := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, "/default/file.txt", nil)
	req.Host = "127.0.0.1:18080"
	// Sign with wrong secret
	signRequest(req, "test-access", "wrong-secret", "us-east-1", now, "")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusForbidden {
		t.Fatalf("expected wrong signature to be rejected with 403, code: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SignatureDoesNotMatch") {
		t.Fatalf("expected SignatureDoesNotMatch error code, body: %s", rec.Body.String())
	}
}

func TestHeaderAuthClockSkew(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	// 20 minutes in past (skew > 15m)
	past := time.Now().UTC().Add(-20 * time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/default/file.txt", nil)
	req.Host = "127.0.0.1:18080"
	signRequest(req, "test-access", "test-secret", "us-east-1", past, "")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusForbidden {
		t.Fatalf("expected skewed request to be rejected with 403, code: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "RequestTimeTooSkewed") {
		t.Fatalf("expected RequestTimeTooSkewed error code, body: %s", rec.Body.String())
	}

	// 20 minutes in future (skew > 15m)
	*reached = false
	future := time.Now().UTC().Add(20 * time.Minute)
	req = httptest.NewRequest(http.MethodGet, "/default/file.txt", nil)
	req.Host = "127.0.0.1:18080"
	signRequest(req, "test-access", "test-secret", "us-east-1", future, "")

	rec = httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusForbidden {
		t.Fatalf("expected future skewed request to be rejected with 403, code: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "RequestTimeTooSkewed") {
		t.Fatalf("expected RequestTimeTooSkewed error code, body: %s", rec.Body.String())
	}
}

func TestHeaderAuthMalformed(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	cases := []struct {
		name string
		auth string
	}{
		{"not_aws4", "Basic dXNlcjpwYXNz"},
		{"missing_fields", "AWS4-HMAC-SHA256 Credential=test"},
		{"malformed_scope", "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1, SignedHeaders=host, Signature=abcdef"},
		{"non_s3_service", "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/ec2/aws4_request, SignedHeaders=host, Signature=abcdef"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*reached = false
			req := httptest.NewRequest(http.MethodGet, "/default/file.txt", nil)
			req.Host = "127.0.0.1:18080"
			req.Header.Set("Authorization", tc.auth)
			req.Header.Set("x-amz-date", time.Now().UTC().Format("20060102T150405Z"))

			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			if *reached || rec.Code != http.StatusBadRequest {
				t.Fatalf("expected %s to return 400, got: %d", tc.name, rec.Code)
			}
		})
	}
}

func TestPresignedQueryLegitimate(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	now := time.Now().UTC()
	u := presignRequestURL("http://127.0.0.1:18080/default/space%20%2B%20percent%25/%E6%97%A5%E6%9C%AC%E8%AA%9E.txt",
		http.MethodGet, "test-access", "test-secret", "us-east-1", now, 60)

	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.Host = "127.0.0.1:18080"

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if !*reached || rec.Code != http.StatusOK {
		t.Fatalf("expected legitimate presigned URL to pass, code: %d, body: %s", rec.Code, rec.Body.String())
	}
}

func TestPresignedQueryTampered(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	now := time.Now().UTC()
	u := presignRequestURL("http://127.0.0.1:18080/default/file.txt",
		http.MethodGet, "test-access", "test-secret", "us-east-1", now, 60)

	// Tamper by adding extra parameter
	tamperedURL := u + "&tampered=1"
	req := httptest.NewRequest(http.MethodGet, tamperedURL, nil)
	req.Host = "127.0.0.1:18080"

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusForbidden {
		t.Fatalf("expected tampered presigned URL to be rejected with 403, code: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SignatureDoesNotMatch") {
		t.Fatalf("expected SignatureDoesNotMatch error, body: %s", rec.Body.String())
	}
}

func TestPresignedQueryExpired(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	past := time.Now().UTC().Add(-120 * time.Second) // 2 minutes ago, expires in 60s
	u := presignRequestURL("http://127.0.0.1:18080/default/file.txt",
		http.MethodGet, "test-access", "test-secret", "us-east-1", past, 60)

	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.Host = "127.0.0.1:18080"

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusForbidden {
		t.Fatalf("expected expired presigned URL to return 403, code: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "RequestExpired") {
		t.Fatalf("expected RequestExpired error code, body: %s", rec.Body.String())
	}
}

func TestBothHeaderAndQueryAuthRejected(t *testing.T) {
	_, mw, reached := setupTestAuth(t)

	now := time.Now().UTC()
	u := presignRequestURL("http://127.0.0.1:18080/default/file.txt",
		http.MethodGet, "test-access", "test-secret", "us-east-1", now, 60)

	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.Host = "127.0.0.1:18080"
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=...")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusBadRequest {
		t.Fatalf("expected both auth mechanisms to return 400 InvalidArgument, code: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "InvalidArgument") {
		t.Fatalf("expected InvalidArgument error code, body: %s", rec.Body.String())
	}
}
func TestHeaderAuthPUTMissingContentSHA256(t *testing.T) {
	_, mw, reached := setupTestAuth(t)
	now := time.Now().UTC()
	body := strings.NewReader("some non-empty payload")
	req := httptest.NewRequest(http.MethodPut, "/default/file.txt", body)
	req.Host = "127.0.0.1:18080"
	req.ContentLength = int64(body.Len())
	signRequestWithoutChecksum(req, "test-access", "test-secret", "us-east-1", now)

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code < 400 {
		t.Fatalf("expected missing content-sha256 on PUT to be rejected, got: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "InvalidRequest") &&
		!strings.Contains(rec.Body.String(), "XAmzContentSHA256Mismatch") {
		t.Fatalf("expected payload integrity rejection, got: %s", rec.Body.String())
	}
}

func TestHeaderAuthPUTSignedHeaderRemoved(t *testing.T) {
	_, mw, reached := setupTestAuth(t)
	now := time.Now().UTC()
	body := strings.NewReader("some non-empty payload")
	req := httptest.NewRequest(http.MethodPut, "/default/file.txt", body)
	req.Host = "127.0.0.1:18080"
	req.ContentLength = int64(body.Len())
	signRequest(req, "test-access", "test-secret", "us-east-1", now, "")
	req.Header.Del("x-amz-content-sha256")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code < 400 {
		t.Fatalf("expected removed signed header to be rejected, got: %d", rec.Code)
	}
}

func TestHeaderAuthPUTAlteredBodyNoHash(t *testing.T) {
	_, mw, reached := setupTestAuth(t)
	now := time.Now().UTC()
	// Sign as empty body
	req := httptest.NewRequest(http.MethodPut, "/default/file.txt", nil)
	req.Host = "127.0.0.1:18080"
	req.ContentLength = 0
	signRequest(req, "test-access", "test-secret", "us-east-1", now, emptyPayloadSHA256)

	// Tamper request: alter body to non-empty
	req.Body = io.NopCloser(strings.NewReader("injected tampered data"))
	req.ContentLength = 22

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusBadRequest {
		t.Fatalf("expected altered body to be rejected with 400, got: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "XAmzContentSHA256Mismatch") {
		t.Fatalf("expected XAmzContentSHA256Mismatch error, got: %s", rec.Body.String())
	}
}

func TestHeaderAuthDuplicateFields(t *testing.T) {
	_, mw, reached := setupTestAuth(t)
	req := httptest.NewRequest(http.MethodGet, "/default/file.txt", nil)
	req.Host = "127.0.0.1:18080"
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/s3/aws4_request, Credential=dup, SignedHeaders=host, Signature=sig")
	req.Header.Set("x-amz-date", time.Now().UTC().Format("20060102T150405Z"))

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusBadRequest {
		t.Fatalf("expected duplicate Credential to return 400, got: %d", rec.Code)
	}
}

func TestHeaderAuthDuplicateSignedHeaders(t *testing.T) {
	_, mw, reached := setupTestAuth(t)
	req := httptest.NewRequest(http.MethodGet, "/default/file.txt", nil)
	req.Host = "127.0.0.1:18080"
	scopeDate := time.Now().UTC().Format("20060102")
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=test-access/%s/us-east-1/s3/aws4_request, SignedHeaders=host;host, Signature=sig", scopeDate))
	req.Header.Set("x-amz-date", time.Now().UTC().Format("20060102T150405Z"))

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if *reached || rec.Code != http.StatusBadRequest {
		t.Fatalf("expected duplicate signed header to return 400, got: %d", rec.Code)
	}
}
