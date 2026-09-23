package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

type CredentialsStore struct {
	mu          sync.RWMutex
	credentials map[string]Credentials
}

func NewCredentialsStore() *CredentialsStore {
	return &CredentialsStore{
		credentials: make(map[string]Credentials),
	}
}

func (store *CredentialsStore) AddCredentials(accessKeyID, secretAccessKey string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.credentials[accessKeyID] = Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}
	slog.Debug("added credentials", "access_key_id", accessKeyID)
}

func (store *CredentialsStore) GetCredentials(accessKeyID string) (Credentials, bool) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	creds, ok := store.credentials[accessKeyID]
	return creds, ok
}

func (store *CredentialsStore) hasCredentials() bool {
	if store == nil {
		return false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return len(store.credentials) > 0
}

type AuthMiddleware struct {
	store     *CredentialsStore
	wrapped   http.Handler
	admission *UploadAdmission
}

func NewAuthMiddleware(store *CredentialsStore, wrapped http.Handler, admission *UploadAdmission) *AuthMiddleware {
	return &AuthMiddleware{
		store:     store,
		wrapped:   wrapped,
		admission: admission,
	}
}

type authError struct {
	status  int
	code    string
	message string
}

func (e *authError) Error() string {
	return e.message
}

func newAuthError(status int, code, message string) *authError {
	return &authError{status: status, code: code, message: message}
}

func writeAuthError(w http.ResponseWriter, r *http.Request, err *authError) {
	slog.Debug("auth verification rejected", "code", err.code, "status", err.status)
	w.Header().Set("Connection", "close")
	writeS3Error(w, r, err.status, err.code, err.message)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func handlePayloadError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Connection", "close")
	if errors.Is(err, ErrStorageLimit) {
		slog.Debug("storage staging limit exceeded", "error", err.Error())
		writeS3Error(w, r, http.StatusServiceUnavailable, "SlowDown", "Storage limit exceeded")
	} else if pErr, ok := err.(*s3PayloadError); ok {
		slog.Debug("payload verification rejected", "code", pErr.code, "status", pErr.status)
		writeS3Error(w, r, pErr.status, pErr.code, pErr.message)
	} else {
		slog.Debug("payload error", "error", err.Error())
		writeS3Error(w, r, http.StatusBadRequest, "InvalidRequest", err.Error())
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (m *AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only GET/HEAD /health is unauthenticated
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == "/health" {
		m.wrapped.ServeHTTP(w, r)
		return
	}

	// When credentials store is empty, authentication is disabled
	if !m.store.hasCredentials() {
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			if m.admission == nil || m.admission.Budget() == nil || m.admission.Budget().Max() <= 0 {
				writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Storage staging budget is not configured")
				return
			}
			release, err := m.admission.Acquire(r.Context())
			if err != nil {
				w.Header().Set("Connection", "close")
				if errors.Is(err, ErrSlowDown) {
					writeS3Error(w, r, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.")
				} else {
					writeS3Error(w, r, http.StatusServiceUnavailable, "SlowDown", "Request canceled or timed out")
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				return
			}
			defer release()

			timeout := m.admission.Timeout()
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()
			r = r.WithContext(ctx)

			rc := http.NewResponseController(w)
			_ = rc.SetReadDeadline(time.Now().Add(timeout))

			cleanup, err := preparePayload(r, m.admission.SpoolDir(), m.admission.Budget())
			if err != nil {
				handlePayloadError(w, r, err)
				return
			}
			defer cleanup()
		}
		m.wrapped.ServeHTTP(w, r)
		return
	}

	authHeader := r.Header.Get("Authorization")
	rawQuery := r.URL.RawQuery
	hasQueryAuth := strings.Contains(rawQuery, "X-Amz-Algorithm=") || strings.Contains(rawQuery, "X-Amz-Signature=")

	if authHeader != "" && hasQueryAuth {
		writeAuthError(w, r, newAuthError(http.StatusBadRequest, "InvalidArgument", "Only one auth mechanism allowed; only the X-Amz-Algorithm query parameter, Signature query string or the Authorization header should be specified"))
		return
	}

	if authHeader == "" && !hasQueryAuth {
		writeAuthError(w, r, newAuthError(http.StatusForbidden, "AccessDenied", "Access Denied"))
		return
	}

	// Validate request credentials and signature BEFORE acquiring admission or preparing/mutating payload
	if authHeader != "" {
		if err := m.verifyHeaderAuth(r, authHeader); err != nil {
			writeAuthError(w, r, err)
			return
		}
	} else {
		if err := m.verifyQueryAuth(r); err != nil {
			writeAuthError(w, r, err)
			return
		}
	}

	// Authentication succeeded. For PUT/POST, acquire admission and prepare/spool payload
	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		if m.admission == nil || m.admission.Budget() == nil || m.admission.Budget().Max() <= 0 {
			writeS3Error(w, r, http.StatusInternalServerError, "InternalError", "Storage staging budget is not configured")
			return
		}
		release, err := m.admission.Acquire(r.Context())
		if err != nil {
			w.Header().Set("Connection", "close")
			if errors.Is(err, ErrSlowDown) {
				writeS3Error(w, r, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.")
			} else {
				writeS3Error(w, r, http.StatusServiceUnavailable, "SlowDown", "Request canceled or timed out")
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}
		defer release()

		timeout := m.admission.Timeout()
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)

		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(timeout))

		cleanup, err := preparePayload(r, m.admission.SpoolDir(), m.admission.Budget())
		if err != nil {
			handlePayloadError(w, r, err)
			return
		}
		defer cleanup()
	}

	m.wrapped.ServeHTTP(w, r)
}

func (m *AuthMiddleware) verifyHeaderAuth(r *http.Request, auth string) *authError {
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Authorization header must start with AWS4-HMAC-SHA256")
	}

	rest := strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 ")
	var credential, signedHeaders, signature string
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, found := strings.Cut(part, "=")
		if !found {
			return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Malformed key-value pair in Authorization header")
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "Credential":
			if credential != "" {
				return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Duplicate Credential parameter")
			}
			credential = v
		case "SignedHeaders":
			if signedHeaders != "" {
				return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Duplicate SignedHeaders parameter")
			}
			signedHeaders = strings.ToLower(v)
		case "Signature":
			if signature != "" {
				return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Duplicate Signature parameter")
			}
			signature = v
		}
	}

	if credential == "" || signedHeaders == "" || signature == "" {
		return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Missing required fields in Authorization header")
	}

	credParts := strings.Split(credential, "/")
	if len(credParts) != 5 || credParts[4] != "aws4_request" {
		return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Credential scope format is invalid")
	}

	accessKeyID := credParts[0]
	scopeDate := credParts[1]
	scopeRegion := credParts[2]
	scopeService := credParts[3]

	if scopeService != "s3" {
		return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Service in credential scope must be s3")
	}
	if len(scopeDate) != 8 {
		return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Date in credential scope must be YYYYMMDD")
	}

	creds, ok := m.store.GetCredentials(accessKeyID)
	if !ok {
		return newAuthError(http.StatusForbidden, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
	}

	var reqTime time.Time
	var reqDateStr string
	if amzDate := strings.TrimSpace(r.Header.Get("X-Amz-Date")); amzDate != "" {
		var err error
		reqTime, err = time.Parse("20060102T150405Z", amzDate)
		if err != nil {
			return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Invalid X-Amz-Date format")
		}
		reqDateStr = amzDate
	} else if dateHeader := strings.TrimSpace(r.Header.Get("Date")); dateHeader != "" {
		var err error
		reqTime, err = http.ParseTime(dateHeader)
		if err != nil {
			return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Invalid Date header format")
		}
		reqDateStr = reqTime.UTC().Format("20060102T150405Z")
	} else {
		return newAuthError(http.StatusForbidden, "AccessDenied", "AWS authentication requires a valid Date or X-Amz-Date header")
	}

	now := time.Now().UTC()
	if reqTime.Before(now.Add(-15*time.Minute)) || reqTime.After(now.Add(15*time.Minute)) {
		return newAuthError(http.StatusForbidden, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large.")
	}

	if reqDateStr[:8] != scopeDate {
		return newAuthError(http.StatusForbidden, "SignatureDoesNotMatch", "Date in credential scope does not match request date")
	}

	// Canonical URI
	canonicalURI := getCanonicalURI(r)

	// Canonical Query String
	canonicalQuery := getCanonicalQueryString(r, false)

	// Canonical Headers & Signed Headers
	signedList := strings.Split(signedHeaders, ";")
	seenHeaders := make(map[string]struct{}, len(signedList))
	hasHost := false
	var canonicalHeaders strings.Builder
	for _, h := range signedList {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Empty header in signed headers list")
		}
		if _, exists := seenHeaders[h]; exists {
			return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Duplicate header in signed headers list")
		}
		seenHeaders[h] = struct{}{}
		if h == "host" {
			hasHost = true
		}
		val := getHeaderValueForSigning(r, h)
		if val == "" && h != "host" && len(r.Header.Values(h)) == 0 {
			return newAuthError(http.StatusForbidden, "SignatureDoesNotMatch", fmt.Sprintf("Signed header '%s' not present in request", h))
		}
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(cleanHeaderValue(val))
		canonicalHeaders.WriteByte('\n')
	}

	if !hasHost {
		return newAuthError(http.StatusBadRequest, "AuthorizationHeaderMalformed", "Host header must be included in signed headers")
	}

	// Payload Hash
	contentSHA256 := strings.TrimSpace(r.Header.Get("x-amz-content-sha256"))
	if strings.EqualFold(contentSHA256, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD") ||
		strings.EqualFold(contentSHA256, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER") {
		return newAuthError(http.StatusNotImplemented, "NotImplemented", "Signed streaming payloads are not supported")
	}
	needSetHeader := false
	if contentSHA256 == "" {
		if (r.Method == http.MethodPut || r.Method == http.MethodPost) && r.ContentLength > 0 {
			return newAuthError(http.StatusBadRequest, "InvalidRequest", "Missing required header 'x-amz-content-sha256'")
		}
		contentSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		needSetHeader = true
	}
	canonicalRequest := r.Method + "\n" +
		canonicalURI + "\n" +
		canonicalQuery + "\n" +
		canonicalHeaders.String() + "\n" +
		signedHeaders + "\n" +
		contentSHA256

	canonicalRequestHash := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalRequest)))
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", scopeDate, scopeRegion, scopeService)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", reqDateStr, credentialScope, canonicalRequestHash)

	signingKey := getSigningKey(creds.SecretAccessKey, scopeDate, scopeRegion, scopeService)
	expectedSig := fmt.Sprintf("%x", hmacSHA256(signingKey, []byte(stringToSign)))

	if subtle.ConstantTimeCompare([]byte(strings.ToLower(signature)), []byte(strings.ToLower(expectedSig))) != 1 {
		return newAuthError(http.StatusForbidden, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.")
	}

	if needSetHeader {
		r.Header.Set("x-amz-content-sha256", contentSHA256)
	}

	return nil
}

func (m *AuthMiddleware) verifyQueryAuth(r *http.Request) *authError {
	query := r.URL.Query()

	algo := query.Get("X-Amz-Algorithm")
	if algo != "AWS4-HMAC-SHA256" {
		return newAuthError(http.StatusBadRequest, "InvalidRequest", "Unsupported authorization algorithm")
	}

	credential := query.Get("X-Amz-Credential")
	if credential == "" {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Missing X-Amz-Credential")
	}
	credParts := strings.Split(credential, "/")
	if len(credParts) != 5 || credParts[4] != "aws4_request" {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Credential parameter is malformed")
	}

	accessKeyID := credParts[0]
	scopeDate := credParts[1]
	scopeRegion := credParts[2]
	scopeService := credParts[3]

	if scopeService != "s3" {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Service in credential scope must be s3")
	}
	if len(scopeDate) != 8 {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Date in credential scope must be YYYYMMDD")
	}

	creds, ok := m.store.GetCredentials(accessKeyID)
	if !ok {
		return newAuthError(http.StatusForbidden, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
	}

	dateStr := query.Get("X-Amz-Date")
	if dateStr == "" {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Missing X-Amz-Date")
	}
	reqTime, err := time.Parse("20060102T150405Z", dateStr)
	if err != nil {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Invalid X-Amz-Date format")
	}
	if dateStr[:8] != scopeDate {
		return newAuthError(http.StatusForbidden, "SignatureDoesNotMatch", "Date in credential scope does not match X-Amz-Date")
	}

	expiresStr := query.Get("X-Amz-Expires")
	if expiresStr == "" {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Missing X-Amz-Expires")
	}
	expiresInt, parseErr := strconv.Atoi(expiresStr)
	if parseErr != nil || expiresInt < 1 || expiresInt > 604800 {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "X-Amz-Expires must be between 1 and 604800")
	}

	now := time.Now().UTC()
	if reqTime.After(now.Add(15 * time.Minute)) {
		return newAuthError(http.StatusForbidden, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large.")
	}
	if now.After(reqTime.Add(time.Duration(expiresInt) * time.Second)) {
		return newAuthError(http.StatusForbidden, "RequestExpired", "Request has expired")
	}

	signedHeaders := strings.ToLower(query.Get("X-Amz-SignedHeaders"))
	if signedHeaders == "" {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Missing X-Amz-SignedHeaders")
	}

	signature := query.Get("X-Amz-Signature")
	if signature == "" {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Missing X-Amz-Signature")
	}

	// Canonical URI
	canonicalURI := getCanonicalURI(r)

	// Canonical Query String
	canonicalQuery := getCanonicalQueryString(r, true)

	// Canonical Headers & Signed Headers
	signedList := strings.Split(signedHeaders, ";")
	seenHeaders := make(map[string]struct{}, len(signedList))
	hasHost := false
	var canonicalHeaders strings.Builder
	for _, h := range signedList {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Empty header in signed headers list")
		}
		if _, exists := seenHeaders[h]; exists {
			return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Duplicate header in signed headers list")
		}
		seenHeaders[h] = struct{}{}
		if h == "host" {
			hasHost = true
		}
		val := getHeaderValueForSigning(r, h)
		if val == "" && h != "host" && len(r.Header.Values(h)) == 0 {
			return newAuthError(http.StatusForbidden, "SignatureDoesNotMatch", fmt.Sprintf("Signed header '%s' not present in request", h))
		}
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(cleanHeaderValue(val))
		canonicalHeaders.WriteByte('\n')
	}

	if !hasHost {
		return newAuthError(http.StatusBadRequest, "AuthorizationQueryParametersError", "Host header must be included in signed headers")
	}

	// Payload Hash
	payloadHash := "UNSIGNED-PAYLOAD"
	if strings.Contains(";"+signedHeaders+";", ";x-amz-content-sha256;") {
		if csha := strings.TrimSpace(r.Header.Get("x-amz-content-sha256")); csha != "" {
			payloadHash = csha
		}
	}

	canonicalRequest := r.Method + "\n" +
		canonicalURI + "\n" +
		canonicalQuery + "\n" +
		canonicalHeaders.String() + "\n" +
		signedHeaders + "\n" +
		payloadHash

	canonicalRequestHash := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalRequest)))
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", scopeDate, scopeRegion, scopeService)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", dateStr, credentialScope, canonicalRequestHash)

	signingKey := getSigningKey(creds.SecretAccessKey, scopeDate, scopeRegion, scopeService)
	expectedSig := fmt.Sprintf("%x", hmacSHA256(signingKey, []byte(stringToSign)))

	if subtle.ConstantTimeCompare([]byte(strings.ToLower(signature)), []byte(strings.ToLower(expectedSig))) != 1 {
		return newAuthError(http.StatusForbidden, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.")
	}

	return nil
}

func getCanonicalURI(r *http.Request) string {
	var rawURI string
	if r.RequestURI != "" {
		u := r.RequestURI
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			if parsed, err := url.Parse(u); err == nil {
				rawURI = parsed.EscapedPath()
			}
		} else {
			rawURI = strings.SplitN(u, "?", 2)[0]
		}
	}
	if rawURI == "" {
		if r.URL.RawPath != "" {
			rawURI = r.URL.RawPath
		} else if r.URL.Path != "" {
			rawURI = r.URL.EscapedPath()
		} else {
			rawURI = "/"
		}
	}
	if !strings.HasPrefix(rawURI, "/") {
		rawURI = "/" + rawURI
	}
	return rawURI
}

type queryPair struct {
	key   string
	value string
}

func getCanonicalQueryString(r *http.Request, omitSignature bool) string {
	rawQuery := r.URL.RawQuery
	if rawQuery == "" && r.RequestURI != "" && strings.Contains(r.RequestURI, "?") {
		rawQuery = strings.SplitN(r.RequestURI, "?", 2)[1]
	}
	if rawQuery == "" {
		return ""
	}

	parts := strings.Split(rawQuery, "&")
	pairs := make([]queryPair, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if omitSignature && k == "X-Amz-Signature" {
			continue
		}
		pairs = append(pairs, queryPair{key: k, value: v})
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key != pairs[j].key {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].value < pairs[j].value
	})

	var buf strings.Builder
	for i, pair := range pairs {
		if i > 0 {
			buf.WriteByte('&')
		}
		buf.WriteString(pair.key)
		buf.WriteByte('=')
		buf.WriteString(pair.value)
	}
	return buf.String()
}

func getHeaderValueForSigning(r *http.Request, h string) string {
	if h == "host" {
		if r.Host != "" {
			return r.Host
		}
		return r.Header.Get("Host")
	}

	vals := r.Header.Values(h)
	if len(vals) == 0 {
		// Case-insensitive lookup fallback
		for k, v := range r.Header {
			if strings.EqualFold(k, h) {
				vals = v
				break
			}
		}
	}
	if len(vals) == 0 {
		return ""
	}
	return strings.Join(vals, ",")
}

func cleanHeaderValue(val string) string {
	val = strings.TrimSpace(val)
	var buf strings.Builder
	inSpace := false
	for _, c := range val {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			if !inSpace {
				buf.WriteByte(' ')
				inSpace = true
			}
		} else {
			buf.WriteRune(c)
			inSpace = false
		}
	}
	return buf.String()
}

func hmacSHA256(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getSigningKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}
