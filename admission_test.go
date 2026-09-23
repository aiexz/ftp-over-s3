package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type trackingReader struct {
	r          io.Reader
	readCalled atomic.Bool
	readBytes  atomic.Int64
}

func (tr *trackingReader) Read(p []byte) (int, error) {
	tr.readCalled.Store(true)
	n, err := tr.r.Read(p)
	tr.readBytes.Add(int64(n))
	return n, err
}

func TestAdmission_OverloadRejectionBeforeBodyRead(t *testing.T) {
	dir := t.TempDir()
	budget := NewDiskBudget(10 * 1024 * 1024)
	state := &State{Root: dir, Budget: budget}
	adm := NewUploadAdmission(state, 2, 10*time.Second)

	store := NewCredentialsStore()
	store.AddCredentials("test-access", "test-secret")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := NewAuthMiddleware(store, handler, adm)

	// Consume both admission slots
	rel1, err1 := adm.Acquire(context.Background())
	if err1 != nil {
		t.Fatalf("unexpected error acquiring slot 1: %v", err1)
	}
	defer rel1()

	rel2, err2 := adm.Acquire(context.Background())
	if err2 != nil {
		t.Fatalf("unexpected error acquiring slot 2: %v", err2)
	}
	defer rel2()

	// Third request arrives - must be rejected with 503 SlowDown without reading body
	rawBody := strings.NewReader("some upload content")
	tracker := &trackingReader{r: rawBody}

	now := time.Now().UTC()
	req := httptest.NewRequest(http.MethodPut, "/default/key.txt", tracker)
	req.Host = "127.0.0.1:18080"
	signRequest(req, "test-access", "test-secret", "us-east-1", now, "")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 SlowDown on overload, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SlowDown") {
		t.Fatalf("expected SlowDown error response, got %s", rec.Body.String())
	}

	// Verify tracker was NEVER read
	if tracker.readCalled.Load() {
		t.Fatalf("request body was read despite admission overload rejection")
	}
}

func TestAdmission_AuthFailureBeforeSlotConsumption(t *testing.T) {
	dir := t.TempDir()
	budget := NewDiskBudget(10 * 1024 * 1024)
	state := &State{Root: dir, Budget: budget}
	adm := NewUploadAdmission(state, 1, 10*time.Second)

	store := NewCredentialsStore()
	store.AddCredentials("test-access", "test-secret")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := NewAuthMiddleware(store, handler, adm)

	// Send PUT request without credentials (fails auth)
	tracker := &trackingReader{r: strings.NewReader("unauthenticated body")}
	req := httptest.NewRequest(http.MethodPut, "/default/key.txt", tracker)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 AccessDenied, got %d", rec.Code)
	}
	if tracker.readCalled.Load() {
		t.Fatalf("request body was read on unauthenticated request")
	}
	if adm.InFlight() != 0 {
		t.Fatalf("expected 0 slots in-flight after auth failure, got %d", adm.InFlight())
	}

	// Slot must be immediately available for an authenticated request
	now := time.Now().UTC()
	bodyBytes := []byte("valid authenticated body")
	validTracker := &trackingReader{r: bytes.NewReader(bodyBytes)}
	req2 := httptest.NewRequest(http.MethodPut, "/default/key.txt", validTracker)
	req2.Host = "127.0.0.1:18080"
	bodySHA := fmt.Sprintf("%x", sha256.Sum256(bodyBytes))
	signRequest(req2, "test-access", "test-secret", "us-east-1", now, bodySHA)
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid request after auth failure, got %d", rec2.Code)
	}
}

type cancelingReader struct {
	cancel context.CancelFunc
	called bool
}

func (cr *cancelingReader) Read(p []byte) (int, error) {
	if !cr.called {
		cr.called = true
		cr.cancel()
	}
	return 0, context.Canceled
}

func TestAdmission_CleanupReleaseOnCanceledBody(t *testing.T) {
	dir := t.TempDir()
	spoolDir := dir + "/spool"
	_ = os.MkdirAll(spoolDir, 0700)

	budget := NewDiskBudget(10 * 1024 * 1024)
	state := &State{Root: dir, Budget: budget}
	adm := NewUploadAdmission(state, 2, 10*time.Second)

	store := NewCredentialsStore()
	store.AddCredentials("test-access", "test-secret")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := NewAuthMiddleware(store, handler, adm)

	ctx, cancel := context.WithCancel(context.Background())
	cr := &cancelingReader{cancel: cancel}

	req := httptest.NewRequest(http.MethodPut, "/default/key.txt", cr).WithContext(ctx)
	req.Host = "127.0.0.1:18080"
	signRequest(req, "test-access", "test-secret", "us-east-1", time.Now().UTC(), "UNSIGNED-PAYLOAD")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	// In-flight slots must be released
	if adm.InFlight() != 0 {
		t.Fatalf("expected 0 in-flight slots after cancellation, got %d", adm.InFlight())
	}

	// Budget must be completely released
	if budget.Used() != 0 {
		t.Fatalf("expected 0 bytes used in budget after cancellation, got %d", budget.Used())
	}

	// Spool directory must not leave abandoned files
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("failed reading spool dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 spool files left behind, found %d", len(entries))
	}
}

func TestAdmission_CleanupReleaseOnInvalidBody(t *testing.T) {
	dir := t.TempDir()
	spoolDir := dir + "/spool"
	_ = os.MkdirAll(spoolDir, 0700)

	budget := NewDiskBudget(10 * 1024 * 1024)
	state := &State{Root: dir, Budget: budget}
	adm := NewUploadAdmission(state, 2, 10*time.Second)

	store := NewCredentialsStore()
	store.AddCredentials("test-access", "test-secret")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mw := NewAuthMiddleware(store, handler, adm)

	// Send PUT with mismatched Content-MD5
	bodyData := []byte("mismatched body data")
	badMD5 := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	req := httptest.NewRequest(http.MethodPut, "/default/key.txt", bytes.NewReader(bodyData))
	req.Host = "127.0.0.1:18080"
	req.Header.Set("Content-MD5", badMD5)
	signRequest(req, "test-access", "test-secret", "us-east-1", time.Now().UTC(), "UNSIGNED-PAYLOAD")

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 BadDigest, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "BadDigest") {
		t.Fatalf("expected BadDigest error, got %s", rec.Body.String())
	}

	// In-flight slot must be released
	if adm.InFlight() != 0 {
		t.Fatalf("expected 0 in-flight slots after bad digest, got %d", adm.InFlight())
	}

	// Budget must be 0
	if budget.Used() != 0 {
		t.Fatalf("expected 0 bytes used in budget after bad digest, got %d", budget.Used())
	}

	// Spool dir must have no leftover files
	entries, _ := os.ReadDir(spoolDir)
	if len(entries) != 0 {
		t.Fatalf("expected 0 spool files left behind, found %d", len(entries))
	}
}

func TestAdmission_NoSpoolOutsideBudget(t *testing.T) {
	store := NewCredentialsStore()
	store.AddCredentials("test-access", "test-secret")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Case 1: nil admission
	mwNil := NewAuthMiddleware(store, handler, nil)
	req1 := httptest.NewRequest(http.MethodPut, "/default/key.txt", strings.NewReader("data"))
	req1.Host = "127.0.0.1:18080"
	signRequest(req1, "test-access", "test-secret", "us-east-1", time.Now().UTC(), "UNSIGNED-PAYLOAD")

	rec1 := httptest.NewRecorder()
	mwNil.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalError when admission is nil, got %d", rec1.Code)
	}

	// Case 2: budget <= 0
	dir := t.TempDir()
	invalidBudget := NewDiskBudget(0)
	state := &State{Root: dir, Budget: invalidBudget}
	admInvalid := NewUploadAdmission(state, 2, 10*time.Second)

	mwInvalid := NewAuthMiddleware(store, handler, admInvalid)
	req2 := httptest.NewRequest(http.MethodPut, "/default/key.txt", strings.NewReader("data"))
	req2.Host = "127.0.0.1:18080"
	signRequest(req2, "test-access", "test-secret", "us-east-1", time.Now().UTC(), "UNSIGNED-PAYLOAD")

	rec2 := httptest.NewRecorder()
	mwInvalid.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalError when budget <= 0, got %d", rec2.Code)
	}
}
