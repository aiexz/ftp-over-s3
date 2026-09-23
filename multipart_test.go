package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testState(t *testing.T, maxBytes int64) *State {
	t.Helper()
	dir := t.TempDir()
	if maxBytes <= 0 {
		maxBytes = 20 * 1024 * 1024 * 1024
	}
	state, err := OpenState(dir, "test-backend", maxBytes)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}
	t.Cleanup(func() {
		_ = state.Close()
	})
	return state
}

func TestMultipartRestartResume(t *testing.T) {
	dir := t.TempDir()
	state1, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState 1 failed: %v", err)
	}

	mgr1, err := NewMultipartManager(state1)
	if err != nil {
		t.Fatalf("NewMultipartManager 1 failed: %v", err)
	}

	meta := ObjectMetadata{
		ContentType:  "application/octet-stream",
		UserMetadata: map[string]string{"project": "durable-mp"},
	}
	session, err := mgr1.CreateUpload("default", "resume-test.bin", meta)
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}
	uploadID := session.UploadID

	p1Data := bytes.Repeat([]byte("A"), 5*1024*1024)
	p1, err := mgr1.UploadPart(session, 1, bytes.NewReader(p1Data), int64(len(p1Data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}

	p2Data := bytes.Repeat([]byte("B"), 5*1024*1024)
	p2, err := mgr1.UploadPart(session, 2, bytes.NewReader(p2Data), int64(len(p2Data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 2 failed: %v", err)
	}

	// Graceful shutdown preserves sessions on disk
	if err := mgr1.Close(); err != nil {
		t.Fatalf("mgr1.Close failed: %v", err)
	}
	if err := state1.Close(); err != nil {
		t.Fatalf("state1.Close failed: %v", err)
	}

	// Reopen state and manager
	state2, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState 2 failed: %v", err)
	}
	defer state2.Close()

	mgr2, err := NewMultipartManager(state2)
	if err != nil {
		t.Fatalf("NewMultipartManager 2 failed: %v", err)
	}
	defer mgr2.Close()

	recoveredSession, ok := mgr2.GetUpload(uploadID)
	if !ok {
		t.Fatalf("expected upload %s to be recovered after restart", uploadID)
	}

	if recoveredSession.Metadata.UserMetadata["project"] != "durable-mp" {
		t.Errorf("recovered metadata mismatch: got %v", recoveredSession.Metadata)
	}

	if len(recoveredSession.Parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(recoveredSession.Parts))
	}
	if recoveredSession.Parts[1].ETag != p1.ETag || recoveredSession.Parts[2].ETag != p2.ETag {
		t.Errorf("recovered ETags mismatch: p1=%s vs %s, p2=%s vs %s",
			recoveredSession.Parts[1].ETag, p1.ETag, recoveredSession.Parts[2].ETag, p2.ETag)
	}

	// Upload part 3 on resumed session
	p3Data := []byte("final-part-data")
	p3, err := mgr2.UploadPart(recoveredSession, 3, bytes.NewReader(p3Data), int64(len(p3Data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 3 failed: %v", err)
	}

	completedParts := []CompletedPart{
		{PartNumber: 1, ETag: p1.ETag},
		{PartNumber: 2, ETag: p2.ETag},
		{PartNumber: 3, ETag: p3.ETag},
	}
	stream, s3ETag, totalSize, err := mgr2.AssembleStream(recoveredSession, completedParts)
	if err != nil {
		t.Fatalf("AssembleStream failed: %v", err)
	}
	defer stream.Close()

	if totalSize != int64(len(p1Data)+len(p2Data)+len(p3Data)) {
		t.Errorf("totalSize mismatch: got %d", totalSize)
	}
	if s3ETag == "" {
		t.Error("s3ETag should not be empty")
	}

	allRead, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll stream failed: %v", err)
	}
	expected := append(append(p1Data, p2Data...), p3Data...)
	if !bytes.Equal(allRead, expected) {
		t.Fatal("assembled stream data mismatch")
	}

	if err := mgr2.FinalizeComplete(recoveredSession); err != nil {
		t.Fatalf("FinalizeComplete failed: %v", err)
	}

	if _, ok := mgr2.GetUpload(uploadID); ok {
		t.Errorf("completed upload should no longer exist in manager")
	}
}

func TestMultipartPartReplacementAtomicity(t *testing.T) {
	dir := t.TempDir()
	state, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}
	defer state.Close()

	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "replace.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	initialData := bytes.Repeat([]byte("A"), 5*1024*1024)
	p1, err := mgr.UploadPart(session, 1, bytes.NewReader(initialData), int64(len(initialData)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}

	initialPath := p1.Path
	if state.Budget.Used() != 5*1024*1024 {
		t.Fatalf("expected budget used 5MB, got %d", state.Budget.Used())
	}

	// Replace part 1 with 6MB of 'B' bytes
	replacementData := bytes.Repeat([]byte("B"), 6*1024*1024)
	p1New, err := mgr.UploadPart(session, 1, bytes.NewReader(replacementData), int64(len(replacementData)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 1 replacement failed: %v", err)
	}

	if p1New.Size != 6*1024*1024 {
		t.Errorf("expected new size 6MB, got %d", p1New.Size)
	}
	if p1New.ETag == p1.ETag {
		t.Errorf("expected new ETag to differ from old ETag")
	}
	if state.Budget.Used() != 6*1024*1024 {
		t.Errorf("expected budget used 6MB, got %d", state.Budget.Used())
	}

	// Verify old file was deleted
	if _, err := os.Stat(initialPath); !os.IsNotExist(err) {
		t.Errorf("expected old part file %s to be deleted, err=%v", initialPath, err)
	}

	// Verify new file exists
	if _, err := os.Stat(p1New.Path); err != nil {
		t.Errorf("expected new part file %s to exist: %v", p1New.Path, err)
	}
}

func TestMultipartCorruptedTruncatedPartRejection(t *testing.T) {
	t.Run("StartupRecoveryRejectsTruncatedPart", func(t *testing.T) {
		dir := t.TempDir()
		state1, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
		if err != nil {
			t.Fatalf("OpenState failed: %v", err)
		}

		mgr1, err := NewMultipartManager(state1)
		if err != nil {
			t.Fatalf("NewMultipartManager failed: %v", err)
		}

		session, err := mgr1.CreateUpload("default", "corrupt-part.bin", ObjectMetadata{})
		if err != nil {
			t.Fatalf("CreateUpload failed: %v", err)
		}

		data := bytes.Repeat([]byte("C"), 5*1024*1024)
		part, err := mgr1.UploadPart(session, 1, bytes.NewReader(data), int64(len(data)), "", "", "", "", "")
		if err != nil {
			t.Fatalf("UploadPart failed: %v", err)
		}

		_ = mgr1.Close()
		_ = state1.Close()

		// Truncate part file on disk
		if err := os.Truncate(part.Path, 1024); err != nil {
			t.Fatalf("Truncate failed: %v", err)
		}

		// Reopening must fail closed and reject corrupted/truncated part
		state2, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
		if err != nil {
			t.Fatalf("OpenState 2 failed: %v", err)
		}
		defer state2.Close()

		_, err = NewMultipartManager(state2)
		if err == nil {
			t.Fatal("expected NewMultipartManager to fail on truncated part file")
		}

		// Verify recoverable data was not deleted on corruption
		if _, statErr := os.Stat(part.Path); os.IsNotExist(statErr) {
			t.Fatal("recoverable part file was deleted despite fail-closed requirement")
		}
	})

	t.Run("StartupRecoveryRejectsCorruptManifest", func(t *testing.T) {
		dir := t.TempDir()
		state1, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
		if err != nil {
			t.Fatalf("OpenState failed: %v", err)
		}

		mgr1, err := NewMultipartManager(state1)
		if err != nil {
			t.Fatalf("NewMultipartManager failed: %v", err)
		}

		session, err := mgr1.CreateUpload("default", "corrupt-mf.bin", ObjectMetadata{})
		if err != nil {
			t.Fatalf("CreateUpload failed: %v", err)
		}
		sessionDir := session.Dir
		manifestPath := filepath.Join(sessionDir, "manifest.json")

		data := bytes.Repeat([]byte("D"), 5*1024*1024)
		part, err := mgr1.UploadPart(session, 1, bytes.NewReader(data), int64(len(data)), "", "", "", "", "")
		if err != nil {
			t.Fatalf("UploadPart failed: %v", err)
		}

		_ = mgr1.Close()
		_ = state1.Close()

		// Write corrupted JSON to manifest
		if err := os.WriteFile(manifestPath, []byte("{\"upload_id\": \"corrupt"), 0600); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		state2, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
		if err != nil {
			t.Fatalf("OpenState 2 failed: %v", err)
		}
		defer state2.Close()

		_, err = NewMultipartManager(state2)
		if err == nil {
			t.Fatal("expected NewMultipartManager to fail on corrupt manifest")
		}

		// Verify session dir and part file were NOT deleted
		if _, statErr := os.Stat(part.Path); os.IsNotExist(statErr) {
			t.Fatal("recoverable part file was deleted on corrupt manifest")
		}
	})

	t.Run("AssembleStreamRejectsTruncatedPartAtRuntime", func(t *testing.T) {
		state := testState(t, 20*1024*1024*1024)
		mgr, err := NewMultipartManager(state)
		if err != nil {
			t.Fatalf("NewMultipartManager failed: %v", err)
		}
		defer mgr.Close()

		session, err := mgr.CreateUpload("default", "stream-corrupt.bin", ObjectMetadata{})
		if err != nil {
			t.Fatalf("CreateUpload failed: %v", err)
		}

		data := bytes.Repeat([]byte("E"), 5*1024*1024)
		part, err := mgr.UploadPart(session, 1, bytes.NewReader(data), int64(len(data)), "", "", "", "", "")
		if err != nil {
			t.Fatalf("UploadPart failed: %v", err)
		}

		// Truncate file behind manager's back
		if err := os.Truncate(part.Path, 100); err != nil {
			t.Fatalf("Truncate failed: %v", err)
		}

		_, _, _, err = mgr.AssembleStream(session, []CompletedPart{{PartNumber: 1, ETag: part.ETag}})
		if !errors.Is(err, ErrInvalidPart) {
			t.Fatalf("expected ErrInvalidPart on truncated part file, got %v", err)
		}
	})
}

func TestMultipartRecoveredQuota(t *testing.T) {
	dir := t.TempDir()
	const maxCap = 20 * 1024 * 1024 // 20 MB

	state1, err := OpenState(dir, "test-backend", maxCap)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}

	mgr1, err := NewMultipartManager(state1)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}

	session, err := mgr1.CreateUpload("default", "quota.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	p1Data := bytes.Repeat([]byte("Q"), 8*1024*1024)
	_, err = mgr1.UploadPart(session, 1, bytes.NewReader(p1Data), int64(len(p1Data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}

	if state1.Budget.Used() != 8*1024*1024 {
		t.Fatalf("expected 8MB used, got %d", state1.Budget.Used())
	}

	_ = mgr1.Close()
	_ = state1.Close()

	// Reopen: budget must be recovered from disk
	state2, err := OpenState(dir, "test-backend", maxCap)
	if err != nil {
		t.Fatalf("OpenState 2 failed: %v", err)
	}
	defer state2.Close()

	mgr2, err := NewMultipartManager(state2)
	if err != nil {
		t.Fatalf("NewMultipartManager 2 failed: %v", err)
	}
	defer mgr2.Close()

	if state2.Budget.Used() != 8*1024*1024 {
		t.Fatalf("expected recovered budget used 8MB, got %d", state2.Budget.Used())
	}

	recoveredSession, ok := mgr2.GetUpload(session.UploadID)
	if !ok {
		t.Fatal("session not found on resumed manager")
	}

	p2Data := bytes.Repeat([]byte("R"), 8*1024*1024)
	_, err = mgr2.UploadPart(recoveredSession, 2, bytes.NewReader(p2Data), int64(len(p2Data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 2 failed: %v", err)
	}

	if state2.Budget.Used() != 16*1024*1024 {
		t.Fatalf("expected 16MB used, got %d", state2.Budget.Used())
	}

	// Part 3 would exceed 20MB limit (16 + 8 = 24 > 20)
	p3Data := bytes.Repeat([]byte("S"), 8*1024*1024)
	_, err = mgr2.UploadPart(recoveredSession, 3, bytes.NewReader(p3Data), int64(len(p3Data)), "", "", "", "", "")
	if !errors.Is(err, ErrStagingLimitExceeded) {
		t.Fatalf("expected ErrStagingLimitExceeded, got %v", err)
	}

	// Abort upload: releases all budget
	if err := mgr2.AbortUpload(session.UploadID); err != nil {
		t.Fatalf("AbortUpload failed: %v", err)
	}

	if state2.Budget.Used() != 0 {
		t.Fatalf("expected 0 bytes used after abort, got %d", state2.Budget.Used())
	}
}

func TestMultipartAbortCompletionStayDeleted(t *testing.T) {
	dir := t.TempDir()
	state1, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}

	mgr1, err := NewMultipartManager(state1)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}

	// Session A to abort
	sA, err := mgr1.CreateUpload("default", "abort-me.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload A failed: %v", err)
	}
	pDataA := bytes.Repeat([]byte("A"), 5*1024*1024)
	_, err = mgr1.UploadPart(sA, 1, bytes.NewReader(pDataA), int64(len(pDataA)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart A failed: %v", err)
	}

	// Session B to complete
	sB, err := mgr1.CreateUpload("default", "complete-me.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload B failed: %v", err)
	}
	pDataB := bytes.Repeat([]byte("B"), 5*1024*1024)
	pB, err := mgr1.UploadPart(sB, 1, bytes.NewReader(pDataB), int64(len(pDataB)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart B failed: %v", err)
	}

	// Abort A
	if err := mgr1.AbortUpload(sA.UploadID); err != nil {
		t.Fatalf("AbortUpload A failed: %v", err)
	}

	// Complete B
	stream, _, _, err := mgr1.AssembleStream(sB, []CompletedPart{{PartNumber: 1, ETag: pB.ETag}})
	if err != nil {
		t.Fatalf("AssembleStream B failed: %v", err)
	}
	_ = stream.Close()
	if err := mgr1.FinalizeComplete(sB); err != nil {
		t.Fatalf("FinalizeComplete B failed: %v", err)
	}

	_ = mgr1.Close()
	_ = state1.Close()

	// Reopen
	state2, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState 2 failed: %v", err)
	}
	defer state2.Close()

	mgr2, err := NewMultipartManager(state2)
	if err != nil {
		t.Fatalf("NewMultipartManager 2 failed: %v", err)
	}
	defer mgr2.Close()

	if _, ok := mgr2.GetUpload(sA.UploadID); ok {
		t.Errorf("aborted upload %s should not exist after reopen", sA.UploadID)
	}
	if _, ok := mgr2.GetUpload(sB.UploadID); ok {
		t.Errorf("completed upload %s should not exist after reopen", sB.UploadID)
	}

	if state2.Budget.Used() != 0 {
		t.Errorf("expected 0 bytes used after reopen, got %d", state2.Budget.Used())
	}
}

func TestMultipartInterruptedCommitRetryable(t *testing.T) {
	dir := t.TempDir()
	state1, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}

	mgr1, err := NewMultipartManager(state1)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}

	session, err := mgr1.CreateUpload("default", "commit-retry.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	pData := bytes.Repeat([]byte("Z"), 5*1024*1024)
	part, err := mgr1.UploadPart(session, 1, bytes.NewReader(pData), int64(len(pData)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}

	// Assemble stream (starts commit)
	stream, _, _, err := mgr1.AssembleStream(session, []CompletedPart{{PartNumber: 1, ETag: part.ETag}})
	if err != nil {
		t.Fatalf("AssembleStream failed: %v", err)
	}

	// Simulate FTP failure: close stream without FinalizeComplete
	_ = stream.Close()

	// Shutdown server without completing
	_ = mgr1.Close()
	_ = state1.Close()

	// Reopen
	state2, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState 2 failed: %v", err)
	}
	defer state2.Close()

	mgr2, err := NewMultipartManager(state2)
	if err != nil {
		t.Fatalf("NewMultipartManager 2 failed: %v", err)
	}
	defer mgr2.Close()

	recovered, ok := mgr2.GetUpload(session.UploadID)
	if !ok {
		t.Fatal("session should remain available after interrupted commit")
	}

	// Retry assemble stream: must succeed!
	retryStream, _, _, err := mgr2.AssembleStream(recovered, []CompletedPart{{PartNumber: 1, ETag: part.ETag}})
	if err != nil {
		t.Fatalf("retry AssembleStream failed: %v", err)
	}
	_ = retryStream.Close()

	if err := mgr2.FinalizeComplete(recovered); err != nil {
		t.Fatalf("FinalizeComplete failed on retry: %v", err)
	}
}

func TestMultipartLifecycle(t *testing.T) {
	state := testState(t, 20*1024*1024*1024)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "test-multipart.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}
	if session.UploadID == "" {
		t.Fatal("UploadID should not be empty")
	}

	// Upload Part 1 (5MB)
	p1Data := bytes.Repeat([]byte("A"), 5*1024*1024)
	p1MD5 := md5.Sum(p1Data)
	p1Hex := hex.EncodeToString(p1MD5[:])
	p1, err := mgr.UploadPart(session, 1, bytes.NewReader(p1Data), int64(len(p1Data)), p1Hex, "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}
	if p1.ETag != fmt.Sprintf("\"%s\"", p1Hex) {
		t.Errorf("expected ETag %q, got %q", fmt.Sprintf("\"%s\"", p1Hex), p1.ETag)
	}

	// Upload Part 2 (5MB)
	p2Data := bytes.Repeat([]byte("B"), 5*1024*1024)
	p2MD5 := md5.Sum(p2Data)
	p2Hex := hex.EncodeToString(p2MD5[:])
	p2, err := mgr.UploadPart(session, 2, bytes.NewReader(p2Data), int64(len(p2Data)), p2Hex, "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 2 failed: %v", err)
	}

	// Upload Part 3 (10 bytes - final part may be < 5MB)
	p3Data := []byte("0123456789")
	p3MD5 := md5.Sum(p3Data)
	p3Hex := hex.EncodeToString(p3MD5[:])
	p3, err := mgr.UploadPart(session, 3, bytes.NewReader(p3Data), int64(len(p3Data)), p3Hex, "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 3 failed: %v", err)
	}

	// List parts
	parts, isTruncated, _, err := mgr.ListParts(session, 1000, 0)
	if err != nil {
		t.Fatalf("ListParts failed: %v", err)
	}
	if isTruncated {
		t.Error("expected not truncated")
	}
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Assemble stream
	completedParts := []CompletedPart{
		{PartNumber: 1, ETag: p1.ETag},
		{PartNumber: 2, ETag: p2.ETag},
		{PartNumber: 3, ETag: p3.ETag},
	}
	stream, s3ETag, totalSize, err := mgr.AssembleStream(session, completedParts)
	if err != nil {
		t.Fatalf("AssembleStream failed: %v", err)
	}
	defer stream.Close()

	if totalSize != int64(len(p1Data)+len(p2Data)+len(p3Data)) {
		t.Errorf("totalSize mismatch: got %d", totalSize)
	}

	combinedMD5 := md5.New()
	combinedMD5.Write(p1MD5[:])
	combinedMD5.Write(p2MD5[:])
	combinedMD5.Write(p3MD5[:])
	expectedETag := fmt.Sprintf("\"%x-3\"", combinedMD5.Sum(nil))
	if s3ETag != expectedETag {
		t.Errorf("expected s3ETag %s, got %s", expectedETag, s3ETag)
	}

	allBytes, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	expectedBytes := append(append(p1Data, p2Data...), p3Data...)
	if !bytes.Equal(allBytes, expectedBytes) {
		t.Error("assembled content mismatch")
	}

	if err := mgr.FinalizeComplete(session); err != nil {
		t.Fatalf("FinalizeComplete failed: %v", err)
	}
}

func TestMultipartEntityTooSmall(t *testing.T) {
	state := testState(t, 20*1024*1024*1024)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "small-parts.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	// Part 1 is only 1MB (< 5MB minimum for non-final part)
	p1Data := bytes.Repeat([]byte("X"), 1024*1024)
	p1, err := mgr.UploadPart(session, 1, bytes.NewReader(p1Data), int64(len(p1Data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 1 failed: %v", err)
	}

	p2Data := []byte("end")
	p2, err := mgr.UploadPart(session, 2, bytes.NewReader(p2Data), int64(len(p2Data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart 2 failed: %v", err)
	}

	parts := []CompletedPart{
		{PartNumber: 1, ETag: p1.ETag},
		{PartNumber: 2, ETag: p2.ETag},
	}
	_, _, _, err = mgr.AssembleStream(session, parts)
	if err != ErrEntityTooSmall {
		t.Fatalf("expected ErrEntityTooSmall, got %v", err)
	}
}

func TestMultipartAbortAndCleanup(t *testing.T) {
	state := testState(t, 20*1024*1024*1024)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "abort-me.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}
	uploadID := session.UploadID
	stagingDir := session.Dir

	p1Data := bytes.Repeat([]byte("Z"), 5*1024*1024)
	_, err = mgr.UploadPart(session, 1, bytes.NewReader(p1Data), int64(len(p1Data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}

	if _, err := os.Stat(stagingDir); os.IsNotExist(err) {
		t.Fatal("staging dir should exist before abort")
	}

	if err := mgr.AbortUpload(uploadID); err != nil {
		t.Fatalf("AbortUpload failed: %v", err)
	}

	if _, err := os.Stat(stagingDir); !os.IsNotExist(err) {
		t.Errorf("staging dir %s should be removed after abort", stagingDir)
	}

	if _, ok := mgr.GetUpload(uploadID); ok {
		t.Error("upload should not exist in manager after abort")
	}

	if state.Budget.Used() != 0 {
		t.Errorf("expected 0 budget used after abort, got %d", state.Budget.Used())
	}
}

func TestMultipartPartOverwritePruning(t *testing.T) {
	state := testState(t, 20*1024*1024*1024)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "overwrite.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	dataV1 := bytes.Repeat([]byte("1"), 5*1024*1024)
	p1, err := mgr.UploadPart(session, 1, bytes.NewReader(dataV1), int64(len(dataV1)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart v1 failed: %v", err)
	}
	oldPath := p1.Path

	dataV2 := bytes.Repeat([]byte("2"), 5*1024*1024)
	p2, err := mgr.UploadPart(session, 1, bytes.NewReader(dataV2), int64(len(dataV2)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart v2 failed: %v", err)
	}

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("old part file %s should be pruned after overwrite", oldPath)
	}
	if _, err := os.Stat(p2.Path); err != nil {
		t.Errorf("new part file %s should exist: %v", p2.Path, err)
	}
}

func TestMultipartConcurrentParts(t *testing.T) {
	state := testState(t, 20*1024*1024*1024)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "concurrent.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	const numParts = 5
	var wg sync.WaitGroup
	errCh := make(chan error, numParts)

	for i := 1; i <= numParts; i++ {
		wg.Add(1)
		go func(partNum int) {
			defer wg.Done()
			data := bytes.Repeat([]byte{byte('A' + partNum)}, 5*1024*1024)
			_, err := mgr.UploadPart(session, partNum, bytes.NewReader(data), int64(len(data)), "", "", "", "", "")
			if err != nil {
				errCh <- fmt.Errorf("part %d failed: %w", partNum, err)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}

	parts, _, _, err := mgr.ListParts(session, 1000, 0)
	if err != nil {
		t.Fatalf("ListParts failed: %v", err)
	}
	if len(parts) != numParts {
		t.Fatalf("expected %d parts, got %d", numParts, len(parts))
	}
}

func TestMultipartAbortUploadLockOrdering(t *testing.T) {
	state := testState(t, 20*1024*1024*1024)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "deadlock.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = mgr.AbortUpload(session.UploadID)
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected during concurrent AbortUpload")
	}
}

func TestMultipartExpirationPruning(t *testing.T) {
	state := testState(t, 20*1024*1024*1024)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "expired.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	data := bytes.Repeat([]byte("X"), 5*1024*1024)
	_, err = mgr.UploadPart(session, 1, bytes.NewReader(data), int64(len(data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}

	// Artificially age session
	session.Initiated = time.Now().Add(-25 * time.Hour)

	mgr.cleanupExpired(24 * time.Hour)

	if _, ok := mgr.GetUpload(session.UploadID); ok {
		t.Error("expected expired session to be pruned")
	}

	if state.Budget.Used() != 0 {
		t.Errorf("expected 0 bytes used after expiration pruning, got %d", state.Budget.Used())
	}
}

func TestMultipartUnknownLengthQuota(t *testing.T) {
	const maxCap = 10 * 1024 * 1024 // 10MB budget
	state := testState(t, maxCap)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	session, err := mgr.CreateUpload("default", "unknown-len.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	// Stream 12MB with contentLength = -1; must fail at 10MB budget limit
	oversizedData := bytes.Repeat([]byte("U"), 12*1024*1024)
	_, err = mgr.UploadPart(session, 1, bytes.NewReader(oversizedData), -1, "", "", "", "", "")
	if !errors.Is(err, ErrStagingLimitExceeded) {
		t.Fatalf("expected ErrStagingLimitExceeded for unknown length body, got %v", err)
	}

	// Budget must be rolled back completely
	if state.Budget.Used() != 0 {
		t.Fatalf("expected 0 budget used after failure, got %d", state.Budget.Used())
	}
}

func TestMultipartRecoveryRawMD5Validation(t *testing.T) {
	dir := t.TempDir()
	state1, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}

	mgr1, err := NewMultipartManager(state1)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}

	session, err := mgr1.CreateUpload("default", "rawmd5.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	data := bytes.Repeat([]byte("M"), 5*1024*1024)
	_, err = mgr1.UploadPart(session, 1, bytes.NewReader(data), int64(len(data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}

	manifestPath := filepath.Join(session.Dir, "manifest.json")
	_ = mgr1.Close()
	_ = state1.Close()

	// Read manifest, clear RawMD5, rewrite
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	// Replace "raw_md5":"..." with empty or missing
	corrupted := bytes.Replace(raw, []byte(`"raw_md5"`), []byte(`"ignored_md5"`), 1)
	if err := os.WriteFile(manifestPath, corrupted, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	state2, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState 2 failed: %v", err)
	}
	defer state2.Close()

	_, err = NewMultipartManager(state2)
	if err == nil {
		t.Fatal("expected NewMultipartManager to fail when raw_md5 is missing or invalid length")
	}
}

func TestMultipartRecoveryMismatchedPartNumber(t *testing.T) {
	dir := t.TempDir()
	state1, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState failed: %v", err)
	}

	mgr1, err := NewMultipartManager(state1)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}

	session, err := mgr1.CreateUpload("default", "mismatch-part.bin", ObjectMetadata{})
	if err != nil {
		t.Fatalf("CreateUpload failed: %v", err)
	}

	data := bytes.Repeat([]byte("P"), 5*1024*1024)
	_, err = mgr1.UploadPart(session, 1, bytes.NewReader(data), int64(len(data)), "", "", "", "", "")
	if err != nil {
		t.Fatalf("UploadPart failed: %v", err)
	}

	manifestPath := filepath.Join(session.Dir, "manifest.json")
	_ = mgr1.Close()
	_ = state1.Close()

	// Read manifest, change embedded PartNumber from 1 to 2
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var mf sessionManifest
	if err := json.Unmarshal(raw, &mf); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	mf.Parts[1].PartNumber = 2
	corrupted, err := json.Marshal(mf)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if err := os.WriteFile(manifestPath, corrupted, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	state2, err := OpenState(dir, "test-backend", 20*1024*1024*1024)
	if err != nil {
		t.Fatalf("OpenState 2 failed: %v", err)
	}
	defer state2.Close()

	_, err = NewMultipartManager(state2)
	if err == nil {
		t.Fatal("expected NewMultipartManager to fail when map key != part.PartNumber")
	}
}

func TestMultipartCreateUploadInvalidMetadata(t *testing.T) {
	state := testState(t, 20*1024*1024*1024)
	mgr, err := NewMultipartManager(state)
	if err != nil {
		t.Fatalf("NewMultipartManager failed: %v", err)
	}
	defer mgr.Close()

	// Invalid metadata: user metadata key too long (> 128 bytes)
	invalidKey := string(bytes.Repeat([]byte("k"), 2000))
	badMeta := ObjectMetadata{
		UserMetadata: map[string]string{invalidKey: "val"},
	}

	_, err = mgr.CreateUpload("default", "bad-meta.bin", badMeta)
	if err == nil {
		t.Fatal("expected CreateUpload to reject invalid metadata")
	}
}
