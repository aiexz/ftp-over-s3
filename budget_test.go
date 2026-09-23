package main

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"
)

func TestDiskBudget_SimultaneousReservations(t *testing.T) {
	const (
		maxBytes     = int64(10000)
		numWorkers   = 50
		reservations = 20
		chunkSize    = int64(50)
	)

	b := NewDiskBudget(maxBytes)

	var wg sync.WaitGroup
	var successCount int64
	var mu sync.Mutex
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < reservations; j++ {
				err := b.Reserve(chunkSize)
				if err == nil {
					mu.Lock()
					successCount++
					mu.Unlock()
				} else if !errors.Is(err, ErrStorageLimit) {
					t.Errorf("expected ErrStorageLimit on exhaustion, got %v", err)
				}
			}
		}()
	}

	wg.Wait()

	used := b.Used()
	if used > maxBytes {
		t.Fatalf("quota exceeded: used %d > max %d", used, maxBytes)
	}
	expectedUsed := successCount * chunkSize
	if used != expectedUsed {
		t.Fatalf("used %d does not match expected %d (successes: %d)", used, expectedUsed, successCount)
	}
	for i := int64(0); i < successCount; i++ {
		b.Release(chunkSize)
	}
	if b.Used() != 0 {
		t.Fatalf("expected 0 used after releasing all, got %d", b.Used())
	}
}

func TestSpoolFile_NoOvershootOnFailedWrites(t *testing.T) {
	dir := t.TempDir()
	const maxCap = int64(500)
	b := NewDiskBudget(maxCap)

	spool, err := NewSpoolFile(dir, b)
	if err != nil {
		t.Fatalf("failed to create spool file: %v", err)
	}
	defer spool.Close()

	// Write 300 bytes - should succeed
	data := make([]byte, 300)
	n, err := spool.Write(data)
	if err != nil || n != 300 {
		t.Fatalf("expected 300 bytes written, got %d, err: %v", n, err)
	}
	if b.Used() != 300 {
		t.Fatalf("expected 300 bytes used in budget, got %d", b.Used())
	}

	// Attempt to write 300 more bytes - would exceed 500 cap
	overshootData := make([]byte, 300)
	_, err = spool.Write(overshootData)
	if !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("expected ErrStorageLimit, got %v", err)
	}

	// Verify no overshoot: budget must still be exactly 300
	if b.Used() != 300 {
		t.Fatalf("budget overshoot after failed write: expected 300, got %d", b.Used())
	}

	// Write 200 bytes - exactly hits 500 cap
	fillData := make([]byte, 200)
	n, err = spool.Write(fillData)
	if err != nil || n != 200 {
		t.Fatalf("expected 200 bytes written, got %d, err: %v", n, err)
	}
	if b.Used() != 500 {
		t.Fatalf("expected exactly 500 bytes used, got %d", b.Used())
	}

	// Any further write must fail
	_, err = spool.Write([]byte("a"))
	if !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("expected ErrStorageLimit at exact capacity, got %v", err)
	}
	if b.Used() != 500 {
		t.Fatalf("expected 500 bytes used, got %d", b.Used())
	}
}

func TestSpoolFile_CloseCleansAndReclaimsOnce(t *testing.T) {
	dir := t.TempDir()
	b := NewDiskBudget(1000)

	spool, err := NewSpoolFile(dir, b)
	if err != nil {
		t.Fatalf("failed to create spool file: %v", err)
	}

	filePath := spool.Name()
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("expected spool file to exist on disk: %v", err)
	}

	data := []byte("hello quota world")
	if _, err := spool.Write(data); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if b.Used() != int64(len(data)) {
		t.Fatalf("expected %d used, got %d", len(data), b.Used())
	}

	// Close first time
	if err := spool.Close(); err != nil {
		t.Fatalf("first close failed: %v", err)
	}

	// Verify file is removed
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("expected spool file to be deleted from disk on close")
	}

	// Verify budget is reclaimed
	if b.Used() != 0 {
		t.Fatalf("expected budget 0 after close, got %d", b.Used())
	}

	// Close second and third time - must be idempotent and not release budget twice
	if err := spool.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
	if err := spool.Close(); err != nil {
		t.Fatalf("third close failed: %v", err)
	}
	if b.Used() != 0 {
		t.Fatalf("budget must remain 0 after duplicate close, got %d", b.Used())
	}
}

func TestSpoolFile_SeekAndOverwriteDoesNotReReserve(t *testing.T) {
	dir := t.TempDir()
	b := NewDiskBudget(1000)

	spool, err := NewSpoolFile(dir, b)
	if err != nil {
		t.Fatalf("failed to create spool file: %v", err)
	}
	defer spool.Close()

	data := []byte("0123456789") // 10 bytes
	if _, err := spool.Write(data); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if b.Used() != 10 {
		t.Fatalf("expected 10 used, got %d", b.Used())
	}

	// Seek back to offset 2 and overwrite 4 bytes
	if _, err := spool.Seek(2, io.SeekStart); err != nil {
		t.Fatalf("seek failed: %v", err)
	}
	if _, err := spool.Write([]byte("ABCD")); err != nil {
		t.Fatalf("overwrite failed: %v", err)
	}

	// Budget must still be exactly 10 because file did not grow
	if b.Used() != 10 {
		t.Fatalf("overwrite within bounds re-reserved quota: expected 10, got %d", b.Used())
	}
	if spool.Size() != 10 {
		t.Fatalf("expected size 10, got %d", spool.Size())
	}

	// Seek to beginning and read back full content
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek failed: %v", err)
	}
	buf := make([]byte, 10)
	if _, err := io.ReadFull(spool, buf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	expected := "01ABCD6789"
	if string(buf) != expected {
		t.Fatalf("expected %q, got %q", expected, string(buf))
	}
}
