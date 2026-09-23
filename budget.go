package main

import (
	"errors"
	"io"
	"os"
	"sync"
)

// ErrStorageLimit is returned when disk budget reservation fails due to capacity exhaustion.
var ErrStorageLimit = errors.New("storage limit exceeded")

// DiskBudget tracks staged temporary bytes and multipart parts against a global maximum.
type DiskBudget struct {
	mu       sync.Mutex
	maxBytes int64
	used     int64
}

// NewDiskBudget creates a new DiskBudget with the specified maximum byte limit.
func NewDiskBudget(maxBytes int64) *DiskBudget {
	if maxBytes < 0 {
		maxBytes = 0
	}
	return &DiskBudget{
		maxBytes: maxBytes,
	}
}

// Reserve attempts to atomically reserve n bytes from the budget.
// It returns ErrStorageLimit if the reservation would exceed the maximum.
func (b *DiskBudget) Reserve(n int64) error {
	if n < 0 {
		return errors.New("negative byte reservation")
	}
	if n == 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxBytes <= 0 || b.used+n > b.maxBytes {
		return ErrStorageLimit
	}
	b.used += n
	return nil
}

// Release returns n bytes back to the budget.
func (b *DiskBudget) Release(n int64) {
	if n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.used -= n
	if b.used < 0 {
		b.used = 0
	}
}

// Used returns the current number of bytes reserved in the budget.
func (b *DiskBudget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Max returns the total configured byte limit.
func (b *DiskBudget) Max() int64 {
	return b.maxBytes
}

// SpoolFile provides a quota-enforced temporary spool file that implements
// io.ReadWriteSeeker, io.Closer, Name() string, and Size() int64.
// It does not embed os.File so all writes are guaranteed to reserve quota before writing.
type SpoolFile struct {
	file      *os.File
	budget    *DiskBudget
	reserved  int64
	size      int64
	closed    bool
	closeOnce sync.Once
	mu        sync.Mutex
}

// NewSpoolFile creates a temporary spool file in dir backed by budget.
func NewSpoolFile(dir string, budget *DiskBudget) (*SpoolFile, error) {
	if budget == nil {
		return nil, errors.New("nil disk budget")
	}
	if dir == "" {
		return nil, errors.New("empty spool directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "spool-*")
	if err != nil {
		return nil, err
	}
	return &SpoolFile{
		file:   f,
		budget: budget,
	}, nil
}

// Write reserves quota before writing data to disk.
// If the write fails or is short, excess reserved bytes are immediately released.
func (s *SpoolFile) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, os.ErrClosed
	}

	curPos, err := s.file.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	writeEnd := curPos + int64(len(p))
	var needed int64
	if writeEnd > s.size {
		needed = writeEnd - s.size
	}

	if needed > 0 {
		if s.budget == nil {
			return 0, errors.New("nil disk budget")
		}
		if err := s.budget.Reserve(needed); err != nil {
			return 0, err
		}
	}

	n, wErr := s.file.Write(p)
	var actualGrowth int64
	newPos := curPos + int64(n)
	if newPos > s.size {
		actualGrowth = newPos - s.size
		s.size = newPos
	}

	excess := needed - actualGrowth
	if excess > 0 && s.budget != nil {
		s.budget.Release(excess)
	}
	s.reserved += actualGrowth

	return n, wErr
}

// Read reads from the underlying temporary file.
func (s *SpoolFile) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, os.ErrClosed
	}
	return s.file.Read(p)
}

// Seek sets the offset for the next Read or Write.
func (s *SpoolFile) Seek(offset int64, whence int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, os.ErrClosed
	}
	return s.file.Seek(offset, whence)
}

// Close closes the file, removes it from disk, and releases all reserved bytes back to budget once.
func (s *SpoolFile) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		if s.file != nil {
			closeErr = s.file.Close()
			_ = os.Remove(s.file.Name())
		}
		if s.reserved > 0 && s.budget != nil {
			s.budget.Release(s.reserved)
			s.reserved = 0
		}
	})
	return closeErr
}

// Name returns the filesystem path of the temporary file.
func (s *SpoolFile) Name() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return ""
	}
	return s.file.Name()
}

// Size returns the maximum byte offset written to this spool file.
func (s *SpoolFile) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}
