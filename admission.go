package main

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"
)

// ErrSlowDown indicates that the upload concurrency limit has been reached.
var ErrSlowDown = errors.New("slow down")

// UploadAdmission limits concurrent uploads and tracks request spool resources.
type UploadAdmission struct {
	state      *State
	spoolDir   string
	budget     *DiskBudget
	sem        chan struct{}
	timeout    time.Duration
	maxUploads int
}

// NewUploadAdmission constructs an admission controller bounded by maxUploads and timeout.
func NewUploadAdmission(state *State, maxUploads int, timeout time.Duration) *UploadAdmission {
	if maxUploads <= 0 {
		maxUploads = 16
	}
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	var spoolDir string
	var budget *DiskBudget
	if state != nil {
		spoolDir = filepath.Join(state.Root, "spool")
		budget = state.Budget
	}
	return &UploadAdmission{
		state:      state,
		spoolDir:   spoolDir,
		budget:     budget,
		sem:        make(chan struct{}, maxUploads),
		timeout:    timeout,
		maxUploads: maxUploads,
	}
}

// SpoolDir returns the staging spool directory.
func (a *UploadAdmission) SpoolDir() string {
	if a == nil {
		return ""
	}
	return a.spoolDir
}

// Budget returns the disk budget for staging.
func (a *UploadAdmission) Budget() *DiskBudget {
	if a == nil {
		return nil
	}
	return a.budget
}

// Timeout returns the configured upload operation timeout.
func (a *UploadAdmission) Timeout() time.Duration {
	if a == nil {
		return 15 * time.Minute
	}
	return a.timeout
}

// InFlight returns the number of active upload slots in use.
func (a *UploadAdmission) InFlight() int {
	if a == nil {
		return 0
	}
	return len(a.sem)
}

// Acquire reserves an upload execution slot without blocking if capacity is exceeded.
// It returns an idempotent release callback on success, or ErrSlowDown if at capacity.
func (a *UploadAdmission) Acquire(ctx context.Context) (func(), error) {
	if a == nil {
		return func() {}, nil
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	select {
	case a.sem <- struct{}{}:
		var once sync.Once
		release := func() {
			once.Do(func() {
				<-a.sem
			})
		}
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, ErrSlowDown
	}
}
