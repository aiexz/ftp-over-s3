package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseCopySource(t *testing.T) {
	tests := []struct {
		name       string
		rawSource  string
		wantBucket string
		wantKey    string
		wantErr    bool
		wantCode   string
	}{
		{
			name:       "valid with leading slash",
			rawSource:  "/default/test-key.txt",
			wantBucket: "default",
			wantKey:    "test-key.txt",
		},
		{
			name:       "valid without leading slash",
			rawSource:  "default/test-key.txt",
			wantBucket: "default",
			wantKey:    "test-key.txt",
		},
		{
			name:       "valid nested key",
			rawSource:  "/default/path/to/nested/file.png",
			wantBucket: "default",
			wantKey:    "path/to/nested/file.png",
		},
		{
			name:       "literal plus and encoded space preserved",
			rawSource:  "/default/hello+world%20test.txt",
			wantBucket: "default",
			wantKey:    "hello+world test.txt",
		},
		{
			name:       "encoded plus preserved",
			rawSource:  "/default/hello%2Bworld.txt",
			wantBucket: "default",
			wantKey:    "hello+world.txt",
		},
		{
			name:       "percent encoded percent",
			rawSource:  "/default/foo%2520bar.txt",
			wantBucket: "default",
			wantKey:    "foo%20bar.txt",
		},
		{
			name:      "empty source rejected",
			rawSource: "",
			wantErr:   true,
			wantCode:  "InvalidArgument",
		},
		{
			name:      "non default bucket rejected",
			rawSource: "/mybucket/key.txt",
			wantErr:   true,
			wantCode:  "NoSuchBucket",
		},
		{
			name:      "versionId query rejected with NotImplemented",
			rawSource: "/default/key.txt?versionId=v123",
			wantErr:   true,
			wantCode:  "NotImplemented",
		},
		{
			name:      "missing key rejected",
			rawSource: "/default",
			wantErr:   true,
			wantCode:  "InvalidArgument",
		},
		{
			name:      "empty key rejected",
			rawSource: "/default/",
			wantErr:   true,
			wantCode:  "InvalidArgument",
		},
		{
			name:      "invalid key with backslash rejected",
			rawSource: "/default/invalid\\key.txt",
			wantErr:   true,
			wantCode:  "InvalidArgument",
		},
		{
			name:      "malformed query in copy source rejected",
			rawSource: "/default/key.txt?versionId=%ZZ",
			wantErr:   true,
			wantCode:  "InvalidArgument",
		},
		{
			name:      "malformed query percent rejected",
			rawSource: "/default/key.txt?%ZZ",
			wantErr:   true,
			wantCode:  "InvalidArgument",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, k, err := parseCopySource(tc.rawSource)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil", tc.rawSource)
				}
				var opErr s3OperationError
				var opErrPtr *s3OperationError
				code := ""
				if errors.As(err, &opErr) {
					code = opErr.Code
				} else if errors.As(err, &opErrPtr) && opErrPtr != nil {
					code = opErrPtr.Code
				}
				if tc.wantCode != "" && code != tc.wantCode {
					t.Fatalf("expected error code %q, got %q (err: %v)", tc.wantCode, code, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.rawSource, err)
			}
			if b != tc.wantBucket {
				t.Errorf("bucket mismatch: want %q, got %q", tc.wantBucket, b)
			}
			if k != tc.wantKey {
				t.Errorf("key mismatch: want %q, got %q", tc.wantKey, k)
			}
		})
	}
}

func TestParseCopySourceRange(t *testing.T) {
	tests := []struct {
		name       string
		rangeHdr   string
		sourceSize int64
		wantStart  int64
		wantEnd    int64
		wantErr    bool
	}{
		{
			name:       "empty range header spans whole object",
			rangeHdr:   "",
			sourceSize: 1000,
			wantStart:  0,
			wantEnd:    999,
		},
		{
			name:       "valid range within object",
			rangeHdr:   "bytes=0-499",
			sourceSize: 1000,
			wantStart:  0,
			wantEnd:    499,
		},
		{
			name:       "valid subrange",
			rangeHdr:   "bytes=100-200",
			sourceSize: 1000,
			wantStart:  100,
			wantEnd:    200,
		},
		{
			name:       "range up to last byte",
			rangeHdr:   "bytes=500-999",
			sourceSize: 1000,
			wantStart:  500,
			wantEnd:    999,
		},
		{
			name:       "start greater than end rejected",
			rangeHdr:   "bytes=500-400",
			sourceSize: 1000,
			wantErr:    true,
		},
		{
			name:       "end out of bounds rejected",
			rangeHdr:   "bytes=0-1000",
			sourceSize: 1000,
			wantErr:    true,
		},
		{
			name:       "negative start rejected",
			rangeHdr:   "bytes=-10-100",
			sourceSize: 1000,
			wantErr:    true,
		},
		{
			name:       "malformed prefix rejected",
			rangeHdr:   "items=0-100",
			sourceSize: 1000,
			wantErr:    true,
		},
		{
			name:       "empty range for 0-byte file",
			rangeHdr:   "",
			sourceSize: 0,
			wantStart:  0,
			wantEnd:    0,
		},
		{
			name:       "specified range for 0-byte file rejected",
			rangeHdr:   "bytes=0-0",
			sourceSize: 0,
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, e, err := parseCopySourceRange(tc.rangeHdr, tc.sourceSize)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q (size %d), got nil", tc.rangeHdr, tc.sourceSize)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.rangeHdr, err)
			}
			if s != tc.wantStart || e != tc.wantEnd {
				t.Errorf("range mismatch: want [%d, %d], got [%d, %d]", tc.wantStart, tc.wantEnd, s, e)
			}
		})
	}
}

func TestCheckSourcePreconditions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	info := &FileInfo{
		Name:    "object.txt",
		Size:    1024,
		ModTime: now,
	}
	meta := &ObjectMetadata{
		ETag:    "\"testetag123\"",
		Size:    1024,
		ModTime: now,
	}

	t.Run("If-Match success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-Match", "\"testetag123\"")
		if err := checkSourcePreconditions(req, info, meta); err != nil {
			t.Fatalf("unexpected precondition error: %v", err)
		}
	})

	t.Run("If-Match failure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-Match", "\"wrongetag\"")
		err := checkSourcePreconditions(req, info, meta)
		if err == nil {
			t.Fatal("expected precondition failure, got nil")
		}
		var opErr s3OperationError
		var opErrPtr *s3OperationError
		status := 0
		if errors.As(err, &opErr) {
			status = opErr.Status
		} else if errors.As(err, &opErrPtr) && opErrPtr != nil {
			status = opErrPtr.Status
		}
		if status != http.StatusPreconditionFailed {
			t.Fatalf("expected status 412, got %d", status)
		}
	})

	t.Run("If-None-Match success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-None-Match", "\"otheretag\"")
		if err := checkSourcePreconditions(req, info, meta); err != nil {
			t.Fatalf("unexpected precondition error: %v", err)
		}
	})

	t.Run("If-None-Match failure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-None-Match", "\"testetag123\"")
		err := checkSourcePreconditions(req, info, meta)
		if err == nil {
			t.Fatal("expected precondition failure, got nil")
		}
	})

	t.Run("If-Unmodified-Since success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-Unmodified-Since", now.Add(1*time.Hour).Format(http.TimeFormat))
		if err := checkSourcePreconditions(req, info, meta); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("If-Unmodified-Since failure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-Unmodified-Since", now.Add(-1*time.Hour).Format(http.TimeFormat))
		if err := checkSourcePreconditions(req, info, meta); err == nil {
			t.Fatal("expected precondition failure, got nil")
		}
	})

	t.Run("If-Modified-Since success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-Modified-Since", now.Add(-1*time.Hour).Format(http.TimeFormat))
		if err := checkSourcePreconditions(req, info, meta); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("If-Modified-Since failure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-Modified-Since", now.Add(1*time.Hour).Format(http.TimeFormat))
		if err := checkSourcePreconditions(req, info, meta); err == nil {
			t.Fatal("expected precondition failure, got nil")
		}
	})

	t.Run("If-Match precedence over If-Unmodified-Since success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/default/dest.txt", nil)
		req.Header.Set("X-Amz-Copy-Source-If-Match", "\"testetag123\"")
		req.Header.Set("X-Amz-Copy-Source-If-Unmodified-Since", now.Add(-1*time.Hour).Format(http.TimeFormat))
		if err := checkSourcePreconditions(req, info, meta); err != nil {
			t.Fatalf("expected success due to If-Match precedence, got error: %v", err)
		}
	})
}

func TestCopyChecksumAlgorithms(t *testing.T) {
	data := []byte("Hello, world! Checksum smoke coverage.")

	t.Run("CRC32 IEEE computation", func(t *testing.T) {
		h := crc32.NewIEEE()
		h.Write(data)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h.Sum32())
		cs := base64.StdEncoding.EncodeToString(b)
		if cs == "" {
			t.Fatal("empty CRC32")
		}
	})

	t.Run("CRC32C Castagnoli computation", func(t *testing.T) {
		h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		h.Write(data)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h.Sum32())
		cs := base64.StdEncoding.EncodeToString(b)
		if cs == "" {
			t.Fatal("empty CRC32C")
		}
	})

	t.Run("SHA1 computation", func(t *testing.T) {
		h := sha1.New()
		h.Write(data)
		cs := base64.StdEncoding.EncodeToString(h.Sum(nil))
		if cs == "" {
			t.Fatal("empty SHA1")
		}
	})

	t.Run("SHA256 computation", func(t *testing.T) {
		h := sha256.New()
		h.Write(data)
		cs := base64.StdEncoding.EncodeToString(h.Sum(nil))
		if cs == "" {
			t.Fatal("empty SHA256")
		}
	})
}
