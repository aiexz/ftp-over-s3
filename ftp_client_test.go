package main

import (
	"errors"
	"net/textproto"
	"os"
	"testing"
	"time"
)

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		isList  bool
		want    string
		wantErr bool
		errIs   error
	}{
		// Valid keys and ordinary dotfiles
		{"simple file", "file.txt", false, "file.txt", false, nil},
		{"nested file", "nested/deeper/data.bin", false, "nested/deeper/data.bin", false, nil},
		{"leading slash", "/nested/alpha.txt", false, "nested/alpha.txt", false, nil},
		{"hidden dotfile", ".hidden", false, ".hidden", false, nil},
		{"gitignore dotfile", ".gitignore", false, ".gitignore", false, nil},
		{"nested dotfile", "nested/.env", false, "nested/.env", false, nil},
		{"utf8 and symbols", "space + percent%/日本語.txt", false, "space + percent%/日本語.txt", false, nil},
		{"empty file name", "empty", false, "empty", false, nil},

		// List root normalization
		{"list empty root", "", true, ".", false, nil},
		{"list dot root", ".", true, ".", false, nil},
		{"list slash root", "/", true, ".", false, nil},
		{"list directory trailing slash", "nested/", true, "nested", false, nil},

		// Dot segment traversal rejections
		{"traversal parent prefix", "../foo", false, "", true, os.ErrInvalid},
		{"traversal parent suffix", "foo/..", false, "", true, os.ErrInvalid},
		{"traversal parent middle", "foo/../bar", false, "", true, os.ErrInvalid},
		{"current dir segment middle", "foo/./bar", false, "", true, os.ErrInvalid},
		{"current dir segment prefix", "./foo", false, "", true, os.ErrInvalid},
		{"current dir segment suffix", "foo/.", false, "", true, os.ErrInvalid},
		{"list with dot segment", "./", true, "", true, os.ErrInvalid},

		// Control character rejections
		{"newline control char", "foo\nbar", false, "", true, os.ErrInvalid},
		{"carriage return", "foo\rbar", false, "", true, os.ErrInvalid},
		{"null byte", "foo\x00bar", false, "", true, os.ErrInvalid},
		{"tab control char", "foo\tbar", false, "", true, os.ErrInvalid},
		{"del control char", "foo\x7fbar", false, "", true, os.ErrInvalid},

		// Repeated slashes
		{"double slash middle", "foo//bar", false, "", true, os.ErrInvalid},
		{"double slash prefix", "//foo", false, "", true, os.ErrInvalid},

		// Reserved internal names
		{"reserved prefix root", ".ftp-over-s3-tmp", false, "", true, os.ErrInvalid},
		{"reserved prefix nested", "nested/.ftp-over-s3-upload", false, "", true, os.ErrInvalid},

		// Object path boundaries
		{"object trailing slash", "dir/", false, "", true, os.ErrInvalid},
		{"empty object path", "", false, "", true, os.ErrInvalid},
		{"root slash object path", "/", false, "", true, os.ErrInvalid},
		{"dot object path", ".", false, "", true, os.ErrInvalid},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validatePath(tc.path, tc.isList)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validatePath(%q, %v) expected error, got nil", tc.path, tc.isList)
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Fatalf("validatePath(%q, %v) error = %v, want errors.Is %v", tc.path, tc.isList, err, tc.errIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("validatePath(%q, %v) unexpected error: %v", tc.path, tc.isList, err)
			}
			if got != tc.want {
				t.Fatalf("validatePath(%q, %v) = %q, want %q", tc.path, tc.isList, got, tc.want)
			}
		})
	}
}

func TestFTPClientConnectionLimit(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		limit  int
	}{
		{"default limit", &Config{}, defaultMaxConnections},
		{"configured limit", &Config{FTPMaxConnections: 3}, 3},
		{"non-positive falls back to default", &Config{FTPMaxConnections: -1}, defaultMaxConnections},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewFTPClient(tc.config)
			if cap(c.sem) != tc.limit {
				t.Fatalf("connection limit = %d, want %d", cap(c.sem), tc.limit)
			}

			for i := 0; i < tc.limit; i++ {
				c.acquire()
			}

			acquired := make(chan struct{})
			go func() {
				c.acquire()
				close(acquired)
				c.release()
			}()

			select {
			case <-acquired:
				t.Fatal("acquired more connection slots than the configured limit")
			case <-time.After(100 * time.Millisecond):
			}

			c.release()
			select {
			case <-acquired:
			case <-time.After(2 * time.Second):
				t.Fatal("released slot was not handed to a waiting operation")
			}

			for i := 0; i < tc.limit-1; i++ {
				c.release()
			}
		})
	}
}

func TestWrapFTPError_Classification(t *testing.T) {
	c := NewFTPClient(&Config{})

	tests := []struct {
		name     string
		err      error
		wantIs   error
		wantCode int
	}{
		{
			name:     "550 Permission denied",
			err:      &textproto.Error{Code: 550, Msg: "550 Permission denied"},
			wantIs:   os.ErrPermission,
			wantCode: 550,
		},
		{
			name:     "550 File not found",
			err:      &textproto.Error{Code: 550, Msg: "550 File not found"},
			wantIs:   os.ErrNotExist,
			wantCode: 550,
		},
		{
			name:     "530 Not logged in",
			err:      &textproto.Error{Code: 530, Msg: "530 Not logged in"},
			wantIs:   os.ErrPermission,
			wantCode: 530,
		},
		{
			name:     "553 Bad filename",
			err:      &textproto.Error{Code: 553, Msg: "553 File name not allowed"},
			wantIs:   os.ErrInvalid,
			wantCode: 553,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := c.wrapFTPError(nil, "file.txt", tc.err)
			if !errors.Is(wrapped, tc.wantIs) {
				t.Fatalf("wrapFTPError() error = %v, want errors.Is %v", wrapped, tc.wantIs)
			}
			var protoErr *textproto.Error
			if !errors.As(wrapped, &protoErr) || protoErr.Code != tc.wantCode {
				t.Fatalf("expected textproto.Error with code %d preserved via errors.As", tc.wantCode)
			}
		})
	}
}
