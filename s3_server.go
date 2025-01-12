package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

type S3Server struct {
	config *Config
	ftp    *FTPClient
}

func NewS3Server(config *Config) *S3Server {
	return &S3Server{
		config: config,
		ftp:    NewFTPClient(config),
	}
}

func (s *S3Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Debug("handling S3 request",
		"method", r.Method,
		"path", r.URL.Path,
		"query", r.URL.Query(),
	)

	switch r.Method {
	case http.MethodGet:
		// Check if this is a bucket listing request
		if strings.Count(r.URL.Path, "/") == 1 && r.URL.Query().Get("list-type") == "2" {
			bucket := strings.Trim(r.URL.Path, "/")
			if bucket == "default" {
				slog.Debug("handling ListObjectsV2 request for bucket", "bucket", bucket)
				s.handleListObjectsV2(w, r)
				return
			}
		}

		if r.URL.Path == "/" {
			if r.URL.Query().Get("list-type") == "2" {
				slog.Debug("handling ListObjectsV2 request")
				s.handleListObjectsV2(w, r)
			} else if r.URL.Query().Get("list-type") != "" || r.URL.Query().Get("prefix") != "" {
				slog.Debug("handling ListObjects request")
				s.handleListObjects(w, r)
			} else {
				slog.Debug("handling ListBuckets request")
				s.handleListBuckets(w, r)
			}
		} else if r.URL.Path == "/health" {
			slog.Debug("handling healthcheck request")
			w.Write([]byte("ok"))
			w.WriteHeader(http.StatusOK)
			return
		} else {
			slog.Debug("handling GetObject request", "path", r.URL.Path)
			s.handleGet(w, r)
		}
	case http.MethodHead:
		slog.Debug("handling HeadObject request", "path", r.URL.Path)
		s.handleHead(w, r)
	case http.MethodPut:
		slog.Debug("handling PutObject request", "path", r.URL.Path)
		s.handlePut(w, r)
	case http.MethodDelete:
		slog.Debug("handling DeleteObject request", "path", r.URL.Path)
		s.handleDelete(w, r)
	default:
		slog.Debug("method not allowed", "method", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// S3 XML response structures
type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"ListAllMyBucketsResult"`
	Owner   Owner    `xml:"Owner"`
	Buckets Buckets  `xml:"Buckets"`
}

type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type Buckets struct {
	Bucket []Bucket `xml:"Bucket"`
}

type Bucket struct {
	Name         string    `xml:"Name"`
	CreationDate time.Time `xml:"CreationDate"`
}

type ListBucketResult struct {
	XMLName  xml.Name   `xml:"ListBucketResult"`
	Name     string     `xml:"Name"`
	Prefix   string     `xml:"Prefix"`
	Marker   string     `xml:"Marker"`
	Contents []S3Object `xml:"Contents"`
}

type ListBucketV2Result struct {
	XMLName               xml.Name       `xml:"ListBucketResult"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	KeyCount              int            `xml:"KeyCount"`
	MaxKeys               int            `xml:"MaxKeys"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	IsTruncated           bool           `xml:"IsTruncated"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	Contents              []S3Object     `xml:"Contents"`
	CommonPrefixes        []CommonPrefix `xml:"CommonPrefixes,omitempty"`
}

type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

type S3Object struct {
	Key          string    `xml:"Key"`
	LastModified time.Time `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Size         int64     `xml:"Size"`
	StorageClass string    `xml:"StorageClass"`
}

func (s *S3Server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	result := ListAllMyBucketsResult{
		Owner: Owner{
			ID:          "ftp-over-s3",
			DisplayName: "ftp-over-s3",
		},
		Buckets: Buckets{
			Bucket: []Bucket{
				{
					Name:         "default",
					CreationDate: time.Now(),
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/xml")
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		slog.Error("failed to encode XML response", "error", err)
		return
	}
}

func (s *S3Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	bucket := strings.Trim(r.URL.Path, "/")
	if bucket == "" {
		bucket = "default"
	}

	slog.Debug("listing objects v2",
		"bucket", bucket,
		"prefix", prefix,
		"delimiter", delimiter,
	)

	result := ListBucketV2Result{
		Name:        bucket,
		Prefix:      prefix,
		Delimiter:   delimiter,
		MaxKeys:     1000,
		IsTruncated: false,
	}

	// Keep track of common prefixes to avoid duplicates
	commonPrefixes := make(map[string]bool)

	// Determine the FTP directory path from the prefix
	ftpPath := "."
	if prefix != "" {
		// Remove trailing slash if present for directory lookup
		ftpPath = strings.TrimSuffix(prefix, "/")
		if ftpPath == "" {
			ftpPath = "."
		}
	}

	slog.Debug("listing contents of FTP directory", "path", ftpPath)
	files, err := s.ftp.List(ftpPath)
	if err != nil {
		slog.Error("failed to list FTP directory",
			"path", ftpPath,
			"error", err,
		)
		// If the path doesn't exist, return empty list instead of error
		if strings.Contains(err.Error(), "550") {
			result.KeyCount = 0
			w.Header().Set("Content-Type", "application/xml")
			if err := xml.NewEncoder(w).Encode(result); err != nil {
				slog.Error("failed to encode XML response", "error", err)
			}
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Debug("found files in FTP directory",
		"path", ftpPath,
		"count", len(files),
	)

	for _, file := range files {
		slog.Debug("processing file",
			"name", file.Name,
			"size", file.Size,
			"modified", file.ModTime,
			"is_dir", file.IsDir,
			"path", ftpPath,
		)

		// Skip directory entries that start with "." (hidden files)
		if strings.HasPrefix(file.Name, ".") {
			continue
		}
		// Skip special directory entries
		if file.Name == "." || file.Name == ".." {
			continue
		}

		// Construct the full key path
		var name string
		if ftpPath == "." {
			name = file.Name
		} else {
			// If we're in a subdirectory, include the path
			name = ftpPath + "/" + file.Name
		}
		if file.IsDir {
			name = name + "/"
		}

		// Handle delimiter (usually "/" for directory-like listing)
		if delimiter != "" {
			// If there's a delimiter after the prefix, this is a CommonPrefix
			rest := strings.TrimPrefix(name, prefix)
			if i := strings.Index(rest, delimiter); i >= 0 {
				commonPrefix := prefix + rest[:i+1]
				if !commonPrefixes[commonPrefix] {
					commonPrefixes[commonPrefix] = true
					result.CommonPrefixes = append(result.CommonPrefixes, CommonPrefix{
						Prefix: commonPrefix,
					})
					slog.Debug("found common prefix", "prefix", commonPrefix)
				}
				continue
			}
		}

		result.Contents = append(result.Contents, S3Object{
			Key:          name,
			LastModified: file.ModTime,
			Size:         file.Size,
			ETag:         `"d41d8cd98f00b204e9800998ecf8427e"`, // Empty file MD5
			StorageClass: "STANDARD",
		})
	}

	result.KeyCount = len(result.Contents) + len(result.CommonPrefixes)

	w.Header().Set("Content-Type", "application/xml")
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		slog.Error("failed to encode XML response", "error", err)
		return
	}
}

func (s *S3Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	slog.Debug("listing objects",
		"prefix", prefix,
		"delimiter", delimiter,
	)

	// For simplicity, we'll treat the FTP root as a single bucket
	result := ListBucketResult{
		Name:   "default",
		Prefix: prefix,
		Marker: "",
	}

	// Determine the FTP directory path from the prefix
	ftpPath := "."
	if prefix != "" {
		// Remove trailing slash if present for directory lookup
		ftpPath = strings.TrimSuffix(prefix, "/")
		if ftpPath == "" {
			ftpPath = "."
		}
	}

	slog.Debug("listing contents of FTP directory", "path", ftpPath)
	files, err := s.ftp.List(ftpPath)
	if err != nil {
		slog.Error("failed to list FTP directory",
			"path", ftpPath,
			"error", err,
		)
		// If the path doesn't exist, return empty list instead of error
		if strings.Contains(err.Error(), "550") {
			w.Header().Set("Content-Type", "application/xml")
			if err := xml.NewEncoder(w).Encode(result); err != nil {
				slog.Error("failed to encode XML response", "error", err)
			}
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Debug("found files in FTP directory",
		"path", ftpPath,
		"count", len(files),
	)

	for _, file := range files {
		slog.Debug("processing file",
			"name", file.Name,
			"size", file.Size,
			"modified", file.ModTime,
			"is_dir", file.IsDir,
			"path", ftpPath,
		)

		// Skip directory entries that start with "." (hidden files)
		if strings.HasPrefix(file.Name, ".") {
			continue
		}
		// Skip special directory entries
		if file.Name == "." || file.Name == ".." {
			continue
		}

		// Construct the full key path
		var name string
		if ftpPath == "." {
			name = file.Name
		} else {
			// If we're in a subdirectory, include the path
			name = ftpPath + "/" + file.Name
		}
		if file.IsDir {
			name = name + "/"
		}

		result.Contents = append(result.Contents, S3Object{
			Key:          name,
			LastModified: file.ModTime,
			Size:         file.Size,
			ETag:         `"d41d8cd98f00b204e9800998ecf8427e"`, // Empty file MD5
			StorageClass: "STANDARD",
		})
	}

	w.Header().Set("Content-Type", "application/xml")
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		slog.Error("failed to encode XML response", "error", err)
		return
	}
}

func (s *S3Server) handleGet(w http.ResponseWriter, r *http.Request) {
	// Remove bucket prefix and leading slash
	path := strings.TrimPrefix(r.URL.Path, "/default/")
	slog.Debug("getting file from FTP", "path", path)

	// Convert empty path or "." to empty string for FTP
	if path == "." || path == "" {
		path = ""
	}

	reader, err := s.ftp.Get(path)
	if err != nil {
		slog.Error("failed to get file from FTP",
			"path", path,
			"error", err,
		)
		if strings.Contains(err.Error(), "550") {
			http.Error(w, "Key \""+path+"\" does not exist", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer reader.Close()

	// Set response headers
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`) // Empty file MD5

	slog.Debug("streaming file contents to client", "path", path)
	written, err := io.Copy(w, reader)
	if err != nil {
		slog.Error("failed to stream file contents",
			"path", path,
			"error", err,
		)
	} else {
		slog.Debug("successfully streamed file",
			"path", path,
			"bytes", written,
		)
	}
}

func (s *S3Server) handlePut(w http.ResponseWriter, r *http.Request) {
	// Remove bucket prefix and leading slash
	path := strings.TrimPrefix(r.URL.Path, "/default/")
	slog.Debug("putting file to FTP", "path", path)

	// Convert empty path or "." to empty string for FTP
	if path == "." || path == "" {
		path = ""
	}

	err := s.ftp.Put(path, r.Body)
	if err != nil {
		slog.Error("failed to put file to FTP",
			"path", path,
			"error", err,
		)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set response headers
	w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`) // Empty file MD5
	slog.Debug("successfully uploaded file", "path", path)
	w.WriteHeader(http.StatusOK)
}

func (s *S3Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	// Remove bucket prefix and leading slash
	path := strings.TrimPrefix(r.URL.Path, "/default/")
	slog.Debug("deleting file from FTP", "path", path)

	// Convert empty path or "." to empty string for FTP
	if path == "." || path == "" {
		path = ""
	}

	err := s.ftp.Delete(path)
	if err != nil {
		slog.Error("failed to delete file from FTP",
			"path", path,
			"error", err,
		)
		if strings.Contains(err.Error(), "550") {
			http.Error(w, "Key \""+path+"\" does not exist", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Debug("successfully deleted file", "path", path)
	w.WriteHeader(http.StatusNoContent)
}

func (s *S3Server) handleHead(w http.ResponseWriter, r *http.Request) {
	// Remove bucket prefix and leading slash
	path := strings.TrimPrefix(r.URL.Path, "/default/")
	slog.Debug("checking file on FTP", "path", path)

	// First, try to list the file to get its metadata
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// Convert directory path for FTP
	if dir == "." {
		dir = ""
	}

	slog.Debug("listing directory for HEAD",
		"dir", dir,
		"base", base,
	)

	files, err := s.ftp.List(dir)
	if err != nil {
		slog.Error("failed to list FTP directory",
			"path", dir,
			"error", err,
		)
		if strings.Contains(err.Error(), "550") {
			http.Error(w, "Key \""+path+"\" does not exist", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Look for the file in the directory listing
	for _, file := range files {
		slog.Debug("checking file",
			"name", file.Name,
			"looking_for", base,
			"size", file.Size,
			"is_dir", file.IsDir,
		)
		if file.Name == base {
			// File found, set headers
			w.Header().Set("Content-Length", fmt.Sprintf("%d", file.Size))
			w.Header().Set("Last-Modified", file.ModTime.UTC().Format(http.TimeFormat))
			w.Header().Set("ETag", `"d41d8cd98f00b204e9800998ecf8427e"`) // Empty file MD5
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// File not found
	http.Error(w, "Key \""+path+"\" does not exist", http.StatusNotFound)
}
