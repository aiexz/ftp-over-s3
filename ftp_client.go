package main

import (
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/jlaffaye/ftp"
)

type FTPClient struct {
	config *Config
	conn   *ftp.ServerConn
}

type FileInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
}

func NewFTPClient(config *Config) *FTPClient {
	return &FTPClient{
		config: config,
	}
}

func (c *FTPClient) connect() error {
	if c.conn != nil {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", c.config.FTPHost, c.config.FTPPort)
	slog.Debug("connecting to FTP server", "address", addr)

	conn, err := ftp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to FTP server: %v", err)
	}

	slog.Debug("logging into FTP server", "username", c.config.FTPUser)
	err = conn.Login(c.config.FTPUser, c.config.FTPPassword)
	if err != nil {
		conn.Quit()
		return fmt.Errorf("failed to login to FTP server: %v", err)
	}

	c.conn = conn
	return nil
}

func (c *FTPClient) List(path string) ([]FileInfo, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	// Clean the path and remove leading slash
	path = strings.TrimPrefix(filepath.Clean(path), "/")
	if path == "" {
		path = "."
	}

	slog.Debug("listing FTP directory", "path", path)

	entries, err := c.conn.List(path)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %v", err)
	}

	var files []FileInfo
	for _, entry := range entries {
		// Skip entries we don't want to show
		if entry.Name == "." || entry.Name == ".." {
			continue
		}

		slog.Debug("processing FTP entry",
			"name", entry.Name,
			"size", entry.Size,
			"type", entry.Type,
			"time", entry.Time,
		)

		files = append(files, FileInfo{
			Name:    entry.Name,
			Size:    int64(entry.Size),
			ModTime: entry.Time,
			IsDir:   entry.Type == ftp.EntryTypeFolder,
		})
	}

	return files, nil
}

func (c *FTPClient) Get(path string) (io.ReadCloser, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	// Clean the path and remove leading slash
	path = strings.TrimPrefix(filepath.Clean(path), "/")
	slog.Debug("retrieving file from FTP", "path", path)

	return c.conn.Retr(path)
}

func (c *FTPClient) Put(path string, reader io.Reader) error {
	if err := c.connect(); err != nil {
		return err
	}

	// Clean the path and remove leading slash
	path = strings.TrimPrefix(filepath.Clean(path), "/")
	slog.Debug("storing file to FTP", "path", path)

	// Create parent directories if they don't exist
	dir := filepath.Dir(path)
	if dir != "." {
		if err := c.createDirectories(dir); err != nil {
			return fmt.Errorf("failed to create directories: %v", err)
		}
	}

	return c.conn.Stor(path, reader)
}

func (c *FTPClient) Delete(path string) error {
	if err := c.connect(); err != nil {
		return err
	}

	// Clean the path and remove leading slash
	path = strings.TrimPrefix(filepath.Clean(path), "/")
	slog.Debug("deleting file from FTP", "path", path)

	return c.conn.Delete(path)
}

func (c *FTPClient) createDirectories(path string) error {
	// Split path into components and remove leading slash
	path = strings.TrimPrefix(filepath.Clean(path), "/")
	parts := strings.Split(path, "/")
	current := ""

	for _, part := range parts {
		if part == "" {
			continue
		}
		if current == "" {
			current = part
		} else {
			current = current + "/" + part
		}
		slog.Debug("creating FTP directory", "path", current)

		// Try to create directory, ignore "already exists" errors
		err := c.conn.MakeDir(current)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}

	return nil
}
