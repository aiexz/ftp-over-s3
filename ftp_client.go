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

func (c *FTPClient) reconnect() error {
	if c.conn != nil {
		c.conn.Quit()
		c.conn = nil
	}
	return c.connect()
}

func (c *FTPClient) handleConnectionError(err error) error {
	if err == nil {
		return nil
	}

	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "broken pipe") ||
		strings.Contains(errMsg, "connection reset") ||
		strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "i/o timeout") ||
		strings.Contains(errMsg, "no connection") ||
		strings.Contains(errMsg, "connection closed") {
		slog.Debug("connection error detected, attempting reconnect", "error", err)
		return c.reconnect()
	}
	return err
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
		if reconnErr := c.handleConnectionError(err); reconnErr != nil {
			return nil, fmt.Errorf("failed to list directory: %v", err)
		}
		// Try again after reconnection
		entries, err = c.conn.List(path)
		if err != nil {
			return nil, fmt.Errorf("failed to list directory after reconnect: %v", err)
		}
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

	reader, err := c.conn.Retr(path)
	if err != nil {
		if reconnErr := c.handleConnectionError(err); reconnErr != nil {
			return nil, err
		}
		// Try again after reconnection
		reader, err = c.conn.Retr(path)
		if err != nil {
			return nil, err
		}
	}
	return reader, nil
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
			if reconnErr := c.handleConnectionError(err); reconnErr != nil {
				return fmt.Errorf("failed to create directories: %v", err)
			}
			// Try creating directories again after reconnection
			if err := c.createDirectories(dir); err != nil {
				return fmt.Errorf("failed to create directories after reconnect: %v", err)
			}
		}
	}

	err := c.conn.Stor(path, reader)
	if err != nil {
		if reconnErr := c.handleConnectionError(err); reconnErr != nil {
			return err
		}
		// Try storing again after reconnection
		err = c.conn.Stor(path, reader)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *FTPClient) Delete(path string) error {
	if err := c.connect(); err != nil {
		return err
	}

	// Clean the path and remove leading slash
	path = strings.TrimPrefix(filepath.Clean(path), "/")
	slog.Debug("deleting file from FTP", "path", path)

	err := c.conn.Delete(path)
	if err != nil {
		if reconnErr := c.handleConnectionError(err); reconnErr != nil {
			return err
		}
		// Try deleting again after reconnection
		err = c.conn.Delete(path)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *FTPClient) directoryExists(path string) bool {
	if path == "" || path == "." {
		return true
	}

	// Try to list the directory
	entries, err := c.conn.List(path)
	if err != nil {
		return false
	}
	return len(entries) >= 0 // If we can list it, it exists
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
		slog.Debug("checking directory", "path", current)

		// First check if directory exists
		if c.directoryExists(current) {
			slog.Debug("directory already exists", "path", current)
			continue
		}

		slog.Debug("creating FTP directory", "path", current)
		err := c.conn.MakeDir(current)
		if err != nil {
			// Even if we checked, the directory might have been created in the meantime
			// So still handle "directory exists" errors gracefully
			errMsg := strings.ToLower(err.Error())
			if strings.Contains(errMsg, "file exists") ||
				strings.Contains(errMsg, "directory exists") ||
				strings.Contains(errMsg, "already exists") ||
				strings.Contains(errMsg, "cannot create") ||
				strings.Contains(errMsg, "create directory operation failed") {
				slog.Debug("directory already exists (race condition), continuing", "path", current)
				continue
			}

			// Handle connection errors
			if reconnErr := c.handleConnectionError(err); reconnErr != nil {
				return err
			}
			// Try creating directory again after reconnection
			if c.directoryExists(current) {
				slog.Debug("directory exists after reconnect", "path", current)
				continue
			}
			err = c.conn.MakeDir(current)
			if err != nil {
				errMsg := strings.ToLower(err.Error())
				if strings.Contains(errMsg, "file exists") ||
					strings.Contains(errMsg, "directory exists") ||
					strings.Contains(errMsg, "already exists") ||
					strings.Contains(errMsg, "cannot create") ||
					strings.Contains(errMsg, "create directory operation failed") {
					slog.Debug("directory already exists after reconnect (race condition), continuing", "path", current)
					continue
				}
				return err
			}
		}
	}

	return nil
}
