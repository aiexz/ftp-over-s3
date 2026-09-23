package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jlaffaye/ftp"
)

var ErrAmbiguousPublish = errors.New("ambiguous publish outcome during rename")

// FTP Backend and Rename Limitations:
// 1. RNFR/RNTO Overwrite Atomicity:
//    RFC 959 does not specify whether RNTO atomically overwrites an existing file.
//    On POSIX filesystems, rename(2) provides atomic overwrites. However, on Windows
//    FTP servers or virtual/cloud FTP backends, RNTO may fail (e.g. 550 or 553 File Exists)
//    if the destination already exists, or the overwrite may not be atomic.
// 2. Cross-Directory/Cross-Filesystem Renames:
//    Many FTP servers reject renaming across different directories, volumes, or mount points.
//    To ensure compatibility, temporary upload files are staged in the exact same directory
//    as the target object.
// 3. Symlink Traversal Protection:
//    FTP commands (RETR, STOR, DELE) operate on server-side paths without an O_NOFOLLOW flag.
//    Symlink traversal prevention is enforced via pre-transfer directory inspection (LIST)
//    for EntryTypeLink and filtering symlink entries. Symlinks created concurrently by
//    external processes between inspection and operation cannot be prevented by the client
//    and require server-side restriction (e.g. chroot or disabling symlinks).

const (
	reservedPrefix        = ".ftp-over-s3-"
	defaultDialTimeout    = 30 * time.Second
	defaultIOTimeout      = 15 * time.Second
	defaultShutTimeout    = 3 * time.Second
	defaultMaxConnections = 2
)

// Backend is the storage-backend contract consumed by the S3 layer. FTPClient
// implements it; the SFTP backend implements the same surface so either can
// be selected via Config without touching callers.
type Backend interface {
	List(path string) ([]FileInfo, error)
	Get(path string) (io.ReadCloser, error)
	Put(path string, reader io.Reader) error
	Delete(path string) error
}

type FTPClient struct {
	config *Config
	// sem bounds the number of concurrent FTP connections this client opens.
	// Servers commonly cap connections per IP (e.g. 421 Too many connections), so
	// parallel operations queue here instead of opening unbounded sockets.
	sem chan struct{}
}

type FileInfo struct {
	Name    string
	Size    int64
	ModTime time.Time
	IsDir   bool
}

func NewFTPClient(config *Config) *FTPClient {
	maxConnections := defaultMaxConnections
	if config.FTPMaxConnections > 0 {
		maxConnections = config.FTPMaxConnections
	}
	return &FTPClient{
		config: config,
		sem:    make(chan struct{}, maxConnections),
	}
}

// acquire reserves a connection slot, blocking while the limit is reached.
func (c *FTPClient) acquire() {
	c.sem <- struct{}{}
}

// release returns a connection slot. It must be called exactly once per acquire.
func (c *FTPClient) release() {
	<-c.sem
}

// timeoutConn wraps net.Conn to enforce per-I/O deadlines on every Read and Write.
// This prevents hung control or data sockets when connection is severed.
type timeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *timeoutConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}

// dataTLSConn adds a graceful TLS shutdown to a protected FTP data connection.
//
// tls.Conn.Close sends close_notify but does not wait for the peer, so the socket
// can be torn down while the server is still reading; some servers then finish
// early and answer STOR with 226 after storing a truncated file. Uploads therefore
// half-close and read until the peer closes, mirroring what Python's
// ftplib.FTP_TLS does via SSLSocket.unwrap(). Read-only transfers (RETR, LIST)
// close immediately: draining a transfer we are abandoning could block on the
// remaining bytes.
//
// The read that waits for the peer is bounded by the per-I/O deadline on the
// underlying socket: a peer that never closes cannot hang the gateway, and the
// expired deadline is reported as a failed shutdown rather than ignored.
type dataTLSConn struct {
	*tls.Conn
	uploading atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// Write records that this connection is used for an upload.
func (c *dataTLSConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.uploading.Store(true)
	}
	return n, err
}

// Handshake completes the TLS handshake. ftp.StorFrom calls it explicitly when a
// zero-byte upload wrote nothing, which is the only way such an upload is
// recognisable as an upload rather than an unread transfer.
func (c *dataTLSConn) Handshake() error {
	if err := c.Conn.Handshake(); err != nil {
		return err
	}
	c.uploading.Store(true)
	return nil
}

func (c *dataTLSConn) Close() error {
	c.closeOnce.Do(func() {
		if !c.uploading.Load() {
			c.closeErr = c.Conn.Close()
			return
		}

		var errs []error
		// CloseWrite sends close_notify, telling the server the stream is complete.
		if err := c.Conn.CloseWrite(); err != nil {
			errs = append(errs, err)
		}

		// Read until the peer closes so no unread bytes remain buffered when the
		// socket is closed (a close with unread data would reset the connection).
		// Any read failure other than a clean EOF is reported, including the
		// per-I/O deadline expiring: the transfer is not confirmed complete.
		buf := make([]byte, 4096)
		for {
			if _, err := c.Conn.Read(buf); err != nil {
				if !errors.Is(err, io.EOF) {
					errs = append(errs, err)
				}
				break
			}
		}

		if err := c.Conn.Close(); err != nil {
			errs = append(errs, err)
		}
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

// connect establishes a new, dedicated FTP connection with per-I/O timeouts.
// Connections are per-operation to ensure concurrent operations do not collide.
// Both control and data sockets route through dialFunc to enforce timeouts.
func (c *FTPClient) connect() (*ftp.ServerConn, error) {
	addr := net.JoinHostPort(c.config.FTPHost, strconv.Itoa(c.config.FTPPort))
	slog.Debug("connecting to FTP server", "address", addr)

	dialer := &net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: 5 * time.Second,
	}

	// Explicit FTPS (AUTH TLS + PROT P). Verification is always on: the server
	// name is pinned to the configured host and InsecureSkipVerify is never set.
	var tlsConfig *tls.Config
	if c.config.FTPTLS {
		tlsConfig = &tls.Config{
			ServerName: c.config.FTPHost,
			MinVersion: tls.VersionTLS12,
		}
	}

	// dialCount distinguishes the control socket (first dial, upgraded by ftp.Dial
	// after AUTH TLS) from data sockets, which must be upgraded here because
	// openDataConn returns the dial func's connection verbatim.
	var dialCount atomic.Int32
	dialFunc := func(network, address string) (net.Conn, error) {
		raw, err := dialer.Dial(network, address)
		if err != nil {
			return nil, err
		}
		// Deadline enforcement stays on the raw socket, so it applies below TLS too.
		conn := net.Conn(&timeoutConn{
			Conn:    raw,
			timeout: defaultIOTimeout,
		})
		if tlsConfig == nil || dialCount.Add(1) == 1 {
			return conn, nil
		}
		// Returning a TLS connection keeps Handshake() visible to StorFrom, which
		// requires it to complete the handshake for zero-byte uploads.
		return &dataTLSConn{Conn: tls.Client(conn, tlsConfig)}, nil
	}

	options := []ftp.DialOption{
		ftp.DialWithDialFunc(dialFunc),
		ftp.DialWithTimeout(defaultDialTimeout),
		ftp.DialWithShutTimeout(defaultShutTimeout),
	}
	if tlsConfig != nil {
		options = append(options, ftp.DialWithExplicitTLS(tlsConfig))
	}

	conn, err := ftp.Dial(addr, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to FTP server: %w", err)
	}

	slog.Debug("logging into FTP server", "username", c.config.FTPUser)
	err = conn.Login(c.config.FTPUser, c.config.FTPPassword)
	if err != nil {
		_ = conn.Quit()
		return nil, fmt.Errorf("failed to login to FTP server: %w", err)
	}

	return conn, nil
}

// validatePath validates slash-separated paths without collapsing aliases or traversal.
// It rejects control characters, repeated slashes, dot segments ('.' and '..'),
// and reserved internal prefixes.
func validatePath(rawPath string, isList bool) (string, error) {
	// Reject control characters (0x00-0x1F, 0x7F) including CRLF, tabs, NUL.
	for i := 0; i < len(rawPath); i++ {
		c := rawPath[i]
		if c < 32 || c == 127 {
			return "", fmt.Errorf("%w: path contains control character 0x%02x", os.ErrInvalid, c)
		}
	}

	// Reject repeated slashes anywhere in path
	if strings.Contains(rawPath, "//") {
		return "", fmt.Errorf("%w: path contains repeated slashes", os.ErrInvalid)
	}

	// For List, root representations ("", ".", "/") are normalized to "."
	if isList {
		if rawPath == "" || rawPath == "." || rawPath == "/" {
			return ".", nil
		}
	}

	p := strings.TrimPrefix(rawPath, "/")
	if isList {
		p = strings.TrimSuffix(p, "/")
		if p == "" {
			return ".", nil
		}
	} else {
		if p == "" {
			return "", fmt.Errorf("%w: object path cannot be empty", os.ErrInvalid)
		}
		if strings.HasSuffix(rawPath, "/") {
			return "", fmt.Errorf("%w: object path cannot end with trailing slash", os.ErrInvalid)
		}
	}

	parts := strings.Split(p, "/")
	for _, part := range parts {
		if part == "" {
			return "", fmt.Errorf("%w: path contains empty segment", os.ErrInvalid)
		}
		if part == "." || part == ".." {
			return "", fmt.Errorf("%w: dot segment %q not allowed in path", os.ErrInvalid, part)
		}
		if strings.HasPrefix(part, reservedPrefix) {
			return "", fmt.Errorf("%w: path component %q uses reserved internal prefix %q", os.ErrInvalid, part, reservedPrefix)
		}
	}

	return p, nil
}

func splitDirFile(p string) (dir string, file string) {
	idx := strings.LastIndex(p, "/")
	if idx < 0 {
		return "", p
	}
	return p[:idx], p[idx+1:]
}

func tempUploadPath(dir string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random temporary filename: %w", err)
	}
	name := fmt.Sprintf("%stmp.%d.%s", reservedPrefix, time.Now().UnixNano(), hex.EncodeToString(b))
	if dir == "" || dir == "." {
		return name, nil
	}
	return dir + "/" + name, nil
}

// uploadByteCounter tracks how many bytes were consumed from the source reader.
// Some FTP servers acknowledge STOR (226) after storing a truncated file, so the
// number of bytes actually delivered is the only trustworthy record of intent.
type uploadByteCounter struct {
	r io.Reader
	n int64
}

func (cr *uploadByteCounter) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

// remoteFileSize reports the size the server recorded for path.
// It prefers SIZE and falls back to a parent directory listing when SIZE is unsupported.
// ok is false when neither method yields a size.
func remoteFileSize(conn *ftp.ServerConn, path string) (size int64, ok bool, err error) {
	remoteSize, err := conn.FileSize(path)
	if err == nil {
		return remoteSize, true, nil
	}

	var protoErr *textproto.Error
	if errors.As(err, &protoErr) &&
		(protoErr.Code == 500 || protoErr.Code == 502 || protoErr.Code == 504) {
		// SIZE is not implemented; fall back to the directory listing.
		dir, file := splitDirFile(path)
		if dir == "" {
			dir = "."
		}
		entries, listErr := conn.List(dir)
		if listErr != nil {
			return 0, false, fmt.Errorf("failed to verify upload size for %q: %w", path, listErr)
		}
		for _, e := range entries {
			if e.Name != file {
				continue
			}
			if e.Type == ftp.EntryTypeFolder {
				return 0, false, fmt.Errorf("upload verification failed: %q is a directory on the server", path)
			}
			return int64(e.Size), true, nil
		}
		return 0, false, fmt.Errorf("upload verification failed: %q not found on the server after transfer", path)
	}

	return 0, false, fmt.Errorf("failed to verify upload size for %q: %w", path, err)
}

// checkSymlinks inspects each path component via directory listings to reject symlink traversal.
func (c *FTPClient) checkSymlinks(conn *ftp.ServerConn, path string) error {
	if path == "" || path == "." {
		return nil
	}

	parts := strings.Split(path, "/")
	currentDir := "."

	for i, part := range parts {
		entries, err := conn.List(currentDir)
		if err != nil {
			var protoErr *textproto.Error
			if errors.As(err, &protoErr) {
				msg := strings.ToLower(protoErr.Msg)
				if strings.Contains(msg, "permission denied") || strings.Contains(msg, "access denied") {
					return fmt.Errorf("%w: %w", os.ErrPermission, err)
				}
			}
			// Directory does not exist yet (e.g. Put creating dirs) or not found
			break
		}

		var foundEntry *ftp.Entry
		for _, e := range entries {
			if e.Name == part {
				foundEntry = e
				break
			}
		}

		if foundEntry != nil {
			if foundEntry.Type == ftp.EntryTypeLink {
				return fmt.Errorf("%w: symlink traversal rejected for %q", os.ErrPermission, part)
			}
			if i < len(parts)-1 && foundEntry.Type != ftp.EntryTypeFolder {
				return fmt.Errorf("%w: path component %q is not a directory", os.ErrInvalid, part)
			}
		} else {
			// Component not found in currentDir: further subcomponents cannot exist
			break
		}

		if currentDir == "." {
			currentDir = part
		} else {
			currentDir = currentDir + "/" + part
		}
	}

	return nil
}

func fileExistsInParent(conn *ftp.ServerConn, path string) (bool, error) {
	dir, file := splitDirFile(path)
	if dir == "" {
		dir = "."
	}

	entries, err := conn.List(dir)
	if err != nil {
		var protoErr *textproto.Error
		if errors.As(err, &protoErr) {
			msg := strings.ToLower(protoErr.Msg)
			if strings.Contains(msg, "permission denied") || strings.Contains(msg, "access denied") {
				return false, fmt.Errorf("%w: %w", os.ErrPermission, err)
			}
			if protoErr.Code == 550 || strings.Contains(msg, "not found") || strings.Contains(msg, "no such") {
				return false, nil
			}
		}
		return false, err
	}

	for _, entry := range entries {
		if entry.Name == file {
			return true, nil
		}
	}
	return false, nil
}

func (c *FTPClient) wrapFTPError(conn *ftp.ServerConn, path string, err error) error {
	if err == nil {
		return nil
	}

	var protoErr *textproto.Error
	if errors.As(err, &protoErr) {
		msg := strings.ToLower(protoErr.Msg)
		if strings.Contains(msg, "permission denied") ||
			strings.Contains(msg, "access denied") ||
			strings.Contains(msg, "not permitted") {
			return fmt.Errorf("%w: %w", os.ErrPermission, err)
		}
		if strings.Contains(msg, "no such file") ||
			strings.Contains(msg, "not found") ||
			strings.Contains(msg, "does not exist") {
			return fmt.Errorf("%w: %w", os.ErrNotExist, err)
		}

		if protoErr.Code == 550 {
			// FTP 550 is ambiguous. If connection is available, query parent directory.
			if conn != nil {
				exists, checkErr := fileExistsInParent(conn, path)
				if checkErr == nil {
					if exists {
						return fmt.Errorf("%w: %w", os.ErrPermission, err)
					}
					return fmt.Errorf("%w: %w", os.ErrNotExist, err)
				}
				if errors.Is(checkErr, os.ErrPermission) {
					return fmt.Errorf("%w: %w", os.ErrPermission, err)
				}
			}
			return err
		}

		if protoErr.Code == 530 {
			return fmt.Errorf("%w: %w", os.ErrPermission, err)
		}
		if protoErr.Code == 553 {
			return fmt.Errorf("%w: %w", os.ErrInvalid, err)
		}
	}

	return err
}

func dirExists(conn *ftp.ServerConn, dir string) (bool, error) {
	if dir == "" || dir == "." {
		return true, nil
	}

	_, err := conn.List(dir)
	if err == nil {
		return true, nil
	}

	var protoErr *textproto.Error
	if errors.As(err, &protoErr) {
		msg := strings.ToLower(protoErr.Msg)
		if strings.Contains(msg, "permission denied") || strings.Contains(msg, "access denied") {
			return false, fmt.Errorf("%w: %w", os.ErrPermission, err)
		}
		if protoErr.Code == 550 || strings.Contains(msg, "not found") || strings.Contains(msg, "no such") {
			return false, nil
		}
	}
	return false, err
}

func (c *FTPClient) createDirectories(conn *ftp.ServerConn, dir string) error {
	if dir == "" || dir == "." {
		return nil
	}

	parts := strings.Split(dir, "/")
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

		exists, err := dirExists(conn, current)
		if err != nil {
			return err
		}
		if exists {
			continue
		}

		slog.Debug("creating FTP directory", "path", current)
		err = conn.MakeDir(current)
		if err != nil {
			confirmed, confirmErr := dirExists(conn, current)
			if confirmErr == nil && confirmed {
				slog.Debug("directory created concurrently, continuing", "path", current)
				continue
			}
			return c.wrapFTPError(conn, current, fmt.Errorf("failed to create directory %q: %w", current, err))
		}
	}

	return nil
}

type ftpReadCloser struct {
	resp    *ftp.Response
	conn    *ftp.ServerConn
	release func()
	once    sync.Once
	err     error
}

func (r *ftpReadCloser) Read(p []byte) (int, error) {
	return r.resp.Read(p)
}

func (r *ftpReadCloser) Close() error {
	r.once.Do(func() {
		var errs []error
		if err := r.resp.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := r.conn.Quit(); err != nil {
			errs = append(errs, err)
		}
		if r.release != nil {
			r.release()
		}
		r.err = errors.Join(errs...)
	})
	return r.err
}

func (c *FTPClient) List(path string) ([]FileInfo, error) {
	p, err := validatePath(path, true)
	if err != nil {
		return nil, err
	}

	c.acquire()
	defer c.release()

	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Quit()

	if p != "." {
		if err := c.checkSymlinks(conn, p); err != nil {
			return nil, err
		}
	}

	slog.Debug("listing FTP directory", "path", p)
	entries, err := conn.List(p)
	if err != nil {
		return nil, c.wrapFTPError(conn, p, err)
	}

	var files []FileInfo
	for _, entry := range entries {
		// Skip '.' and '..'
		if entry.Name == "." || entry.Name == ".." {
			continue
		}
		// Reject / skip symbolic links
		if entry.Type == ftp.EntryTypeLink {
			continue
		}
		// Hide gateway-internal files (reserved prefix)
		if strings.HasPrefix(entry.Name, reservedPrefix) {
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

// Get starts a retrieval and returns a reader that owns the FTP connection and
// the connection slot. The caller must Close the reader to release both.
func (c *FTPClient) Get(path string) (io.ReadCloser, error) {
	p, err := validatePath(path, false)
	if err != nil {
		return nil, err
	}

	// The slot is held until the caller closes the returned reader, because the
	// connection stays open for the duration of the transfer.
	c.acquire()

	conn, err := c.connect()
	if err != nil {
		c.release()
		return nil, err
	}

	if err := c.checkSymlinks(conn, p); err != nil {
		_ = conn.Quit()
		c.release()
		return nil, err
	}

	slog.Debug("retrieving file from FTP", "path", p)
	resp, err := conn.Retr(p)
	if err != nil {
		wrappedErr := c.wrapFTPError(conn, p, err)
		_ = conn.Quit()
		c.release()
		return nil, wrappedErr
	}

	return &ftpReadCloser{
		resp:    resp,
		conn:    conn,
		release: c.release,
	}, nil
}

func (c *FTPClient) Put(path string, reader io.Reader) error {
	p, err := validatePath(path, false)
	if err != nil {
		return err
	}

	c.acquire()
	defer c.release()

	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Quit()

	if err := c.checkSymlinks(conn, p); err != nil {
		return err
	}

	dir, _ := splitDirFile(p)
	if dir != "" {
		if err := c.createDirectories(conn, dir); err != nil {
			return err
		}
	}

	tmpPath, err := tempUploadPath(dir)
	if err != nil {
		return err
	}
	slog.Debug("storing temporary file to FTP", "tempPath", tmpPath, "destPath", p)

	// Login already switched the session to binary mode (TYPE I). Some servers
	// return 226 after storing a truncated file, so count the bytes consumed from
	// the source and verify the remote size before the rename publishes anything.
	counter := &uploadByteCounter{r: reader}
	if err := conn.Stor(tmpPath, counter); err != nil {
		_ = conn.Delete(tmpPath)
		return c.wrapFTPError(conn, p, fmt.Errorf("failed to store temporary file %q: %w", tmpPath, err))
	}

	// Verify the server stored exactly the bytes we sent before publishing.
	remoteSize, known, err := remoteFileSize(conn, tmpPath)
	if err != nil {
		_ = conn.Delete(tmpPath)
		return fmt.Errorf("failed to verify temporary file %q: %w", tmpPath, err)
	}
	if !known {
		_ = conn.Delete(tmpPath)
		return fmt.Errorf("failed to verify temporary file %q: server reported no size", tmpPath)
	}
	if remoteSize != counter.n {
		_ = conn.Delete(tmpPath)
		return fmt.Errorf("upload integrity check failed for %q: server stored %d bytes, sent %d bytes", p, remoteSize, counter.n)
	}

	// Rename temporary file to target path
	slog.Debug("renaming temporary file to target", "from", tmpPath, "to", p)
	if err := conn.Rename(tmpPath, p); err != nil {
		_ = conn.Delete(tmpPath)
		wrappedErr := c.wrapFTPError(conn, p, fmt.Errorf("failed to rename %q to %q: %w", tmpPath, p, err))
		var protoErr *textproto.Error
		if errors.As(err, &protoErr) && protoErr.Code == 550 {
			// Explicit 550 denial: server definitively rejected rename, definitely not published.
			return wrappedErr
		}
		return fmt.Errorf("%w: %w", ErrAmbiguousPublish, wrappedErr)
	}

	return nil
}

func (c *FTPClient) Delete(path string) error {
	p, err := validatePath(path, false)
	if err != nil {
		return err
	}

	c.acquire()
	defer c.release()

	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Quit()

	if err := c.checkSymlinks(conn, p); err != nil {
		return err
	}

	slog.Debug("deleting file from FTP", "path", p)
	err = conn.Delete(p)
	if err != nil {
		return c.wrapFTPError(conn, p, err)
	}

	return nil
}
