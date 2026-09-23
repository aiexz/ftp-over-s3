package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SFTPClient implements Backend over SSH/SFTP. Unlike FTP it uses typed
// status codes, exact STAT attributes, server-side SEEK for ranged reads, and
// a single encrypted connection per operation — no ambiguous RNTO replies,
// coarse LIST timestamps, or overloaded 550 codes.
type SFTPClient struct {
	config *Config
	// sem bounds concurrent sessions; pool holds idle *sftp.Client ready for
	// reuse so List/Stat during one S3 request share a single SSH handshake.
	sem  chan struct{}
	mu   sync.Mutex
	pool []*sftp.Client
}

func NewSFTPClient(config *Config) *SFTPClient {
	maxConnections := defaultMaxConnections
	if config.FTPMaxConnections > 0 {
		maxConnections = config.FTPMaxConnections
	}
	return &SFTPClient{
		config: config,
		sem:    make(chan struct{}, maxConnections),
	}
}

func (c *SFTPClient) acquire() {
	c.sem <- struct{}{}
}

func (c *SFTPClient) release() {
	<-c.sem
}

// sshAuth builds SSH auth methods: private key file first, then password.
// keyFile may be empty (password-only); keyPass may be empty (unencrypted key).
func sshAuth(config *Config) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	keyFile := strings.TrimSpace(config.SFTPKeyFile)
	if keyFile != "" {
		pem, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read SFTP key file: %w", err)
		}
		var signer ssh.Signer
		if config.SFTPKeyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(config.SFTPKeyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(pem)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse SFTP key file: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if config.FTPPassword != "" {
		methods = append(methods, ssh.Password(config.FTPPassword))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("SFTP requires a key file (-sftp-key-file) or password (-ftp-password)")
	}
	return methods, nil
}

func (c *SFTPClient) hostKeyCallback() (ssh.HostKeyCallback, error) {
	knownHosts := strings.TrimSpace(c.config.SFTPKnownHosts)
	if knownHosts == "" {
		return nil, fmt.Errorf("SFTP requires known-hosts (-sftp-known-hosts); refusing to connect without host verification")
	}
	return parseKnownHosts(knownHosts)
}

// session checks out one pooled SFTP session (dialing only when the pool is
// empty) and returns a release func that returns it to the pool for reuse.
// A broken session (use error) is closed instead of repooled via discard.
func (c *SFTPClient) session() (*sftp.Client, func(broken bool), error) {
	c.acquire()
	c.mu.Lock()
	n := len(c.pool)
	var client *sftp.Client
	if n > 0 {
		client = c.pool[n-1]
		c.pool[n-1] = nil
		c.pool = c.pool[:n-1]
	}
	c.mu.Unlock()
	if client == nil {
		var err error
		var cleanup func()
		client, cleanup, err = c.dial()
		_ = cleanup // pooled path owns lifetime via Close instead
		if err != nil {
			c.release()
			return nil, nil, err
		}
	}
	// release returns the session to the pool; broken=true closes it.
	release := func(broken bool) {
		if broken {
			_ = client.Close()
		} else {
			c.mu.Lock()
			c.pool = append(c.pool, client)
			c.mu.Unlock()
		}
		c.release()
	}
	return client, release, nil
}

// withSession runs fn with a pooled session, retrying once on a fresh
// session if the pooled one turns out broken (server-side idle timeout).
func (c *SFTPClient) withSession(fn func(client *sftp.Client) error) error {
	client, release, err := c.session()
	if err != nil {
		return err
	}
	if err := fn(client); err != nil {
		if isBrokenSession(err) {
			release(true)
			client, release, err := c.session()
			if err != nil {
				return err
			}
			err = fn(client)
			release(isBrokenSession(err))
			return err
		}
		release(false)
		return err
	}
	release(false)
	return nil
}

// Close drains pooled sessions. S3Server.Close should call it.
func (c *SFTPClient) Close() error {
	c.mu.Lock()
	pool := c.pool
	c.pool = nil
	c.mu.Unlock()
	var errs []error
	for _, client := range pool {
		if err := client.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isBrokenSession(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sftp.ErrSSHFxConnectionLost) || errors.Is(err, sftp.ErrSSHFxNoConnection) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.ECONNRESET || errno == syscall.EPIPE || errno == syscall.ETIMEDOUT) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection lost") || strings.Contains(msg, "connection reset")
}

// dial opens one SSH+SFTP session.
func (c *SFTPClient) dial() (*sftp.Client, func(), error) {
	auth, err := sshAuth(c.config)
	if err != nil {
		return nil, nil, err
	}
	hostKey, err := c.hostKeyCallback()
	if err != nil {
		return nil, nil, err
	}
	sshConfig := &ssh.ClientConfig{
		User:            c.config.FTPUser,
		Auth:            auth,
		HostKeyCallback: hostKey,
		Timeout:         defaultDialTimeout,
	}
	addr := net.JoinHostPort(c.config.FTPHost, fmt.Sprintf("%d", c.config.FTPPort))
	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to SFTP server: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(defaultDialTimeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("failed to establish SSH connection: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sshConn, chans, reqs)
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("failed to open SFTP session: %w", err)
	}
	cleanup := func() {
		_ = sftpClient.Close()
		_ = client.Close()
	}
	return sftpClient, cleanup, nil
}

// wrapSFTPError maps SFTP failures to os sentinels. pkg/sftp returns typed
// fxerr values (ErrSSHFxNoSuchFile, ErrSSHFxPermissionDenied) and *PathError
// wrapping ENOENT/EACCES — all visible via errors.Is, no string sniffing.
func wrapSFTPError(path string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sftp.ErrSSHFxNoSuchFile) || errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s: %w", os.ErrNotExist, path, err)
	}
	if errors.Is(err, sftp.ErrSSHFxPermissionDenied) || errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w: %s: %w", os.ErrPermission, path, err)
	}
	return fmt.Errorf("sftp operation %q failed: %w", path, err)
}

// sftpMkdirAll creates dir and parents; existing directories are not errors.
func sftpMkdirAll(client *sftp.Client, dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	// Walk incrementally so concurrent creators racing on parents are fine.
	parts := strings.Split(dir, "/")
	current := ""
	if strings.HasPrefix(dir, "/") {
		current = "/"
	}
	for _, part := range parts {
		if part == "" {
			continue
		}
		if current == "" || current == "/" && !strings.HasPrefix(dir, "/") {
			current = part
		} else {
			current = path.Join(current, part)
		}
		if err := client.Mkdir(current); err != nil {
			// Tolerate already-exists (concurrent creator); fail on the rest.
			if fi, statErr := client.Stat(current); statErr == nil && fi.IsDir() {
				continue
			}
			return err
		}
	}
	return nil
}

func sftpFileInfo(fi os.FileInfo) FileInfo {
	return FileInfo{
		Name:    fi.Name(),
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		IsDir:   fi.IsDir(),
	}
}

func (c *SFTPClient) List(p string) ([]FileInfo, error) {
	validated, err := validatePath(p, true)
	if err != nil {
		return nil, err
	}
	var entries []os.FileInfo
	if err := c.withSession(func(client *sftp.Client) error {
		slog.Debug("listing SFTP directory", "path", validated)
		var err error
		entries, err = client.ReadDir(validated)
		if err != nil {
			return wrapSFTPError(validated, err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var files []FileInfo
	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." {
			continue
		}
		if e.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if strings.HasPrefix(e.Name(), reservedPrefix) {
			continue
		}
		files = append(files, sftpFileInfo(e))
	}
	return files, nil
}

// sftpReadSeekCloser streams from an offset using server-side SEEK instead of
// discarding prefix bytes like the FTP path must.
type sftpReadSeekCloser struct {
	f       *sftp.File
	release func(broken bool)
	broken  bool
}

func (r *sftpReadSeekCloser) Read(p []byte) (int, error) {
	n, err := r.f.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && isBrokenSession(err) {
		r.broken = true
	}
	return n, err
}

func (r *sftpReadSeekCloser) Seek(offset int64, whence int) (int64, error) {
	return r.f.Seek(offset, whence)
}

func (r *sftpReadSeekCloser) Close() error {
	err := r.f.Close()
	// A read error mid-stream means the session may be broken; don't repool it.
	r.release(r.broken || isBrokenSession(err))
	return err
}

func (c *SFTPClient) Get(p string) (io.ReadCloser, error) {
	validated, err := validatePath(p, false)
	if err != nil {
		return nil, err
	}
	// Checkout holds a semaphore slot until the caller closes the reader,
	// because the pooled session stays checked out for the transfer.
	c.acquire()
	c.mu.Lock()
	n := len(c.pool)
	var client *sftp.Client
	if n > 0 {
		client = c.pool[n-1]
		c.pool[n-1] = nil
		c.pool = c.pool[:n-1]
	}
	c.mu.Unlock()
	if client == nil {
		var err error
		var cleanup func()
		client, cleanup, err = c.dial()
		_ = cleanup
		if err != nil {
			c.release()
			return nil, err
		}
	}
	release := func(broken bool) {
		if broken {
			_ = client.Close()
		} else {
			c.mu.Lock()
			c.pool = append(c.pool, client)
			c.mu.Unlock()
		}
		c.release()
	}
	open := func() (*sftp.File, error) {
		// O_NOFOLLOW equivalent: reject symlinks before opening.
		if fi, err := client.Lstat(validated); err != nil {
			return nil, wrapSFTPError(validated, err)
		} else if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s is a symlink", os.ErrPermission, validated)
		}
		slog.Debug("retrieving file from SFTP", "path", validated)
		f, err := client.Open(validated)
		if err != nil {
			return nil, wrapSFTPError(validated, err)
		}
		return f, nil
	}
	f, err := open()
	if err != nil && isBrokenSession(err) {
		_ = client.Close()
		var cleanup func()
		client, cleanup, err = c.dial()
		_ = cleanup
		if err != nil {
			release(true)
			return nil, err
		}
		// Rebind release to the fresh session.
		release = func(broken bool) {
			if broken {
				_ = client.Close()
			} else {
				c.mu.Lock()
				c.pool = append(c.pool, client)
				c.mu.Unlock()
			}
			c.release()
		}
		f, err = open()
	}
	if err != nil {
		release(isBrokenSession(err))
		return nil, err
	}
	return &sftpReadSeekCloser{f: f, release: release}, nil
}

func (c *SFTPClient) Put(p string, reader io.Reader) error {
	validated, err := validatePath(p, false)
	if err != nil {
		return err
	}
	if err := c.withSession(func(client *sftp.Client) error {
		if fi, err := client.Lstat(validated); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: %s is a symlink", os.ErrPermission, validated)
			}
		} else if !os.IsNotExist(err) {
			return wrapSFTPError(validated, err)
		}
		dir, _ := splitDirFile(validated)
		if dir != "" {
			if err := sftpMkdirAll(client, dir); err != nil {
				return wrapSFTPError(dir, fmt.Errorf("failed to create directory %q: %w", dir, err))
			}
		}
		tmpPath, err := tempUploadPath(dir)
		if err != nil {
			return err
		}
		slog.Debug("storing temporary file to SFTP", "tempPath", tmpPath, "destPath", validated)
		counter := &uploadByteCounter{r: reader}
		if err := func() error {
			f, err := client.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
			if err != nil {
				return wrapSFTPError(tmpPath, err)
			}
			_, copyErr := io.Copy(f, counter)
			closeErr := f.Close()
			if copyErr != nil {
				_ = client.Remove(tmpPath)
				return fmt.Errorf("failed to store temporary file %q: %w", tmpPath, copyErr)
			}
			if closeErr != nil {
				_ = client.Remove(tmpPath)
				return fmt.Errorf("failed to store temporary file %q: %w", tmpPath, closeErr)
			}
			return nil
		}(); err != nil {
			return err
		}

		// Verify exact byte count before publishing; SFTP write errors are typed,
		// so a clean close plus size check is proof (no truncated-226 problem).
		if fi, err := client.Stat(tmpPath); err != nil {
			_ = client.Remove(tmpPath)
			return wrapSFTPError(tmpPath, fmt.Errorf("failed to verify temporary file %q: %w", tmpPath, err))
		} else if fi.Size() != counter.n {
			_ = client.Remove(tmpPath)
			return fmt.Errorf("upload integrity check failed for %q: server stored %d bytes, sent %d bytes", validated, fi.Size(), counter.n)
		}

		// POSIX rename atomically replaces dest; failure here is definitive
		// (typed status), never the FTP-style lost-reply ambiguity.
		slog.Debug("renaming temporary file to target", "from", tmpPath, "to", validated)
		if err := client.Rename(tmpPath, validated); err != nil {
			_ = client.Remove(tmpPath)
			return wrapSFTPError(validated, fmt.Errorf("failed to rename %q to %q: %w", tmpPath, validated, err))
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (c *SFTPClient) Delete(p string) error {
	validated, err := validatePath(p, false)
	if err != nil {
		return err
	}
	if err := c.withSession(func(client *sftp.Client) error {
		if fi, err := client.Lstat(validated); err != nil {
			return wrapSFTPError(validated, err)
		} else if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symlink", os.ErrPermission, validated)
		}
		slog.Debug("deleting file from SFTP", "path", validated)
		if err := client.Remove(validated); err != nil {
			return wrapSFTPError(validated, err)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
