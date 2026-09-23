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
	sem    chan struct{}
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

// connect dials SSH and opens one SFTP session. Per-operation connections
// keep the semaphore accounting trivial and avoid multiplexing collisions.
func (c *SFTPClient) connect() (*sftp.Client, func(), error) {
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
	c.acquire()
	defer c.release()
	client, cleanup, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	slog.Debug("listing SFTP directory", "path", validated)
	entries, err := client.ReadDir(validated)
	if err != nil {
		return nil, wrapSFTPError(validated, err)
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
	client  *sftp.Client
	cleanup func()
	release func()
}

func (r *sftpReadSeekCloser) Read(p []byte) (int, error) {
	return r.f.Read(p)
}

func (r *sftpReadSeekCloser) Seek(offset int64, whence int) (int64, error) {
	return r.f.Seek(offset, whence)
}

func (r *sftpReadSeekCloser) Close() error {
	err := r.f.Close()
	r.cleanup()
	r.release()
	return err
}

func (c *SFTPClient) Get(p string) (io.ReadCloser, error) {
	validated, err := validatePath(p, false)
	if err != nil {
		return nil, err
	}
	c.acquire()
	client, cleanup, err := c.connect()
	if err != nil {
		c.release()
		return nil, err
	}
	// O_NOFOLLOW equivalent: reject symlinks before opening.
	if fi, err := client.Lstat(validated); err != nil {
		cleanup()
		c.release()
		return nil, wrapSFTPError(validated, err)
	} else if fi.Mode()&os.ModeSymlink != 0 {
		cleanup()
		c.release()
		return nil, fmt.Errorf("%w: %s is a symlink", os.ErrPermission, validated)
	}
	slog.Debug("retrieving file from SFTP", "path", validated)
	f, err := client.Open(validated)
	if err != nil {
		cleanup()
		c.release()
		return nil, wrapSFTPError(validated, err)
	}
	return &sftpReadSeekCloser{f: f, client: client, cleanup: cleanup, release: c.release}, nil
}

func (c *SFTPClient) Put(p string, reader io.Reader) error {
	validated, err := validatePath(p, false)
	if err != nil {
		return err
	}
	c.acquire()
	defer c.release()
	client, cleanup, err := c.connect()
	if err != nil {
		return err
	}
	defer cleanup()

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
}

func (c *SFTPClient) Delete(p string) error {
	validated, err := validatePath(p, false)
	if err != nil {
		return err
	}
	c.acquire()
	defer c.release()
	client, cleanup, err := c.connect()
	if err != nil {
		return err
	}
	defer cleanup()

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
}
