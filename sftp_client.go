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

	// Preloaded at construction so key/known_hosts disk reads and config
	// errors surface at startup, not on the first request.
	auth    []ssh.AuthMethod
	hostKey ssh.HostKeyCallback
}

func NewSFTPClient(config *Config) *SFTPClient {
	maxSessions := defaultMaxConnections
	if config.SFTPMaxSessions > 0 {
		maxSessions = config.SFTPMaxSessions
	} else if config.FTPMaxConnections > 0 {
		maxSessions = config.FTPMaxConnections
	}
	return &SFTPClient{
		config: config,
		sem:    make(chan struct{}, maxSessions),
	}
}

// initAuth preloads the key signer and known_hosts callback. Called by
// NewS3Server at startup (fail fast) and lazily by dial as a fallback.
func (c *SFTPClient) initAuth() error {
	if c.auth != nil && c.hostKey != nil {
		return nil
	}
	auth, err := sshAuth(c.config)
	if err != nil {
		return err
	}
	hostKey, err := c.hostKeyCallback()
	if err != nil {
		return err
	}
	c.auth = auth
	c.hostKey = hostKey
	return nil
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
	if err := c.initAuth(); err != nil {
		return nil, nil, err
	}
	// Per-dial keyboard-interactive closure answers PAM prompts with the
	// configured password (main auth loop also tries publickey first).
	password := c.config.FTPPassword
	sshConfig := &ssh.ClientConfig{
		User: c.config.FTPUser,
		Auth: append(append([]ssh.AuthMethod{}, c.auth...),
			ssh.KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				if password == "" {
					return nil, fmt.Errorf("keyboard-interactive prompt but no password configured")
				}
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		),
		HostKeyCallback: c.hostKey,
		Timeout:         defaultDialTimeout,
		// Prefer modeless security: server's preferred algorithms win, but
		// restrict host-key checking to the known_hosts callback above.
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
	// TCP keepalive probes a hung peer so a dead connection surfaces as an
	// error (and frees the pool slot) instead of blocking forever.
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	// Watchdog: half-open transports eventually fail requests instead of
	// hanging the checked-out slot forever.
	go func() {
		_ = client.Wait()
	}()
	sftpClient, err := sftp.NewClient(client,
		sftp.MaxConcurrentRequestsPerFile(64),
	)
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

// checkNoSymlinks rejects symlink traversal: every component of p (and p
// itself) is Lstat'ed; any symlink fails closed. Mirrors FTP checkSymlinks.
func checkNoSymlinks(client *sftp.Client, p string) error {
	if p == "" || p == "." {
		return nil
	}
	current := ""
	for _, part := range strings.Split(p, "/") {
		if part == "" {
			continue
		}
		if current == "" {
			current = part
		} else {
			current = current + "/" + part
		}
		fi, err := client.Lstat(current)
		if err != nil {
			// Missing components are fine (Put creates them; other ops
			// map absence themselves). Lstat normalises to os.ErrNotExist.
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return wrapSFTPError(current, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symlink", os.ErrPermission, current)
		}
	}
	return nil
}

// sftpMkdirAll creates dir and parents; existing directories are not errors.
func sftpMkdirAll(client *sftp.Client, dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	// validatePath guarantees relative slash-separated paths, so walk
	// incrementally; concurrent creators racing on parents are fine.
	current := ""
	for _, part := range strings.Split(dir, "/") {
		if part == "" {
			continue
		}
		if current == "" {
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
		if err := checkNoSymlinks(client, validated); err != nil {
			return err
		}
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
	closed  bool
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
	if r.closed {
		return nil
	}
	r.closed = true
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
		if err := checkNoSymlinks(client, validated); err != nil {
			return nil, err
		}
		if fi, err := client.Lstat(validated); err != nil {
			return nil, wrapSFTPError(validated, err)
		} else if fi.IsDir() {
			return nil, fmt.Errorf("%w: %s is a directory", os.ErrInvalid, validated)
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
		if err := checkNoSymlinks(client, validated); err != nil {
			return err
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
				_ = removeFileOnly(client, tmpPath)
				return fmt.Errorf("failed to store temporary file %q: %w", tmpPath, copyErr)
			}
			if closeErr != nil {
				_ = removeFileOnly(client, tmpPath)
				return fmt.Errorf("failed to store temporary file %q: %w", tmpPath, closeErr)
			}
			return nil
		}(); err != nil {
			return err
		}

		// Verify exact byte count before publishing; SFTP write errors are typed,
		// so a clean close plus size check is proof (no truncated-226 problem).
		if fi, err := client.Stat(tmpPath); err != nil {
			_ = removeFileOnly(client, tmpPath)
			return wrapSFTPError(tmpPath, fmt.Errorf("failed to verify temporary file %q: %w", tmpPath, err))
		} else if fi.Size() != counter.n {
			_ = removeFileOnly(client, tmpPath)
			return fmt.Errorf("upload integrity check failed for %q: server stored %d bytes, sent %d bytes", validated, fi.Size(), counter.n)
		}

		// Publish via posix-rename when available (atomic overwrite); else
		// remove-then-rename. A transport-level error during rename leaves the
		// outcome unknown -> ErrAmbiguousPublish so callers fail closed.
		slog.Debug("renaming temporary file to target", "from", tmpPath, "to", validated)
		if err := publishFile(client, tmpPath, validated); err != nil {
			_ = removeFileOnly(client, tmpPath)
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// publishFile renames tmp onto dest. It prefers the posix-rename extension
// (atomic overwrite); on servers without it, falls back to remove+rename.
// Transport errors (send failure / lost reply) yield ErrAmbiguousPublish.
func publishFile(client *sftp.Client, tmp, dest string) error {
	if _, ok := client.HasExtension("posix-rename@openssh.com"); ok {
		if err := client.PosixRename(tmp, dest); err != nil {
			if isTransportError(err) {
				return fmt.Errorf("%w: %w", ErrAmbiguousPublish, err)
			}
			return wrapSFTPError(dest, fmt.Errorf("failed to rename %q to %q: %w", tmp, dest, err))
		}
		return nil
	}
	// SFTPv3 RENAME must not overwrite: remove dest first when present.
	if _, err := client.Lstat(dest); err == nil {
		if err := removeFileOnly(client, dest); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return wrapSFTPError(dest, err)
	}
	if err := client.Rename(tmp, dest); err != nil {
		if isTransportError(err) {
			return fmt.Errorf("%w: %w", ErrAmbiguousPublish, err)
		}
		return wrapSFTPError(dest, fmt.Errorf("failed to rename %q to %q: %w", tmp, dest, err))
	}
	return nil
}

// removeFileOnly removes a regular file, never a directory. pkg/sftp's
// Client.Remove falls back to RemoveDirectory, so check Lstat first.
func removeFileOnly(client *sftp.Client, name string) error {
	fi, err := client.Lstat(name)
	if err != nil {
		return wrapSFTPError(name, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%w: %s is a directory", os.ErrInvalid, name)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", os.ErrPermission, name)
	}
	if err := client.Remove(name); err != nil {
		return wrapSFTPError(name, err)
	}
	return nil
}

// isTransportError reports send/reply-level failures where the server may
// have applied the request but the reply was lost.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	if isBrokenSession(err) {
		return true
	}
	if errors.Is(err, sftp.ErrSSHFxConnectionLost) || errors.Is(err, sftp.ErrSSHFxNoConnection) {
		return true
	}
	return false
}

func (c *SFTPClient) Delete(p string) error {
	validated, err := validatePath(p, false)
	if err != nil {
		return err
	}
	if err := c.withSession(func(client *sftp.Client) error {
		if err := checkNoSymlinks(client, validated); err != nil {
			return err
		}
		slog.Debug("deleting file from SFTP", "path", validated)
		// Stat first: Get/Delete on a directory must not proceed.
		if fi, err := client.Lstat(validated); err != nil {
			return wrapSFTPError(validated, err)
		} else if fi.IsDir() {
			return fmt.Errorf("%w: %s is a directory", os.ErrInvalid, validated)
		}
		if err := removeFileOnly(client, validated); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
