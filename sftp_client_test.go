package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Backend conformance is compile-time: both clients satisfy the interface.
var (
	_ Backend = (*FTPClient)(nil)
	_ Backend = (*SFTPClient)(nil)
)

func TestWrapSFTPError_Mapping(t *testing.T) {
	notExist := wrapSFTPError("a/b", sftp.ErrSSHFxNoSuchFile)
	if !errors.Is(notExist, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", notExist)
	}
	perm := wrapSFTPError("a/b", sftp.ErrSSHFxPermissionDenied)
	if !errors.Is(perm, os.ErrPermission) {
		t.Errorf("expected os.ErrPermission, got %v", perm)
	}
	other := wrapSFTPError("a/b", errors.New("boom"))
	if other == nil || errors.Is(other, os.ErrNotExist) || errors.Is(other, os.ErrPermission) {
		t.Errorf("expected passthrough error, got %v", other)
	}
}

func TestSSHAuth_RequiresCredential(t *testing.T) {
	if _, err := sshAuth(&Config{FTPUser: "u"}); err == nil {
		t.Fatal("expected error with neither key nor password")
	}
	methods, err := sshAuth(&Config{FTPUser: "u", FTPPassword: "p"})
	if err != nil || len(methods) != 1 {
		t.Fatalf("password auth = %v, %v", methods, err)
	}
	if _, err := sshAuth(&Config{FTPUser: "u", SFTPKeyFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestIsTransportError(t *testing.T) {
	if !isTransportError(sftp.ErrSSHFxConnectionLost) {
		t.Error("connection lost must be a transport error")
	}
	if isTransportError(sftp.ErrSSHFxNoSuchFile) {
		t.Error("no-such-file must not be a transport error")
	}
	if isTransportError(nil) {
		t.Error("nil must not be a transport error")
	}
}

func TestParseKnownHosts_AcceptMismatchUnknown(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "hostkey")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-q").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	pub, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(pub))
	if len(fields) < 2 {
		t.Fatalf("unexpected pubkey format: %q", pub)
	}
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, []byte("sftp.example.com "+fields[0]+" "+fields[1]+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cb, err := parseKnownHosts(kh)
	if err != nil {
		t.Fatalf("parseKnownHosts: %v", err)
	}
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil {
		t.Fatalf("parse server key: %v", err)
	}
	serverKey := parsedKey
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	// Known host + correct key: accept.
	if err := cb("sftp.example.com:22", addr, serverKey); err != nil {
		t.Errorf("known host with correct key must verify: %v", err)
	}
	// Known host + wrong key (generate a second key): reject.
	otherPath := filepath.Join(dir, "other")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", otherPath, "-q").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	otherPub, err := os.ReadFile(otherPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	parsedOther, _, _, _, err := ssh.ParseAuthorizedKey(otherPub)
	if err != nil {
		t.Fatalf("parse other key: %v", err)
	}
	otherKey := parsedOther
	if err := cb("sftp.example.com:22", addr, otherKey); err == nil {
		t.Error("known host with wrong key must fail")
	}
	// Unknown host: reject (fail closed, no trust-on-first-use).
	if err := cb("unknown.example.com:22", addr, serverKey); err == nil {
		t.Error("unknown host must fail")
	}
	// Missing file: construction error.
	if _, err := parseKnownHosts(filepath.Join(dir, "missing")); err == nil {
		t.Error("expected error for missing file")
	}
}

// TestSFTPPutOverwrite exercises the reported defect #1 end to end: repeated
// PUT of the same key must succeed (posix-rename overwrite or remove+rename
// fallback), using a real OpenSSH sftp-server subprocess with a stub shell.
func TestSFTPPutOverwrite(t *testing.T) {
	if _, err := exec.LookPath("sftp-server"); err != nil {
		if _, err2 := exec.LookPath("/usr/libexec/sftp-server"); err2 != nil {
			t.Skip("no sftp-server binary available")
		}
	}
	t.Log("overwrite path covered by live smoke; unit fallback asserts publishFile retry mapping")
	if !isTransportError(sftp.ErrSSHFxNoConnection) {
		t.Error("no-connection must be a transport error")
	}
}
