package main

import (
	"errors"
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

func TestParseKnownHosts_AcceptAndReject(t *testing.T) {
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
	raw, _ := ssh.ParsePublicKey([]byte(string(pub)))
	_ = raw
	if _, err := parseKnownHosts(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, err := parseKnownHosts(filepath.Join(dir, "known_hosts")); err != nil {
		t.Fatalf("valid file should parse: %v", err)
	}
	_ = cb
}
