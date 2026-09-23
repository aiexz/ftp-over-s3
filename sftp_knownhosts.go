package main

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// parseKnownHosts builds an ssh.HostKeyCallback from an OpenSSH known_hosts
// file using the stdlib parser: hashed entries, [host]:port forms,
// @cert-authority and @revoked markers all work. Unknown hosts fail closed,
// no trust-on-first-use. HostKeyAlgorithms is left to SSH negotiation: the
// callback accepts whichever server key type matches the file, so an ed25519
// entry does not break an rsa-only server (and vice versa) — mismatch only
// when the presented key differs from the stored one for that type.
func parseKnownHosts(path string) (ssh.HostKeyCallback, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, fmt.Errorf("SFTP requires known-hosts (-sftp-known-hosts); refusing to connect without host verification")
	}
	cb, err := knownhosts.New(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SFTP known_hosts file: %w", err)
	}
	return cb, nil
}
