package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// file. Only plain (non-hashed, non-cert) lines are accepted; hashed
// @cert-authority and @revoked markers are rejected so verification stays
// explicit. No implicit trust on first use: unknown hosts fail closed.
func parseKnownHosts(path string) (ssh.HostKeyCallback, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open SFTP known_hosts file: %w", err)
	}
	defer f.Close()

	type hostKey struct {
		algo string
		key  ssh.PublicKey
	}
	// keys[pattern] preserves exact-match entries; hashed entries unsupported.
	keys := make(map[string][]hostKey)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	lineNo := 0
	entries := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("invalid known_hosts line %d: want <hosts> <type> <key>", lineNo)
		}
		idx := 0
		if strings.HasPrefix(fields[0], "@") {
			return nil, fmt.Errorf("unsupported known_hosts marker %q on line %d", fields[0], lineNo)
		}
		if strings.HasPrefix(fields[0], "|") {
			return nil, fmt.Errorf("hashed known_hosts entries unsupported on line %d; add a plain hostname entry", lineNo)
		}
		keyType, keyB64 := fields[idx+1], fields[idx+2]
		raw, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return nil, fmt.Errorf("invalid known_hosts key on line %d: %w", lineNo, err)
		}
		pub, err := ssh.ParsePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid known_hosts key on line %d: %w", lineNo, err)
		}
		if pub.Type() != keyType {
			return nil, fmt.Errorf("known_hosts line %d: type %q does not match key", lineNo, keyType)
		}
		for _, pattern := range strings.Split(fields[idx], ",") {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" || strings.Contains(pattern, "*") || strings.Contains(pattern, "?") || strings.HasPrefix(pattern, "!") {
				return nil, fmt.Errorf("unsupported known_hosts pattern %q on line %d: exact hostnames only", pattern, lineNo)
			}
			keys[pattern] = append(keys[pattern], hostKey{algo: pub.Type(), key: pub})
			entries++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read SFTP known_hosts file: %w", err)
	}
	if entries == 0 {
		return nil, fmt.Errorf("SFTP known_hosts file has no usable entries")
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		host := hostname
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		candidates := keys[host]
		if len(candidates) == 0 {
			return fmt.Errorf("SFTP host %q not in known_hosts; refusing to connect", host)
		}
		for _, c := range candidates {
			if c.algo == key.Type() && bytes.Equal(c.key.Marshal(), key.Marshal()) {
				return nil
			}
		}
		return fmt.Errorf("SFTP host key mismatch for %q; refusing to connect", host)
	}, nil
}
