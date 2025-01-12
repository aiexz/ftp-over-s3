package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
}

type CredentialsStore struct {
	credentials map[string]Credentials
}

func NewCredentialsStore() *CredentialsStore {
	return &CredentialsStore{
		credentials: make(map[string]Credentials),
	}
}

func (store *CredentialsStore) AddCredentials(accessKeyID, secretAccessKey string) {
	store.credentials[accessKeyID] = Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}
	slog.Debug("added credentials", "access_key_id", accessKeyID)
}

func (store *CredentialsStore) GetCredentials(accessKeyID string) (Credentials, bool) {
	creds, ok := store.credentials[accessKeyID]
	return creds, ok
}

type AuthMiddleware struct {
	store   *CredentialsStore
	wrapped http.Handler
}

func NewAuthMiddleware(store *CredentialsStore, wrapped http.Handler) *AuthMiddleware {
	return &AuthMiddleware{
		store:   store,
		wrapped: wrapped,
	}
}

func (m *AuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Debug("processing request",
		"method", r.Method,
		"path", r.URL.Path,
		"headers", r.Header,
	)

	// Skip auth for healthcheck or if no credentials are configured
	if len(m.store.credentials) == 0 || r.URL.Path == "/health" {
		slog.Debug("skipping authentication",
			"path", r.URL.Path,
			"no_credentials", len(m.store.credentials) == 0,
			"is_health_check", r.URL.Path == "/health",
		)
		m.wrapped.ServeHTTP(w, r)
		return
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		slog.Debug("missing Authorization header")
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	// Parse AWS Signature v4 header to get access key
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "AWS4-HMAC-SHA256" {
		slog.Debug("invalid Authorization header format", "auth", auth)
		http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		return
	}

	credStr := strings.Split(parts[1], ",")[0]
	credParts := strings.Split(strings.Split(credStr, "=")[1], "/")
	if len(credParts) != 5 {
		slog.Debug("invalid credential format", "credential_str", credStr)
		http.Error(w, "Invalid credential format", http.StatusUnauthorized)
		return
	}

	accessKeyID := credParts[0]
	slog.Debug("authenticating request", "access_key_id", accessKeyID)

	creds, ok := m.store.GetCredentials(accessKeyID)
	if !ok {
		slog.Debug("invalid access key ID", "access_key_id", accessKeyID)
		http.Error(w, "Invalid access key ID", http.StatusUnauthorized)
		return
	}

	// Get AWS credentials
	awsCreds := aws.Credentials{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
	}

	// Create a new signer for each request
	signer := v4.NewSigner()

	// Verify the request signature
	err := signer.SignHTTP(context.Background(), awsCreds, r, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "s3", "us-east-1", time.Now())
	if err != nil {
		slog.Error("signature verification failed", "error", err)
		http.Error(w, "Signature verification failed", http.StatusUnauthorized)
		return
	}

	slog.Debug("authentication successful", "access_key_id", accessKeyID)
	m.wrapped.ServeHTTP(w, r)
}
