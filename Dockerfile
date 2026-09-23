# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o ftp-over-s3

# Final stage
FROM alpine:3.23

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create persistent state directory writable by nonroot user
RUN mkdir -p /data && chown 65532:65532 /data && chmod 0700 /data

# Copy binary from builder
COPY --from=builder /app/ftp-over-s3 .

# Document supported environment variables
# Required:
# - FTP_USER: FTP username
# - FTP_PASSWORD: FTP password
# Optional:
# - FTP_HOST: FTP server host (default: "localhost")
# - FTP_PORT: FTP server port (default: 21)
# - FTP_TLS: Enable certificate-verified explicit FTPS (default: false)
# - FTP_MAX_CONNECTIONS: Maximum simultaneous FTP connections (default: 2)
# - BACKEND: Storage backend, ftp or sftp (default: "ftp")
# - SFTP_KEY_FILE: SFTP private key file (optional when FTP_PASSWORD set)
# - SFTP_KEY_PASS: SFTP private key passphrase
# - SFTP_KNOWN_HOSTS: SFTP known_hosts file (required for sftp backend)
# - SFTP_MAX_SESSIONS: Maximum pooled SFTP sessions (default: same as FTP_MAX_CONNECTIONS)
# - FORCE_BACKEND: Rebind STATE_DIR to current backend once, then unset (default: "false")
# - S3_ACCESS_KEY_ID: S3 access key for authentication
# - S3_SECRET_KEY: S3 secret key for authentication
# - LOG_LEVEL: Logging level (DEBUG, INFO, WARN, ERROR)
# - LISTEN_ADDR: HTTP listen address (default: ":8080")
# - STATE_DIR: Persistent state directory for metadata, multipart staging, and lock files (default: "/data")
# - MAX_STAGING_BYTES: Global byte limit for request/copy spools and multipart parts (default: 21474836480)
# - MAX_CONCURRENT_UPLOADS: Maximum concurrent body-bearing and copy operations (default: 16)
# - UPLOAD_TIMEOUT: Maximum duration of an upload operation (default: "15m")

ENV STATE_DIR=/data
VOLUME /data

# Expose the default port
EXPOSE 8080

USER 65532:65532

# Set the entrypoint
ENTRYPOINT ["/app/ftp-over-s3"] 