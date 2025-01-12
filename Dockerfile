# Build stage
FROM golang:1.21-alpine AS builder

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
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy binary from builder
COPY --from=builder /app/ftp-over-s3 .

# Document supported environment variables
# Required:
# - FTP_USER: FTP username
# - FTP_PASSWORD: FTP password
# Optional:
# - FTP_HOST: FTP server host (default: "localhost")
# - FTP_PORT: FTP server port (default: 21)
# - S3_ACCESS_KEY_ID: S3 access key for authentication
# - S3_SECRET_KEY: S3 secret key for authentication
# - LOG_LEVEL: Logging level (DEBUG, INFO, WARN, ERROR)

# Expose the default port
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/app/ftp-over-s3"] 