package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Backend              string
	ForceBackend         bool
	SFTPMaxSessions      int
	FTPHost              string
	FTPPort              int
	FTPUser              string
	FTPPassword          string
	FTPTLS               bool
	FTPMaxConnections    int
	SFTPKeyFile          string
	SFTPKeyPass          string
	SFTPKnownHosts       string
	ListenAddr           string
	AccessKeyID          string
	SecretKey            string
	LogLevel             string
	StateDir             string
	MaxStagingBytes      int64
	MaxConcurrentUploads int
	UploadTimeout        time.Duration
}

func main() {
	config := parseConfig()
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(config.LogLevel))); err != nil {
		slog.Error("invalid log level", "error", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
	credStore := NewCredentialsStore()
	if config.AccessKeyID != "" {
		credStore.AddCredentials(config.AccessKeyID, config.SecretKey)
	} else {
		slog.Warn("authentication disabled; do not expose this listener to untrusted networks")
	}
	s3Server, err := NewS3Server(config)
	if err != nil {
		slog.Error("cannot initialize storage state", "error", err)
		os.Exit(1)
	}
	defer s3Server.Close()
	server := &http.Server{
		Addr:              config.ListenAddr,
		Handler:           NewAuthMiddleware(credStore, s3Server, s3Server.admission),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			slog.Error("graceful shutdown timed out", "error", err)
			server.Close()
		}
		close(stopped)
	}()
	slog.Info("starting server", "address", config.ListenAddr, "ftp_host", config.FTPHost, "ftp_port", config.FTPPort)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
	<-stopped
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseConfig() *Config {
	config := &Config{}
	flag.StringVar(&config.Backend, "backend", envDefault("BACKEND", "ftp"), "Storage backend (ftp or sftp)")
	forceBackend := flag.String("force-backend", envDefault("FORCE_BACKEND", "false"), "Rebind state directory to current backend after operator confirmation (true or false)")
	flag.StringVar(&config.FTPHost, "ftp-host", envDefault("FTP_HOST", "localhost"), "FTP/SFTP server host")
	port := flag.String("ftp-port", envDefault("FTP_PORT", "21"), "FTP/SFTP server port")
	ftpTLS := flag.String("ftp-tls", envDefault("FTP_TLS", "false"), "Use certificate-verified explicit FTPS (true or false)")
	maxConnections := flag.String("ftp-max-connections", envDefault("FTP_MAX_CONNECTIONS", "2"), "Maximum simultaneous FTP/SFTP connections")
	sftpSessions := flag.String("sftp-max-sessions", envDefault("SFTP_MAX_SESSIONS", ""), "Maximum pooled SFTP sessions (default: same as -ftp-max-connections)")
	flag.StringVar(&config.FTPUser, "ftp-user", os.Getenv("FTP_USER"), "FTP/SFTP username")
	flag.StringVar(&config.FTPPassword, "ftp-password", os.Getenv("FTP_PASSWORD"), "FTP password or SFTP password auth")
	flag.StringVar(&config.SFTPKeyFile, "sftp-key-file", os.Getenv("SFTP_KEY_FILE"), "SFTP private key file (optional when password set)")
	flag.StringVar(&config.SFTPKeyPass, "sftp-key-pass", os.Getenv("SFTP_KEY_PASS"), "SFTP private key passphrase")
	flag.StringVar(&config.SFTPKnownHosts, "sftp-known-hosts", os.Getenv("SFTP_KNOWN_HOSTS"), "SFTP known_hosts file (required for sftp backend)")
	flag.StringVar(&config.ListenAddr, "listen", envDefault("LISTEN_ADDR", ":8080"), "Address to listen on")
	flag.StringVar(&config.AccessKeyID, "access-key-id", os.Getenv("S3_ACCESS_KEY_ID"), "S3 access key ID")
	flag.StringVar(&config.SecretKey, "secret-key", os.Getenv("S3_SECRET_KEY"), "S3 secret access key")
	flag.StringVar(&config.LogLevel, "log-level", envDefault("LOG_LEVEL", "INFO"), "Log level (DEBUG, INFO, WARN, ERROR)")
	flag.StringVar(&config.StateDir, "state-dir", envDefault("STATE_DIR", ".ftp-over-s3-state"), "Persistent metadata, multipart and temporary spool directory")
	stagingBytes := flag.String("max-staging-bytes", envDefault("MAX_STAGING_BYTES", "21474836480"), "Global byte limit for request/copy spools and multipart parts")
	uploadCount := flag.String("max-concurrent-uploads", envDefault("MAX_CONCURRENT_UPLOADS", "16"), "Maximum concurrent body-bearing and copy operations")
	uploadTimeout := flag.String("upload-timeout", envDefault("UPLOAD_TIMEOUT", "15m"), "Maximum duration of an upload operation")
	flag.Parse()
	var err error
	config.FTPPort, err = strconv.Atoi(*port)
	if err != nil || config.FTPPort < 1 || config.FTPPort > 65535 {
		slog.Error("FTP port must be an integer from 1 to 65535")
		os.Exit(1)
	}
	config.FTPTLS, err = strconv.ParseBool(*ftpTLS)
	if err != nil {
		slog.Error("FTP_TLS / -ftp-tls must be true or false")
		os.Exit(1)
	}
	config.ForceBackend, err = strconv.ParseBool(*forceBackend)
	if err != nil {
		slog.Error("FORCE_BACKEND / -force-backend must be true or false")
		os.Exit(1)
	}
	config.FTPMaxConnections, err = strconv.Atoi(*maxConnections)
	if err != nil || config.FTPMaxConnections < 1 {
		slog.Error("FTP_MAX_CONNECTIONS / -ftp-max-connections must be a positive integer")
		os.Exit(1)
	}
	if strings.TrimSpace(*sftpSessions) == "" {
		config.SFTPMaxSessions = config.FTPMaxConnections
	} else {
		config.SFTPMaxSessions, err = strconv.Atoi(*sftpSessions)
		if err != nil || config.SFTPMaxSessions < 1 {
			slog.Error("SFTP_MAX_SESSIONS / -sftp-max-sessions must be a positive integer")
			os.Exit(1)
		}
	}
	config.MaxStagingBytes, err = strconv.ParseInt(*stagingBytes, 10, 64)
	if err != nil || config.MaxStagingBytes < 1 {
		slog.Error("MAX_STAGING_BYTES / -max-staging-bytes must be a positive integer")
		os.Exit(1)
	}
	config.MaxConcurrentUploads, err = strconv.Atoi(*uploadCount)
	if err != nil || config.MaxConcurrentUploads < 1 {
		slog.Error("MAX_CONCURRENT_UPLOADS / -max-concurrent-uploads must be a positive integer")
		os.Exit(1)
	}
	config.UploadTimeout, err = time.ParseDuration(*uploadTimeout)
	if err != nil || config.UploadTimeout <= 0 {
		slog.Error("UPLOAD_TIMEOUT / -upload-timeout must be a positive duration")
		os.Exit(1)
	}
	if config.StateDir == "" {
		slog.Error("STATE_DIR / -state-dir must not be empty")
		os.Exit(1)
	}
	config.Backend = strings.ToLower(strings.TrimSpace(config.Backend))
	if config.Backend != "ftp" && config.Backend != "sftp" {
		slog.Error("BACKEND / -backend must be ftp or sftp")
		os.Exit(1)
	}
	if config.Backend == "ftp" {
		if config.FTPUser == "" || config.FTPPassword == "" {
			slog.Error("FTP credentials must be provided via flags or environment variables")
			os.Exit(1)
		}
	} else {
		if config.FTPUser == "" || (config.FTPPassword == "" && config.SFTPKeyFile == "") {
			slog.Error("SFTP requires a username plus key file (-sftp-key-file) or password (-ftp-password)")
			os.Exit(1)
		}
		if strings.TrimSpace(config.SFTPKnownHosts) == "" {
			slog.Error("SFTP requires known-hosts via -sftp-known-hosts (no implicit trust on first use)")
			os.Exit(1)
		}
	}
	if (config.AccessKeyID == "") != (config.SecretKey == "") {
		slog.Error("S3 access key and secret key must be configured together")
		os.Exit(1)
	}
	return config
}
