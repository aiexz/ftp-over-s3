package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strconv"
)

type Config struct {
	FTPHost     string
	FTPPort     int
	FTPUser     string
	FTPPassword string
	ListenAddr  string
	AccessKeyID string
	SecretKey   string
	LogLevel    string
}

func main() {
	config := parseConfig()

	// Configure structured logging
	var level slog.Level
	switch config.LogLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
	}
	logHandler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	slog.Info("starting server",
		"address", config.ListenAddr,
		"ftp_host", config.FTPHost,
		"ftp_port", config.FTPPort,
		"log_level", config.LogLevel,
	)

	// Initialize credentials store
	credStore := NewCredentialsStore()
	if config.AccessKeyID != "" && config.SecretKey != "" {
		credStore.AddCredentials(config.AccessKeyID, config.SecretKey)
	}

	// Create S3 server
	s3Server := NewS3Server(config)

	// Wrap with auth middleware
	httpHandler := NewAuthMiddleware(credStore, s3Server)

	if err := http.ListenAndServe(config.ListenAddr, httpHandler); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func parseConfig() *Config {
	config := &Config{}

	flag.StringVar(&config.FTPHost, "ftp-host", "localhost", "FTP server host")
	flag.IntVar(&config.FTPPort, "ftp-port", 21, "FTP server port")
	flag.StringVar(&config.FTPUser, "ftp-user", "", "FTP username")
	flag.StringVar(&config.FTPPassword, "ftp-password", "", "FTP password")
	flag.StringVar(&config.ListenAddr, "listen", ":8080", "Address to listen on")
	flag.StringVar(&config.AccessKeyID, "access-key-id", "", "S3 access key ID")
	flag.StringVar(&config.SecretKey, "secret-key", "", "S3 secret access key")
	flag.StringVar(&config.LogLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR)")

	flag.Parse()

	// Check for required environment variables
	if envHost := os.Getenv("FTP_HOST"); envHost != "" {
		config.FTPHost = envHost
	}
	if envPort := os.Getenv("FTP_PORT"); envPort != "" {
		if port, err := strconv.Atoi(envPort); err == nil {
			config.FTPPort = port
		}
	}
	if envUser := os.Getenv("FTP_USER"); envUser != "" {
		config.FTPUser = envUser
	}
	if envPass := os.Getenv("FTP_PASSWORD"); envPass != "" {
		config.FTPPassword = envPass
	}
	if envAccessKey := os.Getenv("S3_ACCESS_KEY_ID"); envAccessKey != "" {
		config.AccessKeyID = envAccessKey
	}
	if envSecretKey := os.Getenv("S3_SECRET_KEY"); envSecretKey != "" {
		config.SecretKey = envSecretKey
	}
	if envLogLevel := os.Getenv("LOG_LEVEL"); envLogLevel != "" {
		config.LogLevel = envLogLevel
	}

	if config.FTPUser == "" || config.FTPPassword == "" {
		slog.Error("FTP credentials must be provided via flags or environment variables")
		os.Exit(1)
	}

	return config
}
