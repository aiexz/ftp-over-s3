# FTP-over-S3

This is a Go application that implements an S3-compatible server interface using FTP as its backend storage. It allows you to interact with an FTP server using S3-compatible tools and APIs.

## Features

- S3-compatible API endpoints
- FTP backend storage
- AWS Signature Version 4 (SigV4) authentication
- Support for basic S3 operations:
  - List buckets (directories)
  - Get objects
  - Put objects
  - Delete objects

## Quick Start with Docker

The easiest way to run FTP-over-S3 is using Docker:

```bash
docker run -p 8080:8080 \
  -e FTP_HOST=your.ftp.host \
  -e FTP_PORT=21 \
  -e FTP_USER=your_username \
  -e FTP_PASSWORD=your_password \
  -e S3_ACCESS_KEY_ID=your_access_key \
  -e S3_SECRET_KEY=your_secret_key \
  ghcr.io/aiexz/ftp-over-s3:master
```

## Installation

### Using Docker
Pull the image from GitHub Container Registry:
```bash
docker pull ghcr.io/aiexz/ftp-over-s3:master
```

### Building from Source
1. Make sure you have Go 1.21 or later installed
2. Clone this repository
3. Run `go mod download` to download dependencies

## Configuration

### Environment Variables
- Required:
  - `FTP_USER`: FTP username
  - `FTP_PASSWORD`: FTP password
- Optional:
  - `FTP_HOST`: FTP server host (default: "localhost")
  - `FTP_PORT`: FTP server port (default: 21)
  - `S3_ACCESS_KEY_ID`: S3 access key for authentication
  - `S3_SECRET_KEY`: S3 secret key for authentication
  - `LOG_LEVEL`: Logging level (DEBUG, INFO, WARN, ERROR)

### Command Line Flags
All configuration can also be done via command line flags:
- `-ftp-host`: FTP server hostname (default: "localhost")
- `-ftp-port`: FTP server port (default: 21)
- `-ftp-user`: FTP username
- `-ftp-password`: FTP password
- `-listen`: Address to listen on (default: ":8080")
- `-access-key-id`: S3 access key ID for authentication
- `-secret-key`: S3 secret access key for authentication
- `-log-level`: Log level (DEBUG, INFO, WARN, ERROR)

## Authentication

The server implements AWS Signature Version 4 (SigV4) authentication. You need to:

1. Configure the server with an access key ID and secret key:
   ```bash
   # Using environment variables
   export S3_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
   export S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   ```

2. Configure your S3 client with the same credentials:
   ```bash
   # Using AWS CLI
   aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE
   aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
   aws configure set region us-east-1
   ```

If no credentials are configured on the server, authentication will be skipped (useful for development/testing).

## Using with S3 Tools

The server implements a subset of the S3 API, making it compatible with various S3 clients. Here's an example using the AWS CLI:

```bash
# List objects (use --endpoint-url to point to your server)
aws s3 ls --endpoint-url http://localhost:8080

# Upload a file
aws s3 cp myfile.txt s3://default/myfile.txt --endpoint-url http://localhost:8080

# Download a file
aws s3 cp s3://default/myfile.txt downloaded.txt --endpoint-url http://localhost:8080

# Delete a file
aws s3 rm s3://default/myfile.txt --endpoint-url http://localhost:8080
```

## Limitations

- Currently implements only basic S3 operations
- Single bucket implementation (uses FTP root as the default bucket)
- Basic SigV4 authentication implementation (not all AWS features supported)
- Limited error handling and edge cases 

## Sidenote
This was all generated by Cursor. So it's cool that it's working, but I don't know if i will actually support it. Treat it as more like a proof of concept.
