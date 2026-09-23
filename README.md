# FTP-over-S3

A Go HTTP server exposing a **single, path-style S3 bucket named `default`**, backed by the FTP account's login root. Intended for file-transfer clients, not as a replacement for every AWS S3 feature.

## Run

Build the current checkout (Go 1.26 recommended):

```sh
go build -o ftp-over-s3 .
export FTP_HOST=ftp.example.com
export FTP_USER=your_username
export FTP_PASSWORD=your_password
export FTP_TLS=true
export S3_ACCESS_KEY_ID=your_access_key
export S3_SECRET_KEY=your_secret_key
./ftp-over-s3 -listen 127.0.0.1:8080
```

Or build and run a local container image; a previously published image does not contain unpushed changes. The container runs as non-root user `65532:65532` and stores state in `/data`:

```sh
docker build -t ftp-over-s3 .
docker run --rm -p 127.0.0.1:8080:8080 \
  -v ftp-over-s3-state:/data \
  -e FTP_HOST -e FTP_USER -e FTP_PASSWORD -e FTP_TLS \
  -e S3_ACCESS_KEY_ID -e S3_SECRET_KEY \
  ftp-over-s3
```

Mounting the named volume `ftp-over-s3-state:/data` ensures persistent metadata, multipart parts, and backend state survive container restarts.

**Security & Transport:** use `FTP_TLS=true` (or `-ftp-tls=true`) for explicit FTPS: both control and data connections use TLS with certificate and hostname verification. No insecure certificate bypass is provided. Plain FTP remains available for trusted local networks; implicit FTPS is not implemented.

**SFTP backend:** set `BACKEND=sftp` (or `-backend sftp`) to use SFTP instead of FTP. Authentication is key file (`SFTP_KEY_FILE` / `-sftp-key-file`, optional passphrase via `SFTP_KEY_PASS`) with password (`FTP_PASSWORD`) as fallback; host verification via a `known_hosts` file (`SFTP_KNOWN_HOSTS` / `-sftp-known-hosts`) is required — unknown or mismatched hosts fail closed, no trust-on-first-use. Backend identity includes the backend kind, so FTP and SFTP against the same host use separate state bindings. Switching backends against the same `STATE_DIR` fails closed with a backend-mismatch error; to rebind explicitly (committed metadata is revalidated against remote stat), restart once with `FORCE_BACKEND=true` (or `-force-backend=true`), then remove the flag.

The gateway listener is plain HTTP; native HTTPS is not implemented, and deploying dummy or fake TLS domain configurations in the gateway is not supported. For public or remote clients, terminate HTTPS with an external reverse proxy (e.g., Nginx, Caddy, Envoy, or AWS ALB). The reverse proxy **must preserve the raw request `Host` header, URL query string, and un-normalized request path** exactly as received from the client. AWS SigV4 calculates canonical request hashes over the exact host, path, and query strings; rewriting, URL-decoding, or stripping headers causes signature verification failures (`SignatureDoesNotMatch`). Restrict the FTP account to its intended storage root. If both S3 credentials are omitted, authentication is disabled with a startup warning. Supplying only one credential is a startup error.

`ftp.txt` is a local credential reference, not an automatically loaded configuration file. It is excluded from Git and Docker build contexts. Set environment variables or flags; do not commit secrets.

### Configuration

Explicit command-line flags override environment variables.

| Flag | Environment | Default |
|---|---|---|
| `-ftp-host` | `FTP_HOST` | `localhost` |
| `-ftp-port` | `FTP_PORT` | `21` |
| `-ftp-user` | `FTP_USER` | Required |
| `-ftp-password` | `FTP_PASSWORD` | Required |
| `-ftp-tls=true` | `FTP_TLS` | `false`; enable for explicit FTPS |
| `-ftp-max-connections` | `FTP_MAX_CONNECTIONS` | `2`; excess requests wait for a connection slot |
| `-backend` | `BACKEND` | `ftp`; `sftp` selects the SFTP backend |
| `-sftp-key-file` | `SFTP_KEY_FILE` | Empty; SFTP private key file |
| `-sftp-key-pass` | `SFTP_KEY_PASS` | Empty; SFTP private key passphrase |
| `-sftp-known-hosts` | `SFTP_KNOWN_HOSTS` | Required for `sftp` backend; known_hosts file |
| `-force-backend` | `FORCE_BACKEND` | `false`; `true` rebinds `STATE_DIR` to the current backend once |
| `-listen` | `LISTEN_ADDR` | `:8080` |
| `-access-key-id` | `S3_ACCESS_KEY_ID` | Empty: authentication disabled |
| `-secret-key` | `S3_SECRET_KEY` | Empty: authentication disabled |
| `-log-level` | `LOG_LEVEL` | `INFO` |
| `-state-dir` | `STATE_DIR` | `.ftp-over-s3-state` (Docker image sets `/data`) |
| `-max-staging-bytes` | `MAX_STAGING_BYTES` | `21474836480` (20 GiB shared disk budget) |
| `-max-concurrent-uploads` | `MAX_CONCURRENT_UPLOADS` | `16`; concurrent body-bearing PUT/POST and copy admissions |
| `-upload-timeout` | `UPLOAD_TIMEOUT` | `15m`; maximum duration for upload operations |

`GET /health` and `HEAD /health` are unauthenticated liveness checks, not FTP readiness checks. SIGINT or SIGTERM initiates graceful HTTP shutdown (up to 30 seconds). Shutdown and restart preserve durable object metadata (`objects/`) and active multipart upload parts (`uploads/`) on disk; only temporary request spools (`spool/`) are cleaned up on startup.

## Clients

### AWS CLI

```sh
export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY"
export AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://localhost:8080 s3 ls
aws --endpoint-url http://localhost:8080 s3 cp myfile.txt s3://default/myfile.txt
aws --endpoint-url http://localhost:8080 s3 cp s3://default/myfile.txt downloaded.txt
aws --endpoint-url http://localhost:8080 s3 cp s3://default/myfile.txt s3://default/copied.txt --copy-props metadata-directive
aws --endpoint-url http://localhost:8080 s3 mv s3://default/copied.txt s3://default/moved.txt --copy-props metadata-directive
aws --endpoint-url http://localhost:8080 s3 ls s3://default/ --recursive
aws --endpoint-url http://localhost:8080 s3 sync s3://default/ ./downloaded
aws --endpoint-url http://localhost:8080 s3 rm s3://default/myfile.txt
aws --endpoint-url http://localhost:8080 s3 rm s3://default/ --recursive
```

Normal AWS CLI multipart transfers, server-side CopyObject (`aws s3 cp s3://... s3://...`), server-side move (`aws s3 mv`), recursive deletion (`aws s3 rm --recursive` via bulk DeleteObjects), directory sync, and checksums are supported; do not disable checksums to use the gateway. For S3-to-S3 `cp` and `mv`, AWS CLI v2 by default attempts to copy object tags via `GetObjectTagging`; because object tagging is intentionally unsupported (returning 501 `NotImplemented`), S3-to-S3 `cp` and `mv` commands must pass `--copy-props metadata-directive` (or configure `copy_props = metadata-directive` in AWS config) to preserve metadata without requesting tags. Uploads are file objects; directory-marker keys ending in `/` are rejected.

### boto3

Use **SigV4 explicitly**: boto3 can otherwise generate legacy SigV2 presigned URLs even when ordinary requests use SigV4.

```python
import boto3
from botocore.config import Config

s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:8080",
    region_name="us-east-1",
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)
# Upload with metadata
s3.put_object(
    Bucket="default",
    Key="nested/myfile.txt",
    Body=b"file content",
    ContentType="text/plain",
    Metadata={"owner": "alice", "project": "demo"},
)
# Server-side copy with precondition
s3.copy_object(
    Bucket="default",
    Key="nested/copied.txt",
    CopySource={"Bucket": "default", "Key": "nested/myfile.txt"},
    CopySourceIfMatch=s3.head_object(Bucket="default", Key="nested/myfile.txt")["ETag"],
)
# Bulk delete
s3.delete_objects(
    Bucket="default",
    Delete={"Objects": [{"Key": "nested/copied.txt"}]},
)
url = s3.generate_presigned_url(
    "get_object", Params={"Bucket": "default", "Key": "nested/myfile.txt"}, ExpiresIn=300
)
```

## Supported behavior

- SigV4 Authorization headers and presigned URLs, scope/date/expiry verification, constant-time signature comparison.
- ListBuckets, HeadBucket and GetBucketLocation for `default`.
- PutObject, GetObject, HeadObject and idempotent DeleteObject.
- CopyObject and UploadPartCopy: server-side object copies, byte-range copies (`x-amz-copy-source-range`), metadata replacement or copying (`COPY` or `REPLACE`), and copy preconditions (`x-amz-copy-source-if-match`, `x-amz-copy-source-if-none-match`, `x-amz-copy-source-if-unmodified-since`, `x-amz-copy-source-if-modified-since`). Object tagging (`GetObjectTagging`, `PutObjectTagging`) is explicitly unsupported.
- Bulk DeleteObjects (`POST /{bucket}?delete`) with XML payload, supporting quiet and verbose response modes and per-key error reporting.
- Conditional writes and deletes: `If-Match`, `If-None-Match`, and `If-Unmodified-Since` evaluated under a gateway-exclusive global mutation lock.
- Durable object metadata: user-defined metadata (`x-amz-meta-*`) and standard HTTP metadata headers (`Content-Type`, `Cache-Control`, `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Expires`) persisted on disk in `STATE_DIR/objects/`.
- Resumable multipart uploads: CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload, ListParts and ListMultipartUploads. Active sessions and part files survive gateway restarts until the 24-hour TTL expires.
- Durable Content-MD5 ETags for single PUTs and composite multipart ETags (`<hash>-<parts>`) for multipart completions, preserved across restarts.
- Recursive ListObjects V1/V2, partial prefixes, delimiters, pagination and `encoding-type=url`.
- Single byte ranges and conditional reads (`If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`), including parallel ranged downloads.
- Request payload integrity checks: Content-MD5, SHA-256, SHA-1, CRC32, CRC32C and CRC64NVME; unsigned `aws-chunked` checksum trailers. Signed AWS streaming-chunk signatures are explicitly unsupported.
- XML S3 errors for rejected requests and unsupported storage/security features, rather than silent success.

## Storage semantics and limits

- **Durable state directory and process lock:** Gateway state is stored in `STATE_DIR` (default `.ftp-over-s3-state`; `/data` in Docker), containing `objects/` (persisted metadata and ETags), `uploads/` (active multipart sessions and part files), and `spool/` (temporary request spools). `STATE_DIR` must reside on persistent storage outside the FTP root, with strict 0700 private directory permissions enforced to protect credentials and metadata. The directory is guarded by an exclusive process lock (`.lock` via `flock`) and a backend marker (`backend.id`) binding host, port, and username (excluding password and TLS settings) to prevent accidental reuse against a different FTP server. Clean shutdown and gateway restarts preserve metadata and multipart sessions; abandoned temporary spools in `spool/` are cleaned up on startup.
- **Shared admission and disk staging limits:** `MAX_CONCURRENT_UPLOADS` (default 16) bounds concurrent authenticated body-bearing PUT/POST and copy upload admissions. When the limit is reached, incoming requests immediately receive HTTP 503 `SlowDown` ("Please reduce your request rate.") with `Connection: close`. `MAX_STAGING_BYTES` (default 20 GiB / 21474836480 bytes) enforces a shared disk budget across request/copy spools and stored multipart parts. Individual PUTs and multipart parts are capped at **5 GiB**. Multipart supports up to **100 active sessions** and **10,000 parts per session**, with a **5 MiB minimum for non-final parts**.
- **Double staging during multipart uploads:** When uploading a part via `UploadPart`, the incoming body is first spooled into `spool/` (reserving against the shared disk budget) before being written to the session's part file in `uploads/` (which also reserves from the budget) prior to releasing the request spool. Callers must account for this temporary double reservation when calculating staging capacity for concurrent large part uploads. Multipart completion streams parts sequentially without creating a second assembled copy.
- **Gateway-exclusive writer & conditional mutation lock:** The gateway requires exclusive writer ownership of the backend FTP storage. All mutating operations—single PUTs, deletions, multipart completions, copies, and conditional precondition evaluations—are serialized under a global gateway mutation lock. External FTP writers cannot coordinate with this lock.
- **FTP publication, ambiguous renames & fail-closed metadata:** Uploads stage new data to a temporary file beside the destination and verify byte size against reported size before publishing via FTP rename (`RNFR`/`RNTO`). Some FTP servers do not support replacing existing files via rename; such overwrites fail rather than deleting the original first. FTP lacks transactional durability: if a network disconnect or error occurs during or after the rename, the remote state is uncertain. Durable metadata uses two-phase commit: a `.pending` marker is recorded on disk before remote mutation. If an operation fails during or after rename, the pending marker remains. Subsequent reads fail closed by treating the metadata record as absent, preventing stale metadata or ETags from being attached to potentially modified remote files.
- **Durable ETags vs. remote stat fallback:** Objects written through the gateway have their Content-MD5 ETag (or multipart composite ETag) and user metadata stored durably on disk. When loading an object, the gateway validates that the remote FTP file's size and modification timestamp match the persisted record. If the record is missing, corrupted, invalidated by a pending marker, or if remote stat attributes differ (stat mismatch from external FTP edits), the gateway falls back to an opaque size/mtime-derived ETag with `Content-Type: application/octet-stream` and no user metadata. External FTP modifications that preserve identical byte size within the FTP server's timestamp resolution cannot be detected. Do not rely on ETags as an integrity guarantee if external FTP clients write directly to the backend.
- **FTP connection & path rules:** Each FTP operation owns its connection; dial timeout is 30 seconds, and network I/O has a 15-second inactivity deadline. FTP concurrency is bounded by `FTP_MAX_CONNECTIONS`. Paths are not normalized into other keys: dot segments, repeated/leading/trailing slashes, backslashes, control characters, and `.ftp-over-s3-` path components are rejected. Ordinary dotfiles are visible. Symlinks are not exposed; FTP lacks an atomic no-follow primitive, so a chroot/restricted account is still necessary against external symlink races. An FTP filesystem cannot simultaneously represent a file `a` and a directory `a/`. Empty directories are not S3 objects. Recursive listings traverse FTP directories and are not transactionally consistent with concurrent external changes.
- **No multi-instance coordination:** The exclusive process lock on `STATE_DIR` prevents multiple processes from sharing a state directory. Do not run multiple gateway instances against the same FTP backend: there is no distributed locking or multi-instance metadata coordination.
- **Unsupported S3 features:** ACLs, IAM/bucket policies, bucket creation/deletion, bucket versioning, object tagging (tags return 501 `NotImplemented`), Object Lock, server-side encryption, and signed AWS streaming chunk signatures are not implemented.

## Verification

New features (shared admission, durable metadata, CopyObject, UploadPartCopy, bulk DeleteObjects, resumable multipart uploads, and conditional writes/deletes) were verified locally using boto3 integration tests and unit tests. Prior real FTPS smoke testing against Pure-FTPd validated baseline transfer protocol and TLS connection handling.

Unit/regression coverage includes malformed and expired authentication, checksum tampering, payload cleanup, strict chunk framing, unsafe paths, listing tokens, multipart lifecycle/locking failures, disk budget accounting, and metadata durability:

```sh
go test -race ./...
```

`integration_test.py` exercises the actual gateway through boto3 and AWS CLI against a disposable FTP server. It covers escaped keys, empty files, pagination, ranges, presigned URLs, concurrent transfers, 12 MiB multipart round trips and resumable recovery, server-side CopyObject (COPY and REPLACE directives), UploadPartCopy with byte ranges, bulk DeleteObjects (quiet and verbose, per-key error reporting), metadata preservation, conditional creates/updates/deletes (`If-Match`, `If-None-Match`, `If-Unmodified-Since`), interrupted requests, mid-STOR FTP disconnects, false-success truncated transfers, failed renames, unsupported operations, and AWS CLI commands (`cp`, `mv`, `ls --recursive`, `sync`, `rm`).

Install test-only dependencies into a virtual environment; AWS CLI v2 must also be on PATH:

```sh
python3 -m venv /tmp/ftp-s3-test-venv
/tmp/ftp-s3-test-venv/bin/pip install boto3 pyftpdlib
mkdir -p /tmp/ftp-s3-test-root /tmp/ftp-s3-test-state
go build -race -o /tmp/ftp-s3-test .
```

In one terminal, start the disposable FTP fixture:

```sh
/tmp/ftp-s3-test-venv/bin/python integration_test.py \
  --serve-ftp --root /tmp/ftp-s3-test-root --ftp-port 2121
```

In a second terminal, start the gateway with an explicit temporary state directory:

```sh
/tmp/ftp-s3-test -ftp-host 127.0.0.1 -ftp-port 2121 -ftp-tls=false \
  -ftp-user test -ftp-password test -listen 127.0.0.1:18080 \
  -access-key-id test-access -secret-key test-secret \
  -state-dir /tmp/ftp-s3-test-state
```

Then run the checks with a fresh, empty fixture root:

```sh
/tmp/ftp-s3-test-venv/bin/python integration_test.py --root /tmp/ftp-s3-test-root
```

The fixture deliberately injects failures and uses test/test FTP credentials. Never expose it publicly or point this local-fixture suite at production storage.
