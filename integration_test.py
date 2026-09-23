"""Run against a disposable FTP root and running gateway; see README for commands.
Dependencies: boto3, pyftpdlib (only for --serve-ftp).
"""
import argparse
import base64
import concurrent.futures
import hashlib
import io
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


def serve_ftp(root, port):
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler, DTPHandler
    from pyftpdlib.servers import FTPServer
    authorizer = DummyAuthorizer()
    authorizer.add_user("test", "test", root, perm="elradfmwMT")

    class FaultDataHandler(DTPHandler):
        def handle_read(self):
            super().handle_read()
            trigger = Path(root) / ".drop-next"
            if self.file_obj and "/drop/" in self.file_obj.name and self.tot_bytes_received >= 65536 and trigger.exists():
                trigger.unlink()
                self.cmd_channel.close()
                self.close()

        handle_read_event = handle_read

    class FaultHandler(FTPHandler):
        dtp_handler = FaultDataHandler

        def ftp_RNTO(self, path):
            if Path(root, ".deny-rename").exists() and path.endswith("/denied.bin"):
                self.respond("550 Rename denied by integration fault injection.")
                return
            return super().ftp_RNTO(path)

        def on_file_received(self, path):
            trigger = Path(root, ".truncate-next")
            if "/truncate/" in path and trigger.exists():
                trigger.unlink()
                with open(path, "r+b") as stored:
                    stored.truncate(1024)

    FaultHandler.authorizer = authorizer
    FTPServer(("127.0.0.1", port), FaultHandler).serve_forever()


def check(endpoint, root):
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
    from boto3.s3.transfer import TransferConfig

    client = boto3.client("s3", endpoint_url=endpoint,
                          aws_access_key_id="test-access", aws_secret_access_key="test-secret",
                          region_name="us-east-1",
                          config=Config(signature_version="s3v4", s3={"addressing_style": "path"}, retries={"max_attempts": 0}))
    bucket = "default"

    def rejected(code, operation, **kwargs):
        try:
            operation(**kwargs)
        except ClientError as error:
            assert error.response["Error"]["Code"] == code, error.response
        else:
            raise AssertionError(f"expected {code}")

    def get(key, **kwargs):
        response = client.get_object(Bucket=bucket, Key=key, **kwargs)
        with response["Body"] as body:
            return body.read()

    assert [item["Name"] for item in client.list_buckets()["Buckets"]] == [bucket]
    client.head_bucket(Bucket=bucket)
    rejected("404", client.head_bucket, Bucket="other")
    keys = ["nested/alpha.txt", "nested/beta.txt", "nested/deeper/data.bin", ".hidden", "space + percent%/日本語.txt", "empty"]
    for index, key in enumerate(keys):
        data = b"" if key == "empty" else (f"payload-{index}\n".encode() * 137)
        result = client.put_object(Bucket=bucket, Key=key, Body=data)
        assert result["ETag"] == '"' + hashlib.md5(data).hexdigest() + '"', result
        assert get(key) == data
        assert (root / key).read_bytes() == data
        assert client.head_object(Bucket=bucket, Key=key)["ContentLength"] == len(data)
    print("PASS signed checksummed PUT/GET/HEAD, escaped keys, empty and hidden files", flush=True)

    pages = list(client.get_paginator("list_objects_v2").paginate(Bucket=bucket, PaginationConfig={"PageSize": 2}))
    listed = [obj["Key"] for page in pages for obj in page.get("Contents", [])]
    assert listed == sorted(keys), listed
    v1 = list(client.get_paginator("list_objects").paginate(Bucket=bucket, PaginationConfig={"PageSize": 2}))
    assert [obj["Key"] for page in v1 for obj in page.get("Contents", [])] == sorted(keys)
    prefix = client.list_objects_v2(Bucket=bucket, Prefix="nested/a")
    assert [obj["Key"] for obj in prefix.get("Contents", [])] == ["nested/alpha.txt"]
    grouped = client.list_objects_v2(Bucket=bucket, Prefix="nested/", Delimiter="/")
    assert grouped["CommonPrefixes"] == [{"Prefix": "nested/deeper/"}], grouped
    assert len(grouped["Contents"]) == 2
    assert not client.list_objects_v2(Bucket=bucket, MaxKeys=0).get("Contents")
    print("PASS recursive V1/V2 pagination, partial prefixes and delimiters", flush=True)

    data = get(keys[0])
    assert get(keys[0], Range="bytes=2-8") == data[2:9]
    assert get(keys[0], Range="bytes=-7") == data[-7:]
    rejected("InvalidRange", client.get_object, Bucket=bucket, Key=keys[0], Range="bytes=999999-")
    etag = client.head_object(Bucket=bucket, Key=keys[0])["ETag"]
    rejected("PreconditionFailed", client.get_object, Bucket=bucket, Key=keys[0], IfMatch='"wrong"')
    assert get(keys[0], IfMatch=etag) == data
    print("PASS byte ranges and conditional reads", flush=True)

    for key in [keys[0], keys[4]]:
        url = client.generate_presigned_url("get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=60)
        with urllib.request.urlopen(url) as response:
            assert response.read() == get(key)
        try:
            urllib.request.urlopen(url + "&tampered=1")
        except urllib.error.HTTPError as error:
            assert error.code == 403
        else:
            raise AssertionError("tampered presigned URL accepted")
    bad = boto3.client("s3", endpoint_url=endpoint, aws_access_key_id="test-access", aws_secret_access_key="wrong",
                       region_name="us-east-1", config=Config(retries={"max_attempts": 0}))
    rejected("SignatureDoesNotMatch", bad.list_buckets)
    request = urllib.request.Request(endpoint + "/", headers={"Authorization": "AWS4-HMAC-SHA256 broken"})
    try:
        urllib.request.urlopen(request)
    except urllib.error.HTTPError as error:
        assert error.code in (400, 403)
    else:
        raise AssertionError("malformed authorization accepted")
    print("PASS real SDK signatures, presigning, tampering and malformed auth rejection", flush=True)

    def roundtrip(index):
        key = f"concurrent/{index}"
        data = bytes([index]) * (128 * 1024 + index)
        client.put_object(Bucket=bucket, Key=key, Body=data)
        assert get(key) == data
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(roundtrip, range(16)))
    print("PASS 16 concurrent byte-for-byte transfer round trips", flush=True)

    large = os.urandom(12 * 1024 * 1024 + 317)
    client.upload_fileobj(io.BytesIO(large), bucket, "large.bin",
                          Config=TransferConfig(multipart_threshold=5*1024*1024, multipart_chunksize=5*1024*1024, max_concurrency=3))
    assert get("large.bin") == large
    assert (root / "large.bin").read_bytes() == large
    downloaded = io.BytesIO()
    client.download_fileobj(bucket, "large.bin", downloaded, Config=TransferConfig(multipart_threshold=5*1024*1024, multipart_chunksize=5*1024*1024))
    assert downloaded.getvalue() == large
    print("PASS real SDK concurrent multipart upload and ranged download, 12 MiB", flush=True)

    upload = client.create_multipart_upload(Bucket=bucket, Key="manual.bin")["UploadId"]
    p1 = client.upload_part(Bucket=bucket, Key="manual.bin", UploadId=upload, PartNumber=1, Body=b"a"*(5*1024*1024))
    p2 = client.upload_part(Bucket=bucket, Key="manual.bin", UploadId=upload, PartNumber=2, Body=b"final")
    parts = [{"PartNumber": 1, "ETag": p1["ETag"]}, {"PartNumber": 2, "ETag": p2["ETag"]}]
    assert len(client.list_parts(Bucket=bucket, Key="manual.bin", UploadId=upload)["Parts"]) == 2
    rejected("InvalidPartOrder", client.complete_multipart_upload, Bucket=bucket, Key="manual.bin", UploadId=upload, MultipartUpload={"Parts": list(reversed(parts))})
    rejected("InvalidPart", client.complete_multipart_upload, Bucket=bucket, Key="manual.bin", UploadId=upload, MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": '"wrong"'}]})
    client.complete_multipart_upload(Bucket=bucket, Key="manual.bin", UploadId=upload, MultipartUpload={"Parts": parts})
    assert get("manual.bin") == b"a"*(5*1024*1024)+b"final"
    aborted = client.create_multipart_upload(Bucket=bucket, Key="aborted")["UploadId"]
    client.abort_multipart_upload(Bucket=bucket, Key="aborted", UploadId=aborted)
    rejected("NoSuchUpload", client.list_parts, Bucket=bucket, Key="aborted", UploadId=aborted)
    assert not client.list_multipart_uploads(Bucket=bucket).get("Uploads")
    print("PASS multipart validation, completion, listing and abort lifecycle", flush=True)

    original = b"original object remains intact"
    client.put_object(Bucket=bucket, Key="interrupted", Body=original)
    presigned = client.generate_presigned_url("put_object", Params={"Bucket": bucket, "Key": "interrupted"}, ExpiresIn=60)
    parsed = urllib.parse.urlsplit(presigned)
    conn = socket.create_connection((parsed.hostname, parsed.port))
    conn.sendall((f"PUT {parsed.path}?{parsed.query} HTTP/1.1\r\nHost: {parsed.netloc}\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n").encode() + b"partial")
    conn.close()
    time.sleep(0.3)
    assert get("interrupted") == original
    rejected("BadDigest", client.put_object, Bucket=bucket, Key="interrupted", Body=b"bad", ContentMD5="AAAAAAAAAAAAAAAAAAAAAA==")
    assert get("interrupted") == original
    print("PASS interrupted and invalid-checksum overwrites preserve existing object", flush=True)

    for key, trigger in [("drop/object.bin", ".drop-next"), ("denied.bin", ".deny-rename"), ("truncate/object.bin", ".truncate-next")]:
        previous = client.put_object(Bucket=bucket, Key=key, Body=original,
                                     ContentType="text/plain", Metadata={"preserved": "yes"})
        (root / trigger).touch()
        try:
            client.put_object(Bucket=bucket, Key=key, Body=b"replacement" * 200000)
        except ClientError:
            pass
        else:
            raise AssertionError(f"fault injection for {key} unexpectedly succeeded")
        finally:
            (root / trigger).unlink(missing_ok=True)
        assert (root / key).read_bytes() == original
        assert get(key) == original
        preserved = client.head_object(Bucket=bucket, Key=key)
        assert preserved["ETag"] == previous["ETag"]
        assert preserved["ContentType"] == "text/plain" and preserved["Metadata"] == {"preserved": "yes"}
    print("PASS FTP disconnect, failed rename and false-success truncation preserve existing objects", flush=True)

    client.delete_object(Bucket=bucket, Key="empty")
    client.delete_object(Bucket=bucket, Key="empty")
    rejected("NoSuchKey", client.get_object, Bucket=bucket, Key="empty")
    rejected("NotImplemented", client.put_object, Bucket=bucket, Key="encrypted", Body=b"x", ServerSideEncryption="AES256")
    rejected("NotImplemented", client.get_bucket_versioning, Bucket=bucket)
    for key in ["nested/../escape", "nested//alias", "nested/trailing/", "/leading"]:
        rejected("InvalidArgument", client.put_object, Bucket=bucket, Key=key, Body=b"must not be stored")
    print("PASS idempotent deletion and explicit unsupported-feature errors", flush=True)

    source_key = "copy/source + %.txt"
    source_data = b"metadata survives copies"
    uploaded = client.put_object(Bucket=bucket, Key=source_key, Body=source_data,
                                 ContentType="text/plain", CacheControl="max-age=60", Metadata={"owner": "integration"})
    copied = client.copy_object(Bucket=bucket, Key="copy/copied.txt",
                                CopySource={"Bucket": bucket, "Key": source_key},
                                CopySourceIfMatch=uploaded["ETag"])
    assert copied["CopyObjectResult"]["ETag"] == uploaded["ETag"]
    head = client.head_object(Bucket=bucket, Key="copy/copied.txt")
    assert head["Metadata"] == {"owner": "integration"} and head["ContentType"] == "text/plain"
    assert head["CacheControl"] == "max-age=60" and get("copy/copied.txt") == source_data
    rejected("PreconditionFailed", client.copy_object, Bucket=bucket, Key="copy/copied.txt",
             CopySource={"Bucket": bucket, "Key": source_key}, CopySourceIfMatch='"wrong"')
    client.copy_object(Bucket=bucket, Key="copy/copied.txt",
                       CopySource={"Bucket": bucket, "Key": "copy/copied.txt"},
                       MetadataDirective="REPLACE", ContentType="application/custom", Metadata={"owner": "replaced"})
    head = client.head_object(Bucket=bucket, Key="copy/copied.txt")
    assert head["Metadata"] == {"owner": "replaced"} and head["ContentType"] == "application/custom"
    assert get("copy/copied.txt") == source_data
    upload = client.create_multipart_upload(Bucket=bucket, Key="copy/ranged.bin", Metadata={"range": "yes"})["UploadId"]
    part = client.upload_part_copy(Bucket=bucket, Key="copy/ranged.bin", UploadId=upload, PartNumber=1,
                                   CopySource={"Bucket": bucket, "Key": source_key}, CopySourceRange="bytes=2-9")
    client.complete_multipart_upload(Bucket=bucket, Key="copy/ranged.bin", UploadId=upload,
                                     MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": part["CopyPartResult"]["ETag"]}]})
    assert get("copy/ranged.bin") == source_data[2:10]
    assert client.head_object(Bucket=bucket, Key="copy/ranged.bin")["Metadata"] == {"range": "yes"}
    print("PASS metadata COPY/REPLACE, escaped sources, conditional copy and ranged UploadPartCopy", flush=True)

    def conditional_create(index):
        data = f"winner-{index}".encode()
        try:
            client.put_object(Bucket=bucket, Key="conditional/race", Body=data, IfNoneMatch="*")
            return data
        except ClientError as error:
            assert error.response["Error"]["Code"] == "PreconditionFailed", error.response
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
        winners = [value for value in workers.map(conditional_create, range(8)) if value is not None]
    assert len(winners) == 1 and get("conditional/race") == winners[0]
    old_etag = client.head_object(Bucket=bucket, Key="conditional/race")["ETag"]
    client.put_object(Bucket=bucket, Key="conditional/race", Body=b"updated", IfMatch=old_etag)
    rejected("PreconditionFailed", client.put_object, Bucket=bucket, Key="conditional/race", Body=b"stale", IfMatch=old_etag)
    rejected("PreconditionFailed", client.delete_object, Bucket=bucket, Key="conditional/race", IfMatch=old_etag)
    assert get("conditional/race") == b"updated"
    current_etag = client.head_object(Bucket=bucket, Key="conditional/race")["ETag"]
    client.delete_object(Bucket=bucket, Key="conditional/race", IfMatch=current_etag)
    print("PASS competing conditional creates, stale updates and conditional deletes", flush=True)

    guarded = "bulk-guarded"
    client.put_object(Bucket=bucket, Key=guarded, Body=b"must survive invalid bulk requests")
    from botocore.auth import S3SigV4QueryAuth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials
    unsigned_delete = AWSRequest(method="POST", url=f"{endpoint}/{bucket}?delete=")
    S3SigV4QueryAuth(Credentials("test-access", "test-secret"), "s3", "us-east-1", expires=60).add_auth(unsigned_delete)
    delete_url = unsigned_delete.url
    valid_xml = f"<Delete><Object><Key>{guarded}</Key></Object></Delete>".encode()
    malformed_xml = valid_xml + b"<trailing/>"
    for body, checksum, code in [(valid_xml, False, "MissingContentMD5"),
                                  (malformed_xml, True, "MalformedXML")]:
        headers = {"Content-Type": "application/xml"}
        if checksum:
            headers["Content-MD5"] = base64.b64encode(hashlib.md5(body).digest()).decode()
        request = urllib.request.Request(delete_url, data=body, headers=headers, method="POST")
        try:
            urllib.request.urlopen(request)
        except urllib.error.HTTPError as error:
            parsed_error = ET.fromstring(error.read())
            assert parsed_error.findtext("Code") == code, ET.tostring(parsed_error)
        else:
            raise AssertionError(f"invalid bulk request accepted: {code}")
        assert get(guarded) == b"must survive invalid bulk requests"
    print("PASS missing bulk integrity and trailing XML rejection before deletion", flush=True)

    deleted = client.delete_objects(Bucket=bucket, Delete={"Objects": [
        {"Key": "copy/copied.txt"}, {"Key": "copy/missing"}, {"Key": "../unsafe"}]})
    assert {item["Key"] for item in deleted["Deleted"]} == {"copy/copied.txt", "copy/missing"}
    assert deleted["Errors"][0]["Key"] == "../unsafe"
    quiet = client.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": "copy/ranged.bin"}], "Quiet": True})
    assert not quiet.get("Deleted") and not quiet.get("Errors")
    rejected("NoSuchKey", client.get_object, Bucket=bucket, Key="copy/copied.txt")
    rejected("NoSuchKey", client.get_object, Bucket=bucket, Key="copy/ranged.bin")
    print("PASS bulk deletion, per-key errors and quiet responses", flush=True)

    env = dict(os.environ, AWS_ACCESS_KEY_ID="test-access", AWS_SECRET_ACCESS_KEY="test-secret", AWS_DEFAULT_REGION="us-east-1", AWS_EC2_METADATA_DISABLED="true", AWS_PAGER="")
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory)/"source.bin"
        target = Path(directory)/"target.bin"
        source.write_bytes(large)
        base = ["aws", "--endpoint-url", endpoint]
        subprocess.run(base+["s3", "cp", str(source), "s3://default/cli.bin", "--only-show-errors"], env=env, check=True)
        subprocess.run(base+["s3", "cp", "s3://default/cli.bin", str(target), "--only-show-errors"], env=env, check=True)
        assert target.read_bytes() == large
        subprocess.run(base+["s3", "cp", "s3://default/cli.bin", "s3://default/cli-copy.bin", "--copy-props", "metadata-directive", "--only-show-errors"], env=env, check=True)
        assert get("cli-copy.bin") == large
        subprocess.run(base+["s3", "mv", "s3://default/cli-copy.bin", "s3://default/cli-moved.bin", "--copy-props", "metadata-directive", "--only-show-errors"], env=env, check=True)
        assert get("cli-moved.bin") == large
        rejected("NoSuchKey", client.get_object, Bucket=bucket, Key="cli-copy.bin")
        subprocess.run(base+["s3", "ls", "s3://default/nested/", "--recursive"], env=env, check=True)
        sync = Path(directory)/"sync"
        subprocess.run(base+["s3", "sync", "s3://default/nested/", str(sync), "--only-show-errors"], env=env, check=True)
        assert (sync/"alpha.txt").read_bytes() == get("nested/alpha.txt")
        assert (sync/"deeper/data.bin").read_bytes() == get("nested/deeper/data.bin")
        subprocess.run(base+["s3", "rm", "s3://default/cli.bin", "--only-show-errors"], env=env, check=True)
    print("PASS AWS CLI multipart cp, server-side cp/mv, download, recursive ls, sync and rm", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve-ftp", action="store_true")
    parser.add_argument("--ftp-port", type=int, default=2121)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:18080")
    args = parser.parse_args()
    if args.serve_ftp:
        serve_ftp(str(args.root), args.ftp_port)
    else:
        check(args.endpoint, args.root)
