package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeleteObjectsXMLValidation(t *testing.T) {
	t.Run("valid XML unmarshaling", func(t *testing.T) {
		body := `<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
			<Quiet>true</Quiet>
			<Object><Key>file1.txt</Key></Object>
			<Object><Key>file2.txt</Key><VersionId>v1</VersionId></Object>
		</Delete>`

		var req DeleteRequest
		if err := xml.Unmarshal([]byte(body), &req); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}
		if !req.Quiet {
			t.Errorf("expected Quiet=true, got false")
		}
		if len(req.Objects) != 2 {
			t.Fatalf("expected 2 objects, got %d", len(req.Objects))
		}
		if req.Objects[0].Key != "file1.txt" || req.Objects[0].VersionId != "" {
			t.Errorf("unexpected obj 0: %+v", req.Objects[0])
		}
		if req.Objects[1].Key != "file2.txt" || req.Objects[1].VersionId != "v1" {
			t.Errorf("unexpected obj 1: %+v", req.Objects[1])
		}
	})

	t.Run("malformed XML fails", func(t *testing.T) {
		body := `<Delete><Object><Key>unclosed`
		var req DeleteRequest
		if err := xml.Unmarshal([]byte(body), &req); err == nil {
			t.Fatal("expected error on malformed XML, got nil")
		}
	})
}

func TestDeleteObjectsIntegrityAndValidation(t *testing.T) {
	srv := &S3Server{}

	t.Run("missing integrity header returns 400 MissingContentMD5", func(t *testing.T) {
		body := `<Delete><Object><Key>test.txt</Key></Object></Delete>`
		req := httptest.NewRequest(http.MethodPost, "/default?delete", strings.NewReader(body))
		w := httptest.NewRecorder()

		srv.handleDeleteObjects(w, req, "default")
		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", resp.StatusCode)
		}
		respBody := w.Body.String()
		if !strings.Contains(respBody, "MissingContentMD5") {
			t.Fatalf("expected MissingContentMD5 in body, got: %s", respBody)
		}
	})

	t.Run("X-Ftp-Content-Md5 alone without client integrity header rejected with MissingContentMD5", func(t *testing.T) {
		body := `<Delete><Object><Key>test.txt</Key></Object></Delete>`
		req := httptest.NewRequest(http.MethodPost, "/default?delete", strings.NewReader(body))
		req.Header.Set("X-Ftp-Content-Md5", "0123456789abcdef0123456789abcdef")
		w := httptest.NewRecorder()

		srv.handleDeleteObjects(w, req, "default")
		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", resp.StatusCode)
		}
		respBody := w.Body.String()
		if !strings.Contains(respBody, "MissingContentMD5") {
			t.Fatalf("expected MissingContentMD5 in body, got: %s", respBody)
		}
	})

	t.Run("empty object list returns MalformedXML", func(t *testing.T) {
		body := `<Delete><Quiet>false</Quiet></Delete>`
		req := httptest.NewRequest(http.MethodPost, "/default?delete", strings.NewReader(body))
		h := md5.Sum([]byte(body))
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(h[:]))
		w := httptest.NewRecorder()

		srv.handleDeleteObjects(w, req, "default")
		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", resp.StatusCode)
		}
		respBody := w.Body.String()
		if !strings.Contains(respBody, "MalformedXML") {
			t.Fatalf("expected MalformedXML in body, got: %s", respBody)
		}
	})

	t.Run("trailing elements rejected as MalformedXML", func(t *testing.T) {
		body := `<Delete><Object><Key>bulk-guarded</Key></Object></Delete><trailing/>`
		req := httptest.NewRequest(http.MethodPost, "/default?delete", strings.NewReader(body))
		h := md5.Sum([]byte(body))
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(h[:]))
		w := httptest.NewRecorder()

		srv.handleDeleteObjects(w, req, "default")
		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", resp.StatusCode)
		}
		respBody := w.Body.String()
		if !strings.Contains(respBody, "MalformedXML") {
			t.Fatalf("expected MalformedXML in body, got: %s", respBody)
		}
	})

	t.Run("over 1000 objects rejected with InvalidArgument", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString("<Delete>")
		for i := 0; i < 1001; i++ {
			fmt.Fprintf(&buf, "<Object><Key>file%d.txt</Key></Object>", i)
		}
		buf.WriteString("</Delete>")
		payload := buf.Bytes()

		req := httptest.NewRequest(http.MethodPost, "/default?delete", bytes.NewReader(payload))
		h := md5.Sum(payload)
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(h[:]))
		w := httptest.NewRecorder()

		srv.handleDeleteObjects(w, req, "default")
		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", resp.StatusCode)
		}
		respBody := w.Body.String()
		if !strings.Contains(respBody, "InvalidArgument") {
			t.Fatalf("expected InvalidArgument in body, got: %s", respBody)
		}
	})

	t.Run("versionId rejected per-key without touching key", func(t *testing.T) {
		body := `<Delete>
			<Object><Key>versioned.txt</Key><VersionId>v100</VersionId></Object>
			<Object><Key>bad\key.txt</Key></Object>
		</Delete>`
		req := httptest.NewRequest(http.MethodPost, "/default?delete", strings.NewReader(body))
		h := md5.Sum([]byte(body))
		req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(h[:]))
		w := httptest.NewRecorder()

		srv.handleDeleteObjects(w, req, "default")
		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}

		var res DeleteResult
		if err := xml.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal DeleteResult: %v", err)
		}
		if len(res.Error) != 2 {
			t.Fatalf("expected 2 errors, got %d", len(res.Error))
		}
		if res.Error[0].Key != "versioned.txt" || res.Error[0].Code != "NotImplemented" || res.Error[0].VersionId != "v100" {
			t.Errorf("unexpected error 0: %+v", res.Error[0])
		}
		if res.Error[1].Key != "bad\\key.txt" || res.Error[1].Code != "InvalidArgument" {
			t.Errorf("unexpected error 1: %+v", res.Error[1])
		}
	})
}
