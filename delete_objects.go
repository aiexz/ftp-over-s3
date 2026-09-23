package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"
)

const maxDeletePayloadBytes = int64(2 * 1024 * 1024) // 2 MiB bound on bulk delete XML payload

// DeleteRequest represents the incoming XML payload for DeleteObjects.
type DeleteRequest struct {
	XMLName xml.Name           `xml:"Delete"`
	Quiet   bool               `xml:"Quiet"`
	Objects []DeleteRequestObj `xml:"Object"`
}

// DeleteRequestObj represents a single object entry in DeleteRequest.
type DeleteRequestObj struct {
	Key       string `xml:"Key"`
	VersionId string `xml:"VersionId"`
}

// DeleteResult represents the XML response for DeleteObjects.
type DeleteResult struct {
	XMLName xml.Name      `xml:"DeleteResult"`
	Xmlns   string        `xml:"xmlns,attr"`
	Deleted []DeletedObj  `xml:"Deleted,omitempty"`
	Error   []DeleteError `xml:"Error,omitempty"`
}

// DeletedObj represents a successfully deleted object in DeleteResult.
type DeletedObj struct {
	Key       string `xml:"Key"`
	VersionId string `xml:"VersionId,omitempty"`
}

// DeleteError represents a per-key failure in DeleteResult.
type DeleteError struct {
	Key       string `xml:"Key"`
	VersionId string `xml:"VersionId,omitempty"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
}

// handleDeleteObjects handles POST requests to /{bucket}?delete for bulk object deletion.
func (s *S3Server) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	if bucket != "default" {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusNotFound,
			Code:    "NoSuchBucket",
			Message: "The specified bucket does not exist.",
		})
		return
	}

	if r.Method != http.MethodPost {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusMethodNotAllowed,
			Code:    "MethodNotAllowed",
			Message: "Method not allowed.",
		})
		return
	}

	// Validate presence of an integrity header: Content-MD5, x-amz-checksum-*, or hex sha256
	hasIntegrity := r.Header.Get("Content-MD5") != "" ||
		r.Header.Get("x-amz-checksum-crc32") != "" ||
		r.Header.Get("x-amz-checksum-crc32c") != "" ||
		r.Header.Get("x-amz-checksum-sha1") != "" ||
		r.Header.Get("x-amz-checksum-sha256") != ""

	if !hasIntegrity {
		sha := strings.TrimSpace(r.Header.Get("x-amz-content-sha256"))
		if len(sha) == 64 && isHexStr(sha) {
			hasIntegrity = true
		}
	}

	if !hasIntegrity {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "MissingContentMD5",
			Message: "Missing required header for this request: Content-MD5",
		})
		return
	}

	// Read bounded payload
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxDeletePayloadBytes+1))
	if err != nil {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "IncompleteBody",
			Message: "Failed reading request body.",
		})
		return
	}
	if int64(len(bodyBytes)) > maxDeletePayloadBytes {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "MaxMessageLengthExceeded",
			Message: "Your request was too large.",
		})
		return
	}

	// If preparePayload did not already verify Content-MD5 (e.g. in a direct test), verify it here
	if r.Header.Get("X-Ftp-Content-Md5") == "" && r.Header.Get("Content-MD5") != "" {
		clientMD5Str := strings.TrimSpace(r.Header.Get("Content-MD5"))
		expectedMD5, decErr := base64.StdEncoding.DecodeString(clientMD5Str)
		if decErr != nil || len(expectedMD5) != 16 {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusBadRequest,
				Code:    "InvalidDigest",
				Message: "The Content-MD5 you specified is not valid.",
			})
			return
		}
		actualMD5 := md5.Sum(bodyBytes)
		if !bytes.Equal(expectedMD5, actualMD5[:]) {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusBadRequest,
				Code:    "BadDigest",
				Message: "The Content-MD5 you specified did not match what we received.",
			})
			return
		}
	}

	var delReq DeleteRequest
	decoder := xml.NewDecoder(bytes.NewReader(bodyBytes))
	if err := decoder.Decode(&delReq); err != nil {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "MalformedXML",
			Message: "The XML you provided was not well-formed or did not validate against our published schema",
		})
		return
	}

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusBadRequest,
				Code:    "MalformedXML",
				Message: "The XML you provided was not well-formed or did not validate against our published schema",
			})
			return
		}
		switch t := token.(type) {
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				writeOperationError(w, r, s3OperationError{
					Status:  http.StatusBadRequest,
					Code:    "MalformedXML",
					Message: "The XML you provided was not well-formed or did not validate against our published schema",
				})
				return
			}
		case xml.Comment, xml.ProcInst:
			continue
		default:
			writeOperationError(w, r, s3OperationError{
				Status:  http.StatusBadRequest,
				Code:    "MalformedXML",
				Message: "The XML you provided was not well-formed or did not validate against our published schema",
			})
			return
		}
	}

	if len(delReq.Objects) == 0 {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "MalformedXML",
			Message: "The XML you provided was not well-formed or did not validate against our published schema",
		})
		return
	}

	if len(delReq.Objects) > 1000 {
		writeOperationError(w, r, s3OperationError{
			Status:  http.StatusBadRequest,
			Code:    "InvalidArgument",
			Message: "The number of keys in delete request exceeds the maximum allowed (1000).",
		})
		return
	}

	result := DeleteResult{
		Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/",
	}

	for _, obj := range delReq.Objects {
		// Reject unsupported version requests without touching the key
		if obj.VersionId != "" {
			result.Error = append(result.Error, DeleteError{
				Key:       obj.Key,
				VersionId: obj.VersionId,
				Code:      "NotImplemented",
				Message:   "Versioning is not supported",
			})
			continue
		}

		if err := validateKey(obj.Key); err != nil {
			result.Error = append(result.Error, DeleteError{
				Key:     obj.Key,
				Code:    "InvalidArgument",
				Message: err.Error(),
			})
			continue
		}

		err := s.deleteObject(r, obj.Key)
		if err != nil {
			var opErr s3OperationError
			var opErrPtr *s3OperationError
			if errors.As(err, &opErr) {
				result.Error = append(result.Error, DeleteError{
					Key:     obj.Key,
					Code:    opErr.Code,
					Message: opErr.Message,
				})
			} else if errors.As(err, &opErrPtr) && opErrPtr != nil {
				result.Error = append(result.Error, DeleteError{
					Key:     obj.Key,
					Code:    opErrPtr.Code,
					Message: opErrPtr.Message,
				})
			} else {
				result.Error = append(result.Error, DeleteError{
					Key:     obj.Key,
					Code:    "InternalError",
					Message: err.Error(),
				})
			}
		} else {
			if !delReq.Quiet {
				result.Deleted = append(result.Deleted, DeletedObj{
					Key: obj.Key,
				})
			}
		}
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(result)
}
