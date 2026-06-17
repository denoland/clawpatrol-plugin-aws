package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestS3Operation(t *testing.T) {
	mk := func(method, host, path, rawquery, copySource string) *http.Request {
		r := &http.Request{
			Method: method,
			Host:   host,
			Header: http.Header{},
			URL:    &url.URL{Path: path, RawQuery: rawquery},
		}
		if copySource != "" {
			r.Header.Set("X-Amz-Copy-Source", copySource)
		}
		return r
	}
	const ph = "s3.amazonaws.com"            // path-style
	const phR = "s3.us-east-1.amazonaws.com" // path-style, regional
	const vh = "bucket.s3.us-east-1.amazonaws.com"

	cases := []struct {
		name string
		req  *http.Request
		want string
	}{
		// Service / bucket / object addressing, path-style.
		{"list buckets", mk("GET", ph, "/", "", ""), "ListBuckets"},
		{"list objects v1", mk("GET", ph, "/bucket", "", ""), "ListObjects"},
		{"list objects v2", mk("GET", ph, "/bucket", "list-type=2", ""), "ListObjectsV2"},
		{"head bucket", mk("HEAD", ph, "/bucket", "", ""), "HeadBucket"},
		{"create bucket", mk("PUT", ph, "/bucket", "", ""), "CreateBucket"},
		{"delete bucket", mk("DELETE", ph, "/bucket", "", ""), "DeleteBucket"},
		{"get object", mk("GET", ph, "/bucket/key", "", ""), "GetObject"},
		{"head object", mk("HEAD", ph, "/bucket/key.txt", "", ""), "HeadObject"},
		{"put object", mk("PUT", ph, "/bucket/key", "", ""), "PutObject"},
		{"copy object", mk("PUT", ph, "/bucket/key", "", "/src/k"), "CopyObject"},
		{"delete object", mk("DELETE", ph, "/bucket/key", "", ""), "DeleteObject"},
		{"delete objects", mk("POST", ph, "/bucket", "delete", ""), "DeleteObjects"},

		// Virtual-host addressing (bucket in the host, key is the whole path).
		{"vh list objects", mk("GET", vh, "/", "", ""), "ListObjects"},
		{"vh get object", mk("GET", vh, "/some/key", "", ""), "GetObject"},
		{"vh put object", mk("PUT", vh, "/some/key", "", ""), "PutObject"},

		// Subresources.
		{"get object acl", mk("GET", ph, "/bucket/key", "acl", ""), "GetObjectAcl"},
		{"put object tagging", mk("PUT", ph, "/bucket/key", "tagging", ""), "PutObjectTagging"},
		{"delete object tagging", mk("DELETE", ph, "/bucket/key", "tagging", ""), "DeleteObjectTagging"},
		{"list object versions", mk("GET", phR, "/bucket", "versions", ""), "ListObjectVersions"},
		{"get bucket location", mk("GET", ph, "/bucket", "location", ""), "GetBucketLocation"},
		{"get bucket policy", mk("GET", ph, "/bucket", "policy", ""), "GetBucketPolicy"},
		{"list multipart uploads", mk("GET", ph, "/bucket", "uploads", ""), "ListMultipartUploads"},
		{"get bucket lifecycle", mk("GET", ph, "/bucket", "lifecycle", ""), "GetBucketLifecycleConfiguration"},

		// Multipart object lifecycle.
		{"create multipart", mk("POST", ph, "/bucket/key", "uploads", ""), "CreateMultipartUpload"},
		{"upload part", mk("PUT", ph, "/bucket/key", "partNumber=1&uploadId=abc", ""), "UploadPart"},
		{"upload part copy", mk("PUT", ph, "/bucket/key", "partNumber=1&uploadId=abc", "/src/k"), "UploadPartCopy"},
		{"complete multipart", mk("POST", ph, "/bucket/key", "uploadId=abc", ""), "CompleteMultipartUpload"},
		{"abort multipart", mk("DELETE", ph, "/bucket/key", "uploadId=abc", ""), "AbortMultipartUpload"},
		{"list parts", mk("GET", ph, "/bucket/key", "uploadId=abc", ""), "ListParts"},
		{"restore object", mk("POST", ph, "/bucket/key", "restore", ""), "RestoreObject"},
		{"select object content", mk("POST", ph, "/bucket/key", "select&select-type=2", ""), "SelectObjectContent"},

		// A write method with a subresource that only maps to a read method
		// must NOT borrow the read op — it falls through to the write default,
		// so it can never be auto-allowed as a read.
		{"put object with read-only subresource", mk("PUT", ph, "/bucket/key", "versions", ""), "PutObject"},
		{"delete object with select subresource", mk("DELETE", ph, "/bucket/key", "select", ""), "DeleteObject"},
		{"post bucket unknown subresource", mk("POST", ph, "/bucket", "frobnicate", ""), "PostBucket"},
		// Unknown HTTP method: METHOD-path fallback (no read prefix, gated as
		// a mutation), never a fabricated operation.
		{"unknown method fallback", mk("FROBNICATE", ph, "/bucket/key", "", ""), "FROBNICATE /bucket/key"},
	}
	for _, c := range cases {
		if got := s3Operation(c.req); got != c.want {
			t.Errorf("%s: s3Operation = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestS3BucketInHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"s3.amazonaws.com", false},
		{"s3.us-east-1.amazonaws.com", false},
		{"s3-fips.us-east-1.amazonaws.com", false},
		{"s3.dualstack.us-east-1.amazonaws.com", false},
		{"bucket.s3.amazonaws.com", true},
		{"my.dotted.bucket.s3.us-east-1.amazonaws.com", true},
		{"not-amazon.example.com", false},
	}
	for _, c := range cases {
		if got := s3BucketInHost(c.host); got != c.want {
			t.Errorf("s3BucketInHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
