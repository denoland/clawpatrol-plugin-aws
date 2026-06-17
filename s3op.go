package main

import (
	"net/http"
	"strings"
)

// S3 is a REST service: the operation is not on the wire as an X-Amz-Target
// or an Action= parameter, it is implied by the HTTP method, whether the
// request addresses the service / a bucket / an object, and the subresource
// query parameter (?acl, ?tagging, ?uploads, ...). s3Operation reconstructs
// the API operation name (the CloudTrail eventName, e.g. "DeleteObject",
// "ListObjectsV2") so aws.action is a real operation name instead of
// "DELETE /bucket/key".
//
// Both addressing styles are handled: path-style ("s3.amazonaws.com/bucket/key")
// carries the bucket as the first path segment; virtual-host-style
// ("bucket.s3.amazonaws.com/key") carries it in the host, so the whole path
// is the key. s3BucketInHost distinguishes them from the host.

// s3Level is whether a request addresses the service root, a bucket, or an
// object within a bucket.
type s3Level int

const (
	s3Service s3Level = iota // GET / -> ListBuckets
	s3Bucket                 // operates on a bucket
	s3Object                 // operates on an object (key present)
)

// s3BucketInHost reports whether the bucket is encoded in the host
// (virtual-host-style). The host has already been lowercased and resolved to
// service "s3" by parseServiceRegion; here we only need to know whether a
// label precedes the "s3"/"s3-..." service label, which means the leftmost
// label is the bucket.
func s3BucketInHost(host string) bool {
	host = strings.ToLower(host)
	const suffix = ".amazonaws.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(host, suffix), ".")
	// Path-style hosts are exactly "s3", "s3-<region>", "s3.<region>",
	// "s3-fips.<region>", "s3.dualstack.<region>", etc. — the leftmost label
	// always begins with "s3". A virtual-host bucket prepends a label that
	// does not, e.g. "mybucket.s3.us-east-1".
	return len(labels) > 0 && !strings.HasPrefix(labels[0], "s3")
}

// s3Target classifies the request as service/bucket/object addressing.
func s3Target(host, path string) s3Level {
	trimmed := strings.Trim(path, "/")
	if s3BucketInHost(host) {
		if trimmed == "" {
			return s3Bucket
		}
		return s3Object
	}
	if trimmed == "" {
		return s3Service
	}
	if i := strings.IndexByte(trimmed, '/'); i >= 0 && trimmed[i+1:] != "" {
		return s3Object
	}
	return s3Bucket
}

// s3SubresourceOps maps a subresource query key to the operation for each
// method, per addressing level. A missing method entry means that
// method+subresource combination is not a recognized operation and falls back
// to the method/level default. Keys are the S3 subresource query parameters.
var (
	s3BucketSubresource = map[string]map[string]string{
		"acl":                  {"GET": "GetBucketAcl", "PUT": "PutBucketAcl"},
		"policy":               {"GET": "GetBucketPolicy", "PUT": "PutBucketPolicy", "DELETE": "DeleteBucketPolicy"},
		"policyStatus":         {"GET": "GetBucketPolicyStatus"},
		"tagging":              {"GET": "GetBucketTagging", "PUT": "PutBucketTagging", "DELETE": "DeleteBucketTagging"},
		"versioning":           {"GET": "GetBucketVersioning", "PUT": "PutBucketVersioning"},
		"versions":             {"GET": "ListObjectVersions"},
		"location":             {"GET": "GetBucketLocation"},
		"lifecycle":            {"GET": "GetBucketLifecycleConfiguration", "PUT": "PutBucketLifecycleConfiguration", "DELETE": "DeleteBucketLifecycle"},
		"cors":                 {"GET": "GetBucketCors", "PUT": "PutBucketCors", "DELETE": "DeleteBucketCors"},
		"website":              {"GET": "GetBucketWebsite", "PUT": "PutBucketWebsite", "DELETE": "DeleteBucketWebsite"},
		"logging":              {"GET": "GetBucketLogging", "PUT": "PutBucketLogging"},
		"notification":         {"GET": "GetBucketNotificationConfiguration", "PUT": "PutBucketNotificationConfiguration"},
		"replication":          {"GET": "GetBucketReplication", "PUT": "PutBucketReplication", "DELETE": "DeleteBucketReplication"},
		"encryption":           {"GET": "GetBucketEncryption", "PUT": "PutBucketEncryption", "DELETE": "DeleteBucketEncryption"},
		"object-lock":          {"GET": "GetObjectLockConfiguration", "PUT": "PutObjectLockConfiguration"},
		"accelerate":           {"GET": "GetBucketAccelerateConfiguration", "PUT": "PutBucketAccelerateConfiguration"},
		"requestPayment":       {"GET": "GetBucketRequestPayment", "PUT": "PutBucketRequestPayment"},
		"publicAccessBlock":    {"GET": "GetPublicAccessBlock", "PUT": "PutPublicAccessBlock", "DELETE": "DeletePublicAccessBlock"},
		"ownershipControls":    {"GET": "GetBucketOwnershipControls", "PUT": "PutBucketOwnershipControls", "DELETE": "DeleteBucketOwnershipControls"},
		"analytics":            {"GET": "GetBucketAnalyticsConfiguration", "PUT": "PutBucketAnalyticsConfiguration", "DELETE": "DeleteBucketAnalyticsConfiguration"},
		"inventory":            {"GET": "GetBucketInventoryConfiguration", "PUT": "PutBucketInventoryConfiguration", "DELETE": "DeleteBucketInventoryConfiguration"},
		"metrics":              {"GET": "GetBucketMetricsConfiguration", "PUT": "PutBucketMetricsConfiguration", "DELETE": "DeleteBucketMetricsConfiguration"},
		"intelligent-tiering":  {"GET": "GetBucketIntelligentTieringConfiguration", "PUT": "PutBucketIntelligentTieringConfiguration", "DELETE": "DeleteBucketIntelligentTieringConfiguration"},
		"uploads":              {"GET": "ListMultipartUploads"},
		"delete":               {"POST": "DeleteObjects"},
		"object-lambda-acl":    {"GET": "GetBucketAcl", "PUT": "PutBucketAcl"},
		"requestPaymentConfig": {"GET": "GetBucketRequestPayment"},
	}
	s3ObjectSubresource = map[string]map[string]string{
		"acl":        {"GET": "GetObjectAcl", "PUT": "PutObjectAcl"},
		"tagging":    {"GET": "GetObjectTagging", "PUT": "PutObjectTagging", "DELETE": "DeleteObjectTagging"},
		"retention":  {"GET": "GetObjectRetention", "PUT": "PutObjectRetention"},
		"legal-hold": {"GET": "GetObjectLegalHold", "PUT": "PutObjectLegalHold"},
		"torrent":    {"GET": "GetObjectTorrent"},
		"attributes": {"GET": "GetObjectAttributes"},
		"restore":    {"POST": "RestoreObject"},
		"select":     {"POST": "SelectObjectContent"},
	}
)

// s3Operation returns the S3 API operation name for req. body is unused but
// kept for signature symmetry with the other action parsers.
func s3Operation(req *http.Request) string {
	q := req.URL.Query()
	level := s3Target(req.Host, req.URL.Path)
	method := strings.ToUpper(req.Method)

	switch level {
	case s3Service:
		// Only the service root: GET / lists buckets.
		if method == http.MethodGet {
			return "ListBuckets"
		}
		return method + " /"

	case s3Bucket:
		if op := s3SubresourceOp(s3BucketSubresource, q, method); op != "" {
			return op
		}
		switch method {
		case http.MethodGet:
			// list-type=2 is ListObjectsV2; bare GET bucket is the v1 ListObjects.
			if q.Get("list-type") == "2" {
				return "ListObjectsV2"
			}
			return "ListObjects"
		case http.MethodHead:
			return "HeadBucket"
		case http.MethodPut:
			return "CreateBucket"
		case http.MethodDelete:
			return "DeleteBucket"
		case http.MethodPost:
			return "PostBucket"
		}

	case s3Object:
		if op := s3SubresourceOp(s3ObjectSubresource, q, method); op != "" {
			return op
		}
		// Multipart upload lifecycle keys on the uploadId / uploads query.
		if _, ok := q["uploads"]; ok && method == http.MethodPost {
			return "CreateMultipartUpload"
		}
		if q.Get("uploadId") != "" {
			switch method {
			case http.MethodPut:
				if req.Header.Get("X-Amz-Copy-Source") != "" {
					return "UploadPartCopy"
				}
				return "UploadPart"
			case http.MethodPost:
				return "CompleteMultipartUpload"
			case http.MethodDelete:
				return "AbortMultipartUpload"
			case http.MethodGet:
				return "ListParts"
			}
		}
		switch method {
		case http.MethodGet:
			return "GetObject"
		case http.MethodHead:
			return "HeadObject"
		case http.MethodPut:
			if req.Header.Get("X-Amz-Copy-Source") != "" {
				return "CopyObject"
			}
			return "PutObject"
		case http.MethodDelete:
			return "DeleteObject"
		case http.MethodPost:
			return "PostObject"
		}
	}
	// Unknown method: keep it operation-shaped but unmistakably non-standard
	// so it can never accidentally match a read prefix.
	return method + " " + req.URL.Path
}

// s3SubresourceOp returns the operation for the first recognized subresource
// query key present, or "" when none match for this method.
func s3SubresourceOp(table map[string]map[string]string, q map[string][]string, method string) string {
	for key, byMethod := range table {
		if _, present := q[key]; !present {
			continue
		}
		if op, ok := byMethod[method]; ok {
			return op
		}
	}
	return ""
}
