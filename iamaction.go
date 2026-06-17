package main

import "strings"

// iamAction maps a (wire service, API operation/event name) to the IAM action
// string used in policies, e.g. ("s3", "ListObjectsV2") -> "s3:ListBucket",
// ("ec2", "DescribeInstances") -> "ec2:DescribeInstances".
//
// For the overwhelming majority of services and operations the IAM action is
// simply "<service>:<Operation>". Two kinds of divergence are corrected:
//
//   - The IAM service prefix differs from the host's service label
//     (monitoring -> cloudwatch, email -> ses, ...). See iamServicePrefix.
//   - S3, whose IAM action names are historically irregular and frequently
//     differ from the API operation name (ListObjectsV2 -> s3:ListBucket,
//     GetBucketLifecycleConfiguration -> s3:GetLifecycleConfiguration, ...).
//     See s3IAMAction.
//
// iam_action is best-effort: exact for the common data-plane operations and
// the curated divergences below, and "<service>:<Operation>" otherwise. It
// returns "" when no operation could be determined (event empty or a raw
// "METHOD path" fallback), so the caller omits the facet field and any rule
// matching on aws.iam_action fails closed rather than matching a guess.
func iamAction(service, event string) string {
	if service == "" || event == "" || strings.ContainsAny(event, " /") {
		return ""
	}
	if service == "s3" {
		if a, ok := s3IAMAction[event]; ok {
			return a
		}
	}
	return iamServicePrefix(service) + ":" + event
}

// iamServicePrefix maps a host service label to its IAM action prefix when the
// two differ; otherwise the service label is the prefix.
func iamServicePrefix(service string) string {
	if p, ok := iamPrefixOverride[service]; ok {
		return p
	}
	return service
}

var iamPrefixOverride = map[string]string{
	"monitoring":       "cloudwatch",
	"email":            "ses",
	"streams.dynamodb": "dynamodb",
}

// s3IAMAction overrides the S3 API operation -> IAM action where they differ.
// Operations absent here use the "s3:<Operation>" default, which is correct
// for the bulk of S3 (GetObject, PutObject, DeleteObject, GetBucketPolicy,
// GetBucketTagging, GetBucketAcl, GetBucketLocation, ...).
var s3IAMAction = map[string]string{
	"ListBuckets":             "s3:ListAllMyBuckets",
	"ListObjects":             "s3:ListBucket",
	"ListObjectsV2":           "s3:ListBucket",
	"HeadBucket":              "s3:ListBucket",
	"ListObjectVersions":      "s3:ListBucketVersions",
	"ListMultipartUploads":    "s3:ListBucketMultipartUploads",
	"ListParts":               "s3:ListMultipartUploadParts",
	"HeadObject":              "s3:GetObject",
	"SelectObjectContent":     "s3:GetObject",
	"CopyObject":              "s3:PutObject",
	"UploadPart":              "s3:PutObject",
	"UploadPartCopy":          "s3:PutObject",
	"CreateMultipartUpload":   "s3:PutObject",
	"CompleteMultipartUpload": "s3:PutObject",
	"PostObject":              "s3:PutObject",
	"DeleteObjects":           "s3:DeleteObject",
	// Bucket configuration subresources whose IAM action name drops "Bucket"
	// or otherwise differs from the API operation name.
	"GetBucketLifecycleConfiguration":    "s3:GetLifecycleConfiguration",
	"PutBucketLifecycleConfiguration":    "s3:PutLifecycleConfiguration",
	"DeleteBucketLifecycle":              "s3:PutLifecycleConfiguration",
	"GetBucketCors":                      "s3:GetBucketCORS",
	"PutBucketCors":                      "s3:PutBucketCORS",
	"DeleteBucketCors":                   "s3:PutBucketCORS",
	"GetBucketReplication":               "s3:GetReplicationConfiguration",
	"PutBucketReplication":               "s3:PutReplicationConfiguration",
	"DeleteBucketReplication":            "s3:PutReplicationConfiguration",
	"GetBucketEncryption":                "s3:GetEncryptionConfiguration",
	"PutBucketEncryption":                "s3:PutEncryptionConfiguration",
	"DeleteBucketEncryption":             "s3:PutEncryptionConfiguration",
	"GetBucketNotificationConfiguration": "s3:GetBucketNotification",
	"PutBucketNotificationConfiguration": "s3:PutBucketNotification",
	"GetBucketAccelerateConfiguration":   "s3:GetAccelerateConfiguration",
	"PutBucketAccelerateConfiguration":   "s3:PutAccelerateConfiguration",
	"GetObjectLockConfiguration":         "s3:GetBucketObjectLockConfiguration",
	"PutObjectLockConfiguration":         "s3:PutBucketObjectLockConfiguration",
}
