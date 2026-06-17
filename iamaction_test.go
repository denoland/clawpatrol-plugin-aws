package main

import "testing"

func TestIAMAction(t *testing.T) {
	cases := []struct {
		service, event, want string
	}{
		// Default: <service>:<Operation>.
		{"ec2", "DescribeInstances", "ec2:DescribeInstances"},
		{"dynamodb", "PutItem", "dynamodb:PutItem"},
		{"savingsplans", "DescribeSavingsPlans", "savingsplans:DescribeSavingsPlans"},
		{"s3", "GetObject", "s3:GetObject"},
		{"s3", "PutObject", "s3:PutObject"},
		{"s3", "DeleteObject", "s3:DeleteObject"},
		{"s3", "GetBucketPolicy", "s3:GetBucketPolicy"},
		// S3 list family diverges from the API operation name.
		{"s3", "ListObjectsV2", "s3:ListBucket"},
		{"s3", "ListObjects", "s3:ListBucket"},
		{"s3", "HeadObject", "s3:GetObject"},
		{"s3", "HeadBucket", "s3:ListBucket"},
		{"s3", "ListObjectVersions", "s3:ListBucketVersions"},
		{"s3", "CopyObject", "s3:PutObject"},
		{"s3", "GetBucketLifecycleConfiguration", "s3:GetLifecycleConfiguration"},
		// Service-prefix overrides.
		{"monitoring", "GetMetricData", "cloudwatch:GetMetricData"},
		{"email", "SendEmail", "ses:SendEmail"},
		// Unresolvable -> "" so the caller omits the field (fail closed).
		{"", "GetObject", ""},
		{"s3", "", ""},
		{"s3", "POST /bucket/key", ""},
		{"execute-api", "DELETE /GetThing", ""},
	}
	for _, c := range cases {
		if got := iamAction(c.service, c.event); got != c.want {
			t.Errorf("iamAction(%q,%q) = %q, want %q", c.service, c.event, got, c.want)
		}
	}
}
