package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestParseServiceRegion(t *testing.T) {
	cases := []struct{ host, service, region string }{
		// S3 global signs in us-east-1.
		{"s3.amazonaws.com", "s3", "us-east-1"},
		{"my-bucket.s3.amazonaws.com", "s3", "us-east-1"},
		{"s3.us-west-2.amazonaws.com", "s3", "us-west-2"},
		{"dynamodb.us-east-1.amazonaws.com", "dynamodb", "us-east-1"},
		{"execute-api.eu-west-1.amazonaws.com", "execute-api", "eu-west-1"},
		{"iam.amazonaws.com", "iam", ""},
		{"DynamoDB.US-East-1.amazonaws.com", "dynamodb", "us-east-1"}, // case-folded
		// Virtual-host-style S3: service is "s3", not the bucket name.
		{"my-bucket.s3.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"clawpatrol-avocet2-test-820178564529.s3.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"dotted.bucket.name.s3.us-west-2.amazonaws.com", "s3", "us-west-2"},
		// Dualstack / FIPS qualifiers sit between service and region.
		{"s3.dualstack.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"my-bucket.s3.dualstack.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"s3-fips.us-east-1.amazonaws.com", "s3", "us-east-1"},
		// Access points / object lambda sign as "s3".
		{"my-ap.s3-accesspoint.us-east-1.amazonaws.com", "s3", "us-east-1"},
		{"my-ol.s3-object-lambda.us-east-1.amazonaws.com", "s3", "us-east-1"},
		// Legacy dash-region + the s3-external-1 us-east-1 alias.
		{"s3-us-west-2.amazonaws.com", "s3", "us-west-2"},
		{"my-bucket.s3-eu-west-1.amazonaws.com", "s3", "eu-west-1"},
		{"s3-external-1.amazonaws.com", "s3", "us-east-1"},
		// S3 Control keeps its own signing name.
		{"s3-control.us-east-1.amazonaws.com", "s3-control", "us-east-1"},
		// GovCloud region (4 parts).
		{"sts.us-gov-west-1.amazonaws.com", "sts", "us-gov-west-1"},
		{"example.com", "", ""},
	}
	for _, c := range cases {
		s, r := parseServiceRegion(c.host)
		if s != c.service || r != c.region {
			t.Errorf("parseServiceRegion(%q) = (%q,%q), want (%q,%q)", c.host, s, r, c.service, c.region)
		}
	}
}

func TestParseAction(t *testing.T) {
	const formCT = "application/x-www-form-urlencoded"
	mk := func(target, rawquery, method, path, contentType string) *http.Request {
		r := &http.Request{Method: method, Header: http.Header{}, URL: &url.URL{Path: path, RawQuery: rawquery}}
		if target != "" {
			r.Header.Set("X-Amz-Target", target)
		}
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		return r
	}
	cases := []struct {
		name    string
		req     *http.Request
		body    string
		service string
		want    string // "" together with wantErr: the request is refused
		wantErr bool
	}{
		{"json target", mk("DynamoDB_20120810.PutItem", "", "POST", "/", ""), "", "dynamodb", "PutItem", false},
		{"target no dot", mk("Discovery", "", "POST", "/", ""), "", "discovery", "Discovery", false},
		{"query action in url", mk("", "Action=DescribeInstances&Version=2016-11-15", "POST", "/", ""), "", "ec2", "DescribeInstances", false},
		{"query action in form body", mk("", "", "POST", "/", formCT), "Action=DescribeRegions&Version=2016-11-15", "ec2", "DescribeRegions", false},
		{"form body charset suffix", mk("", "", "POST", "/", formCT+"; charset=utf-8"), "Action=DescribeVpcs", "ec2", "DescribeVpcs", false},
		{"form body no action", mk("", "", "POST", "/", formCT), "Version=2016-11-15", "ec2", "POST /", false},
		{"non-form body ignored", mk("", "", "POST", "/path", "application/json"), "Action=ShouldNotMatch", "lambda", "POST /path", false},
		// S3 routes through s3Operation (covered in s3op_test.go); here we only
		// confirm parseAction dispatches S3 to it instead of the METHOD-path
		// fallback. A read-verby object key is still a write (PutObject), not a
		// forged read.
		{"s3 delete object", mk("", "", "DELETE", "/bucket/key", ""), "", "s3", "DeleteObject", false},
		// REST-JSON operation-as-path (savingsplans, allow-listed): recover op.
		{"restjson read op", mk("", "", "POST", "/DescribeSavingsPlans", "application/json"), "", "savingsplans", "DescribeSavingsPlans", false},
		{"restjson mutation op", mk("", "", "POST", "/CreateSavingsPlan", "application/json"), "", "savingsplans", "CreateSavingsPlan", false},
		// Only a lone segment counts even for an allow-listed service.
		{"savingsplans multi-segment", mk("", "", "POST", "/Foo/Bar", "application/json"), "", "savingsplans", "POST /Foo/Bar", false},
		{"savingsplans dot segment", mk("", "", "POST", "/../Foo", "application/json"), "", "savingsplans", "POST /../Foo", false},
		// Allow-list is fail-closed: non-allow-listed services whose path is an
		// arbitrary, agent-controlled resource must NOT have a CamelCase
		// segment read as an operation — that would forge a read verdict on a
		// write and bypass the approval gate.
		{"execute-api forged read not op", mk("", "", "DELETE", "/GetThing", "application/json"), "", "execute-api", "DELETE /GetThing", false},
		{"mediastore forged read not op", mk("", "", "DELETE", "/GetReport", ""), "", "mediastore", "DELETE /GetReport", false},
		{"s3 object put with read-verby key", mk("", "", "PUT", "/bucket/DescribeThing", ""), "", "s3", "PutObject", false},
		{"empty service not op", mk("", "", "POST", "/GetThing", "application/json"), "", "", "POST /GetThing", false},
		// Resource-path services are also not allow-listed.
		{"lowercase segment not op", mk("", "", "POST", "/functions", "application/json"), "", "lambda", "POST /functions", false},
		{"versioned multi-segment not op", mk("", "", "POST", "/2013-04-01/hostedzone", ""), "", "route53", "POST /2013-04-01/hostedzone", false},
		// Operation-name confusion: the agent writes the whole request, so a
		// slot the service ignores is a decoy. EC2 ignores X-Amz-Target and
		// runs the form body; ranking the header first would gate a
		// termination as a read. Conflicting names are refused, not ranked.
		{"target decoy over form body", mk("AmazonEC2.DescribeRegions", "", "POST", "/", formCT), "Action=TerminateInstances&Version=2016-11-15", "ec2", "", true},
		// The body is read as a form whatever the Content-Type claims: EC2
		// dispatches a form body sent as application/json just the same.
		{"target decoy with json content type", mk("AmazonEC2.DescribeRegions", "", "POST", "/", "application/json"), "Action=TerminateInstances&Version=2016-11-15", "ec2", "", true},
		{"form body action despite json content type", mk("", "", "POST", "/", "application/json"), "Action=TerminateInstances&Version=2016-11-15", "ec2", "TerminateInstances", false},
		{"url decoy over form body", mk("", "Action=DescribeRegions", "POST", "/", formCT), "Action=TerminateInstances", "ec2", "", true},
		{"url decoy over json target", mk("DynamoDB_20120810.DeleteItem", "Action=ListTables", "POST", "/", "application/x-amz-json-1.0"), "", "dynamodb", "", true},
		// Duplicates disagree across services (EC2 runs the last in a body,
		// IAM and STS the first), so both values count.
		{"duplicate action in body", mk("", "", "POST", "/", formCT), "Action=DescribeRegions&Action=TerminateInstances", "ec2", "", true},
		{"duplicate action in url", mk("", "Action=ListUsers&Action=DeleteUser", "POST", "/", ""), "", "iam", "", true},
		{"duplicate action agreeing", mk("", "", "POST", "/", formCT), "Action=DescribeRegions&Action=DescribeRegions", "ec2", "DescribeRegions", false},
		{"url and body action agreeing", mk("", "Action=DescribeRegions", "POST", "/", formCT), "Action=DescribeRegions", "ec2", "DescribeRegions", false},
		// Off the service root the operation is the path; a name planted in
		// the header, the query or the body must not rename it.
		{"lambda invoke url decoy", mk("", "Action=ListFunctions", "POST", "/2015-03-31/functions/f/invocations", "application/json"), "", "lambda", "POST /2015-03-31/functions/f/invocations", false},
		{"lambda invoke target decoy", mk("AWSLambda.ListFunctions", "", "POST", "/2015-03-31/functions/f/invocations", "application/json"), "", "lambda", "POST /2015-03-31/functions/f/invocations", false},
		{"lambda invoke form-body decoy payload", mk("", "", "POST", "/2015-03-31/functions/f/invocations", formCT), "Action=ListFunctions", "lambda", "POST /2015-03-31/functions/f/invocations", false},
		{"savingsplans target decoy", mk("Foo.DescribeSavingsPlans", "", "POST", "/CreateSavingsPlan", "application/json"), "", "savingsplans", "CreateSavingsPlan", false},
		// A target that cannot name an AWS operation names nothing.
		{"non-operation-shaped target", mk("foo-bar", "", "POST", "/", ""), "", "discovery", "POST /", false},
		// Too large to scan: no operation name at all, so it is gated as a
		// mutation rather than trusted from the header.
		{"oversized body ignores target", mk("DynamoDB_20120810.PutItem", "", "POST", "/", "application/x-amz-json-1.0"), strings.Repeat("x", maxActionScanBody+1), "dynamodb", "POST /", false},
	}
	for _, c := range cases {
		got, err := parseAction(c.req, []byte(c.body), c.service)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: parseAction = %q, want a refusal", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: parseAction refused unexpectedly: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: parseAction = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAccessKeyFromAuthorization(t *testing.T) {
	cases := []struct{ authz, want string }{
		{"AWS4-HMAC-SHA256 Credential=AKIA035475582903XXXX/20240101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=ab", "AKIA035475582903XXXX"},
		{"Bearer xyz", ""},
		{"", ""},
		{"AWS4-HMAC-SHA256 Credential=AKIANOSLASH", ""},
	}
	for _, c := range cases {
		if got := accessKeyFromAuthorization(c.authz); got != c.want {
			t.Errorf("accessKeyFromAuthorization(%q) = %q, want %q", c.authz, got, c.want)
		}
	}
}

func TestAccountFromAuthorization(t *testing.T) {
	cases := []struct{ authz, want string }{
		{"AWS4-HMAC-SHA256 Credential=AKIA035475582903XXXX/20240101/us-east-1/s3/aws4_request", "035475582903"},
		{"AWS4-HMAC-SHA256 Credential=AKIA0582642866010000/20240101/us-east-1/s3/aws4_request", "058264286601"},
		{"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240101/us-east-1/s3/aws4_request", ""}, // no 12-digit run
		{"Bearer token", ""},
	}
	for _, c := range cases {
		if got := accountFromAuthorization(c.authz); got != c.want {
			t.Errorf("accountFromAuthorization(%q) = %q, want %q", c.authz, got, c.want)
		}
	}
}

func TestFirst12DigitRun(t *testing.T) {
	cases := []struct{ in, want string }{
		{"AKIA035475582903XXXX", "035475582903"},
		{"12345678901", ""}, // only 11
		{"123456789012", "123456789012"},
		{"ab1234cd5678ef9012", ""}, // no 12 consecutive
		{"x123456789012y", "123456789012"},
	}
	for _, c := range cases {
		if got := first12DigitRun(c.in); got != c.want {
			t.Errorf("first12DigitRun(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAllowed(t *testing.T) {
	for _, a := range []string{"allow", "hitl_allow"} {
		if !allowed(a) {
			t.Errorf("allowed(%q) = false, want true", a)
		}
	}
	for _, a := range []string{"deny", "hitl_deny", "error", ""} {
		if allowed(a) {
			t.Errorf("allowed(%q) = true, want false", a)
		}
	}
}
