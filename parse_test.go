package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseServiceRegion(t *testing.T) {
	cases := []struct{ host, service, region string }{
		{"s3.amazonaws.com", "s3", ""},
		{"s3.us-west-2.amazonaws.com", "s3", "us-west-2"},
		{"dynamodb.us-east-1.amazonaws.com", "dynamodb", "us-east-1"},
		{"execute-api.eu-west-1.amazonaws.com", "execute-api", "eu-west-1"},
		{"iam.amazonaws.com", "iam", ""},
		{"DynamoDB.US-East-1.amazonaws.com", "dynamodb", "us-east-1"}, // case-folded
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
	mk := func(target, rawquery, method, path string) *http.Request {
		r := &http.Request{Method: method, Header: http.Header{}, URL: &url.URL{Path: path, RawQuery: rawquery}}
		if target != "" {
			r.Header.Set("X-Amz-Target", target)
		}
		return r
	}
	cases := []struct {
		name string
		req  *http.Request
		want string
	}{
		{"json target", mk("DynamoDB_20120810.PutItem", "", "POST", "/"), "PutItem"},
		{"target no dot", mk("Discovery", "", "POST", "/"), "Discovery"},
		{"query action", mk("", "Action=DescribeInstances&Version=2016-11-15", "POST", "/"), "DescribeInstances"},
		{"s3 fallback", mk("", "", "DELETE", "/bucket/key"), "DELETE /bucket/key"},
	}
	for _, c := range cases {
		if got := parseAction(c.req); got != c.want {
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
