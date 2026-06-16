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
