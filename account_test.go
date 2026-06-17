package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestAccountName(t *testing.T) {
	accts := []string{"820178564529=arnau-sandbox", " 035475582903 = denoland ", "malformed-no-eq"}
	cases := []struct{ id, want string }{
		{"820178564529", "arnau-sandbox"},
		{"035475582903", "denoland"}, // surrounding spaces trimmed
		{"000000000000", ""},
	}
	for _, c := range cases {
		if got := accountName(accts, c.id); got != c.want {
			t.Errorf("accountName(%q) = %q, want %q", c.id, got, c.want)
		}
	}
	if got := accountName(nil, "820178564529"); got != "" {
		t.Errorf("accountName(nil) = %q, want empty", got)
	}
}

func TestApprovalSummary(t *testing.T) {
	mk := func(method, path string) *http.Request {
		return &http.Request{Method: method, URL: &url.URL{Path: path}}
	}
	// Named account, REST op (no redundant operation suffix).
	got := approvalSummary(mk("PUT", "/key"), "s3", "PUT /key", "us-east-1", "820178564529", "arnau-sandbox", "s3.us-east-1.amazonaws.com")
	if want := "PUT s3 s3.us-east-1.amazonaws.com/key in account arnau-sandbox (820178564529) us-east-1"; got != want {
		t.Errorf("named summary = %q, want %q", got, want)
	}
	// Unnamed account, query-protocol op (operation name surfaced).
	got = approvalSummary(mk("POST", "/"), "ec2", "TerminateInstances", "us-east-1", "820178564529", "", "ec2.us-east-1.amazonaws.com")
	if want := "POST ec2 ec2.us-east-1.amazonaws.com/ [TerminateInstances] in account 820178564529 us-east-1"; got != want {
		t.Errorf("unnamed summary = %q, want %q", got, want)
	}
}
