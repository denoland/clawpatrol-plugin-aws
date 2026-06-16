package main

import (
	"net/http"
	"strings"
)

// parseServiceRegion derives the AWS service and region from the host,
// e.g. "dynamodb.us-east-1.amazonaws.com" -> ("dynamodb", "us-east-1"),
// "s3.amazonaws.com" -> ("s3", "").
func parseServiceRegion(host string) (service, region string) {
	host = strings.ToLower(host)
	const suffix = ".amazonaws.com"
	if !strings.HasSuffix(host, suffix) {
		return "", ""
	}
	labels := strings.Split(strings.TrimSuffix(host, suffix), ".")
	if len(labels) == 0 || labels[0] == "" {
		return "", ""
	}
	service = labels[0]
	if len(labels) >= 2 && looksLikeRegion(labels[1]) {
		region = labels[1]
	}
	return service, region
}

func looksLikeRegion(s string) bool {
	// e.g. us-east-1, eu-west-2, ap-southeast-1.
	return strings.Count(s, "-") >= 2
}

// parseAction extracts the operation name. JSON-protocol services carry it
// in X-Amz-Target ("DynamoDB_20120810.PutItem" -> "PutItem"); query
// services in an Action parameter; otherwise it falls back to METHOD path.
func parseAction(req *http.Request) string {
	if t := req.Header.Get("X-Amz-Target"); t != "" {
		if i := strings.LastIndex(t, "."); i >= 0 {
			return t[i+1:]
		}
		return t
	}
	if a := req.URL.Query().Get("Action"); a != "" {
		return a
	}
	return req.Method + " " + req.URL.Path
}

// accessKeyFromAuthorization pulls the access key id out of a SigV4
// Authorization header:
//
//	AWS4-HMAC-SHA256 Credential=AKIA…/20240101/us-east-1/s3/aws4_request, …
//
// returning "AKIA…" (the part before the first "/" of the credential
// scope), or "" if the header isn't SigV4.
func accessKeyFromAuthorization(authz string) string {
	const marker = "Credential="
	i := strings.Index(authz, marker)
	if i < 0 {
		return ""
	}
	rest := authz[i+len(marker):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return ""
}

// accountFromAuthorization derives the target 12-digit AWS account id from
// the agent's request. The operator encodes the account id in the agent's
// per-account placeholder access key id (e.g. "AKIA035475582903XXXX"); this
// returns the first 12-consecutive-digit run found in it, or "".
func accountFromAuthorization(authz string) string {
	return first12DigitRun(accessKeyFromAuthorization(authz))
}

func first12DigitRun(s string) string {
	run := 0
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			if run == 0 {
				start = i
			}
			run++
			if run == 12 {
				return s[start : start+12]
			}
		} else {
			run = 0
		}
	}
	return ""
}
