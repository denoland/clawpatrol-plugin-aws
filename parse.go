package main

import (
	"net/http"
	"net/url"
	"strings"
)

// parseServiceRegion derives the AWS service and region from the host,
// e.g. "dynamodb.us-east-1.amazonaws.com" -> ("dynamodb", "us-east-1"),
// "s3.amazonaws.com" -> ("s3", "").
//
// The region, when present, is the last label before ".amazonaws.com"
// (us-east-1); the service is the label just before it. When the last
// label isn't a region the service is that last label itself (iam, s3).
// Anchoring on the region label this way means virtual-host-style S3
// ("<bucket>.s3.<region>.amazonaws.com", or "<bucket>.s3.amazonaws.com")
// resolves to service "s3" rather than the bucket name — getting the
// service wrong breaks the SigV4 re-signing (AuthorizationHeaderMalformed).
func parseServiceRegion(host string) (service, region string) {
	host = strings.ToLower(host)
	const suffix = ".amazonaws.com"
	if !strings.HasSuffix(host, suffix) {
		return "", ""
	}
	labels := strings.Split(strings.TrimSuffix(host, suffix), ".")
	n := len(labels)
	if n == 0 || labels[n-1] == "" {
		return "", ""
	}
	if looksLikeRegion(labels[n-1]) {
		region = labels[n-1]
		if n >= 2 {
			service = labels[n-2]
		}
	} else {
		service = labels[n-1]
	}
	// Legacy dash-region S3 endpoints: "s3-us-west-2" -> service "s3",
	// region "us-west-2" (also "<bucket>.s3-us-west-2.amazonaws.com").
	if region == "" && strings.HasPrefix(service, "s3-") {
		region = strings.TrimPrefix(service, "s3-")
		service = "s3"
	}
	return service, region
}

// looksLikeRegion reports whether label is an AWS region code such as
// us-east-1, eu-west-2, ap-southeast-1, or us-gov-west-1: a 2-letter geo
// prefix and a numeric suffix, at least three dash-separated parts. The
// geo-prefix check keeps service labels that merely contain dashes
// (execute-api) or an "s3-<region>" endpoint label from being mistaken
// for a region.
func looksLikeRegion(label string) bool {
	parts := strings.Split(label, "-")
	if len(parts) < 3 {
		return false
	}
	if len(parts[0]) != 2 || !isLowerLetters(parts[0]) {
		return false
	}
	return isDigits(parts[len(parts)-1])
}

func isLowerLetters(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// parseAction extracts the operation name. JSON-protocol services carry it
// in X-Amz-Target ("DynamoDB_20120810.PutItem" -> "PutItem"); query
// services in an Action parameter — in the URL query for GET requests, or
// in the form-encoded body for POST requests (ec2, iam, sts, autoscaling,
// rds, cloudformation, sqs, sns, ...); otherwise it falls back to METHOD
// path (S3-style REST: "DELETE /bucket/key"). body is the already-read
// request body.
func parseAction(req *http.Request, body []byte) string {
	if t := req.Header.Get("X-Amz-Target"); t != "" {
		if i := strings.LastIndex(t, "."); i >= 0 {
			return t[i+1:]
		}
		return t
	}
	if a := req.URL.Query().Get("Action"); a != "" {
		return a
	}
	if a := formAction(req, body); a != "" {
		return a
	}
	return req.Method + " " + req.URL.Path
}

// formAction returns the Action parameter from a query-protocol request's
// form-encoded body, or "" when the request isn't form-encoded or carries
// no Action. AWS query-protocol services POST
// "Action=DescribeRegions&Version=..." as application/x-www-form-urlencoded.
func formAction(req *http.Request, body []byte) string {
	ct := req.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return ""
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}
	return vals.Get("Action")
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
