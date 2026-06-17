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
	i := len(labels) - 1
	if i < 0 || labels[i] == "" {
		return "", ""
	}
	// Region is the last label when it's a region code (us-east-1).
	if looksLikeRegion(labels[i]) {
		region = labels[i]
		i--
	}
	// Skip addressing qualifiers between the service and region labels
	// (dualstack / fips), e.g. "<bucket>.s3.dualstack.<region>" — they're
	// not the service.
	for i >= 0 && isAddressingQualifier(labels[i]) {
		i--
	}
	if i < 0 {
		return "", region
	}
	service = labels[i]
	service, region = normalizeS3Endpoint(service, region)
	return service, region
}

func isAddressingQualifier(label string) bool {
	return label == "dualstack" || label == "fips"
}

// normalizeS3Endpoint maps the S3 endpoint host variants to the "s3" SigV4
// signing name and recovers the region from the legacy host forms. Plain S3
// — virtual-host, FIPS, access-point, object-lambda, the legacy dash-region
// and "s3-external-1" aliases — all sign under service name "s3". S3 Control
// keeps its own signing name. The S3 global endpoint signs in us-east-1.
func normalizeS3Endpoint(service, region string) (string, string) {
	switch service {
	case "s3", "s3-accesspoint", "s3-fips", "s3-object-lambda":
		service = "s3"
	case "s3-external-1":
		service, region = "s3", "us-east-1"
	default:
		// Legacy "s3-<region>" dash form, only when the suffix really is a
		// region (so s3-control and similar fall through untouched).
		if region == "" && strings.HasPrefix(service, "s3-") {
			if cand := service[len("s3-"):]; looksLikeRegion(cand) {
				service, region = "s3", cand
			}
		}
	}
	if service == "s3" && region == "" {
		region = "us-east-1"
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
// rds, cloudformation, sqs, sns, ...); REST-JSON services (savingsplans,
// ...) name the operation as the request path ("POST /DescribeSavingsPlans");
// S3 implies it from method + path + subresource (see s3Operation);
// otherwise it falls back to METHOD path. body is the already-read request
// body; service is the SigV4 signing name from the host.
func parseAction(req *http.Request, body []byte, service string) string {
	// S3 is REST: the operation is implied by method + path + subresource,
	// never carried as X-Amz-Target / Action. Reconstruct the operation name.
	if service == "s3" {
		return s3Operation(req)
	}
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
	if op := restJSONPathOperation(service, req.URL.Path); op != "" {
		return op
	}
	return req.Method + " " + req.URL.Path
}

// restJSONOperationServices is the allow-list of AWS services that use the
// REST-JSON protocol with the operation name AS the request path
// ("POST /DescribeSavingsPlans"). For these, and only these, the lone path
// segment is a trustworthy operation name.
//
// This is an allow-list on purpose. For every other service the request path
// is a resource the agent controls — an S3 object key, an execute-api
// customer route, a mediastore object key, a Lambda function name — which an
// attacker could name "GetFoo" / "DeleteBar" to forge a read verdict on a
// write. A deny-list (exclude S3 only) is fail-open: any service not thought
// of is silently opted in. An allow-list is fail-closed: an unknown service
// falls through to "METHOD path" and is gated as a mutation. Add a service
// here only after confirming its wire path really is the operation name.
var restJSONOperationServices = map[string]bool{
	"savingsplans": true,
}

// restJSONPathOperation recovers the operation name of a REST-JSON
// operation-as-path service (see restJSONOperationServices) from a lone
// CamelCase path segment: "POST /DescribeSavingsPlans" ->
// "DescribeSavingsPlans". Without it such reads classify as "POST /<Op>",
// match no read prefix, and fall to the mutation/approval branch. Returns ""
// for any other (or empty) service, and for multi-segment or non-CamelCase
// paths.
func restJSONPathOperation(service, path string) string {
	if !restJSONOperationServices[service] {
		return ""
	}
	seg := strings.Trim(path, "/")
	if seg == "" || strings.ContainsRune(seg, '/') {
		return ""
	}
	if !isOperationName(seg) {
		return ""
	}
	return seg
}

// isOperationName reports whether s has the shape of an AWS operation name:
// an uppercase initial followed by ASCII letters/digits only (CamelCase, no
// separators), e.g. "DescribeSavingsPlans".
func isOperationName(s string) bool {
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
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
