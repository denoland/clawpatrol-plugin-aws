package main

import (
	"fmt"
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

// parseAction extracts the operation name AWS will dispatch on. JSON-protocol
// services carry it in X-Amz-Target ("DynamoDB_20120810.PutItem" ->
// "PutItem"); query services in an Action parameter — in the URL query, or in
// the form-encoded body of a POST (ec2, iam, sts, autoscaling, rds,
// cloudformation, sqs, sns, ...); REST-JSON services (savingsplans, ...) name
// the operation as the request path ("POST /DescribeSavingsPlans"); S3 implies
// it from method + path + subresource (see s3Operation); otherwise it falls
// back to METHOD path. body is the already-read request body; service is the
// SigV4 signing name from the host.
//
// The plugin does not know which protocol a service speaks, so it must not
// rank those sources against each other. The agent writes the whole request,
// and a source the service ignores is not inert — it is a free decoy. Ranking
// X-Amz-Target above the form body, for instance, lets "X-Amz-Target:
// x.DescribeRegions" on a POST whose body says "Action=TerminateInstances"
// be gated as a read while EC2 runs the termination: EC2 ignores the header
// entirely (verified on the wire). So every operation name the request
// carries is collected instead, and a request carrying two distinct ones is
// refused with a non-nil error rather than classified by a guess.
func parseAction(req *http.Request, body []byte, service string) (string, error) {
	// S3 is REST: the operation is implied by method + path + subresource,
	// never carried as X-Amz-Target / Action. Reconstruct the operation name.
	if service == "s3" {
		return s3Operation(req), nil
	}
	names := actionCandidates(req, body)
	if len(names) > 1 {
		return "", fmt.Errorf("request carries conflicting operation names (%s); "+
			"refusing rather than guessing which one AWS would run",
			strings.Join(names, ", "))
	}
	if len(names) == 1 {
		return names[0], nil
	}
	if op := restJSONPathOperation(service, req.URL.Path); op != "" {
		return op, nil
	}
	return req.Method + " " + req.URL.Path, nil
}

// maxActionScanBody bounds the body the action parse looks at. Past it the
// request is treated as naming no operation at all — not even by its
// X-Amz-Target — so it falls through to "METHOD path" and is gated as a
// mutation. Fail-closed on purpose: a body too large to scan is a body we
// cannot rule out an "Action=" in, and every AWS request that names its
// operation this way is orders of magnitude smaller (S3, the one service with
// large bodies, never reaches here).
const maxActionScanBody = 4 << 20

// actionCandidates returns the distinct operation names req carries, in source
// order, or nothing when the request names no operation and the caller should
// fall back to the path.
//
// A name counts only when the request addresses the service root ("/"). Every
// protocol that names its operation in the headers, the query or the body
// addresses "/" — the JSON protocols and the query protocol both POST there.
// On any other path the operation is the path, and the path is an
// agent-controlled resource: a Lambda function name, an execute-api route, a
// mediastore key. Honoring a name from elsewhere in the request there would
// let "POST /2015-03-31/functions/f/invocations?Action=ListFunctions" be gated
// as a read while Lambda runs the function. (The cost is the query protocol's
// resource-path form — the legacy SQS queue-URL endpoints — which now falls
// through to "METHOD path" and is gated as a mutation. Current SDKs call SQS
// over the JSON protocol at "/".)
//
// The body is read as a form whatever the Content-Type says, because the
// services that dispatch on it do the same: EC2 runs a form-encoded body sent
// as application/json (verified on the wire), so gating on the header would
// leave the decoy open.
//
// Every value of a repeated Action counts, not just the first: services
// disagree on which duplicate wins (on the wire, EC2 takes the last one in a
// body, IAM and STS the first), so a body carrying both
// "Action=DescribeRegions" and "Action=TerminateInstances" is ambiguous, not
// a read.
//
// Only operation-shaped values count (see isOperationName), so an ordinary
// JSON body contributes nothing. A JSON body that does contain something like
// "&Action=DeleteThing" is flagged and the request refused: that is the same
// text a query service would dispatch on, so it is genuinely ambiguous.
func actionCandidates(req *http.Request, body []byte) []string {
	if req.URL.Path != "/" && req.URL.Path != "" {
		return nil
	}
	if len(body) > maxActionScanBody {
		return nil
	}
	var names []string
	add := func(n string) {
		if !isOperationName(n) {
			return
		}
		for _, have := range names {
			if have == n {
				return
			}
		}
		names = append(names, n)
	}
	add(targetOperation(req.Header.Get("X-Amz-Target")))
	for _, a := range req.URL.Query()["Action"] {
		add(a)
	}
	for _, a := range formActions(body) {
		add(a)
	}
	return names
}

// targetOperation is the operation an X-Amz-Target header names:
// "DynamoDB_20120810.PutItem" -> "PutItem", or the whole value when it carries
// no service prefix.
func targetOperation(target string) string {
	if i := strings.LastIndex(target, "."); i >= 0 {
		return target[i+1:]
	}
	return target
}

// formActions returns every value of the "Action" parameter in a form-encoded
// request body. AWS query-protocol services POST
// "Action=DescribeRegions&Version=..." as application/x-www-form-urlencoded,
// but they parse that body whatever the Content-Type says, so this does too.
// A malformed body still yields the pairs that did parse: the goal is to see
// every Action AWS could see, not to validate the body.
func formActions(body []byte) []string {
	vals, _ := url.ParseQuery(string(body))
	return vals["Action"]
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
